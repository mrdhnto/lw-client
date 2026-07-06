#!/usr/bin/env node

import { Command } from 'commander'
import { WebSocket } from 'ws'
import { scanPath } from './scanner.js'
import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import { machineIdSync } from 'node-machine-id'
import * as dotenv from 'dotenv'
import keytar from 'keytar'

// Load .env if present
dotenv.config({ path: path.join(process.cwd(), '.env') })

const CONFIG_PATH = path.join(os.homedir(), '.lw-client.json')

async function loadConfig() {
  try {
    let config = null
    if (fs.existsSync(CONFIG_PATH)) {
      config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'))
    }
    
    // Migrate legacy plaintext token if it exists
    if (config && config.token) {
      await keytar.setPassword('library-watcher', 'client-token', config.token)
      const migratedConfig = { url: config.url }
      fs.writeFileSync(CONFIG_PATH, JSON.stringify(migratedConfig, null, 2))
      return config
    }
    
    if (config && config.url) {
      const secureToken = await keytar.getPassword('library-watcher', 'client-token')
      return { url: config.url, token: secureToken }
    }
    return null
  } catch (err) {
    console.error('Failed to load config:', err)
    return null
  }
}

async function saveConfig(data) {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true })
  
  if (data.token) {
    await keytar.setPassword('library-watcher', 'client-token', data.token)
  }
  
  const publicConfig = { url: data.url }
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(publicConfig, null, 2))
}

const program = new Command()

program
  .name('lw-client')
  .description('Library Watcher remote scanning client')
  .option('-u, --url <url>', 'WebSocket server URL (e.g. ws://192.168.1.1:8080/api/client/ws)')
  .option('-t, --token <token>', 'Authentication token')
  .action(async () => {
    const opts = program.opts()
    if (opts.url && opts.token) {
      await saveConfig({ url: opts.url, token: opts.token })
      start(opts.url, opts.token)
    } else if (opts.url || opts.token) {
      console.error('Both --url and --token are required for first-time setup')
      process.exit(1)
    } else {
      program.help()
    }
  })

program
  .command('connect')
  .description('Connect using saved configuration')
  .action(async () => {
    const config = await loadConfig()
    if (!config || !config.url || !config.token) {
      console.error('No saved configuration or token found. Run: lw-client -u <url> -t <token>')
      process.exit(1)
    }
    start(config.url, config.token)
  })

program.parse(process.argv)

async function start(wsUrl, tokenOrRefresh) {
  // Determine if we should force WSS vs WS
  const isForceWss = process.env.FORCE_WSS === 'true'
  const isDev = process.env.NODE_ENV === 'development'
  
  // Format URL properly
  let parsedUrl
  let url = wsUrl
  try {
    if (!url.startsWith('ws://') && !url.startsWith('wss://')) {
      const defaultProtocol = isForceWss || !isDev ? 'wss://' : 'ws://'
      url = `${defaultProtocol}${url}`
    }
    
    if (isForceWss && url.startsWith('ws://')) {
      url = url.replace('ws://', 'wss://')
    }
    parsedUrl = new URL(url)
  } catch (e) {
    console.error('Invalid URL provided:', url)
    process.exit(1)
  }

  const httpUrl = url.replace('ws://', 'http://').replace('wss://', 'https://').replace('/api/client/ws', '')
  let hardwareId = 'unknown'

  try {
    hardwareId = machineIdSync()
  } catch (err) {
    console.error('Warning: Failed to generate hardware fingerprint:', err.message)
  }

  // Auth logic: Exchange token for JWT
  let accessToken = null
  let tempCreds = null

  async function authenticate() {
    try {
      // If we are connecting normally, read refresh token from keytar
      let refreshToken = await keytar.getPassword('library-watcher', 'client-token')
      let isFirstTime = false

      // If tokenOrRefresh is provided from command line, and it's not the refresh token we just loaded
      if (tokenOrRefresh && tokenOrRefresh !== refreshToken) {
        isFirstTime = true
      }

      if (isFirstTime) {
        console.log('Authenticating with registration token...')
        const res = await fetch(`${httpUrl}/api/client/auth`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token: tokenOrRefresh, hostname: os.hostname(), hardwareId })
        })
        
        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.message || 'Authentication failed')
        }
        
        const data = await res.json()
        await keytar.setPassword('library-watcher', 'client-token', data.refreshToken)
        accessToken = data.accessToken
        tempCreds = data.tempCreds
        
        // Remove tokenOrRefresh so future reconnects use the refresh token
        tokenOrRefresh = null
      } else if (refreshToken) {
        console.log('Refreshing session token...')
        const res = await fetch(`${httpUrl}/api/client/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refreshToken })
        })
        
        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.message || 'Failed to refresh token')
        }
        
        const data = await res.json()
        accessToken = data.accessToken
      } else {
        throw new Error('No valid token or refresh token found')
      }
    } catch (err) {
      console.error('Authentication error:', err.message)
      process.exit(1)
    }
  }

  const MAX_RECONNECT_DELAY = 30000
  const BASE_RECONNECT_DELAY = 1000
  let reconnectAttempt = 0
  let intentionalClose = false
  let currentTaskId = null
  let hasShownCreds = false

  async function connect() {
    if (!accessToken) {
      await authenticate()
    }

    const ws = new WebSocket(url)

    ws.on('open', () => {
      console.log('Connected to server, sending handshake...')
      reconnectAttempt = 0

      ws.send(JSON.stringify({
        type: 'handshake',
        token: accessToken
      }))
    })

    ws.on('message', async (raw) => {
      let msg
      try {
        msg = JSON.parse(raw.toString())
      } catch {
        console.error('Invalid message from server:', raw.toString())
        return
      }

      try {
        await handleMessage(ws, msg)
      } catch (err) {
        console.error('Error handling message:', err.message)
        ws.send(JSON.stringify({ type: 'error', message: err.message }))
      }
    })

    ws.on('close', (code, reason) => {
      console.log('Disconnected from server')
      currentTaskId = null
      accessToken = null // Force re-authentication on reconnect

      if (!intentionalClose) {
        const delay = Math.min(BASE_RECONNECT_DELAY * Math.pow(2, reconnectAttempt), MAX_RECONNECT_DELAY)
        reconnectAttempt++
        console.log(`Reconnecting in ${delay / 1000}s... (attempt ${reconnectAttempt})`)
        setTimeout(connect, delay)
      } else {
        process.exit(0)
      }
    })

    ws.on('error', (err) => {
      const msg = err.message || err.code || err.toString() || 'Unknown connection error'
      console.error(`WebSocket error: ${msg}`)
      console.error(`  Ensure the server is running and the URL is correct: ${url}`)
    })
  }

  async function handleMessage(ws, msg) {
    switch (msg.type) {
      case 'handshake-ok': {
        console.log(`Authenticated as client: ${msg.clientId} (${msg.hostname})`)
        if (tempCreds && !hasShownCreds) {
          console.log(`\n  Temporary account created — log in at the web UI:`)
          console.log(`    Username: ${tempCreds.username}`)
          console.log(`    Password: ${tempCreds.password}\n`)
          hasShownCreds = true
        }
        currentTaskId = null
        break
      }

      case 'error': {
        console.error('Server error:', msg.message)
        // If it's an auth error on the WebSocket, don't intentionalClose, let it reconnect and refresh the token
        if (msg.message.includes('auth') || msg.message.includes('token')) {
            console.log('Session expired, will attempt to refresh...')
        } else if (msg.message.includes('claimed') || msg.message.includes('Hardware fingerprint')) {
          intentionalClose = true
          ws.close()
        }
        break
      }

      case 'kick': {
        console.log('Kicked by server')
        intentionalClose = true
        ws.close()
        break
      }

      case 'rename': {
        console.log(`Renamed to: ${msg.name}`)
        break
      }

      case 'scan': {
        console.log(`Starting scan: ${msg.path} (task ${msg.taskId})`)
        currentTaskId = msg.taskId

        ws.send(JSON.stringify({
          type: 'scan-status',
          taskId: msg.taskId,
          status: 'scanning'
        }))

        try {
          const files = await scanPath(
            msg.path,
            (scanned, total, currentFile) => {
              ws.send(JSON.stringify({
                type: 'scan-progress',
                taskId: msg.taskId,
                scanned,
                total,
                currentFile
              }))
            },
            msg.levelOneOnly || false
          )

          ws.send(JSON.stringify({
            type: 'scan-complete',
            taskId: msg.taskId,
            files
          }))

          console.log(`Scan complete: ${files.length} files hashed`)
          currentTaskId = null
        } catch (err) {
          ws.send(JSON.stringify({
            type: 'scan-error',
            taskId: msg.taskId,
            message: err.message
          }))
          console.error('Scan failed:', err.message)
          currentTaskId = null
        }
        break
      }

      case 'ping': {
        ws.send(JSON.stringify({ type: 'pong' }))
        break
      }

      default:
        console.warn('Unknown message type:', msg.type)
    }
  }

  process.on('SIGINT', () => {
    console.log('\nShutting down...')
    intentionalClose = true
    process.exit(0)
  })

  process.on('SIGTERM', () => {
    intentionalClose = true
    process.exit(0)
  })

  connect()
}
