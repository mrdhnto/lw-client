#!/usr/bin/env node

import { Command } from 'commander'
import { WebSocket } from 'ws'
import { scanPath } from './scanner.js'
import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import mid from 'node-machine-id'
import dotenv from 'dotenv'
import keytar from 'keytar'

// node-machine-id is a CommonJS bundle; named ESM imports fail on modern Node.
const { machineIdSync } = mid

// Load .env if present
dotenv.config({ path: path.join(process.cwd(), '.env') })

const CONFIG_PATH = path.join(os.homedir(), '.lw-client.json')
const KEYTAR_SERVICE = 'library-watcher'
const KEYTAR_ACCOUNT = 'client-token'
const DEFAULT_WS_PATH = '/api/client/ws'

async function loadConfig() {
  try {
    if (!fs.existsSync(CONFIG_PATH)) return null

    const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'))
    const refreshToken = await keytar.getPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT)

    return {
      url: config.url,
      // Legacy configs stored the one-time registration token in plaintext.
      // Keep it in memory so it can be exchanged once, but never treat it as
      // a refresh token. A stored refresh token always wins.
      registrationToken: refreshToken ? null : (config.token || null),
      refreshToken
    }
  } catch (err) {
    console.error('Failed to load config:', err)
    return null
  }
}

async function saveConfig(url) {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true })
  fs.writeFileSync(CONFIG_PATH, JSON.stringify({ url }, null, 2))
}

async function saveRefreshToken(token) {
  await keytar.setPassword(KEYTAR_SERVICE, KEYTAR_ACCOUNT, token)
}

function isPrivateHost(host) {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase()
  if (h === 'localhost' || h === '::1' || h === '0.0.0.0') return true
  if (/^127\./.test(h)) return true
  if (/^10\./.test(h)) return true
  if (/^192\.168\./.test(h)) return true
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true
  if (/^169\.254\./.test(h)) return true
  return false
}

function normalizeWsUrl(input, forceWss, isDev) {
  const raw = String(input).trim()
  const hasProtocol = /^(wss?|https?):\/\//i.test(raw)
  const parsed = new URL(hasProtocol ? raw : `ws://${raw}`)

  // Accept http(s) URLs pasted from the browser and convert them.
  if (parsed.protocol === 'http:') parsed.protocol = 'ws:'
  else if (parsed.protocol === 'https:') parsed.protocol = 'wss:'

  if (forceWss) {
    parsed.protocol = 'wss:'
  } else if (!hasProtocol) {
    parsed.protocol = (!isDev && !isPrivateHost(parsed.hostname)) ? 'wss:' : 'ws:'
  }

  if (!parsed.pathname || parsed.pathname === '/') {
    parsed.pathname = DEFAULT_WS_PATH
  }

  return parsed
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
      await saveConfig(opts.url)
      start(opts.url, { registrationToken: opts.token })
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
    if (!config || !config.url || (!config.registrationToken && !config.refreshToken)) {
      console.error('No saved configuration or token found. Run: lw-client -u <url> -t <token>')
      process.exit(1)
    }
    start(config.url, {
      registrationToken: config.registrationToken,
      refreshToken: config.refreshToken
    })
  })

program.parse(process.argv)

async function start(wsUrl, credentials) {
  // Determine if we should force WSS vs WS
  const isForceWss = process.env.FORCE_WSS === 'true'
  const isDev = process.env.NODE_ENV === 'development'

  let parsedUrl
  try {
    parsedUrl = normalizeWsUrl(wsUrl, isForceWss, isDev)
  } catch (e) {
    console.error('Invalid URL provided:', wsUrl)
    process.exit(1)
  }

  const url = parsedUrl.toString()
  const httpUrl = `${parsedUrl.protocol === 'wss:' ? 'https:' : 'http:'}//${parsedUrl.host}`
  let hardwareId = 'unknown'

  try {
    hardwareId = machineIdSync()
  } catch (err) {
    console.error('Warning: Failed to generate hardware fingerprint:', err.message)
  }

  // Auth logic: Exchange the one-time registration token for a JWT, then
  // refresh it on reconnects. The registration token is never persisted.
  let accessToken = null
  let tempCreds = null

  async function authenticate() {
    try {
      if (credentials.registrationToken) {
        console.log('Authenticating with registration token...')
        const res = await fetch(`${httpUrl}/api/client/auth`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: credentials.registrationToken,
            hostname: os.hostname(),
            hardwareId
          })
        })

        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.message || `Authentication failed (HTTP ${res.status})`)
        }

        const data = await res.json()
        await saveRefreshToken(data.refreshToken)
        credentials.refreshToken = data.refreshToken
        credentials.registrationToken = null
        accessToken = data.accessToken
        tempCreds = data.tempCreds

        // Drop any legacy plaintext token from the config file.
        await saveConfig(url)
        return
      }

      if (credentials.refreshToken) {
        console.log('Refreshing session token...')
        const res = await fetch(`${httpUrl}/api/client/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refreshToken: credentials.refreshToken })
        })

        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.message || `Failed to refresh token (HTTP ${res.status})`)
        }

        const data = await res.json()
        accessToken = data.accessToken
        return
      }

      throw new Error('No registration token or refresh token found')
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
  let authFailures = 0

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
        authFailures = 0
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
        if (msg.message.includes('auth') || msg.message.includes('token')) {
          authFailures++
          if (authFailures >= 2) {
            console.error('Authentication keeps failing. Check the server JWT_SECRET, or generate a new token.')
            intentionalClose = true
            ws.close()
          } else {
            console.log('Session expired, will attempt to refresh...')
          }
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
