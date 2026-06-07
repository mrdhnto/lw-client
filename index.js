#!/usr/bin/env node

import { Command } from 'commander'
import { WebSocket } from 'ws'
import { scanPath } from './scanner.js'
import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'

const CONFIG_PATH = path.join(os.homedir(), '.lw-client.json')

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'))
  } catch {
    return null
  }
}

function saveConfig(data) {
  fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true })
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(data, null, 2))
}

const program = new Command()

program
  .name('lw-client')
  .description('Library Watcher remote scanning client')
  .option('-u, --url <url>', 'WebSocket server URL (e.g. ws://192.168.1.1:8080/api/client/ws)')
  .option('-t, --token <token>', 'Authentication token')
  .action(() => {
    const opts = program.opts()
    if (opts.url && opts.token) {
      saveConfig({ url: opts.url, token: opts.token })
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
  .action(() => {
    const config = loadConfig()
    if (!config || !config.url || !config.token) {
      console.error('No saved configuration found. Run: lw-client -u <url> -t <token>')
      process.exit(1)
    }
    start(config.url, config.token)
  })

program.parse(process.argv)

function start(url, token) {
  const MAX_RECONNECT_DELAY = 30000
  const BASE_RECONNECT_DELAY = 1000
  let reconnectAttempt = 0
  let intentionalClose = false
  let currentTaskId = null

  function connect() {
    const ws = new WebSocket(url)

    ws.on('open', () => {
      console.log('Connected to server')
      reconnectAttempt = 0

      ws.send(JSON.stringify({
        type: 'handshake',
        token: token,
        hostname: os.hostname()
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
      console.error('WebSocket error:', err.message)
    })
  }

  async function handleMessage(ws, msg) {
    switch (msg.type) {
      case 'handshake-ok': {
        console.log(`Authenticated as client: ${msg.clientId} (${msg.hostname})`)
        currentTaskId = null
        break
      }

      case 'error': {
        console.error('Server error:', msg.message)
        if (msg.message.includes('token') || msg.message.includes('auth') || msg.message.includes('claimed')) {
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
