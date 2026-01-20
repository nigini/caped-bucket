const http = require('http')
const dotenv = require('dotenv')
const { matchFilters, verifyEvent } = require('nostr-tools')
const { WebSocketServer } = require('ws')
const cap = require('./cap-enforcement')

dotenv.config()

// ─────────────────────────────────────────────────────────────
// HTTP Server (NIP-11 Relay Info)
// ─────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  if (req.url === '/' && req.headers.accept === 'application/nostr+json') {
    res.writeHead(200, {
      'Content-Type': 'application/nostr+json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': '*',
      'Access-Control-Allow-Methods': '*'
    })

    res.end(JSON.stringify({
      name: process.env.RELAY_NAME,
      icon: process.env.RELAY_ICON,
      pubkey: process.env.RELAY_PUBKEY,
      description: process.env.RELAY_DESCRIPTION,
      software: "https://github.com/nigini/bucket",
      supported_nips: [1, 11],
    }))
  } else {
    res.writeHead(404)
    res.end('Not Found')
  }
})

// ─────────────────────────────────────────────────────────────
// Global State
// ─────────────────────────────────────────────────────────────

const gsubs = new Map()   // Global subscriptions
const events = new Map()  // Event store

const wss = new WebSocketServer({ server })

// Clear events every hour (configurable via env)
const TTL = parseInt(process.env.EVENT_TTL) || 3600_000
setInterval(() => {
  console.log('[RELAY] Clearing event store...')
  events.clear()
}, TTL)

// ─────────────────────────────────────────────────────────────
// Logging Helpers
// ─────────────────────────────────────────────────────────────

function logIncoming(socketId, type, details = '') {
  console.log(`[${socketId.slice(0, 6)}] → ${type}`, details)
}

function logOutgoing(socketId, type, details = '') {
  console.log(`[${socketId.slice(0, 6)}] ← ${type}`, details)
}

// ─────────────────────────────────────────────────────────────
// WebSocket Connection Handler
// ─────────────────────────────────────────────────────────────

wss.on('connection', socket => {
  // Generate unique socket ID
  const socketId = Math.random().toString(36).slice(2) + Date.now().toString(36)
  socket._id = socketId

  const lsubs = new Map()  // Local subscriptions for this connection

  console.log(`[${socketId.slice(0, 6)}] ✦ Connected`)

  // Helper to send messages
  const send = msg => {
    socket.send(JSON.stringify(msg))
  }

  // Initialize CAP enforcement for this connection and get challenge
  const challenge = cap.initConnection(socketId)

  // Send NIP-42 AUTH challenge immediately
  logOutgoing(socketId, 'AUTH', `challenge=${challenge.slice(0, 8)}...`)
  send(['AUTH', challenge])

  // Callback factory for real-time subscriptions
  const makecb = (lsubid, filters) => event => {
    if (matchFilters(filters, event)) {
      // Check read permission before sending
      if (!cap.canRead(socketId, event)) return

      logOutgoing(socketId, 'EVENT', `sub=${lsubid} id=${event.id.slice(0, 8)}...`)
      send(['EVENT', lsubid, event])
    }
  }

  // ─────────────────────────────────────────────────────────────
  // Message Handler
  // ─────────────────────────────────────────────────────────────

  socket.on('message', msg => {
    try {
      const message = JSON.parse(msg)
      const msgType = message[0]

      // ─────────────────────────────────────────────────────────
      // AUTH: NIP-42 Authentication (with optional CAP)
      // ─────────────────────────────────────────────────────────
      if (msgType === 'AUTH') {
        const authEvent = message[1]
        logIncoming(socketId, 'AUTH', `kind=${authEvent.kind} pubkey=${authEvent.pubkey?.slice(0, 8)}...`)

        const result = cap.handleAuth(socketId, authEvent)

        if (result.ok) {
          logOutgoing(socketId, 'OK', `auth=${authEvent.id?.slice(0, 8)}... authenticated`)
          send(['OK', authEvent.id, true, result.message])
        } else {
          logOutgoing(socketId, 'OK', `auth=${authEvent.id?.slice(0, 8)}... rejected: ${result.message}`)
          send(['OK', authEvent.id, false, result.message])
        }
        return
      }

      // ─────────────────────────────────────────────────────────
      // EVENT: Publish an event
      // ─────────────────────────────────────────────────────────
      if (msgType === 'EVENT') {
        const event = message[1]
        logIncoming(socketId, 'EVENT', `kind=${event.kind} id=${event.id?.slice(0, 8)}...`)

        // Verify event signature
        if (!verifyEvent(event)) {
          logOutgoing(socketId, 'OK', `id=${event.id?.slice(0, 8)}... rejected: invalid signature`)
          send(['OK', event.id, false, 'invalid: signature verification failed'])
          return
        }

        // Check CAP write permission
        const writeCheck = cap.canWrite(socketId, event)
        if (!writeCheck.ok) {
          logOutgoing(socketId, 'OK', `id=${event.id?.slice(0, 8)}... rejected: ${writeCheck.reason}`)
          send(['OK', event.id, false, writeCheck.reason])
          return
        }

        // Process for commons registration (kind:39002)
        cap.processEvent(event)

        // Store event
        events.set(event.id, event)

        // Notify all subscribers
        for (const cb of gsubs.values()) {
          cb(event)
        }

        logOutgoing(socketId, 'OK', `id=${event.id?.slice(0, 8)}... accepted`)
        send(['OK', event.id, true, ''])
        return
      }

      // ─────────────────────────────────────────────────────────
      // REQ: Subscribe to events
      // ─────────────────────────────────────────────────────────
      if (msgType === 'REQ') {
        const lsubid = message[1]
        const gsubid = `${socketId}:${lsubid}`
        const filters = message.slice(2)

        logIncoming(socketId, 'REQ', `sub=${lsubid} filters=${JSON.stringify(filters).slice(0, 50)}...`)

        // Store subscription
        lsubs.set(lsubid, gsubid)
        gsubs.set(gsubid, makecb(lsubid, filters))

        // Send matching historical events
        let sentCount = 0
        for (const event of events.values()) {
          if (matchFilters(filters, event)) {
            // Check read permission before sending
            if (!cap.canRead(socketId, event)) continue

            send(['EVENT', lsubid, event])
            sentCount++
          }
        }

        logOutgoing(socketId, 'EOSE', `sub=${lsubid} sent=${sentCount}`)
        send(['EOSE', lsubid])
        return
      }

      // ─────────────────────────────────────────────────────────
      // CLOSE: Close subscription
      // ─────────────────────────────────────────────────────────
      if (msgType === 'CLOSE') {
        const lsubid = message[1]
        const gsubid = `${socketId}:${lsubid}`

        logIncoming(socketId, 'CLOSE', `sub=${lsubid}`)

        lsubs.delete(lsubid)
        gsubs.delete(gsubid)
        return
      }

      // Unknown message type
      console.log(`[${socketId.slice(0, 6)}] ? Unknown message type: ${msgType}`)

    } catch (e) {
      console.error(`[${socketId.slice(0, 6)}] ✗ Error:`, e.message)
    }
  })

  // ─────────────────────────────────────────────────────────────
  // Disconnect Handler
  // ─────────────────────────────────────────────────────────────

  socket.on('close', () => {
    console.log(`[${socketId.slice(0, 6)}] ✦ Disconnected`)

    // Clean up subscriptions
    for (const [subid, gsubid] of lsubs.entries()) {
      gsubs.delete(gsubid)
    }
    lsubs.clear()

    // Clean up CAP enforcement
    cap.cleanupConnection(socketId)
  })
})

// ─────────────────────────────────────────────────────────────
// Start Server
// ─────────────────────────────────────────────────────────────

server.listen(process.env.PORT, () => {
  console.log('═══════════════════════════════════════════════════════')
  console.log('  Bucket Relay with CAP Enforcement')
  console.log('═══════════════════════════════════════════════════════')
  console.log(`  Port: ${process.env.PORT}`)
  console.log(`  Event TTL: ${TTL / 1000}s`)
  console.log('═══════════════════════════════════════════════════════')
})
