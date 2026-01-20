/**
 * CAP Enforcement Module for Bucket Relay
 *
 * Provides capability-based access control for Nostr commons.
 */

const { verifyEvent } = require('nostr-tools')

// ─────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────

// Per-connection state: socketId → { pubkey, grants[], challenge }
const connections = new Map()

// AUTH event kind (NIP-42)
const AUTH_KIND = 22242

// Enforced commons: Set of "39002:<collective>:<uuid>"
const enforcedCommons = new Set()

// ─────────────────────────────────────────────────────────────
// Logging
// ─────────────────────────────────────────────────────────────

const LOG_PREFIX = '[CAP]'

function log(socketId, ...args) {
  const id = socketId ? `[${socketId.slice(0, 6)}]` : ''
  console.log(LOG_PREFIX, id, ...args)
}

function logEvent(socketId, direction, type, details) {
  const arrow = direction === 'in' ? '→' : '←'
  log(socketId, arrow, type, details || '')
}

// ─────────────────────────────────────────────────────────────
// Connection Management
// ─────────────────────────────────────────────────────────────

function initConnection(socketId) {
  // Generate random challenge for NIP-42
  const challenge = Math.random().toString(36).slice(2) + Date.now().toString(36)
  connections.set(socketId, { pubkey: null, grants: [], challenge })
  log(socketId, 'Connection initialized, challenge:', challenge.slice(0, 8) + '...')
  return challenge
}

function cleanupConnection(socketId) {
  connections.delete(socketId)
  log(socketId, 'Connection cleaned up')
}

// ─────────────────────────────────────────────────────────────
// CAP-AUTH Handler
// ─────────────────────────────────────────────────────────────

/**
 * Handle AUTH message (NIP-42 with CAP extension)
 * @param {string} socketId - Connection identifier
 * @param {object} authEvent - Signed kind:22242 event with challenge and CAP
 * @returns {{ ok: boolean, message: string }}
 */
function handleAuth(socketId, authEvent) {
  logEvent(socketId, 'in', 'AUTH', `pubkey=${authEvent.pubkey?.slice(0, 8)}...`)

  const conn = connections.get(socketId)
  if (!conn) {
    const msg = 'connection not initialized'
    logEvent(socketId, 'out', 'OK', msg)
    return { ok: false, message: msg }
  }

  // 1. Verify event kind is 22242 (NIP-42)
  if (authEvent.kind !== AUTH_KIND) {
    const msg = `invalid auth kind: expected ${AUTH_KIND}, got ${authEvent.kind}`
    logEvent(socketId, 'out', 'OK', msg)
    return { ok: false, message: msg }
  }

  // 2. Verify outer signature (proves sender owns pubkey)
  if (!verifyEvent(authEvent)) {
    const msg = 'invalid auth signature'
    logEvent(socketId, 'out', 'OK', msg)
    return { ok: false, message: msg }
  }

  // 3. Verify challenge matches (prevents replay attacks)
  const challengeTag = authEvent.tags?.find(t => t[0] === 'challenge')
  if (!challengeTag || challengeTag[1] !== conn.challenge) {
    const msg = 'invalid or missing challenge'
    logEvent(socketId, 'out', 'OK', msg)
    return { ok: false, message: msg }
  }

  // 4. Extract embedded CAP (optional - not required if collective is posting directly)
  const capTag = authEvent.tags?.find(t => t[0] === 'cap')

  if (!capTag || !capTag[1]) {
    // No CAP provided - just authenticate the pubkey (for collective direct access)
    connections.set(socketId, { ...conn, pubkey: authEvent.pubkey, grants: [] })
    log(socketId, '✓ Authenticated (no CAP):', `pubkey=${authEvent.pubkey.slice(0, 8)}...`)
    return { ok: true, message: 'authenticated' }
  }

  // 5. Parse and validate the CAP
  let cap
  try {
    cap = JSON.parse(capTag[1])
  } catch (e) {
    const msg = 'invalid cap JSON'
    logEvent(socketId, 'out', 'OK', msg)
    return { ok: false, message: msg }
  }

  // 6. Verify CAP signature (proves collective issued it)
  if (!verifyEvent(cap)) {
    const msg = 'invalid cap signature'
    logEvent(socketId, 'out', 'OK', msg)
    return { ok: false, message: msg }
  }

  // 7. Check grantee matches auth pubkey
  const grantee = cap.tags?.find(t => t[0] === 'p')?.[1]
  if (grantee !== authEvent.pubkey) {
    const msg = `grantee mismatch: cap=${grantee?.slice(0, 8)}, auth=${authEvent.pubkey?.slice(0, 8)}`
    logEvent(socketId, 'out', 'OK', msg)
    return { ok: false, message: msg }
  }

  // 8. Check CAP expiry
  const expiry = cap.tags?.find(t => t[0] === 'expiry')?.[1]
  if (expiry && parseInt(expiry) < Date.now() / 1000) {
    const msg = 'cap expired'
    logEvent(socketId, 'out', 'OK', msg)
    return { ok: false, message: msg }
  }

  // 9. Parse and store grants
  const grants = parseGrants(cap)
  connections.set(socketId, { ...conn, pubkey: authEvent.pubkey, grants })

  log(socketId, '✓ Authenticated with CAP:', `pubkey=${authEvent.pubkey.slice(0, 8)}..., grants=${grants.length}`)
  grants.forEach(g => log(socketId, '  grant:', g.action, g.scope, '→', g.commons))

  return { ok: true, message: 'authenticated' }
}

/**
 * Parse grants from CAP tags
 */
function parseGrants(cap) {
  const grants = []

  // Get commons reference
  const commonsTag = cap.tags?.find(t => t[0] === 'a')
  const commons = commonsTag?.[1] || '*'

  // Get action grants
  for (const tag of cap.tags || []) {
    if (tag[0] === 'cap') {
      grants.push({
        action: tag[1],      // publish, delete, access, delegate
        scope: tag[2] || '*', // kind:1, *, etc.
        commons: commons
      })
    }
  }

  return grants
}

// ─────────────────────────────────────────────────────────────
// Commons Management
// ─────────────────────────────────────────────────────────────

/**
 * Process event to auto-register commons (kind:39002)
 * @param {object} event - Nostr event
 */
function processEvent(event) {
  if (event.kind === 39002) {
    const dTag = event.tags?.find(t => t[0] === 'd')?.[1]
    if (dTag) {
      const commonsRef = `39002:${event.pubkey}:${dTag}`
      enforcedCommons.add(commonsRef)
      log(null, '📂 Commons registered:', commonsRef)
    }
  }
}

// ─────────────────────────────────────────────────────────────
// Access Control
// ─────────────────────────────────────────────────────────────

/**
 * Check if socket can write event to commons
 * @param {string} socketId - Connection identifier
 * @param {object} event - Event to write
 * @returns {{ ok: boolean, reason?: string }}
 */
function canWrite(socketId, event) {
  // Find commons reference in event
  const commonsTag = event.tags?.find(t => t[0] === 'a' && t[1]?.startsWith('39002:'))

  // Not targeting a commons - allow
  if (!commonsTag) {
    return { ok: true }
  }

  const commons = commonsTag[1]

  // Commons not enforced - allow
  if (!enforcedCommons.has(commons)) {
    return { ok: true }
  }

  // Check if collective is publishing directly (no CAP needed)
  const collectivePubkey = commons.split(':')[1]
  if (event.pubkey === collectivePubkey) {
    log(socketId, '✓ Write allowed: collective direct publish')
    return { ok: true }
  }

  // Need CAP - check connection
  const conn = connections.get(socketId)
  if (!conn || !conn.pubkey) {
    // Use NIP-42 standard prefix so clients know to authenticate
    const reason = 'auth-required: authentication required'
    log(socketId, '✗ Write denied:', reason)
    return { ok: false, reason }
  }

  // Check if event author matches authenticated pubkey
  if (event.pubkey !== conn.pubkey) {
    const reason = `blocked: pubkey mismatch (auth=${conn.pubkey.slice(0, 8)}, event=${event.pubkey.slice(0, 8)})`
    log(socketId, '✗ Write denied:', reason)
    return { ok: false, reason }
  }

  // Check grants
  const hasGrant = conn.grants.some(g =>
    g.action === 'publish' &&
    matchesScope(g.scope, event.kind) &&
    matchesCommons(g.commons, commons)
  )

  if (!hasGrant) {
    const reason = `blocked: no publish grant for kind:${event.kind} in ${commons}`
    log(socketId, '✗ Write denied:', reason)
    return { ok: false, reason }
  }

  log(socketId, '✓ Write allowed: CAP verified')
  return { ok: true }
}

/**
 * Check if socket can read event from commons
 * @param {string} socketId - Connection identifier
 * @param {object} event - Event to read
 * @returns {boolean}
 */
function canRead(socketId, event) {
  // Find commons reference in event
  const commonsTag = event.tags?.find(t => t[0] === 'a' && t[1]?.startsWith('39002:'))

  // Not in a commons - allow
  if (!commonsTag) {
    return true
  }

  const commons = commonsTag[1]

  // Commons not enforced - allow
  if (!enforcedCommons.has(commons)) {
    return true
  }

  // Need CAP - check connection
  const conn = connections.get(socketId)
  if (!conn || !conn.pubkey) {
    log(socketId, '✗ Read filtered: not authenticated')
    return false
  }

  // Check grants (access or publish implies read)
  const hasGrant = conn.grants.some(g =>
    (g.action === 'access' || g.action === 'publish') &&
    matchesCommons(g.commons, commons)
  )

  if (!hasGrant) {
    log(socketId, '✗ Read filtered: no access grant for', commons)
    return false
  }

  return true
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

/**
 * Check if scope matches event kind
 */
function matchesScope(scope, kind) {
  if (scope === '*') return true
  if (scope === `kind:${kind}`) return true
  if (scope === `${kind}`) return true
  return false
}

/**
 * Check if grant commons matches target commons
 * Supports wildcards: "39002:abc:*" matches "39002:abc:general"
 */
function matchesCommons(grantCommons, targetCommons) {
  if (grantCommons === '*') return true
  if (grantCommons === targetCommons) return true

  // Wildcard match: "39002:abc:*" matches "39002:abc:anything"
  if (grantCommons.endsWith(':*')) {
    const prefix = grantCommons.slice(0, -1) // Remove trailing *
    return targetCommons.startsWith(prefix)
  }

  return false
}

// ─────────────────────────────────────────────────────────────
// Debug helpers
// ─────────────────────────────────────────────────────────────

function getStatus() {
  return {
    connections: connections.size,
    enforcedCommons: Array.from(enforcedCommons),
    authenticated: Array.from(connections.entries())
      .filter(([_, c]) => c.pubkey)
      .map(([id, c]) => ({ socketId: id.slice(0, 6), pubkey: c.pubkey.slice(0, 8) }))
  }
}

// ─────────────────────────────────────────────────────────────
// Exports
// ─────────────────────────────────────────────────────────────

module.exports = {
  initConnection,
  cleanupConnection,
  handleAuth,
  processEvent,
  canWrite,
  canRead,
  getStatus,
  log,
  logEvent
}
