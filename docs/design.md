# fsync Design Document

## Overview

fsync is a decentralized peer-to-peer file synchronization system. Devices on the same network discover each other automatically and sync file changes without a central server.

## Architecture

```
┌──────────────────────────────────────────────────┐
│  Application Layer                               │
│  ├── File watching (notify + tokio bridge)       │
│  ├── Ignore system (.gitignore, .ignore, etc.)   │
│  ├── Changelog (offline catch-up)                │
│  └── Trust model (vouching / approval)           │
├──────────────────────────────────────────────────┤
│  Protocol Layer                                  │
│  ├── Sync protocol (file state exchange)         │
│  └── Peer management                             │
├──────────────────────────────────────────────────┤
│  Transport Layer — QUIC (quinn)                  │
│  ├── Streams (TCP-like, reliable, ordered)       │
│  │   ├── File transfers                          │
│  │   ├── State exchange                          │
│  │   └── Unidirectional streams:                 │
│  │       └── "I have changes" notifications      │
│  └── Datagrams (UDP-like, unreliable)            │
│      └── (reserved)                              │
├──────────────────────────────────────────────────┤
│  Discovery Layer — mDNS (mdns-sd)                │
│  └── Automatic LAN peer discovery                │
└──────────────────────────────────────────────────┘
```

## Phases

### Phase 1: Local Discovery (current)
- [x] File watching with notify
- [x] Ignore system (.gitignore, .ignore, .fsyncignore)
- [x] Debounced event batching
- [x] mDNS service registration and browsing
- [x] Peer discovery on LAN

### Phase 2: Encrypted Transport
- [x] QUIC via quinn
- [x] Ed25519 keypair for peer identity
- [x] Self-signed TLS cert from keypair
- [ ] Streams for file transfer
- [ ] Unidirectional streams for change notifications

### Phase 3: File Sync Protocol
- [ ] Sync state exchange (vector clocks / timestamps)
- [ ] File chunking and transfer
- [ ] Conflict resolution

### Phase 4: Offline Support
- [ ] Changelog (append-only JSONL on disk)
- [ ] Catch-up on peer rejoin
- [ ] Compaction policy

### Phase 5: Mesh Networking
- [ ] Peer exchange (telling peers about other peers)
- [ ] Multi-hop routing
- [ ] Trust model (approval / vouching)

### Phase 6: WAN Support (possible, pre-1.0)
- [ ] NAT traversal (hole punching or relay)
- [ ] Public key exchange / trust bootstrapping
- [ ] Relay fallback (when direct connection fails)

## Identity

Each peer generates an Ed25519 keypair on first run. The public key IS the peer ID (64 hex chars).

```rust
// Peer ID = hex-encoded Ed25519 public key
// Collision probability: ~2^-256 (effectively zero)
let peer_id = hex::encode(verifying_key.as_bytes());
```

Key is persisted to disk so the peer ID is stable across restarts.

## Discovery (mdns-sd)

- Service type: `_fsync._udp.local.`
- Instance name: env `FSYNC_PEER_NAME` or system hostname (truncated to 15 chars per RFC 6763)
- Runs its own daemon thread, bridges to async via flume channels
- Each peer both advertises (register) and discovers (browse)

## Transport (QUIC via quinn)

### Why QUIC over raw TCP
- Built-in TLS 1.3 (encryption + authentication)
- Multiplexed streams (no head-of-line blocking)
- Unidirectional streams for lightweight notifications
- Single UDP socket for everything

### Streams vs Datagrams
| Feature         | Streams (TCP-like)                          | Datagrams (UDP-like) |
|-----------------|---------------------------------------------|----------------------|
| Reliable        | Yes                                         | No (can be dropped)  |
| Ordered         | Yes                                         | No                   |
| Use case        | File transfers, state sync, change pings    | (reserved)           |
| Flow control    | Yes                                         | No                   |

Change notifications are sent over **unidirectional streams** — a sender
opens a send-only stream to notify a peer it has changes, so notifications
get reliability and ordering without needing to read a response on the same
stream.

### Connection flow
```
Peer A (desktop)          Peer B (laptop)
     │                         │
     │  mDNS discovers peer    │
     │  ←───────────────────→  │
     │                         │
     │  QUIC connect           │
     │  TLS handshake          │
     │  (verify peer_id)       │
     │  ←───────────────────→  │
     │                         │
     │  Exchange sync state    │
     │  Transfer changed files │
     │  ←───────────────────→  │
```

## File Watching

Uses `notify` with a `broadcast::channel` bridge to async:

```
notify (sync, own thread)
    → broadcast::channel
        → tokio::select! in WatcherReceiver::recv()
            → debounced event batches
```

- Debounce delay: 5 seconds (configurable)
- Debounce delay: 0 in tests
- Ignores are checked and reloaded in the notify callback
- Ignore file changes (.gitignore etc.) trigger live reload

## Ignore System

Supported files: `.gitignore`, `.ignore`, `.fsyncignore`

Uses the `ignore` crate's `matched_path_or_any_parents` method (not `matched`) to correctly handle directory-level ignore patterns like `/target`.

## Changelog & Offline Support

Each peer maintains an append-only changelog on disk:

```
~/.fsync/changelog.log    (append-only change entries)
```

Format: length-prefixed postcard-serialized entries (or JSONL).

### Catch-up flow
```
1. Peer comes back online
2. Advertises via mDNS
3. Connects to known peer
4. Sends: "my last changelog timestamp is X"
5. Remote peer sends all entries after X
6. Applied locally
```

### Compaction policy
- Only keep entries newer than the oldest last-seen timestamp among all known peers
- Max retention: 30 days (hard cap)
- If a peer was offline longer than 30 days, trigger full resync instead
- Compact by rewriting the file atomically (write to temp, rename)

## Peer Name

```rust
fn get_peer_name() -> String {
    std::env::var("FSYNC_PEER_NAME")
        .unwrap_or_else(|_| hostname::get().unwrap().to_string_lossy().to_string())
}
```

Truncated to 15 characters for mDNS compatibility.

## Dependencies

```toml
[dependencies]
blake3 = "*"           # file hashing
ignore = "0.4.31"      # gitignore matching
mdns-sd = "*"          # mDNS discovery
notify = "8.2.0"       # file system watching
quinn = "0.11"         # QUIC transport
rcgen = "0.13"         # self-signed certs
tokio = { features = ["full"] }
tracing = "*"          # logging
thiserror = "*"
hostname = "0.4"
postcard = "*"         # efficient serialization
serde = { version = "1", features = ["derive"] }
```

## Key Design Decisions

1. **No central server** — fully decentralized P2P
2. **No FUSE** — at least until v1.0.0
3. **QUIC over TCP** — built-in encryption, multiplexing, datagrams
4. **Ed25519 for identity** — public key = peer ID, also used for TLS certs
5. **mdns-sd over libmdns** — more actively maintained, runtime-agnostic
6. **Changelog over FUSE** — simple on-disk log for offline catch-up
7. **Trust model deferred** — get sync working first, add vouching/approval later
8. **Mesh deferred** — start with direct LAN connections, add multi-hop later

## WAN Support (possible, pre-1.0)

> **Status**: Under consideration. LAN is the priority. WAN support would be a
> stretch goal before v1.0.0 if there's time and demand.

### Why WAN is harder than LAN

| LAN (mDNS)                         | WAN                                    |
|------------------------------------|----------------------------------------|
| Peers on same broadcast domain     | Peers behind NATs / firewalls         |
| mDNS just works                    | Need NAT traversal or relay            |
| Direct IP connectivity             | IPs change, ports blocked              |
| No trust bootstrapping needed      | Must verify identity without meeting  |

### Where to start if you do WAN

**1. NAT Traversal — hole punching**

QUIC runs over UDP, which makes hole punching viable. Both peers connect to a
lightweight signaling server (not a relay — just for address exchange) to learn
each other's public IP:port, then attempt a simultaneous UDP send to punch
through the NAT.

```
Peer A                Signaling Server              Peer B
  │  "here's my public addr"            │  "here's my public addr"
  │  ──────────────────────────→        │  ←──────────────────────
  │                                     │
  │  Peer A sends to Peer B's public addr
  │  Peer B sends to Peer A's public addr
  │  ←──── NAT punches through ──────→  │
  │                                     │
  │  QUIC connection established        │
```

Crate to explore: `webrtc-util` has STUN/TURN/hole-punching primitives.
Or roll your own minimal STUN client (STUN is ~200 lines of code).

**2. Signaling Server**

A minimal server that peers register with and exchange addresses with
trusted peers. Could be as simple as:

- Peer A registers: "I'm peer_id X, my address is Y"
- Peer B asks: "give me the address for peer_id X"
- Server responds

This is the one "central" piece — but it's stateless and can be self-hosted.
You could also use a DHT (like Kademlia via `libp2p-kad`) for fully
decentralized address lookup, but that's significantly more complex.

**3. Relay Fallback (TURN-like)**

When hole punching fails (symmetric NATs, restricted firewalls), peers fall
back to relaying data through a TURN server. This adds latency and cost but
guarantees connectivity.

Crate to explore: `webrtc-rs` has a TURN implementation, or use `turn-rs`.

**4. Trust Bootstrapping Over WAN**

On LAN, physical proximity is implicit trust. On WAN, you need:

- Pre-shared keys: manually exchange peer IDs before connecting (like Signal's
  safety numbers)
- Vouching: an existing trusted peer vouches for a new peer (web of trust)
- TOFU (Trust On First Use): accept the first connection, remember the key
  (like SSH host keys)

Recommendation: start with TOFU (simplest), add vouching later.

**5. The Protocol Doesn't Change**

The good news: your sync protocol, changelog, file transfer — all of that
stays the same. The only additions are:

- NAT traversal handshake (before QUIC connect)
- Signaling server client (for address exchange)
- Relay fallback (for stubborn networks)

QUIC handles everything else.

### Dependencies you'd add for WAN

```toml
# Only needed if you do WAN
stun = "0.6"           # STUN client for NAT detection
turn = "0.11"          # TURN relay (if doing relay fallback)
```

### Recommendation

Get through Phase 4 first. If users are asking for WAN sync, you'll know
there's demand. The protocol layer is transport-agnostic — adding WAN later
is a matter of adding a new connection path, not rewriting anything.
