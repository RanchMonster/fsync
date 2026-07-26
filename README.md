<p align="center">
  <b>fsync</b><br>
  <i>Decentralized file sync. No servers. No accounts. Just your devices.</i>
</p>

---

> **Status**: Early development. Not usable yet. APIs will break. Expect nothing.
> If you're here, you're early.

## What is this?

fsync keeps files in sync across your devices using peer-to-peer connections.
No cloud. No central server. Your laptop and desktop talk directly to each other
over your local network (and eventually the internet).

- **Automatic discovery** — peers find each other on the LAN, no configuration
- **Encrypted** — QUIC with TLS 1.3, everything is encrypted in transit
- **Offline-resilient** — turn a device off, come back later, it catches up
- **Ignores what you tell it** — respects `.gitignore`, `.ignore`, `.fsyncignore`

## How it works (eventually)

```
Device A                           Device B
  │                                  │
  │  "hey I'm here" (mDNS)           │
  │  ←─────────────────────────→     │
  │                                  │
  │  "what'd you miss?"              │
  │  "everything since timestamp X"  │
  │  ─────── file chunks ─────────→  │
  │                                  │
  │  synced.                         │
```

## Building

```bash
cargo build
```

Requires Rust 2024 edition (nightly or stable when available).

## Rules

These are the project's guiding principles. Not all are implemented yet, but
they guide where the project is going.

### Core Rules

1. **No central server. Ever.** The moment you add a server, you've made a
   cloud service with extra steps.

2. **No accounts. No registration.** Your device's identity is a cryptographic
   keypair. That's it.

3. **Encrypted by default.** Nothing moves between devices unencrypted. Period.

4. **Respect ignore files.** If it's in `.gitignore`, `.ignore`, or
   `.fsyncignore`, it doesn't leave the device.

5. **Offline is a first-class state.** Devices can be off for minutes or months.
   When they come back, they catch up. No data is lost.

6. **No FUSE until v1.0.0.** Keep it simple. File watching, not virtual
   filesystems.

7. **LAN first, WAN later.** Get local sync working perfectly before tackling
   the internet.

8. **Peer trust is explicit.** No device joins the sync group without being
   approved. Either a user approves it, or an existing peer vouches for it.

### Contributing Rules
1. All PRs have to be reviewed by either a maintainer or long-time contributor.
2. All PRs should be obviously what a PR accomplishes just by title and or description.
3. All PR approval workflows must pass.
4. Never abraviate names.
5. Negative programming perference.
6. State assertions are required (they must be debug_assertions for costly checks).
7. Don't put types in your names.
8. Put units in names.
9. All rust enforced naming conventions must be followed.
10. Avoid large dependencie trees.
> **TODO**: Add your own rules here. This section is for project-specific
> contribution guidelines, code style, PR process, etc.

#### Commit Message Format

All commits MUST follow this format:

```
[flag]:[short message] [description]
```

**Flags:**
- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation only
- `refactor` — code change that neither fixes a bug nor adds a feature
- `test` — adding or updating tests
- `chore` — maintenance tasks (dependencies, CI, etc.)

**Examples:**
```
fix:typo in README causing link to be broken
The markdown link for the install section was missing the closing paren
```
```
feat:add mDNS discovery for LAN peer detection
Implemented service registration and browsing using mdns-sd crate.
Peers now automatically find each other on the local network.
```
```
docs:added design document with architecture overview
Covers all planned phases from LAN discovery through WAN support.
```
```
- [ ] All commits follow the message format above
- [ ] Code compiles without warnings
- [ ] Tests pass
```

## Project Structure

```
src/
├── main.rs              # entry point
├── fs_watcher.rs        # file system watching + ignore system
├── protocol.rs          # mDNS discovery + peer management
│   └── error.rs         # protocol error types
docs/
├── design.md            # architecture + design decisions
```

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

Contributions welcome, but this project is in early development. Open an issue
first for anything non-trivial so we can align on direction.

> **TODO**: Add your own guidelines here.
