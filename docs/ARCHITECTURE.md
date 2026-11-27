# KumoKeep Architecture

KumoKeep is a small, self-hosted, multi-user personal cloud with four features:
**files**, **notes**, **photos** and a **password manager**. It is exposed to the
internet and has a mobile app.

This document records the decisions and the reasons behind them. When a decision
changes, update this file in the same change.

## Goals

1. **Lightweight.** One process, one binary, one data directory. Idle memory in
   the tens of MB. No external services (no database server, no Redis, no cron).
2. **Secure by default.** Safe to expose to the internet. The password vault is
   end-to-end encrypted, so a full server compromise does not reveal passwords.
3. **No lock-in.** Files stay as plain files on disk. Standard protocols (WebDAV,
   the Bitwarden client protocol) mean existing clients work.
4. **Only what's needed.** No app store, no plugin system, no office suite.

## High-level overview

```
            Internet
               │  HTTPS (TLS 1.3, HTTP/2 + HTTP/3)
         ┌─────▼─────┐
         │   Caddy   │  TLS, certificates, compression
         └─────┬─────┘
               │ HTTP (localhost / private network)
┌──────────────▼───────────────────────────────────────────┐
│                  kumokeep (one Go binary)                  │
│                                                            │
│  /            embedded SvelteKit web app (static files)    │
│  /api/v1      KumoKeep JSON API (OpenAPI)  ◄── web, mobile │
│  /dav         WebDAV for files             ◄── desktop sync│
│  /uploads     tus resumable uploads        ◄── mobile photos│
│  /vault/...   Bitwarden-compatible API     ◄── Bitwarden apps│
│                                                            │
│  background job workers (thumbnails, EXIF, cleanup)        │
└──────────────┬───────────────────────────┬────────────────┘
               │                           │
        ┌──────▼──────┐            ┌───────▼────────┐
        │ SQLite (WAL)│            │  data/users/   │
        │ kumokeep.db │            │  <uuid>/files  │
        └─────────────┘            └────────────────┘
```

Clients:

| Client | Used for | Talks to |
|---|---|---|
| Web app (SvelteKit) | Everything except vault autofill | `/api/v1`, `/uploads` |
| KumoKeep mobile app (Flutter) | Photos (auto-upload), notes, files | `/api/v1`, `/uploads` |
| Official Bitwarden apps and extensions | Passwords and autofill | `/vault/*` |
| Any WebDAV client (OS file managers, rclone) | File sync | `/dav` |

## Tech stack

| Layer | Choice | Why |
|---|---|---|
| Backend language | **Go** | Memory-safe, compiles to one static binary, strong standard library for HTTP and crypto. |
| HTTP routing | Standard library `net/http` (Go 1.22+ patterns) | No framework dependency. |
| Database | **SQLite** in WAL mode via `modernc.org/sqlite` (pure Go, no cgo) | No server to run or secure. Backup = one file (plus Litestream). Fine for dozens of users. |
| SQL access | **sqlc** (type-safe Go code generated from SQL) | Plain SQL, no ORM, compile-time checked. |
| Migrations | **goose**, migrations embedded in the binary | Run automatically on startup. |
| API contract | **OpenAPI 3.1** in `api/openapi.yaml` | Single source of truth for web and mobile clients. Handlers are hand-written for now; `oapi-codegen` types and a generated Dart client come in once the API grows past auth. |
| Resumable uploads | **tus** protocol (`github.com/tus/tusd`) | Photo backup over flaky mobile connections. |
| WebDAV | `golang.org/x/net/webdav` | Existing desktop and mobile clients work without custom code. |
| Images | **libvips** via `govips` (cgo), `libheif` for HEIC | Fastest, most memory-efficient thumbnailing. Lives in the photos package only. |
| Video thumbnails | `ffmpeg` (optional external binary) | Only if installed. |
| Web frontend | **SvelteKit** with `adapter-static`, TypeScript | Small bundles, no Node server in production. Built files embedded with `go:embed`. |
| Mobile app | **Flutter** (Dart) | One codebase for iOS and Android. `photo_manager` + `workmanager` for background photo upload. |
| Reverse proxy | **Caddy** | Automatic HTTPS. |
| Backups | **Litestream** (SQLite) + restic (files) | Continuous, point-in-time restore. |
| Container | Distroless image | No shell, no package manager: small attack surface. |

### Why not...

- **PHP / Node backend:** heavier at runtime and a larger dependency surface.
- **Postgres:** a second service to run, secure and back up. All database access
  goes through repository interfaces, so switching later stays possible.
- **JWTs:** cannot be revoked without a server-side list anyway. Opaque random
  tokens stored hashed in the database are simpler and revocable.
- **Own password manager clients:** mobile autofill needs native Android and iOS
  extensions, and writing our own end-to-end crypto is where security bugs come
  from. See [Password manager](#password-manager).

## Repository layout

```
KumoKeep/
├── api/openapi.yaml          # KumoKeep API contract (not the vault API)
├── server/                   # Go module: github.com/andrei-soimu/KumoKeep/server
│   ├── cmd/kumokeep/         # main: `serve`, `admin` subcommands
│   └── internal/
│       ├── config/           # env-based configuration
│       ├── db/               # SQLite open, migrations, sqlc queries + generated code
│       ├── auth/             # password hashing, tokens, sessions, middleware
│       ├── httpserver/       # router, middleware, JSON helpers
│       ├── web/              # embedded web app build (web/build → web/dist)
│       ├── files/            # (planned) storage, WebDAV
│       ├── notes/            # (planned)
│       ├── photos/           # (planned) library, thumbnails, EXIF
│       ├── vault/            # (planned) Bitwarden-compatible API
│       └── jobs/             # (planned) SQLite-backed job queue
├── web/                      # SvelteKit app
├── mobile/                   # Flutter app
├── deploy/                   # Dockerfile, Caddyfile, example config
└── docs/
```

## Data storage

```
$KUMOKEEP_DATA_DIR/
├── kumokeep.db               # SQLite: users, sessions, metadata, notes, vault
├── users/<user-uuid>/
│   ├── files/                # the user's files, as plain files
│   └── .trash/
├── cache/thumbnails/<user-uuid>/...
└── uploads/                  # in-progress tus uploads
```

- Paths use **user UUIDs, never usernames**, so renames don't move data and
  usernames can't be used for path tricks.
- All file access goes through `os.Root` (Go 1.24+), which makes it impossible
  to escape a user's directory via `..` or symlinks.
- File metadata (size, hash, MIME type, photo EXIF) is indexed in SQLite. The
  filesystem is the source of truth for file contents; a rescan rebuilds the index.
- Disk encryption (LUKS) protects data at rest. The app does not encrypt files
  itself, except the vault (end-to-end, see below).

## Users and authorization

- **Multi-user** with two roles: `admin` and `user`. Per-user storage quotas.
- **Registration by invitation only.** An admin creates an invite link (random
  token, expiry, optional email). The first admin is created with
  `kumokeep admin create`.
- **Authorization is enforced in one place.** Every handler gets the current user
  from the request context, and every query on user-owned data filters by
  `user_id`. Shared resources go through one `authz` check. This prevents the
  most common multi-user bug: reading another user's data by changing an ID.
- All IDs exposed in the API are random UUIDs.

## Authentication

| Client | Mechanism |
|---|---|
| Web app | Session cookie `__Host-kk_session` (`HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`). 30-day sliding expiry. |
| Mobile app | Short-lived access token (15 min) + rotating refresh token (30 days), both opaque. Stored in Keychain / Android Keystore. Reuse of an old refresh token revokes the whole device session. |
| WebDAV clients | Per-device **app passwords** (HTTP Basic over TLS). Cannot log into the web app. |
| Bitwarden apps | The Bitwarden protocol's own login, against a **separate master password**. See below. |

- Passwords are hashed with **Argon2id** (`golang.org/x/crypto/argon2`), parameters
  stored in the hash string so they can be raised later.
- Tokens are 256-bit random values. Only their **SHA-256 hash** is stored, so a
  database leak doesn't leak usable sessions.
- **Second factor:** TOTP and **WebAuthn/passkeys**. Required for admins.
- **Brute-force protection:** rate limits per IP and per account, with
  increasing delays, and audit-log entries for failures.
- Every user has a **Devices** page listing sessions, app passwords and mobile
  devices, each revocable.

## Web security

- **Content-Security-Policy:** `default-src 'self'`, no inline scripts except
  SvelteKit's bootstrap script, allowed by its SHA-256 hash. SvelteKit writes
  that policy as a `<meta>` tag at build time (`csp` in `web/vite.config.ts`);
  the server adds `frame-ancestors 'none'; object-src 'none'; base-uri 'none'`
  as a header. API responses get `default-src 'none'`.
- Other headers: `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: same-origin`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`.
- **CSRF:** state-changing browser requests must be same-origin (Go's
  `http.CrossOriginProtection`, which checks `Sec-Fetch-Site` / `Origin`), and
  JSON endpoints require `Content-Type: application/json`. Session cookies are
  `SameSite=Lax`.
- **User-uploaded content** is never served as active content from the main
  origin. Previews are served from a separate content origin when
  `KUMOKEEP_CONTENT_URL` is configured; otherwise as `Content-Disposition: attachment`
  with a sandboxing CSP.
- Request body limits everywhere; uploads only through tus or WebDAV.
- Fuzz tests for parsers that handle untrusted input (EXIF, WebDAV XML, paths).
- `govulncheck` and dependency updates in CI.
- An **audit log** records security events: logins, failures, 2FA changes,
  invites, admin actions, device revocations.

## Features

### Files

- Web UI: browse, upload, download, move, rename, trash, restore.
- WebDAV at `/dav` for desktop and mobile sync clients, authenticated with app passwords.
- Share links: random token, optional expiry and password, read-only by default.
- Quotas checked on every write.

### Notes

- Markdown notes with folders and tags, stored in SQLite with full-text search (FTS5).
- Edited from the web app and the mobile app (offline-first on mobile, synced
  with per-note revision numbers; conflicts keep both versions).
- Not end-to-end encrypted, so server-side search works. An optional end-to-end
  "locked note" may be added later.

### Photos

- A timeline and albums view over image and video files in the user's storage.
  A photo is a file; the photos feature adds an index on top.
- Mobile auto-upload via tus into `files/Photos/<year>/<month>/`, deduplicated by
  content hash.
- Background jobs extract EXIF (date taken, GPS, camera), generate thumbnails in
  two sizes (WebP), and video poster frames if `ffmpeg` exists.
- EXIF GPS data is stripped from shared photos by default.

### Password manager

KumoKeep implements a **subset of the Bitwarden client–server protocol**, so the
official, open-source Bitwarden apps (iOS, Android, browser extensions, desktop,
CLI) work against it, including mobile autofill. This is the approach Vaultwarden
takes; its source and issue tracker are the main reference, since Bitwarden does
not publish a spec for third-party servers.

- **Zero-knowledge.** Clients derive keys from the master password (PBKDF2 or
  Argon2id, per account settings) and encrypt everything before upload. The
  server stores only ciphertext and a server-side Argon2id hash of the client's
  master password hash.
- **Separate master password.** The vault password is not the KumoKeep login
  password. Only existing KumoKeep users can create a vault account (the
  Bitwarden registration endpoint requires a valid KumoKeep invite or a
  registration token from the web app).
- Mounted under `/vault`. Users enter `https://<host>/vault` as the self-hosted
  server URL in Bitwarden apps, which then call `/vault/api`, `/vault/identity`,
  `/vault/notifications` and `/vault/icons`.
- All accounts are reported as premium (TOTP, attachments).
- **Implementation order:**
  1. `prelogin`, registration, `identity/connect/token` (password + refresh grants)
  2. `sync`, ciphers CRUD, folders
  3. Two-factor (TOTP), attachments, websocket notifications
  4. Organizations / collections for sharing between users
- Never use the "Bitwarden" name for KumoKeep; "compatible with Bitwarden
  clients" is fine. Do not copy code from Bitwarden's server (AGPL + Bitwarden
  License); implement from client behaviour and public documentation.
- Risk: client updates can change the protocol. Track Vaultwarden releases and
  pin a tested client-version range in the docs.

## Mobile app (Flutter)

- Features: photo auto-upload and timeline, notes (offline-first), file browser.
- Passwords are handled by the official Bitwarden app, not this app.
- Login: username + password (+ 2FA), then device tokens in secure storage.
- API client generated from `api/openapi.yaml`.

## Background jobs

A small queue in SQLite (`jobs` table) with a pool of goroutines. Jobs are
idempotent and retried with backoff. Used for thumbnails, EXIF, trash expiry,
session cleanup and quota recalculation. No external scheduler.

## Configuration

Environment variables (a config file may be added later):

| Variable | Default | Meaning |
|---|---|---|
| `KUMOKEEP_ADDR` | `127.0.0.1:8080` | Listen address. Keep it on localhost behind Caddy. |
| `KUMOKEEP_DATA_DIR` | `./data` | Data directory (database, files, cache). |
| `KUMOKEEP_BASE_URL` | `http://localhost:8080` | Public URL, used for links, cookies and origin checks. |
| `KUMOKEEP_CONTENT_URL` | *(empty)* | Optional separate origin for serving user content. |
| `KUMOKEEP_TRUST_PROXY` | `false` | Take the client IP from the rightmost `X-Forwarded-For` entry. Enable only behind your own proxy. |
| `KUMOKEEP_DEV` | `false` | Development mode: human-readable debug logs. Cookies get `Secure` whenever the base URL is `https`. |

## Deployment

- Run `kumokeep serve` behind Caddy (example in `deploy/Caddyfile`), or use the
  distroless Docker image (`deploy/Dockerfile`).
- Back up with Litestream for `kumokeep.db` and restic for `users/`.

## Roadmap

1. **Foundation:** config, SQLite + migrations, users, invites, sessions, login,
   security middleware, web app shell. *(scaffolded)*
2. **Files:** storage, web UI, WebDAV, app passwords, share links, quotas.
3. **Notes:** CRUD, FTS search, mobile sync.
4. **Photos:** index, jobs, thumbnails, timeline, mobile auto-upload.
5. **Vault:** Bitwarden-compatible API, in the order above.
6. **Hardening:** 2FA/passkeys, rate limiting, audit log UI, fuzzing, Docker image.
