# MyMTA — A Mail Transfer Agent Built from Scratch in Rust

A from-scratch MTA implementation in Rust, developed in phases. The goal is a
fully functional mail transfer agent covering SMTP ingestion, queueing, DNS
resolution, outbound delivery, authentication, and deliverability.

---

## Project Phases & Status

| # | Phase | Status |
|---|-------|--------|
| 1 | SMTP Ingestion | ✅ **Complete** |
| 1b | HTTP Injection API | ✅ **Complete** |
| 2 | Queueing | ✅ **Complete** |
| 3 | DNS Resolution | ✅ **Complete** |
| 4 | Outbound SMTP Delivery | ⬜ Planned |
| 5 | Authentication (SPF, DKIM, DMARC) | ⬜ Planned |
| 6 | Deliverability Features | ⬜ Planned |

---

## Phase 1 — SMTP Ingestion  ✅

### Features Implemented

1. **SMTP State Machine (RFC 5321)**
   - Full command set: `EHLO`, `HELO`, `MAIL FROM`, `RCPT TO`, `DATA`,
     `QUIT`, `RSET`, `NOOP`, `VRFY`, `HELP`
   - Strict state transitions: `Connected → Ready → MailFrom → RcptTo →
     ReceivingData → Ready` (loops for multiple messages)
   - Proper error codes for out-of-sequence commands (503), syntax errors
     (501), unrecognized commands (500)
   - ESMTP SIZE parameter — early rejection of oversized messages
   - Null sender (`MAIL FROM:<>`) support for bounce messages

2. **Message Parsing & Validation (RFC 5322)**
   - Header parsing with folded-header (continuation line) support
   - Required-header validation: `From` and `Date` must be present
   - Line-length validation (998-char limit per RFC 5322 §2.1.1)
   - Case-insensitive header lookups
   - Automatic `Message-ID` generation if missing
   - Automatic `Received` header prepended per RFC 5321 §4.4
   - Dot-unstuffing (RFC 5321 §4.5.2)

3. **Disk Spooling**
   - Each message stored as two files:
     - `{queue_id}.env.json` — Envelope metadata (JSON: sender, recipients,
       timestamps, peer address, ESMTP params)
     - `{queue_id}.eml` — Raw email with enriched headers
   - **Atomic writes**: write to temp file → `fsync` → rename into place
   - Queue listing, read-back, and removal operations

4. **PIPELINING (RFC 2920)**
   - Server advertises `PIPELINING` in EHLO response
   - Batched command processing: responses are buffered while the TCP
     read-buffer still has data, then flushed in one write
   - Correct DATA-mode transition within a pipelined batch

### Architecture

```
src/
├── main.rs              # Entry point — runs SMTP + HTTP concurrently
├── lib.rs               # Library crate root
├── config.rs            # Runtime configuration (TOML + env + defaults)
├── smtp/
│   ├── mod.rs
│   ├── command.rs       # SMTP command parser + email address validation
│   ├── response.rs      # SMTP response builder (single & multiline)
│   ├── session.rs       # State machine (pure logic, no I/O)
│   └── server.rs        # Async TCP server + pipelining driver
├── http/
│   ├── mod.rs
│   └── api.rs           # HTTP injection API (axum): /v1/inject, /v1/health
├── message/
│   ├── mod.rs
│   ├── envelope.rs      # SMTP envelope (MAIL FROM / RCPT TO metadata)
│   └── parser.rs        # RFC 5322 header parser + validator
└── spool/
    ├── mod.rs
    └── disk.rs           # Disk-based message spool with atomic writes
```

### Configuration

Configuration is resolved in layers (each overrides the previous):

1. **Compiled-in defaults** — always present
2. **TOML config file** — loaded via `--config` / `-c` flag
3. **Environment variables** (`MTA_*`) — override everything for container/CI use

#### Config file (`mymta.toml`)

A sample `mymta.toml` is included in the repo root. Every field is optional —
only the values you specify override the defaults.

```toml
[server]
listen   = "0.0.0.0:2525"
hostname = "mx.example.com"

[limits]
max_message_size = 26214400   # 25 MB
max_recipients   = 200

[spool]
dir = "/var/spool/mymta"

[logging]
level = "info"

[http]
listen = "0.0.0.0:8025"
```

#### Environment variable overrides

| Variable | Default | Description |
|----------|---------|-------------|
| `MTA_LISTEN` | `0.0.0.0:2525` | SMTP address:port to listen on |
| `MTA_HOSTNAME` | `localhost` | Hostname in greeting & EHLO response |
| `MTA_MAX_MESSAGE_SIZE` | `10485760` (10 MB) | Max message size in bytes |
| `MTA_MAX_RECIPIENTS` | `100` | Max RCPT TO per message |
| `MTA_SPOOL_DIR` | `spool` | Directory for spooled messages |
| `MTA_LOG_LEVEL` | `info` | Log level (error/warn/info/debug/trace) |
| `MTA_HTTP_LISTEN` | `0.0.0.0:8025` | HTTP API address:port |

### Running

```bash
# Build
cargo build --release

# Run with defaults (listens on port 2525)
cargo run

# Run with a config file
cargo run -- --config mymta.toml
cargo run -- -c /etc/mymta/mymta.toml

# Config file + env-var override (env wins for spool dir)
MTA_SPOOL_DIR=/tmp/test-spool cargo run -- -c mymta.toml

# Env vars only (no config file)
MTA_HOSTNAME=mx.example.com MTA_LISTEN=0.0.0.0:25 cargo run

# Show CLI help
cargo run -- --help
```

### Manual Validation

#### 1. Test with `telnet` / `nc`

```bash
# In terminal 1 — start the server
cargo run

# In terminal 2 — connect
telnet 127.0.0.1 2525
```

Then type the SMTP conversation:

```
EHLO test.local
MAIL FROM:<alice@example.com>
RCPT TO:<bob@example.com>
DATA
From: alice@example.com
To: bob@example.com
Date: Mon, 01 Jan 2024 00:00:00 +0000
Subject: Hello from MyMTA

This is a test message!
.
QUIT
```

Expected responses:
- `220 localhost ESMTP MyMTA Service ready`
- `250-localhost greets test.local` (multiline with PIPELINING, SIZE, etc.)
- `250 2.0.0 OK` (MAIL FROM)
- `250 2.0.0 OK` (RCPT TO)
- `354 Start mail input; end with <CRLF>.<CRLF>`
- `250 2.0.0 OK queued as XXXXXXXXXXXX`
- `221 2.0.0 localhost closing connection`

#### 2. Verify spooled message

```bash
ls spool/
# Shows:  XXXXXXXXXXXX.env.json   XXXXXXXXXXXX.eml

cat spool/*.env.json   # Envelope with sender, recipients, timestamps
cat spool/*.eml         # Full message with Received + Message-ID headers
```

#### 3. Test pipelining

```bash
printf 'EHLO pipe.test\r\n' | nc 127.0.0.1 2525 &
sleep 0.1
# Or use a script that sends multiple commands in one TCP write:
printf 'EHLO pipe.test\r\nMAIL FROM:<a@b.com>\r\nRCPT TO:<c@d.com>\r\nDATA\r\n' | nc 127.0.0.1 2525
```

#### 4. Run the test suite

```bash
# All 96 tests (75 unit + 7 SMTP integration + 14 HTTP integration)
cargo test

# With output
cargo test -- --nocapture

# Specific module
cargo test smtp::command
cargo test smtp::session
cargo test message::parser
cargo test spool::disk
cargo test --test integration_tests
```

### Test Coverage Summary

| Module | Tests | Coverage |
|--------|-------|----------|
| `config` | 7 | Defaults, full TOML load, partial TOML, missing file, bad TOML, bad address, no-file fallback |
| `smtp::command` | 19 | Parsing all commands, case insensitivity, address validation, pipelining flags |
| `smtp::response` | 4 | Single/multiline format, greeting, EHLO capabilities |
| `smtp::session` | 18 | State transitions, full conversation, RSET, size limits, dot-unstuffing |
| `message::envelope` | 4 | Create, set, reset, Received header generation |
| `message::parser` | 8 | Parsing, folding, required headers, line lengths, Message-ID, roundtrip |
| `spool::disk` | 4 | Store+read, list, remove, directory creation |
| **SMTP Integration** | **7** | Full conversation, pipelining, bad sequences, RSET, multi-transaction, NOOP/HELP, unknown commands |
| **HTTP Integration** | **14** | Health, structured inject, raw inject, sender validation, recipient validation, empty/too-many recipients, empty sender, missing headers, multi-recipient, custom headers, null sender, 404, bad JSON |
| **Total** | **96** | |

---

## Phase 1b — HTTP Injection API  ✅

### Overview

An HTTP/JSON API that provides a second injection path alongside SMTP.  Both
paths share the **same spool directory** and run through **identical
validation** (email address checks, required-header enforcement, size limits,
Message-ID / Received enrichment).

The HTTP server is powered by [axum](https://docs.rs/axum) and starts
automatically alongside the SMTP server on a configurable port (default
`:8025`).

### Endpoints

#### `GET /v1/health`

Liveness probe.

```json
{ "status": "ok", "version": "0.1.0" }
```

#### `POST /v1/inject` — Structured injection

The server builds a complete RFC 5322 message from the provided fields.  `Date`,
`Message-ID`, and `Received` headers are added automatically.

**Request body:**

```json
{
  "from": "alice@example.com",
  "to": ["bob@example.com", "carol@example.com"],
  "subject": "Hello from the HTTP API",
  "body": "Plain-text message content.",
  "headers": {
    "Reply-To": "noreply@example.com",
    "X-Mailer": "MyApp/1.0"
  }
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `from` | string | ✅ | Envelope sender — must be a valid email address |
| `to` | string[] | ✅ | One or more recipients (validated, max enforced) |
| `subject` | string | | Optional subject line |
| `body` | string | ✅ | Plain-text message body |
| `headers` | object | | Optional extra headers (key → value) |

**Success (200):**

```json
{ "status": "queued", "queue_id": "A1B2C3D4E5F6" }
```

**Errors (400 / 413 / 500):**

```json
{
  "error": "message validation failed",
  "details": ["missing required header: From", "missing required header: Date"]
}
```

#### `POST /v1/inject/raw` — Raw message injection

For advanced callers who build the RFC 5322 message themselves.  The server
runs the same parse/validate/enrich pipeline.

**Request body:**

```json
{
  "sender": "alice@example.com",
  "recipients": ["bob@example.com"],
  "raw_message": "From: alice@example.com\r\nTo: bob@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nSubject: Raw inject\r\n\r\nBody text.\r\n"
}
```

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `sender` | string | ✅ | Envelope sender (empty = null sender for bounces) |
| `recipients` | string[] | ✅ | Envelope recipients |
| `raw_message` | string | ✅ | Complete RFC 5322 message |

### Validation Pipeline (shared with SMTP)

Every message injected via HTTP goes through the same checks as SMTP `DATA`:

1. **Sender address validation** — format check via `validate_email_address()`
2. **Recipient address validation** — each recipient checked, count enforced
3. **Message size limit** — `max_message_size` from config (default 10 MB)
4. **RFC 5322 parsing** — header syntax, folded-header unfolding
5. **Required headers** — `From` and `Date` must be present
6. **Line-length limit** — 998-char max per RFC 5322 §2.1.1
7. **Message-ID** — auto-generated if missing
8. **Received header** — prepended per RFC 5321 §4.4
9. **Atomic disk spool** — temp → fsync → rename, same as SMTP path

### Manual Testing

```bash
# Start the server (SMTP on :2525, HTTP on :8025)
cargo run

# Health check
curl http://localhost:8025/v1/health

# Inject a structured message
curl -X POST http://localhost:8025/v1/inject \
  -H 'Content-Type: application/json' \
  -d '{
    "from": "alice@example.com",
    "to": ["bob@example.com"],
    "subject": "Hello from HTTP",
    "body": "This is a test message."
  }'

# Inject a raw RFC 5322 message
curl -X POST http://localhost:8025/v1/inject/raw \
  -H 'Content-Type: application/json' \
  -d '{
    "sender": "alice@example.com",
    "recipients": ["bob@example.com"],
    "raw_message": "From: alice@example.com\r\nTo: bob@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nSubject: Raw test\r\n\r\nHello!\r\n"
  }'

# Verify spooled messages
ls spool/
cat spool/*.env.json
cat spool/*.eml
```

---

## Phase 2 — Queueing  ✅

### Overview

The queue manager orchestrates outbound delivery scheduling. Messages are
organized into per-destination queues, with retry scheduling and concurrency
limits to ensure reliable, controlled delivery.

### Features Implemented

1. **Per-Destination Queues**
   - One queue per destination domain (extracted from recipient addresses)
   - Messages are grouped by domain for efficient MX targeting
   - Priority ordering within each queue (0=High, 1=Normal, 2=Low)

2. **Retry Scheduling with Exponential Backoff**
   - Configurable initial delay (default: 60s)
   - Multiplier applied after each failed attempt (default: 2.0×)
   - Maximum delay cap (default: 1 hour)
   - Maximum attempts before giving up (default: 10)

3. **Concurrency Limits**
   - Default concurrency of 5 deliveries per destination
   - Prevents overwhelming remote servers
   - Slots released on success or failure

4. **QueueManager API**
   - `enqueue()` — add a newly spooled message
   - `next_for_delivery()` — pick the next ready message respecting concurrency
   - `on_delivery_success()` — remove from spool and release slot
   - `on_delivery_failure()` — schedule retry or discard

### Architecture

```
src/queue/
├── mod.rs           # Re-exports QueueManager, RetrySchedule
├── manager.rs       # QueueManager + DestinationQueue + QueuedMessage
└── retry.rs         # RetrySchedule with backoff math
```

### Configuration

Queue settings live under `[queue]` in `mymta.toml` and can be overridden
via environment variables:

| Config Key | Env Variable | Default | Description |
|------------|--------------|---------|-------------|
| `concurrency` | `MTA_QUEUE_CONCURRENCY` | 5 | Max concurrent deliveries per domain |
| `retry_initial_delay` | `MTA_QUEUE_RETRY_INITIAL_DELAY` | 60 | Seconds before first retry |
| `retry_backoff` | `MTA_QUEUE_RETRY_BACKOFF` | 2.0 | Multiplier per failed attempt |
| `retry_max_delay` | `MTA_QUEUE_RETRY_MAX_DELAY` | 3600 | Cap on retry delay (seconds) |
| `retry_max_attempts` | `MTA_QUEUE_RETRY_MAX_ATTEMPTS` | 10 | Attempts before giving up |

Example `mymta.toml` snippet:

```toml
[queue]
concurrency = 10
retry_initial_delay = 30
retry_backoff = 1.5
retry_max_delay = 1800
retry_max_attempts = 8
```

### Manual Testing

```bash
# Build and run
cargo run

# Inject a message via HTTP or SMTP (see Phase 1 / 1b sections)
# The message is automatically enqueued for delivery

# Inspect the queue state (currently via logs / spool files)
ls spool/
cat spool/*.env.json
```

Future CLI tools (`mymta queue list`, `mymta queue stats`) are planned.

### Test Coverage

| Test | Description |
|------|-------------|
| `enqueue_and_pickup` | Spool → enqueue → deliver → success removes from spool |
| `concurrency_limit` | Only N messages delivered in parallel per domain |
| `priority_ordering` | High priority messages are picked before low priority |

---

## Phase 3 — DNS Resolution  ✅

### Overview

DNS resolution is essential for outbound delivery. The resolver finds MX hosts
for destination domains, falls back to A/AAAA when no MX exists, and caches
results to reduce latency and load.

All tests use `MockDnsResolver` — **zero network calls**.

### Features Implemented

1. **MX Record Lookup**
   - Query MX records for a domain
   - Parse preference + exchange host
   - Return sorted by preference (lower = higher priority)

2. **A/AAAA Fallback**
   - If no MX records, fall back to A (and AAAA) as implicit MX per RFC 5321 §5.1
   - Used by delivery layer when MX lookup returns empty/NODATA

3. **TTL-Aware Caching**
   - Positive cache: MX, A, AAAA records stored with their DNS TTL
   - Negative cache: NXDOMAIN / NODATA cached with a shorter TTL (default 5 min)
   - Max TTL cap (default 1 hour) prevents stale entries

4. **CNAME Handling**
   - Mock resolver supports explicit CNAME programming for tests
   - Real resolver relies on hickory's internal CNAME handling

5. **Error Classification (Delivery Impact)**

   | Error | Meaning | Delivery Action |
   |-------|---------|-----------------|
   | `NXDOMAIN` | Domain doesn't exist | **Permanent** → Bounce |
   | `NODATA` | No MX/A/AAAA records | **Permanent** → Bounce |
   | `SERVFAIL` | Server failure | **Temporary** → Retry |
   | `REFUSED` | Query refused | **Temporary** → Retry |
   | `Timeout` | No response | **Temporary** → Retry |
   | `CNAME loop` | Chain too deep | **Permanent** → Bounce |

### Architecture

```
src/dns/
├── mod.rs        # Re-exports
├── error.rs      # DnsError + DnsFailureMode (permanent vs temporary)
├── cache.rs      # DnsCache with TTL + negative caching
└── resolver.rs   # DnsResolver trait + MockDnsResolver + RealResolver
```

### Usage (Trait-Based)

```rust
use mymta::dns::{DnsResolver, MockDnsResolver, MxResult};

// In production, use RealResolver (hickory-resolver backed)
// In tests, inject MockDnsResolver — no network ever

let resolver: &dyn DnsResolver = &mock;
match resolver.resolve_mx("example.com").await {
    MxResult::Ok(records) => { /* pick MX by preference */ }
    MxResult::Err(e) if e.is_permanent() => { /* bounce */ }
    MxResult::Err(e) if e.is_temporary() => { /* retry later */ }
    _ => {}
}
```

### Configuration

| Setting | Env Variable | Default | Description |
|---------|--------------|---------|-------------|
| `dns_timeout_secs` | `MTA_DNS_TIMEOUT` | 5 | Per-query timeout |
| `dns_cache_max_ttl_secs` | `MTA_DNS_CACHE_MAX_TTL` | 3600 | Cap on positive TTL |
| `dns_cache_neg_ttl_secs` | `MTA_DNS_CACHE_NEG_TTL` | 300 | Negative cache TTL |
| `dns_max_cname_depth` | `MTA_DNS_MAX_CNAME_DEPTH` | 8 | Max CNAME chain |

### Test Coverage

All 21 DNS tests use `MockDnsResolver` — **zero network calls**:

| Test | Description |
|------|-------------|
| `mock_mx_ok` | Program MX success, verify records returned |
| `mock_mx_nxdomain` | Unprogrammed domain → NXDOMAIN (permanent) |
| `mock_mx_servfail` | Program SERVFAIL → temporary |
| `mock_timeout_is_temporary` | Timeout classified as retryable |
| `mock_a_ok` / `mock_aaaa_ok` | IPv4/IPv6 resolution |
| `mock_case_insensitive` | Domain lookups are case-insensitive |
| `mx_cache_hit_and_miss` | Cache stores and retrieves |
| `mx_cache_expires` | TTL expiry works |
| `negative_cache` | NXDOMAIN/NODATA cached |
| `ttl_cap` | DNS TTLs capped by max_ttl |

---

## Upcoming Phases

### Phase 4 — Outbound SMTP Delivery
- Connect to remote MX servers
- TLS/STARTTLS support
- Delivery status tracking (delivered, deferred, bounced)

### Phase 5 — Authentication
- SPF verification
- DKIM signing
- DMARC policy enforcement
- SMTP AUTH (for submission)

### Phase 6 — Deliverability Features
- Rate limiting
- IP warm-up scheduling
- Bounce classification
- Feedback loop (FBL) processing
- Reputation monitoring