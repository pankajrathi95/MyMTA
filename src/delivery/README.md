# MyMTA Delivery Module

This module implements **Phase 4: Outbound SMTP Delivery** for the MyMTA mail transfer agent.

## Overview

The delivery module handles sending email messages to remote SMTP servers. It includes:

1. **MX Resolution** - DNS lookup of Mail Exchange records with A/AAAA fallback
2. **SMTP Client** - Full RFC 5321 compliant SMTP client implementation
3. **Connection Management** - TCP connections with configurable timeouts
4. **TLS Support** - STARTTLS and implicit TLS (SMTPS) support
5. **Error Handling** - Classification of transient vs permanent failures

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   MxResolver    │────▶│   SmtpClient     │────▶│  SmtpConnector  │
│                 │     │                  │     │                 │
│ - resolve()     │     │ - deliver()      │     │ - connect()     │
│ - MX fallback   │     │ - EHLO/MAIL/DATA │     │ - STARTTLS      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   DnsResolver   │     │  DeliveryResult  │     │  TcpStream/TLS  │
│                 │     │                  │     │                 │
│ - resolve_mx()  │     │ - per-recipient  │     │ - async I/O     │
│ - resolve_a()   │     │ - TLS status     │     │ - timeouts      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
```

## Usage

### Basic Delivery

```rust
use mymta::delivery::{MxResolver, SmtpClient, SmtpConnector, ConnectionConfig};
use mymta::dns::resolver::RealResolver;
use std::sync::Arc;

// Create DNS resolver
let resolver = Arc::new(RealResolver::new()?);
let mx_resolver = MxResolver::new(resolver);

// Resolve destination
let destinations = mx_resolver.resolve("example.com").await?;

// Create SMTP client
let config = ConnectionConfig::default();
let connector = SmtpConnector::new(config);
let client = SmtpClient::new(connector);

// Deliver message
let result = client.deliver(
    &destinations,
    "sender@example.com",
    &["recipient@example.com".to_string()],
    b"Subject: Hello\r\n\r\nWorld!\r\n",
).await?;

// Check results
for (recipient, status) in &result.recipients {
    match status {
        RecipientResult::Success { message } => {
            println!("Delivered: {}", recipient);
        }
        RecipientResult::TransientFailure(e) => {
            println!("Retry later: {} - {}", recipient, e);
        }
        RecipientResult::PermanentFailure(e) => {
            println!("Bounce: {} - {}", recipient, e);
        }
    }
}
```

### Error Handling

The module classifies errors as:

- **Transient (4xx)**: Temporary failures that should be retried
  - 421 Service unavailable
  - 451 Local error
  - Connection timeouts
  - DNS resolution failures

- **Permanent (5xx)**: Permanent failures that should generate bounces
  - 550 User unknown
  - 552 Message too large
  - 553 Invalid address

```rust
match error {
    e if e.is_transient() => {
        // Schedule retry with exponential backoff
    }
    e if e.is_permanent() => {
        // Generate DSN (bounce message)
    }
}
```

### MX Resolution Strategy

Per RFC 5321 Section 5.1:

1. Query MX records for the domain
2. Sort MX records by preference (lowest first)
3. Resolve each MX exchange to IP addresses (AAAA first, then A)
4. If no MX records exist, fallback to A/AAAA records on the domain
5. Try each destination in order until one succeeds

### Configuration

```rust
let config = ConnectionConfig {
    connect_timeout: Duration::from_secs(30),    // TCP connect timeout
    command_timeout: Duration::from_secs(60),    // EHLO/MAIL/RCPT timeout
    data_timeout: Duration::from_secs(300),      // Message body timeout
    enable_starttls: true,                        // Enable STARTTLS
    require_tls: false,                          // Require TLS (fail if unavailable)
    implicit_tls: false,                         // Use SMTPS (port 465)
    local_hostname: "mymta.example.com".to_string(), // For EHLO/HELO
};
```

## Testing

Run unit tests:
```bash
cargo test --lib delivery
```

Run integration tests:
```bash
cargo test --test delivery_tests
```

Run the example:
```bash
cargo run --example delivery_example
```

## Implementation Details

### SMTP Protocol Compliance

- **EHLO/HELO**: Extended hello with capability detection
- **MAIL FROM**: With SIZE parameter
- **RCPT TO**: Per-recipient result tracking
- **DATA**: Proper dot-stuffing and termination
- **QUIT**: Graceful connection close

### Response Parsing

Multi-line responses are properly handled:
```
250-mx.example.com greets you
250-SIZE 52428800
250-8BITMIME
250 OK
```

### Dot-Stuffing

Lines starting with `.` are escaped per RFC 5321:
```
Input:  "Hello\r\n.World\r\n"
Output: "Hello\r\n..World\r\n.\r\n"
```

## Future Enhancements

- [ ] SMTP AUTH (PLAIN, LOGIN, CRAM-MD5)
- [ ] Connection pooling
- [ ] PIPELINING support
- [ ] DSN (Delivery Status Notifications)
- [ ] Internationalized email (SMTPUTF8)
- [ ] Multiple delivery attempts per message
