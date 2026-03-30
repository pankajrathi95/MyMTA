// tests/http_tests.rs
//
// Integration tests for the HTTP injection API.
// Spins up the axum HTTP server on an ephemeral port and exercises each
// endpoint with raw TCP / HTTP/1.1 requests.

use std::sync::Arc;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use mymta::config::Config;
use mymta::http::api::{self, ApiState};
use mymta::spool::disk::DiskSpool;

// ── helpers ─────────────────────────────────────────────────────────

/// Start the HTTP API on an ephemeral port and return the bound address.
async fn start_http_server(tmp: &TempDir) -> std::net::SocketAddr {
    let spool_dir = tmp.path().join("spool");
    let spool = Arc::new(DiskSpool::new(&spool_dir).await.unwrap());

    let mut cfg = Config::default();
    cfg.spool_dir = spool_dir;
    let config = Arc::new(cfg);

    let state = ApiState {
        config,
        spool,
    };

    // Bind to port 0 for an OS-assigned ephemeral port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let app = api::create_router(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Give the server a moment to start accepting
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

/// Send a raw HTTP/1.1 request and return (status_code, response_body).
async fn http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> (u16, String) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (mut read_half, mut write_half) = stream.into_split();

    let content = body.unwrap_or("");
    let request = if body.is_some() {
        format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            method, path, content.len(), content
        )
    } else {
        format!(
            "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            method, path
        )
    };

    write_half.write_all(request.as_bytes()).await.unwrap();

    // Read the full response (server will close after responding because of
    // Connection: close).
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        read_half.read_to_end(&mut response),
    )
    .await
    .expect("response timed out")
    .unwrap();

    let response = String::from_utf8_lossy(&response).to_string();

    // Parse status code from "HTTP/1.1 200 OK\r\n..."
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    // Parse body — handle both chunked and content-length responses.
    // For chunked encoding the body after the header separator starts with
    // the chunk size.  We strip the transfer-encoding framing.
    let raw_body = response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .to_string();

    let body_str = if response.contains("transfer-encoding: chunked") {
        // Simple chunked-decode: first line is hex size, then data, then "0\r\n"
        decode_chunked(&raw_body)
    } else {
        raw_body
    };

    (status, body_str)
}

/// Minimal chunked transfer-encoding decoder (for test use only).
fn decode_chunked(raw: &str) -> String {
    let mut result = String::new();
    let mut remaining = raw;
    loop {
        // Each chunk: <hex-size>\r\n<data>\r\n
        let size_end = match remaining.find("\r\n") {
            Some(pos) => pos,
            None => break,
        };
        let size_str = &remaining[..size_end];
        let size = match usize::from_str_radix(size_str.trim(), 16) {
            Ok(s) => s,
            Err(_) => break,
        };
        if size == 0 {
            break;
        }
        let data_start = size_end + 2;
        if data_start + size > remaining.len() {
            // partial chunk — just grab what we can
            result.push_str(&remaining[data_start..]);
            break;
        }
        result.push_str(&remaining[data_start..data_start + size]);
        remaining = &remaining[data_start + size..];
        // skip trailing \r\n
        if remaining.starts_with("\r\n") {
            remaining = &remaining[2..];
        }
    }
    result
}

// ── tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn health_endpoint() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let (status, body) = http_request(addr, "GET", "/v1/health", None).await;
    assert_eq!(status, 200, "health check failed: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert!(json["version"].is_string());
}

#[tokio::test]
async fn inject_structured_message() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let payload = serde_json::json!({
        "from": "alice@example.com",
        "to": ["bob@example.com"],
        "subject": "Hello via HTTP",
        "body": "This is a test message injected via the HTTP API."
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 200, "inject failed: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "queued");
    assert!(json["queue_id"].is_string());
    let queue_id = json["queue_id"].as_str().unwrap();
    assert!(!queue_id.is_empty());

    // Verify the message was spooled to disk
    let spool = DiskSpool::new(tmp.path().join("spool")).await.unwrap();
    let ids = spool.list_queue().await.unwrap();
    assert_eq!(ids.len(), 1, "expected 1 spooled message, got {}", ids.len());

    // Verify the envelope
    let env = spool.read_envelope(queue_id).await.unwrap();
    assert_eq!(env.sender, "alice@example.com");
    assert_eq!(env.recipients, vec!["bob@example.com"]);

    // Verify the message content
    let msg_data = spool.read_message(queue_id).await.unwrap();
    let text = String::from_utf8_lossy(&msg_data);
    assert!(text.contains("Subject: Hello via HTTP"), "subject missing from spooled message");
    assert!(text.contains("From: alice@example.com"), "From header missing");
    assert!(text.contains("Received:"), "Received header not added");
    assert!(text.contains("Message-ID:"), "Message-ID not added");
    assert!(text.contains("Date:"), "Date header missing");
}

#[tokio::test]
async fn inject_raw_message() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let raw_msg = "From: sender@example.com\r\nTo: rcpt@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nSubject: Raw Inject Test\r\n\r\nRaw body content.\r\n";
    let payload = serde_json::json!({
        "sender": "sender@example.com",
        "recipients": ["rcpt@example.com"],
        "raw_message": raw_msg
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject/raw",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 200, "raw inject failed: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["status"], "queued");
    let queue_id = json["queue_id"].as_str().unwrap();

    let spool = DiskSpool::new(tmp.path().join("spool")).await.unwrap();
    let msg_data = spool.read_message(queue_id).await.unwrap();
    let text = String::from_utf8_lossy(&msg_data);
    assert!(text.contains("Subject: Raw Inject Test"));
    assert!(text.contains("Received:"));
}

#[tokio::test]
async fn inject_validates_sender_address() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let payload = serde_json::json!({
        "from": "not-a-valid-address",
        "to": ["bob@example.com"],
        "body": "test"
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 400, "expected 400 for bad sender: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("sender"));
}

#[tokio::test]
async fn inject_validates_recipient_address() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let payload = serde_json::json!({
        "from": "alice@example.com",
        "to": ["bad-address"],
        "body": "test"
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 400, "expected 400 for bad recipient: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("recipient"));
}

#[tokio::test]
async fn inject_rejects_empty_recipients() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let payload = serde_json::json!({
        "from": "alice@example.com",
        "to": [],
        "body": "test"
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 400, "expected 400 for empty recipients: {}", body);
}

#[tokio::test]
async fn inject_rejects_too_many_recipients() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    // Default max_recipients is 100; send 101
    let recipients: Vec<String> = (0..101)
        .map(|i| format!("user{}@example.com", i))
        .collect();

    let payload = serde_json::json!({
        "from": "alice@example.com",
        "to": recipients,
        "body": "test"
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 400, "expected 400 for too many recipients: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("too many"));
}

#[tokio::test]
async fn inject_rejects_empty_sender() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let payload = serde_json::json!({
        "from": "",
        "to": ["bob@example.com"],
        "body": "test"
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 400, "expected 400 for empty sender: {}", body);
}

#[tokio::test]
async fn inject_raw_validates_missing_required_headers() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    // Missing From and Date headers
    let payload = serde_json::json!({
        "sender": "alice@example.com",
        "recipients": ["bob@example.com"],
        "raw_message": "Subject: No from or date\r\n\r\nBody\r\n"
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject/raw",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 400, "expected 400 for missing required headers: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(json["error"], "message validation failed");
    let details = json["details"].as_array().unwrap();
    assert!(details.len() >= 2, "should report missing From and Date");
}

#[tokio::test]
async fn inject_multiple_recipients() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let payload = serde_json::json!({
        "from": "alice@example.com",
        "to": ["bob@example.com", "carol@example.com", "dave@example.com"],
        "subject": "Multi-recipient",
        "body": "Hello everyone!"
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 200, "multi-recipient inject failed: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let queue_id = json["queue_id"].as_str().unwrap();

    let spool = DiskSpool::new(tmp.path().join("spool")).await.unwrap();
    let env = spool.read_envelope(queue_id).await.unwrap();
    assert_eq!(env.recipients.len(), 3);
}

#[tokio::test]
async fn inject_with_custom_headers() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let payload = serde_json::json!({
        "from": "alice@example.com",
        "to": ["bob@example.com"],
        "subject": "Custom Headers",
        "body": "Test body",
        "headers": {
            "Reply-To": "noreply@example.com",
            "X-Mailer": "MyApp/1.0"
        }
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 200, "custom headers inject failed: {}", body);

    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let queue_id = json["queue_id"].as_str().unwrap();

    let spool = DiskSpool::new(tmp.path().join("spool")).await.unwrap();
    let msg_data = spool.read_message(queue_id).await.unwrap();
    let text = String::from_utf8_lossy(&msg_data);
    assert!(text.contains("Reply-To: noreply@example.com"));
    assert!(text.contains("X-Mailer: MyApp/1.0"));
}

#[tokio::test]
async fn inject_raw_null_sender_allowed() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let raw_msg = "From: mailer-daemon@example.com\r\nTo: user@example.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\nSubject: Bounce\r\n\r\nUndeliverable.\r\n";
    let payload = serde_json::json!({
        "sender": "",
        "recipients": ["user@example.com"],
        "raw_message": raw_msg
    });

    let (status, body) = http_request(
        addr, "POST", "/v1/inject/raw",
        Some(&payload.to_string()),
    ).await;
    assert_eq!(status, 200, "null sender inject failed: {}", body);
}

#[tokio::test]
async fn not_found_returns_404() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let (status, _body) = http_request(addr, "GET", "/v1/nonexistent", None).await;
    assert_eq!(status, 404, "expected 404 for unknown route");
}

#[tokio::test]
async fn bad_json_returns_422() {
    let tmp = TempDir::new().unwrap();
    let addr = start_http_server(&tmp).await;

    let (status, _body) = http_request(
        addr, "POST", "/v1/inject",
        Some("this is not json"),
    ).await;
    // axum returns 422 Unprocessable Entity for JSON parse failures
    assert!(
        status == 422 || status == 400,
        "expected 422 or 400 for bad JSON, got: {}", status
    );
}