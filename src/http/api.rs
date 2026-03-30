// src/http/api.rs
//
// HTTP API for email injection.
//
// Endpoints:
//   GET  /v1/health       — liveness check
//   POST /v1/inject       — structured JSON injection (builds RFC 5322 message)
//   POST /v1/inject/raw   — raw message injection (caller supplies RFC 5322 body)
//
// All validations from the SMTP path (address checks, header validation,
// size limits, required headers) are reused here.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use uuid::Uuid;

use crate::config::Config;
use crate::message::envelope::Envelope;
use crate::message::parser::ParsedMessage;
use crate::smtp::command::validate_email_address;
use crate::spool::disk::DiskSpool;

// ── shared state ────────────────────────────────────────────────────

/// State shared across all HTTP handlers.
#[derive(Clone)]
pub struct ApiState {
    pub config: Arc<Config>,
    pub spool: Arc<DiskSpool>,
}

// ── request / response types ────────────────────────────────────────

/// Structured injection request — the server builds the RFC 5322 message.
#[derive(Debug, Deserialize)]
pub struct InjectRequest {
    /// Envelope sender (MAIL FROM equivalent).
    pub from: String,
    /// Envelope + header recipients.
    pub to: Vec<String>,
    /// Optional subject line.
    #[serde(default)]
    pub subject: Option<String>,
    /// Plain-text message body.
    pub body: String,
    /// Optional extra headers (e.g. Reply-To, X-Mailer).
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
}

/// Raw injection request — caller provides the complete RFC 5322 message.
#[derive(Debug, Deserialize)]
pub struct InjectRawRequest {
    /// Envelope sender.
    pub sender: String,
    /// Envelope recipients.
    pub recipients: Vec<String>,
    /// Complete RFC 5322 message (headers + blank line + body).
    pub raw_message: String,
}

/// Successful injection response.
#[derive(Debug, Serialize)]
pub struct InjectResponse {
    pub status: String,
    pub queue_id: String,
}

/// Error response body.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Vec<String>>,
}

/// Health-check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

// ── router ──────────────────────────────────────────────────────────

/// Build the axum Router with all API routes.
pub fn create_router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/inject", post(inject))
        .route("/v1/inject/raw", post(inject_raw))
        .with_state(state)
}

// ── HTTP server runner ──────────────────────────────────────────────

/// Start the HTTP API server on the given address.
pub async fn run_http_server(state: ApiState, addr: SocketAddr) -> std::io::Result<()> {
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "HTTP API server listening");
    axum::serve(listener, app)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

// ── handlers ────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
    })
}

/// POST /v1/inject — build a message from structured fields, validate, spool.
async fn inject(
    State(state): State<ApiState>,
    Json(req): Json<InjectRequest>,
) -> Result<Json<InjectResponse>, (StatusCode, Json<ErrorResponse>)> {
    // 1. Validate sender
    if req.from.is_empty() {
        return Err(bad_request("sender (from) is required"));
    }
    validate_email_address(&req.from)
        .map_err(|e| bad_request(&format!("invalid sender address: {}", e)))?;

    // 2. Validate recipients
    validate_recipients(&req.to, state.config.max_recipients)?;

    // 3. Build RFC 5322 message
    let date = Utc::now().format("%a, %d %b %Y %H:%M:%S %z").to_string();
    let mut raw_msg = String::new();
    raw_msg.push_str(&format!("From: {}\r\n", req.from));
    raw_msg.push_str(&format!("To: {}\r\n", req.to.join(", ")));
    raw_msg.push_str(&format!("Date: {}\r\n", date));
    if let Some(ref subj) = req.subject {
        raw_msg.push_str(&format!("Subject: {}\r\n", subj));
    }
    if let Some(ref hdrs) = req.headers {
        for (name, value) in hdrs {
            raw_msg.push_str(&format!("{}: {}\r\n", name, value));
        }
    }
    raw_msg.push_str("\r\n");
    raw_msg.push_str(&req.body);
    raw_msg.push_str("\r\n");

    // 4. Validate, enrich, spool — shared pipeline
    let queue_id = process_and_spool(
        &state,
        raw_msg.as_bytes(),
        req.from,
        req.to,
    )
    .await?;

    Ok(Json(InjectResponse {
        status: "queued".into(),
        queue_id,
    }))
}

/// POST /v1/inject/raw — accept a caller-supplied RFC 5322 message.
async fn inject_raw(
    State(state): State<ApiState>,
    Json(req): Json<InjectRawRequest>,
) -> Result<Json<InjectResponse>, (StatusCode, Json<ErrorResponse>)> {
    // 1. Validate sender (empty = null sender, allowed)
    if !req.sender.is_empty() {
        validate_email_address(&req.sender)
            .map_err(|e| bad_request(&format!("invalid sender address: {}", e)))?;
    }

    // 2. Validate recipients
    validate_recipients(&req.recipients, state.config.max_recipients)?;

    // 3. Validate, enrich, spool — shared pipeline
    let queue_id = process_and_spool(
        &state,
        req.raw_message.as_bytes(),
        req.sender,
        req.recipients,
    )
    .await?;

    Ok(Json(InjectResponse {
        status: "queued".into(),
        queue_id,
    }))
}

// ── shared helpers ──────────────────────────────────────────────────

/// Validate the recipient list (non-empty, within limits, valid addresses).
fn validate_recipients(
    recipients: &[String],
    max: usize,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if recipients.is_empty() {
        return Err(bad_request("at least one recipient is required"));
    }
    if recipients.len() > max {
        return Err(bad_request(&format!(
            "too many recipients (max {})",
            max
        )));
    }
    for addr in recipients {
        validate_email_address(addr)
            .map_err(|e| bad_request(&format!("invalid recipient '{}': {}", addr, e)))?;
    }
    Ok(())
}

/// Parse, validate, enrich, and spool a message.  Returns the queue-id.
async fn process_and_spool(
    state: &ApiState,
    raw_bytes: &[u8],
    sender: String,
    recipients: Vec<String>,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    // Size check
    if raw_bytes.len() > state.config.max_message_size {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                error: format!(
                    "message size {} exceeds maximum {}",
                    raw_bytes.len(),
                    state.config.max_message_size
                ),
                details: None,
            }),
        ));
    }

    // Parse & validate (same rules as SMTP DATA path)
    let mut parsed = ParsedMessage::parse(raw_bytes).map_err(|errs| {
        let details: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "message validation failed".into(),
                details: Some(details),
            }),
        )
    })?;

    // Enrich
    parsed.ensure_message_id(&state.config.hostname);
    let queue_id = generate_queue_id();

    let mut envelope = Envelope::new();
    envelope.stamp(queue_id.clone());
    envelope.set_sender(sender, vec![]);
    for rcpt in recipients {
        envelope.add_recipient(rcpt);
    }

    parsed.prepend_received(&envelope.received_header(&state.config.hostname));
    let final_data = parsed.to_bytes();

    // Spool to disk
    state.spool.store(&envelope, &final_data).await.map_err(|e| {
        tracing::error!(error = %e, "failed to spool message via HTTP API");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("failed to spool message: {}", e),
                details: None,
            }),
        )
    })?;

    tracing::info!(queue_id = %queue_id, "message injected via HTTP API");
    Ok(queue_id)
}

fn bad_request(msg: &str) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error: msg.to_string(),
            details: None,
        }),
    )
}

fn generate_queue_id() -> String {
    let u = Uuid::new_v4();
    let bytes = u.as_bytes();
    format!(
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}