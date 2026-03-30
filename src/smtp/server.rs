// src/smtp/server.rs
//
// Async TCP server that accepts SMTP connections and drives the session state
// machine.  Supports RFC 2920 PIPELINING: we buffer command responses while
// the BufReader still has un-consumed data, and flush them all at once when
// the buffer drains.

use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tracing;

use crate::config::Config;
use crate::message::parser::ParsedMessage;
use crate::smtp::response::SmtpResponse;
use crate::smtp::session::{DataResult, SmtpSession};
use crate::spool::disk::DiskSpool;

/// The main SMTP server.
pub struct SmtpServer {
    config: Arc<Config>,
    spool: Arc<DiskSpool>,
}

impl SmtpServer {
    pub async fn new(config: Config) -> std::io::Result<Self> {
        let spool = DiskSpool::new(&config.spool_dir).await?;
        Ok(Self {
            config: Arc::new(config),
            spool: Arc::new(spool),
        })
    }

    /// Create from pre-existing shared `Config` and `DiskSpool` (used when
    /// the HTTP API server needs to share the same spool).
    pub fn with_shared(config: Arc<Config>, spool: Arc<DiskSpool>) -> Self {
        Self { config, spool }
    }

    /// Start listening and accepting connections.
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        tracing::info!(
            addr = %self.config.listen_addr,
            hostname = %self.config.hostname,
            "SMTP server listening"
        );

        loop {
            let (stream, peer) = listener.accept().await?;
            tracing::info!(peer = %peer, "new connection");
            let config = Arc::clone(&self.config);
            let spool = Arc::clone(&self.spool);

            tokio::spawn(async move {
                if let Err(e) = handle_connection(stream, config, spool).await {
                    tracing::error!(peer = %peer, error = %e, "connection error");
                }
                tracing::info!(peer = %peer, "connection closed");
            });
        }
    }
}

/// Drive one SMTP connection to completion.
async fn handle_connection(
    stream: TcpStream,
    config: Arc<Config>,
    spool: Arc<DiskSpool>,
) -> std::io::Result<()> {
    let peer = stream.peer_addr()?;
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    let mut session = SmtpSession::new(
        peer,
        &config.hostname,
        config.max_message_size,
        config.max_recipients,
    );

    // ── send 220 greeting immediately on connect ──────────────────
    send_response(&mut writer, &session.greeting()).await?;
    writer.flush().await?;

    let mut line_buf = String::new();
    // Pending responses for pipelining — we hold them until the BufReader's
    // internal buffer is empty (meaning we've consumed all pipelined commands
    // that arrived in the same TCP segment).
    let mut pending: Vec<SmtpResponse> = Vec::new();

    loop {
        line_buf.clear();
        match reader.read_line(&mut line_buf).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                if session.is_receiving_data() {
                    // ── DATA mode ───────────────────────────────────
                    match session.feed_data_line(&line_buf) {
                        DataResult::Continue => {}
                        DataResult::Done(resp) => {
                            // Spool the message
                            if let Some(data) = session.take_message_data() {
                                spool_message(&spool, &session, &data, &config.hostname).await;
                            }
                            send_response(&mut writer, &resp).await?;
                        }
                        DataResult::Error(resp) => {
                            send_response(&mut writer, &resp).await?;
                        }
                    }
                } else {
                    // ── command mode ─────────────────────────────────
                    let resp = session.process_command(line_buf.trim());
                    pending.push(resp);

                    // PIPELINING: if there is more buffered data, keep
                    // processing commands before flushing responses.
                    // Flush when the read buffer is empty OR we just entered
                    // DATA mode / QUIT.
                    let should_flush = reader.buffer().is_empty()
                        || session.is_receiving_data()
                        || session.is_closing();

                    if should_flush {
                        for r in pending.drain(..) {
                            send_response(&mut writer, &r).await?;
                        }
                        writer.flush().await?;
                    }

                    if session.is_closing() {
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::warn!(peer = %peer, error = %e, "read error");
                break;
            }
        }
    }

    Ok(())
}

/// Parse, decorate, and spool a completed message.
async fn spool_message(
    spool: &DiskSpool,
    session: &SmtpSession,
    raw_data: &[u8],
    hostname: &str,
) {
    // Try to parse & enrich; if parsing fails we still spool the raw data.
    let final_data = match ParsedMessage::parse(raw_data) {
        Ok(mut msg) => {
            msg.ensure_message_id(hostname);
            msg.prepend_received(&session.envelope().received_header(hostname));
            msg.to_bytes()
        }
        Err(errors) => {
            tracing::warn!(
                queue_id = %session.queue_id(),
                errors = ?errors,
                "message validation warnings — spooling raw"
            );
            raw_data.to_vec()
        }
    };

    if let Err(e) = spool.store(session.envelope(), &final_data).await {
        tracing::error!(
            queue_id = %session.queue_id(),
            error = %e,
            "failed to spool message"
        );
    }
}

/// Write a single SMTP response to the writer (does NOT flush).
async fn send_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: &SmtpResponse,
) -> std::io::Result<()> {
    writer.write_all(response.to_wire().as_bytes()).await
}