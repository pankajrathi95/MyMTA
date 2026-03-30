// tests/integration_tests.rs
//
// Integration tests that spin up a real TCP server and drive full SMTP
// conversations (including pipelining) against it.

use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tempfile::TempDir;

// ── helpers ─────────────────────────────────────────────────────────

/// Start the MTA on an ephemeral port and return the address.
async fn start_server(tmp: &TempDir) -> std::net::SocketAddr {
    // Bind to port 0 to get an OS-assigned port
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let spool_dir = tmp.path().join("spool");
    tokio::fs::create_dir_all(&spool_dir).await.unwrap();

    tokio::spawn(async move {
        // Accept connections in a loop using the raw session + spool
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            let spool_dir = spool_dir.clone();
            tokio::spawn(async move {
                let _ = drive_connection(stream, peer, &spool_dir).await;
            });
        }
    });

    addr
}

/// Drive a connection using the library's session + spool directly.
async fn drive_connection(
    stream: tokio::net::TcpStream,
    peer: std::net::SocketAddr,
    spool_dir: &std::path::Path,
) -> std::io::Result<()> {
    use mymta::message::parser::ParsedMessage;
    use mymta::smtp::response::SmtpResponse;
    use mymta::smtp::session::{DataResult, SmtpSession};
    use mymta::spool::disk::DiskSpool;

    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = tokio::io::BufWriter::new(write_half);

    let spool: DiskSpool = DiskSpool::new(spool_dir).await?;
    let mut session = SmtpSession::new(peer, "test.mta.local", 10_485_760, 100);

    // Send greeting
    let greeting_wire = session.greeting().to_wire();
    writer.write_all(greeting_wire.as_bytes()).await?;
    writer.flush().await?;

    let mut line = String::new();
    let mut pending_responses: Vec<SmtpResponse> = Vec::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                if session.is_receiving_data() {
                    match session.feed_data_line(&line) {
                        DataResult::Continue => {}
                        DataResult::Done(resp) => {
                            if let Some(data) = session.take_message_data() {
                                // Parse & spool
                                let final_data = match ParsedMessage::parse(&data) {
                                    Ok(mut msg) => {
                                        msg.ensure_message_id("test.mta.local");
                                        msg.prepend_received(
                                            &session
                                                .envelope()
                                                .received_header("test.mta.local"),
                                        );
                                        msg.to_bytes()
                                    }
                                    Err(_) => data,
                                };
                                let _ = spool.store(session.envelope(), &final_data).await;
                            }
                            writer.write_all(resp.to_wire().as_bytes()).await?;
                            writer.flush().await?;
                        }
                        DataResult::Error(resp) => {
                            writer.write_all(resp.to_wire().as_bytes()).await?;
                            writer.flush().await?;
                        }
                    }
                } else {
                    let resp = session.process_command(line.trim());
                    pending_responses.push(resp);

                    let should_flush = reader.buffer().is_empty()
                        || session.is_receiving_data()
                        || session.is_closing();

                    if should_flush {
                        for r in pending_responses.drain(..) {
                            let wire = r.to_wire();
                            writer.write_all(wire.as_bytes()).await?;
                        }
                        writer.flush().await?;
                    }

                    if session.is_closing() {
                        break;
                    }
                }
            }
            Err(_) => break,
        }
    }
    Ok(())
}

/// Read one SMTP response line (may be multiline).
async fn read_response(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
    let mut full = String::new();
    loop {
        let mut line = String::new();
        let r = timeout(Duration::from_secs(5), reader.read_line(&mut line)).await;
        match r {
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {
                full.push_str(&line);
                // If the 4th char is a space (not '-'), this is the last line.
                if line.len() >= 4 && line.as_bytes()[3] == b' ' {
                    break;
                }
            }
            _ => break,
        }
    }
    full
}

/// Connect to the server and read the greeting.
async fn connect(addr: std::net::SocketAddr) -> (BufReader<tokio::net::tcp::OwnedReadHalf>, tokio::net::tcp::OwnedWriteHalf) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let (rh, wh) = stream.into_split();
    let mut reader = BufReader::new(rh);
    let greeting = read_response(&mut reader).await;
    assert!(greeting.starts_with("220 "), "expected 220 greeting, got: {}", greeting);
    (reader, wh)
}

/// Send a command and get the response.
async fn cmd(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    command: &str,
) -> String {
    writer.write_all(format!("{}\r\n", command).as_bytes()).await.unwrap();
    writer.flush().await.unwrap();
    read_response(reader).await
}

// ── tests ───────────────────────────────────────────────────────────

#[tokio::test]
async fn full_smtp_conversation() {
    let tmp = TempDir::new().unwrap();
    let addr = start_server(&tmp).await;
    let (mut reader, mut writer) = connect(addr).await;

    // EHLO
    let resp = cmd(&mut reader, &mut writer, "EHLO test.client").await;
    assert!(resp.starts_with("250"), "EHLO failed: {}", resp);
    assert!(resp.contains("PIPELINING"));

    // MAIL FROM
    let resp = cmd(&mut reader, &mut writer, "MAIL FROM:<alice@example.com>").await;
    assert!(resp.starts_with("250"), "MAIL FROM failed: {}", resp);

    // RCPT TO
    let resp = cmd(&mut reader, &mut writer, "RCPT TO:<bob@example.com>").await;
    assert!(resp.starts_with("250"), "RCPT TO failed: {}", resp);

    // DATA
    let resp = cmd(&mut reader, &mut writer, "DATA").await;
    assert!(resp.starts_with("354"), "DATA failed: {}", resp);

    // Send message body
    let body = "From: alice@example.com\r\n\
                To: bob@example.com\r\n\
                Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
                Subject: Integration Test\r\n\
                \r\n\
                This is a test message.\r\n\
                .\r\n";
    writer.write_all(body.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    let resp = read_response(&mut reader).await;
    assert!(resp.starts_with("250"), "data accept failed: {}", resp);
    assert!(resp.contains("queued"), "response should contain queue id");

    // QUIT
    let resp = cmd(&mut reader, &mut writer, "QUIT").await;
    assert!(resp.starts_with("221"), "QUIT failed: {}", resp);

    // Verify message was spooled
    let spool_dir = tmp.path().join("spool");
    let mut entries = tokio::fs::read_dir(&spool_dir).await.unwrap();
    let mut eml_count = 0;
    let mut env_count = 0;
    while let Some(entry) = entries.next_entry().await.unwrap() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".eml") {
            eml_count += 1;
            // Verify the spooled message contains our content
            let data = tokio::fs::read(entry.path()).await.unwrap();
            let text = String::from_utf8_lossy(&data);
            assert!(text.contains("Integration Test"), "message content missing");
            assert!(text.contains("Received:"), "Received header missing");
        }
        if name.ends_with(".env.json") {
            env_count += 1;
        }
    }
    assert_eq!(eml_count, 1, "expected 1 .eml file");
    assert_eq!(env_count, 1, "expected 1 .env.json file");
}

#[tokio::test]
async fn pipelining_multiple_commands() {
    let tmp = TempDir::new().unwrap();
    let addr = start_server(&tmp).await;
    let (mut reader, mut writer) = connect(addr).await;

    // First do EHLO (non-pipelineable, needs individual response)
    let resp = cmd(&mut reader, &mut writer, "EHLO pipeline.test").await;
    assert!(resp.starts_with("250"));

    // Now pipeline: MAIL FROM + RCPT TO + RCPT TO + DATA — all in one write
    let pipelined = "MAIL FROM:<sender@pipe.com>\r\n\
                     RCPT TO:<rcpt1@pipe.com>\r\n\
                     RCPT TO:<rcpt2@pipe.com>\r\n\
                     DATA\r\n";
    writer.write_all(pipelined.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    // Should get 4 responses back
    let r1 = read_response(&mut reader).await;
    assert!(r1.starts_with("250"), "MAIL FROM: {}", r1);
    let r2 = read_response(&mut reader).await;
    assert!(r2.starts_with("250"), "RCPT TO 1: {}", r2);
    let r3 = read_response(&mut reader).await;
    assert!(r3.starts_with("250"), "RCPT TO 2: {}", r3);
    let r4 = read_response(&mut reader).await;
    assert!(r4.starts_with("354"), "DATA: {}", r4);

    // Now send message body
    let body = "From: sender@pipe.com\r\n\
                Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n\
                Subject: Pipelined\r\n\
                \r\n\
                Pipelined message\r\n\
                .\r\n";
    writer.write_all(body.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();

    let resp = read_response(&mut reader).await;
    assert!(resp.starts_with("250"), "queued: {}", resp);

    // Cleanup
    cmd(&mut reader, &mut writer, "QUIT").await;
}

#[tokio::test]
async fn bad_sequence_errors() {
    let tmp = TempDir::new().unwrap();
    let addr = start_server(&tmp).await;
    let (mut reader, mut writer) = connect(addr).await;

    // MAIL FROM before EHLO → 503
    let resp = cmd(&mut reader, &mut writer, "MAIL FROM:<a@b.com>").await;
    assert!(resp.starts_with("503"), "expected 503: {}", resp);

    // EHLO then RCPT TO without MAIL FROM → 503
    cmd(&mut reader, &mut writer, "EHLO test").await;
    let resp = cmd(&mut reader, &mut writer, "RCPT TO:<a@b.com>").await;
    assert!(resp.starts_with("503"), "expected 503: {}", resp);

    // DATA without RCPT TO → 503
    cmd(&mut reader, &mut writer, "MAIL FROM:<a@b.com>").await;
    let resp = cmd(&mut reader, &mut writer, "DATA").await;
    assert!(resp.starts_with("503"), "expected 503: {}", resp);

    cmd(&mut reader, &mut writer, "QUIT").await;
}

#[tokio::test]
async fn unknown_command_returns_500() {
    let tmp = TempDir::new().unwrap();
    let addr = start_server(&tmp).await;
    let (mut reader, mut writer) = connect(addr).await;

    let resp = cmd(&mut reader, &mut writer, "XYZZY").await;
    assert!(resp.starts_with("500"), "expected 500: {}", resp);

    cmd(&mut reader, &mut writer, "QUIT").await;
}

#[tokio::test]
async fn rset_mid_transaction() {
    let tmp = TempDir::new().unwrap();
    let addr = start_server(&tmp).await;
    let (mut reader, mut writer) = connect(addr).await;

    cmd(&mut reader, &mut writer, "EHLO test").await;
    cmd(&mut reader, &mut writer, "MAIL FROM:<a@b.com>").await;
    cmd(&mut reader, &mut writer, "RCPT TO:<c@d.com>").await;

    // RSET should clear the transaction
    let resp = cmd(&mut reader, &mut writer, "RSET").await;
    assert!(resp.starts_with("250"), "RSET: {}", resp);

    // Now RCPT TO should fail (no MAIL FROM)
    let resp = cmd(&mut reader, &mut writer, "RCPT TO:<e@f.com>").await;
    assert!(resp.starts_with("503"), "expected 503 after RSET: {}", resp);

    cmd(&mut reader, &mut writer, "QUIT").await;
}

#[tokio::test]
async fn multiple_transactions_same_connection() {
    let tmp = TempDir::new().unwrap();
    let addr = start_server(&tmp).await;
    let (mut reader, mut writer) = connect(addr).await;

    cmd(&mut reader, &mut writer, "EHLO test").await;

    // First transaction
    cmd(&mut reader, &mut writer, "MAIL FROM:<a@b.com>").await;
    cmd(&mut reader, &mut writer, "RCPT TO:<c@d.com>").await;
    cmd(&mut reader, &mut writer, "DATA").await;
    let body1 = "From: a@b.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nMsg 1\r\n.\r\n";
    writer.write_all(body1.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();
    let resp = read_response(&mut reader).await;
    assert!(resp.starts_with("250"));

    // Second transaction (no RSET needed — session returns to Ready after DATA)
    cmd(&mut reader, &mut writer, "MAIL FROM:<x@y.com>").await;
    cmd(&mut reader, &mut writer, "RCPT TO:<z@w.com>").await;
    cmd(&mut reader, &mut writer, "DATA").await;
    let body2 = "From: x@y.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\nMsg 2\r\n.\r\n";
    writer.write_all(body2.as_bytes()).await.unwrap();
    writer.flush().await.unwrap();
    let resp = read_response(&mut reader).await;
    assert!(resp.starts_with("250"));

    cmd(&mut reader, &mut writer, "QUIT").await;

    // Should have 2 messages spooled
    let spool_dir = tmp.path().join("spool");
    let mut entries = tokio::fs::read_dir(&spool_dir).await.unwrap();
    let mut eml_count = 0;
    while let Some(entry) = entries.next_entry().await.unwrap() {
        if entry.file_name().to_string_lossy().ends_with(".eml") {
            eml_count += 1;
        }
    }
    assert_eq!(eml_count, 2, "expected 2 spooled messages");
}

#[tokio::test]
async fn noop_and_help_always_work() {
    let tmp = TempDir::new().unwrap();
    let addr = start_server(&tmp).await;
    let (mut reader, mut writer) = connect(addr).await;

    // NOOP before EHLO
    let resp = cmd(&mut reader, &mut writer, "NOOP").await;
    assert!(resp.starts_with("250"), "NOOP: {}", resp);

    // HELP before EHLO
    let resp = cmd(&mut reader, &mut writer, "HELP").await;
    assert!(resp.starts_with("214"), "HELP: {}", resp);

    cmd(&mut reader, &mut writer, "QUIT").await;
}