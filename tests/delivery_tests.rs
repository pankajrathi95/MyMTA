// tests/delivery_tests.rs
//
// Integration tests for outbound SMTP delivery.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use mymta::delivery::{
    ConnectionConfig, DeliveryError, DeliveryResult, MxResolver, RecipientResult,
    ResolvedDestination, SmtpClient, SmtpConnector, SmtpStage,
};
use mymta::dns::resolver::MockDnsResolver;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// A mock SMTP server for testing.
struct MockSmtpServer {
    listener: TcpListener,
    responses: Vec<(u16, String)>,
    received_commands: Vec<String>,
}

impl MockSmtpServer {
    async fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self {
            listener,
            responses: vec![
                (220, "mock.server ESMTP ready".to_string()),
                (250, "mock.server greets you".to_string()),
                (250, "OK".to_string()),
                (250, "OK".to_string()),
                (354, "Start mail input".to_string()),
                (250, "Message accepted".to_string()),
                (221, "Bye".to_string()),
            ],
            received_commands: Vec::new(),
        }
    }

    fn local_addr(&self) -> SocketAddr {
        self.listener.local_addr().unwrap()
    }

    /// Run the server with default successful responses.
    async fn run_success(mut self) -> Vec<String> {
        let (stream, _) = self.listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let mut in_data_mode = false;

        // Send greeting
        writer
            .write_all(format!("{} {}\r\n", self.responses[0].0, self.responses[0].1).as_bytes())
            .await
            .unwrap();
        writer.flush().await.unwrap();

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await.unwrap();
            if n == 0 {
                break;
            }

            let cmd = line.trim().to_string();
            
            // In DATA mode, just collect lines until we see "."
            if in_data_mode {
                if cmd == "." {
                    in_data_mode = false;
                    if let Err(_) = writer.write_all(b"250 Message accepted\r\n").await {
                        break;
                    }
                    if let Err(_) = writer.flush().await {
                        break;
                    }
                }
                // Don't add body lines to received_commands
                continue;
            }

            self.received_commands.push(cmd.clone());

            if cmd.starts_with("QUIT") {
                // Send response and close gracefully
                let _ = writer.write_all(b"221 Bye\r\n").await;
                let _ = writer.flush().await;
                let _ = writer.shutdown().await;
                break;
            }

            // Respond based on command type
            let response = if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                "250-mock.server greets you\r\n250-SIZE 52428800\r\n250-8BITMIME\r\n250 OK\r\n"
            } else if cmd.starts_with("MAIL FROM") {
                "250 OK\r\n"
            } else if cmd.starts_with("RCPT TO") {
                "250 OK\r\n"
            } else if cmd.starts_with("DATA") {
                in_data_mode = true;
                "354 Start mail input\r\n"
            } else {
                "500 Command not recognized\r\n"
            };

            if let Err(_) = writer.write_all(response.as_bytes()).await {
                break;
            }
            if let Err(_) = writer.flush().await {
                break;
            }
        }

        self.received_commands
    }

    /// Run with specific recipient rejection.
    async fn run_with_rejection(mut self, reject_recipient: &str) -> Vec<String> {
        let (stream, _) = self.listener.accept().await.unwrap();
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let mut in_data_mode = false;

        // Send greeting
        writer.write_all(b"220 mock.server ESMTP ready\r\n").await.unwrap();
        writer.flush().await.unwrap();

        loop {
            line.clear();
            let n = reader.read_line(&mut line).await.unwrap();
            if n == 0 {
                break;
            }

            let cmd = line.trim().to_string();

            // In DATA mode, just collect lines until we see "."
            if in_data_mode {
                if cmd == "." {
                    in_data_mode = false;
                    if let Err(_) = writer.write_all(b"250 Message accepted\r\n").await {
                        break;
                    }
                    if let Err(_) = writer.flush().await {
                        break;
                    }
                }
                continue;
            }

            self.received_commands.push(cmd.clone());

            if cmd.starts_with("QUIT") {
                // Send response and close gracefully
                let _ = writer.write_all(b"221 Bye\r\n").await;
                let _ = writer.flush().await;
                let _ = writer.shutdown().await;
                break;
            }

            let response = if cmd.starts_with("RCPT TO") && cmd.contains(reject_recipient) {
                "550 User unknown\r\n"
            } else if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                "250-mock.server greets you\r\n250 OK\r\n"
            } else if cmd.starts_with("MAIL FROM") {
                "250 OK\r\n"
            } else if cmd.starts_with("RCPT TO") {
                "250 OK\r\n"
            } else if cmd.starts_with("DATA") {
                in_data_mode = true;
                "354 Start mail input\r\n"
            } else {
                "500 Command not recognized\r\n"
            };

            if let Err(_) = writer.write_all(response.as_bytes()).await {
                break;
            }
            if let Err(_) = writer.flush().await {
                break;
            }
        }

        self.received_commands
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("mymta=debug")
        .try_init();
}

#[tokio::test]
async fn test_successful_delivery() {
    init_tracing();
    
    // Start mock server
    let server = MockSmtpServer::new().await;
    let server_addr = server.local_addr();

    // Run server in background
    let server_handle = tokio::spawn(async move { server.run_success().await });

    // Create a resolved destination pointing to our mock server
    let dest = ResolvedDestination {
        domain: "test.com".to_string(),
        exchange: "mx.test.com".to_string(),
        addresses: vec![server_addr.ip()],
        preference: 10,
        port: server_addr.port(),
    };

    // Create client and deliver
    let config = ConnectionConfig {
        local_hostname: "client.test".to_string(),
        ..Default::default()
    };
    let connector = SmtpConnector::new(config);
    let client = SmtpClient::new(connector);

    let result = client
        .deliver(
            &[dest],
            "sender@test.com",
            &["recipient@test.com".to_string()],
            b"Subject: Test\r\n\r\nHello!\r\n",
        )
        .await;

    // Wait for server to complete
    let received_cmds = server_handle.await.unwrap();

    // Verify result
    assert!(result.is_ok(), "Delivery failed: {:?}", result.err());
    let result = result.unwrap();
    assert!(result.connected);
    assert_eq!(result.successful_recipients().len(), 1);
    assert_eq!(result.transient_failed_recipients().len(), 0);
    assert_eq!(result.permanent_failed_recipients().len(), 0);

    // Verify commands received by server
    assert!(received_cmds.iter().any(|c| c.starts_with("EHLO")));
    assert!(received_cmds.iter().any(|c| c.starts_with("MAIL FROM")));
    assert!(received_cmds.iter().any(|c| c.starts_with("RCPT TO")));
    assert!(received_cmds.iter().any(|c| c.starts_with("DATA")));
    assert!(received_cmds.iter().any(|c| c.starts_with("QUIT")));
}

#[tokio::test]
async fn test_delivery_with_rejected_recipient() {
    // Start mock server
    let server = MockSmtpServer::new().await;
    let server_addr = server.local_addr();

    // Run server in background with rejection
    let server_handle =
        tokio::spawn(async move { server.run_with_rejection("bad@test.com").await });

    let dest = ResolvedDestination {
        domain: "test.com".to_string(),
        exchange: "mx.test.com".to_string(),
        addresses: vec![server_addr.ip()],
        preference: 10,
        port: server_addr.port(),
    };

    let config = ConnectionConfig {
        local_hostname: "client.test".to_string(),
        ..Default::default()
    };
    let connector = SmtpConnector::new(config);
    let client = SmtpClient::new(connector);

    let result = client
        .deliver(
            &[dest],
            "sender@test.com",
            &[
                "good@test.com".to_string(),
                "bad@test.com".to_string(),
                "also_good@test.com".to_string(),
            ],
            b"Subject: Test\r\n\r\nHello!\r\n",
        )
        .await;

    let _received_cmds = server_handle.await.unwrap();

    assert!(result.is_ok());
    let result = result.unwrap();

    // One recipient should be rejected
    assert_eq!(result.successful_recipients().len(), 2);
    assert_eq!(result.permanent_failed_recipients().len(), 1);
    assert!(result.permanent_failed_recipients()[0].contains("bad@test.com"));
}

#[tokio::test]
async fn test_mx_resolution_integration() {
    let mock = Arc::new(MockDnsResolver::new());

    // Setup DNS records
    mock.set_mx(
        "example.com",
        vec![
            mymta::dns::resolver::MxRecord {
                preference: 10,
                exchange: "mail1.example.com".to_string(),
            },
            mymta::dns::resolver::MxRecord {
                preference: 20,
                exchange: "mail2.example.com".to_string(),
            },
        ],
        Duration::from_secs(300),
    )
    .await;

    mock.set_a(
        "mail1.example.com",
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
        Duration::from_secs(300),
    )
    .await;

    mock.set_a(
        "mail2.example.com",
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))],
        Duration::from_secs(300),
    )
    .await;

    let resolver = MxResolver::new(mock);
    let destinations = resolver.resolve("example.com").await.unwrap();

    assert_eq!(destinations.len(), 2);
    // Should be sorted by preference
    assert_eq!(destinations[0].preference, 10);
    assert_eq!(destinations[0].exchange, "mail1.example.com");
    assert_eq!(destinations[1].preference, 20);
    assert_eq!(destinations[1].exchange, "mail2.example.com");
}

#[tokio::test]
async fn test_mx_a_fallback_integration() {
    let mock = Arc::new(MockDnsResolver::new());

    // No MX records, just A record
    mock.set_a(
        "example.com",
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
        Duration::from_secs(300),
    )
    .await;

    let resolver = MxResolver::new(mock);
    let destinations = resolver.resolve("example.com").await.unwrap();

    assert_eq!(destinations.len(), 1);
    assert_eq!(destinations[0].exchange, "example.com"); // Domain itself
    assert_eq!(destinations[0].addresses.len(), 1);
}

#[tokio::test]
async fn test_dns_resolution_failure() {
    let mock = Arc::new(MockDnsResolver::new());
    // Don't set any records - should fail

    let resolver = MxResolver::new(mock);
    let result = resolver.resolve("nonexistent.com").await;

    assert!(result.is_err());
    match result.unwrap_err() {
        DeliveryError::DnsResolutionFailed { domain, .. } => {
            assert_eq!(domain, "nonexistent.com");
        }
        _ => panic!("Expected DnsResolutionFailed error"),
    }
}

#[test]
fn test_delivery_error_classification() {
    // Test permanent vs transient classification
    let permanent = DeliveryError::from_smtp_response(550, "User unknown", SmtpStage::RcptTo);
    assert!(permanent.is_permanent());
    assert!(!permanent.is_transient());

    let transient = DeliveryError::from_smtp_response(451, "Try later", SmtpStage::RcptTo);
    assert!(!transient.is_permanent());
    assert!(transient.is_transient());

    let transient = DeliveryError::from_smtp_response(421, "Service unavailable", SmtpStage::Ehlo);
    assert!(!transient.is_permanent());
    assert!(transient.is_transient());
}

#[test]
fn test_delivery_result_aggregation() {
    let mut result = DeliveryResult::new(Some("mx.example.com".to_string()));

    result.add_recipient(
        "alice@example.com".to_string(),
        RecipientResult::Success {
            message: "OK".to_string(),
        },
    );
    result.add_recipient(
        "bob@example.com".to_string(),
        RecipientResult::Success {
            message: "OK".to_string(),
        },
    );
    result.add_recipient(
        "charlie@example.com".to_string(),
        RecipientResult::PermanentFailure(DeliveryError::from_smtp_response(
            550,
            "No such user",
            SmtpStage::RcptTo,
        )),
    );

    assert!(!result.all_succeeded());
    assert_eq!(result.successful_recipients().len(), 2);
    assert_eq!(result.permanent_failed_recipients().len(), 1);
}

#[tokio::test]
async fn test_multiple_mx_fallback() {
    // This test verifies that if the first MX fails, we try the second
    // We'll start two servers - one that rejects connections, one that accepts

    // First server - will reject
    let server1 = MockSmtpServer::new().await;
    let addr1 = server1.local_addr();

    // Accept and immediately close to simulate failure
    tokio::spawn(async move {
        let (mut stream, _) = server1.listener.accept().await.unwrap();
        // Send error and close
        let _ = stream.write_all(b"421 Service unavailable\r\n").await;
        let _ = stream.shutdown().await;
    });

    // Give first server time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second server - will accept
    let server2 = MockSmtpServer::new().await;
    let addr2 = server2.local_addr();

    let server2_handle = tokio::spawn(async move { server2.run_success().await });

    // Create destinations - first will fail, second should succeed
    let dests = vec![
        ResolvedDestination {
            domain: "test.com".to_string(),
            exchange: "mx1.test.com".to_string(),
            addresses: vec![addr1.ip()],
            preference: 10,
            port: addr1.port(),
        },
        ResolvedDestination {
            domain: "test.com".to_string(),
            exchange: "mx2.test.com".to_string(),
            addresses: vec![addr2.ip()],
            preference: 20,
            port: addr2.port(),
        },
    ];

    let config = ConnectionConfig {
        local_hostname: "client.test".to_string(),
        connect_timeout: Duration::from_secs(5),
        ..Default::default()
    };
    let connector = SmtpConnector::new(config);
    let client = SmtpClient::new(connector);

    let result = client
        .deliver(
            &dests,
            "sender@test.com",
            &["recipient@test.com".to_string()],
            b"Subject: Test\r\n\r\nHello!\r\n",
        )
        .await;

    let _cmds = server2_handle.await.unwrap();

    // Should succeed via second MX
    assert!(result.is_ok(), "Should succeed via fallback MX");
    let result = result.unwrap();
    assert!(result.connected);
    assert_eq!(result.mx_server, Some("mx2.test.com".to_string()));
}
