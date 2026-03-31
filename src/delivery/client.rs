// src/delivery/client.rs
//
// SMTP client implementation for outbound delivery.
// Implements RFC 5321 client protocol.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::delivery::connector::{ConnectionConfig, SmtpConnection, SmtpConnector};
use crate::delivery::error::{DeliveryError, SmtpStage};
use crate::delivery::mx_resolve::{ResolvedDestination, select_destination};
use crate::delivery::result::{DeliveryResult, RecipientResult};

/// SMTP capabilities advertised by the server.
#[derive(Debug, Clone, Default)]
pub struct SmtpCapabilities {
    /// Server supports STARTTLS
    pub starttls: bool,
    /// Maximum message size (if advertised)
    pub max_size: Option<usize>,
    /// Server supports 8BITMIME
    pub eightbitmime: bool,
    /// Server supports PIPELINING
    pub pipelining: bool,
    /// Server supports AUTH (list of mechanisms)
    pub auth_mechanisms: Vec<String>,
    /// Server hostname from EHLO response
    pub server_hostname: String,
}

impl SmtpCapabilities {
    /// Parse capabilities from EHLO response lines.
    fn parse(lines: &[String]) -> Self {
        let mut caps = Self::default();

        for line in lines {
            let upper = line.to_ascii_uppercase();
            if upper.starts_with("STARTTLS") {
                caps.starttls = true;
            } else if upper.starts_with("SIZE ") {
                if let Some(size_str) = line.split_whitespace().nth(1) {
                    caps.max_size = size_str.parse().ok();
                }
            } else if upper.starts_with("8BITMIME") {
                caps.eightbitmime = true;
            } else if upper.starts_with("PIPELINING") {
                caps.pipelining = true;
            } else if upper.starts_with("AUTH ") {
                caps.auth_mechanisms = line[5..].split_whitespace().map(|s| s.to_string()).collect();
            }
        }

        caps
    }
}

/// An SMTP response from the server.
#[derive(Debug, Clone)]
pub struct SmtpClientResponse {
    /// Response code (e.g., 250, 550)
    pub code: u16,
    /// Response message lines
    pub lines: Vec<String>,
}

impl SmtpClientResponse {
    /// Returns true if this is a success response (2xx).
    pub fn is_success(&self) -> bool {
        self.code >= 200 && self.code < 300
    }
    
    /// Returns true if this is a transient failure (4xx).
    pub fn is_transient(&self) -> bool {
        self.code >= 400 && self.code < 500
    }
    
    /// Returns true if this is a permanent failure (5xx).
    pub fn is_permanent(&self) -> bool {
        self.code >= 500 && self.code < 600
    }
    
    /// Get the full message as a single string.
    pub fn message(&self) -> String {
        self.lines.join(" ")
    }
}

/// SMTP client for delivering messages.
pub struct SmtpClient {
    connector: SmtpConnector,
    config: ConnectionConfig,
}

impl SmtpClient {
    /// Create a new SMTP client.
    pub fn new(connector: SmtpConnector) -> Self {
        let config = connector.config().clone();
        Self {
            connector,
            config,
        }
    }

    /// Deliver a message to the specified destination.
    ///
    /// This handles the full delivery process:
    /// 1. Connect to the destination
    /// 2. Read greeting
    /// 3. EHLO/HELO
    /// 4. STARTTLS (if enabled and available)
    /// 5. MAIL FROM
    /// 6. RCPT TO (for each recipient)
    /// 7. DATA + message body
    /// 8. QUIT
    pub async fn deliver(
        &self,
        destinations: &[ResolvedDestination],
        sender: &str,
        recipients: &[String],
        message_body: &[u8],
    ) -> Result<DeliveryResult, DeliveryError> {
        let mut result = DeliveryResult::new(None);
        let mut attempted_addrs = Vec::new();

        // Try each destination in order of preference
        while let Some(dest) = select_destination(destinations, &attempted_addrs) {
            let addrs = dest.to_socket_addrs();
            
            match self.try_deliver_to(&addrs, sender, recipients, message_body).await {
                Ok((delivery_result, used_addr)) => {
                    result = delivery_result;
                    result.mx_server = Some(dest.exchange.clone());
                    return Ok(result);
                }
                Err(e) => {
                    // Mark all addresses for this destination as attempted
                    attempted_addrs.extend(addrs);
                    
                    // If this is the last destination, return the error
                    if select_destination(destinations, &attempted_addrs).is_none() {
                        return Err(e);
                    }
                    // Otherwise try next destination
                    tracing::warn!(
                        "Delivery to {} failed, trying next MX: {}",
                        dest.exchange,
                        e
                    );
                }
            }
        }

        Err(DeliveryError::ConnectionFailed {
            attempted: attempted_addrs.iter().map(|a| a.to_string()).collect(),
            reason: "All destinations exhausted".to_string(),
        })
    }

    /// Try to deliver to a specific set of addresses (one destination).
    async fn try_deliver_to(
        &self,
        addrs: &[std::net::SocketAddr],
        sender: &str,
        recipients: &[String],
        message_body: &[u8],
    ) -> Result<(DeliveryResult, std::net::SocketAddr), DeliveryError> {
        // Connect
        let mut conn = self.connector.connect(addrs).await?;
        let used_addr = addrs[0]; // Simplified - connector returns first successful

        let mut result = DeliveryResult::new(None);
        result.connected = true;

        // Read greeting
        let greeting = self.read_response(&mut conn).await?;
        if !greeting.is_success() {
            return Err(DeliveryError::from_smtp_response(
                greeting.code,
                &greeting.message(),
                SmtpStage::Connect,
            ));
        }

        // EHLO
        let capabilities = self.ehlo(&mut conn).await?;

        // STARTTLS if enabled and available
        #[cfg(feature = "tls")]
        if self.config.enable_starttls && capabilities.starttls {
            conn = self.starttls(conn).await?;
            // Re-EHLO after TLS
            let _ = self.ehlo(&mut conn).await?;
            result.tls_used = true;
        }

        // MAIL FROM
        self.mail_from(&mut conn, sender, message_body.len()).await?;

        // RCPT TO for each recipient
        for recipient in recipients {
            tracing::debug!("Trying RCPT TO for {}", recipient);
            match self.rcpt_to(&mut conn, recipient).await {
                Ok(_) => {
                    tracing::debug!("RCPT TO succeeded for {}", recipient);
                    result.add_recipient(
                        recipient.clone(),
                        RecipientResult::Success {
                            message: "Accepted".to_string(),
                        },
                    );
                }
                Err(e) => {
                    tracing::debug!("RCPT TO failed for {}: {}", recipient, e);
                    let result_type = if e.is_permanent() {
                        RecipientResult::PermanentFailure(e.clone())
                    } else {
                        RecipientResult::TransientFailure(e.clone())
                    };
                    result.add_recipient(recipient.clone(), result_type);
                }
            }
        }
        tracing::debug!("Successful recipients: {}", result.successful_recipients().len());

        // If no recipients accepted, skip DATA
        if result.successful_recipients().is_empty() {
            self.quit(&mut conn).await.ok();
            return Ok((result, used_addr));
        }

        // DATA
        self.data(&mut conn).await?;

        // Send message body
        self.send_body(&mut conn, message_body).await?;

        // Read final response
        let final_resp = self.read_response(&mut conn).await?;
        tracing::debug!("Final DATA response: {} {}", final_resp.code, final_resp.message());
        if !final_resp.is_success() {
            tracing::debug!("DATA failed, marking recipients as failed");
            // Mark all successful recipients as failed
            let error = DeliveryError::from_smtp_response(
                final_resp.code,
                &final_resp.message(),
                SmtpStage::Body,
            );
            
            // Update results
            for (addr, res) in &mut result.recipients {
                if res.is_success() {
                    *res = if error.is_permanent() {
                        RecipientResult::PermanentFailure(error.clone())
                    } else {
                        RecipientResult::TransientFailure(error.clone())
                    };
                }
            }
        } else {
            tracing::debug!("DATA succeeded");
        }

        // QUIT
        self.quit(&mut conn).await.ok();

        Ok((result, used_addr))
    }

    /// Send EHLO command and parse capabilities.
    async fn ehlo(&self, conn: &mut SmtpConnection) -> Result<SmtpCapabilities, DeliveryError> {
        let cmd = format!("EHLO {}\r\n", self.config.local_hostname);
        self.send_line(conn, &cmd).await?;

        let response = self.read_response(conn).await?;
        if !response.is_success() {
            // Try HELO fallback
            return self.helo(conn).await;
        }

        Ok(SmtpCapabilities::parse(&response.lines))
    }

    /// Send HELO command (fallback if EHLO not supported).
    async fn helo(&self, conn: &mut SmtpConnection) -> Result<SmtpCapabilities, DeliveryError> {
        let cmd = format!("HELO {}\r\n", self.config.local_hostname);
        self.send_line(conn, &cmd).await?;

        let response = self.read_response(conn).await?;
        if !response.is_success() {
            return Err(DeliveryError::from_smtp_response(
                response.code,
                &response.message(),
                SmtpStage::Ehlo,
            ));
        }

        Ok(SmtpCapabilities::default())
    }

    /// Send MAIL FROM command.
    async fn mail_from(
        &self,
        conn: &mut SmtpConnection,
        sender: &str,
        size: usize,
    ) -> Result<(), DeliveryError> {
        let cmd = if sender.is_empty() {
            format!("MAIL FROM:<> SIZE={}\r\n", size)
        } else {
            format!("MAIL FROM:<{}> SIZE={}\r\n", sender, size)
        };
        
        self.send_line(conn, &cmd).await?;

        let response = self.read_response(conn).await?;
        if !response.is_success() {
            return Err(DeliveryError::from_smtp_response(
                response.code,
                &response.message(),
                SmtpStage::MailFrom,
            ));
        }

        Ok(())
    }

    /// Send RCPT TO command.
    async fn rcpt_to(&self, conn: &mut SmtpConnection, recipient: &str) -> Result<(), DeliveryError> {
        let cmd = format!("RCPT TO:<{}>\r\n", recipient);
        tracing::debug!("Sending RCPT TO for {}", recipient);
        self.send_line(conn, &cmd).await?;

        let response = self.read_response(conn).await?;
        tracing::debug!("RCPT TO response: {} {}", response.code, response.message());
        if !response.is_success() {
            return Err(DeliveryError::from_smtp_response(
                response.code,
                &response.message(),
                SmtpStage::RcptTo,
            ));
        }

        Ok(())
    }

    /// Send DATA command.
    async fn data(&self, conn: &mut SmtpConnection) -> Result<(), DeliveryError> {
        self.send_line(conn, "DATA\r\n").await?;

        let response = self.read_response(conn).await?;
        // 354 means proceed with data
        if response.code != 354 {
            return Err(DeliveryError::from_smtp_response(
                response.code,
                &response.message(),
                SmtpStage::Data,
            ));
        }

        Ok(())
    }

    /// Send message body with dot-stuffing.
    async fn send_body(
        &self,
        conn: &mut SmtpConnection,
        body: &[u8],
    ) -> Result<(), DeliveryError> {
        // Process body line by line for dot-stuffing
        let mut in_buffer = body;
        let mut out_buffer = Vec::with_capacity(body.len() + 1024);

        // Normalize line endings to CRLF and handle dot-stuffing
        while !in_buffer.is_empty() {
            // Find end of line (LF)
            let line_end = in_buffer
                .iter()
                .position(|&b| b == b'\n')
                .map(|i| i + 1)
                .unwrap_or(in_buffer.len());

            let line = &in_buffer[..line_end];

            // Check if line ends with CRLF or just LF
            let content = if line.ends_with(b"\r\n") {
                &line[..line.len() - 2]  // Content without CRLF
            } else if line.ends_with(b"\n") {
                &line[..line.len() - 1]  // Content without LF
            } else {
                line  // No line ending
            };

            // Dot-stuffing: if line starts with '.', add another '.'
            if content.starts_with(b".") {
                out_buffer.push(b'.');
            }

            out_buffer.extend_from_slice(content);
            out_buffer.extend_from_slice(b"\r\n");  // Always use CRLF
            in_buffer = &in_buffer[line_end..];
        }

        // Add termination sequence (just .\r\n, since we already end with \r\n)
        out_buffer.extend_from_slice(b".\r\n");

        tracing::debug!("Sending body ({} bytes): {:?}", out_buffer.len(), String::from_utf8_lossy(&out_buffer));

        // Send with timeout
        timeout(self.config.data_timeout, conn.write_all(&out_buffer))
            .await
            .map_err(|_| DeliveryError::Timeout {
                stage: SmtpStage::Body,
                duration_secs: self.config.data_timeout.as_secs(),
            })?
            .map_err(|e| DeliveryError::IoError {
                stage: SmtpStage::Body,
                message: e.to_string(),
            })?;

        conn.flush().await.map_err(|e| DeliveryError::IoError {
            stage: SmtpStage::Body,
            message: e.to_string(),
        })?;

        Ok(())
    }

    /// Send QUIT command.
    async fn quit(&self, conn: &mut SmtpConnection) -> Result<(), DeliveryError> {
        self.send_line(conn, "QUIT\r\n").await?;
        let _ = self.read_response(conn).await; // Don't care about response
        Ok(())
    }

    /// Upgrade connection to TLS (STARTTLS).
    #[cfg(feature = "tls")]
    async fn starttls(&self, conn: SmtpConnection) -> Result<SmtpConnection, DeliveryError> {
        // This would need access to the underlying TcpStream
        // For now, return an error indicating TLS is not fully implemented
        Err(DeliveryError::TlsFailed {
            stage: SmtpStage::Tls,
            reason: "STARTTLS requires connector access".to_string(),
        })
    }

    /// Send a line to the server.
    async fn send_line(
        &self,
        conn: &mut SmtpConnection,
        line: &str,
    ) -> Result<(), DeliveryError> {
        timeout(self.config.command_timeout, conn.write_all(line.as_bytes()))
            .await
            .map_err(|_| DeliveryError::Timeout {
                stage: SmtpStage::Data,
                duration_secs: self.config.command_timeout.as_secs(),
            })?
            .map_err(|e| DeliveryError::IoError {
                stage: SmtpStage::Data,
                message: e.to_string(),
            })?;

        timeout(self.config.command_timeout, conn.flush())
            .await
            .map_err(|_| DeliveryError::Timeout {
                stage: SmtpStage::Data,
                duration_secs: self.config.command_timeout.as_secs(),
            })?
            .map_err(|e| DeliveryError::IoError {
                stage: SmtpStage::Data,
                message: e.to_string(),
            })?;

        Ok(())
    }

    /// Read a response from the server.
    async fn read_response(
        &self,
        conn: &mut SmtpConnection,
    ) -> Result<SmtpClientResponse, DeliveryError> {
        let mut lines = Vec::new();
        let mut code = 0u16;
        let mut line_buffer = Vec::new();

        loop {
            // Read byte by byte until we get a complete line
            let mut byte = [0u8; 1];
            let bytes_read = timeout(self.config.command_timeout, conn.read(&mut byte))
                .await
                .map_err(|_| DeliveryError::Timeout {
                    stage: SmtpStage::Data,
                    duration_secs: self.config.command_timeout.as_secs(),
                })?
                .map_err(|e| DeliveryError::IoError {
                    stage: SmtpStage::Data,
                    message: e.to_string(),
                })?;

            if bytes_read == 0 {
                return Err(DeliveryError::IoError {
                    stage: SmtpStage::Data,
                    message: "Connection closed unexpectedly".to_string(),
                });
            }

            line_buffer.push(byte[0]);

            // Check for line ending (CRLF)
            if line_buffer.ends_with(b"\r\n") {
                // Remove CRLF
                let line = String::from_utf8_lossy(&line_buffer[..line_buffer.len() - 2]);
                let line_str = line.to_string();

                // Parse response code from first line
                if code == 0 && line_str.len() >= 3 {
                    if let Ok(c) = line_str[..3].parse::<u16>() {
                        code = c;
                    } else {
                        return Err(DeliveryError::ProtocolError {
                            stage: SmtpStage::Data,
                            expected: "3-digit response code".to_string(),
                            received: line_str,
                        });
                    }
                }

                // Check if this is the last line (space after code) or continuation (dash)
                if line_str.len() >= 4 && line_str.as_bytes()[3] == b' ' {
                    lines.push(line_str[4..].to_string());
                    break;
                } else if line_str.len() >= 4 && line_str.as_bytes()[3] == b'-' {
                    lines.push(line_str[4..].to_string());
                    // Continue reading more lines
                } else {
                    lines.push(line_str[3..].to_string());
                    break;
                }

                line_buffer.clear();
            }
        }

        Ok(SmtpClientResponse { code, lines })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capabilities_parsing() {
        let lines = vec![
            "mx.example.com greets you".to_string(),
            "STARTTLS".to_string(),
            "SIZE 52428800".to_string(),
            "8BITMIME".to_string(),
            "PIPELINING".to_string(),
            "AUTH PLAIN LOGIN".to_string(),
        ];

        let caps = SmtpCapabilities::parse(&lines);
        assert!(caps.starttls);
        assert_eq!(caps.max_size, Some(52428800));
        assert!(caps.eightbitmime);
        assert!(caps.pipelining);
        assert_eq!(caps.auth_mechanisms, vec!["PLAIN", "LOGIN"]);
    }

    #[test]
    fn test_response_classification() {
        let success = SmtpClientResponse {
            code: 250,
            lines: vec!["OK".to_string()],
        };
        assert!(success.is_success());
        assert!(!success.is_transient());
        assert!(!success.is_permanent());

        let transient = SmtpClientResponse {
            code: 451,
            lines: vec!["Try later".to_string()],
        };
        assert!(!transient.is_success());
        assert!(transient.is_transient());
        assert!(!transient.is_permanent());

        let permanent = SmtpClientResponse {
            code: 550,
            lines: vec!["User unknown".to_string()],
        };
        assert!(!permanent.is_success());
        assert!(!permanent.is_transient());
        assert!(permanent.is_permanent());
    }
}
