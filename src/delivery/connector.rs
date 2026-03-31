// src/delivery/connector.rs
//
// TCP connection management with optional TLS/STARTTLS support.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::delivery::error::{DeliveryError, SmtpStage};

/// Configuration for SMTP connections.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Connect timeout
    pub connect_timeout: Duration,
    /// Command timeout (for EHLO, MAIL, RCPT, etc.)
    pub command_timeout: Duration,
    /// Data timeout (for message body transmission)
    pub data_timeout: Duration,
    /// Enable STARTTLS
    pub enable_starttls: bool,
    /// Require TLS (fail if STARTTLS not available)
    pub require_tls: bool,
    /// Use implicit TLS (SMTPS on port 465)
    pub implicit_tls: bool,
    /// Local hostname for EHLO/HELO
    pub local_hostname: String,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(30),
            command_timeout: Duration::from_secs(60),
            data_timeout: Duration::from_secs(300),
            enable_starttls: true,
            require_tls: false,
            implicit_tls: false,
            local_hostname: "localhost".to_string(),
        }
    }
}

/// An SMTP connection - either plaintext or TLS-encrypted.
pub enum SmtpConnection {
    /// Plaintext TCP connection
    Plain(TcpStream),
    /// TLS-encrypted connection
    #[cfg(feature = "tls")]
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl SmtpConnection {
    /// Check if this connection is TLS-encrypted.
    pub fn is_tls(&self) -> bool {
        match self {
            SmtpConnection::Plain(_) => false,
            #[cfg(feature = "tls")]
            SmtpConnection::Tls(_) => true,
        }
    }
}

// Implement AsyncRead and AsyncWrite for SmtpConnection
impl AsyncRead for SmtpConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            SmtpConnection::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            #[cfg(feature = "tls")]
            SmtpConnection::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for SmtpConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            SmtpConnection::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            #[cfg(feature = "tls")]
            SmtpConnection::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            SmtpConnection::Plain(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(feature = "tls")]
            SmtpConnection::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            SmtpConnection::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(feature = "tls")]
            SmtpConnection::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// SMTP connection manager.
pub struct SmtpConnector {
    config: ConnectionConfig,
    #[cfg(feature = "tls")]
    tls_connector: Option<tokio_rustls::TlsConnector>,
}

impl SmtpConnector {
    /// Create a new connector with the given configuration.
    pub fn new(config: ConnectionConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "tls")]
            tls_connector: None,
        }
    }

    /// Create with TLS support (for implicit TLS or STARTTLS).
    #[cfg(feature = "tls")]
    pub fn with_tls(config: ConnectionConfig, tls_connector: tokio_rustls::TlsConnector) -> Self {
        Self {
            config,
            tls_connector: Some(tls_connector),
        }
    }

    /// Connect to a remote SMTP server.
    ///
    /// Tries each address in order until one succeeds.
    pub async fn connect(&self, addrs: &[SocketAddr]) -> Result<SmtpConnection, DeliveryError> {
        let mut last_error = None;

        for addr in addrs {
            match self.try_connect(*addr).await {
                Ok(conn) => return Ok(conn),
                Err(e) => {
                    tracing::debug!("Connection to {} failed: {}", addr, e);
                    last_error = Some(e);
                }
            }
        }

        Err(DeliveryError::ConnectionFailed {
            attempted: addrs.iter().map(|a| a.to_string()).collect(),
            reason: last_error
                .map(|e| e.to_string())
                .unwrap_or_else(|| "All connection attempts failed".to_string()),
        })
    }

    /// Try to connect to a single address.
    async fn try_connect(&self, addr: SocketAddr) -> Result<SmtpConnection, DeliveryError> {
        let stream = timeout(self.config.connect_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| DeliveryError::Timeout {
                stage: SmtpStage::Connect,
                duration_secs: self.config.connect_timeout.as_secs(),
            })?
            .map_err(|e| DeliveryError::IoError {
                stage: SmtpStage::Connect,
                message: e.to_string(),
            })?;

        #[cfg(feature = "tls")]
        if self.config.implicit_tls {
            return self.upgrade_to_tls(stream, addr).await;
        }

        Ok(SmtpConnection::Plain(stream))
    }

    /// Upgrade a plaintext connection to TLS (STARTTLS).
    #[cfg(feature = "tls")]
    pub async fn starttls(
        &self,
        stream: TcpStream,
        hostname: &str,
    ) -> Result<SmtpConnection, DeliveryError> {
        self.upgrade_to_tls(stream, hostname).await
    }

    #[cfg(feature = "tls")]
    async fn upgrade_to_tls(
        &self,
        stream: TcpStream,
        addr: impl AsRef<str>,
    ) -> Result<SmtpConnection, DeliveryError> {
        let connector = self.tls_connector.as_ref().ok_or_else(|| {
            DeliveryError::TlsFailed {
                stage: SmtpStage::Tls,
                reason: "TLS not configured".to_string(),
            }
        })?;

        let server_name = addr
            .as_ref()
            .try_into()
            .map_err(|_| DeliveryError::TlsFailed {
                stage: SmtpStage::Tls,
                reason: "Invalid server name".to_string(),
            })?;

        let tls_stream = timeout(self.config.command_timeout, connector.connect(server_name, stream))
            .await
            .map_err(|_| DeliveryError::Timeout {
                stage: SmtpStage::Tls,
                duration_secs: self.config.command_timeout.as_secs(),
            })?
            .map_err(|e| DeliveryError::TlsFailed {
                stage: SmtpStage::Tls,
                reason: e.to_string(),
            })?;

        Ok(SmtpConnection::Tls(tls_stream))
    }

    /// Get the connection configuration.
    pub fn config(&self) -> &ConnectionConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_config_default() {
        let config = ConnectionConfig::default();
        assert_eq!(config.connect_timeout, Duration::from_secs(30));
        assert_eq!(config.command_timeout, Duration::from_secs(60));
        assert_eq!(config.data_timeout, Duration::from_secs(300));
        assert!(config.enable_starttls);
        assert!(!config.require_tls);
        assert!(!config.implicit_tls);
    }

    #[tokio::test]
    async fn test_connector_creation() {
        let config = ConnectionConfig::default();
        let connector = SmtpConnector::new(config.clone());
        assert_eq!(connector.config().local_hostname, "localhost");
    }
}
