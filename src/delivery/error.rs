// src/delivery/error.rs
//
// Delivery error types and SMTP stage tracking.

use std::fmt;

/// The SMTP protocol stage where an error occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpStage {
    /// Initial connection establishment
    Connect,
    /// TLS handshake/STARTTLS
    Tls,
    /// EHLO/HELO command
    Ehlo,
    /// MAIL FROM command
    MailFrom,
    /// RCPT TO command
    RcptTo,
    /// DATA command
    Data,
    /// Message body transmission
    Body,
    /// QUIT command
    Quit,
}

impl fmt::Display for SmtpStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SmtpStage::Connect => write!(f, "CONNECT"),
            SmtpStage::Tls => write!(f, "TLS"),
            SmtpStage::Ehlo => write!(f, "EHLO"),
            SmtpStage::MailFrom => write!(f, "MAIL FROM"),
            SmtpStage::RcptTo => write!(f, "RCPT TO"),
            SmtpStage::Data => write!(f, "DATA"),
            SmtpStage::Body => write!(f, "BODY"),
            SmtpStage::Quit => write!(f, "QUIT"),
        }
    }
}

/// Errors that can occur during delivery.
#[derive(Debug, Clone)]
pub enum DeliveryError {
    /// DNS resolution failed
    DnsResolutionFailed {
        domain: String,
        reason: String,
    },

    /// Could not establish TCP connection to any MX
    ConnectionFailed {
        attempted: Vec<String>,
        reason: String,
    },

    /// TLS/STARTTLS error
    TlsFailed {
        stage: SmtpStage,
        reason: String,
    },

    /// SMTP server returned an error response
    SmtpRejected {
        code: u16,
        message: String,
        stage: SmtpStage,
    },

    /// Protocol violation or unexpected response
    ProtocolError {
        stage: SmtpStage,
        expected: String,
        received: String,
    },

    /// I/O error during communication
    IoError {
        stage: SmtpStage,
        message: String,
    },

    /// Operation timed out
    Timeout {
        stage: SmtpStage,
        duration_secs: u64,
    },

    /// Message content error (e.g., dot-stuffing failure)
    ContentError {
        reason: String,
    },
}

impl DeliveryError {
    /// Returns true if this is a permanent failure (should not retry).
    pub fn is_permanent(&self) -> bool {
        use DeliveryError::*;
        match self {
            // DNS failures may be transient (network issues)
            DnsResolutionFailed { .. } => false,

            // Connection failures are typically transient
            ConnectionFailed { .. } => false,

            // TLS failures: could be transient (e.g., handshake timeout)
            // or permanent (certificate mismatch)
            TlsFailed { .. } => false,

            // SMTP response codes: 5xx = permanent, 4xx = transient
            SmtpRejected { code, .. } => *code >= 500 && *code < 600,

            // Protocol errors are usually permanent (misconfiguration)
            ProtocolError { .. } => true,

            // I/O errors are typically transient
            IoError { .. } => false,

            // Timeouts are transient
            Timeout { .. } => false,

            // Content errors are permanent (message is malformed)
            ContentError { .. } => true,
        }
    }

    /// Returns true if this is a transient failure (should retry).
    pub fn is_transient(&self) -> bool {
        !self.is_permanent()
    }

    /// Get the SMTP stage where the error occurred, if applicable.
    pub fn stage(&self) -> Option<SmtpStage> {
        use DeliveryError::*;
        match self {
            TlsFailed { stage, .. } => Some(*stage),
            SmtpRejected { stage, .. } => Some(*stage),
            ProtocolError { stage, .. } => Some(*stage),
            IoError { stage, .. } => Some(*stage),
            Timeout { stage, .. } => Some(*stage),
            _ => None,
        }
    }

    /// Create an error for a specific SMTP response code.
    pub fn from_smtp_response(code: u16, message: &str, stage: SmtpStage) -> Self {
        DeliveryError::SmtpRejected {
            code,
            message: message.to_string(),
            stage,
        }
    }
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use DeliveryError::*;
        match self {
            DnsResolutionFailed { domain, reason } => {
                write!(f, "DNS resolution failed for '{}': {}", domain, reason)
            }
            ConnectionFailed { attempted, reason } => {
                write!(f, "Connection failed (tried {:?}): {}", attempted, reason)
            }
            TlsFailed { stage, reason } => {
                write!(f, "TLS failed at {}: {}", stage, reason)
            }
            SmtpRejected { code, message, stage } => {
                write!(f, "SMTP error at {}: {} {}", stage, code, message)
            }
            ProtocolError {
                stage,
                expected,
                received,
            } => {
                write!(
                    f,
                    "Protocol error at {}: expected '{}', got '{}'",
                    stage, expected, received
                )
            }
            IoError { stage, message } => {
                write!(f, "I/O error at {}: {}", stage, message)
            }
            Timeout {
                stage,
                duration_secs,
            } => {
                write!(f, "Timeout at {} after {}s", stage, duration_secs)
            }
            ContentError { reason } => {
                write!(f, "Content error: {}", reason)
            }
        }
    }
}

impl std::error::Error for DeliveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smtp_rejected_permanent_vs_transient() {
        // 5xx = permanent
        let err = DeliveryError::from_smtp_response(550, "No such user", SmtpStage::RcptTo);
        assert!(err.is_permanent());
        assert!(!err.is_transient());

        // 4xx = transient
        let err = DeliveryError::from_smtp_response(450, "Mailbox busy", SmtpStage::RcptTo);
        assert!(!err.is_permanent());
        assert!(err.is_transient());
    }

    #[test]
    fn test_error_stage_extraction() {
        let err = DeliveryError::Timeout {
            stage: SmtpStage::Data,
            duration_secs: 30,
        };
        assert_eq!(err.stage(), Some(SmtpStage::Data));

        let err = DeliveryError::DnsResolutionFailed {
            domain: "example.com".to_string(),
            reason: "NXDOMAIN".to_string(),
        };
        assert_eq!(err.stage(), None);
    }

    #[test]
    fn test_display_formatting() {
        let err = DeliveryError::SmtpRejected {
            code: 550,
            message: "User unknown".to_string(),
            stage: SmtpStage::RcptTo,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("550"));
        assert!(msg.contains("User unknown"));
        assert!(msg.contains("RCPT TO"));
    }
}
