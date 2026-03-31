// src/delivery/result.rs
//
// Delivery result types for tracking success/failure per recipient.

use super::error::DeliveryError;

/// Result of delivery attempt for a single recipient.
#[derive(Debug, Clone)]
pub enum RecipientResult {
    /// Delivery succeeded
    Success {
        /// Remote server's response message
        message: String,
    },
    /// Permanent failure - should generate bounce
    PermanentFailure(DeliveryError),
    /// Transient failure - should retry later
    TransientFailure(DeliveryError),
}

impl RecipientResult {
    /// Returns true if delivery succeeded.
    pub fn is_success(&self) -> bool {
        matches!(self, RecipientResult::Success { .. })
    }

    /// Returns true if this is a permanent failure.
    pub fn is_permanent(&self) -> bool {
        matches!(self, RecipientResult::PermanentFailure(_))
    }

    /// Returns true if this is a transient failure (retryable).
    pub fn is_transient(&self) -> bool {
        matches!(self, RecipientResult::TransientFailure(_))
    }

    /// Get the error if this is a failure.
    pub fn error(&self) -> Option<&DeliveryError> {
        match self {
            RecipientResult::PermanentFailure(e) => Some(e),
            RecipientResult::TransientFailure(e) => Some(e),
            _ => None,
        }
    }
}

/// Overall delivery result for a message.
#[derive(Debug, Clone)]
pub struct DeliveryResult {
    /// Results per recipient (email address -> result)
    pub recipients: Vec<(String, RecipientResult)>,
    /// Whether the connection was established successfully
    pub connected: bool,
    /// Whether TLS was used
    pub tls_used: bool,
    /// The MX server that was used (if any)
    pub mx_server: Option<String>,
}

impl DeliveryResult {
    /// Create a new delivery result.
    pub fn new(mx_server: Option<String>) -> Self {
        Self {
            recipients: Vec::new(),
            connected: false,
            tls_used: false,
            mx_server,
        }
    }

    /// Add a recipient result.
    pub fn add_recipient(&mut self, address: String, result: RecipientResult) {
        self.recipients.push((address, result));
    }

    /// Returns true if all recipients were delivered successfully.
    pub fn all_succeeded(&self) -> bool {
        self.recipients.iter().all(|(_, r)| r.is_success())
    }

    /// Returns true if all failures are permanent (generates bounces).
    pub fn all_permanent_failures(&self) -> bool {
        self.recipients
            .iter()
            .all(|(_, r)| r.is_success() || r.is_permanent())
    }

    /// Returns true if any recipient has a transient failure (should retry).
    pub fn has_transient_failures(&self) -> bool {
        self.recipients.iter().any(|(_, r)| r.is_transient())
    }

    /// Get all successfully delivered recipients.
    pub fn successful_recipients(&self) -> Vec<&String> {
        self.recipients
            .iter()
            .filter(|(_, r)| r.is_success())
            .map(|(a, _)| a)
            .collect()
    }

    /// Get recipients with permanent failures.
    pub fn permanent_failed_recipients(&self) -> Vec<&String> {
        self.recipients
            .iter()
            .filter(|(_, r)| r.is_permanent())
            .map(|(a, _)| a)
            .collect()
    }

    /// Get recipients with transient failures.
    pub fn transient_failed_recipients(&self) -> Vec<&String> {
        self.recipients
            .iter()
            .filter(|(_, r)| r.is_transient())
            .map(|(a, _)| a)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delivery::error::{DeliveryError, SmtpStage};

    #[test]
    fn test_recipient_result_success() {
        let r = RecipientResult::Success {
            message: "OK".to_string(),
        };
        assert!(r.is_success());
        assert!(!r.is_permanent());
        assert!(!r.is_transient());
        assert!(r.error().is_none());
    }

    #[test]
    fn test_recipient_result_permanent() {
        let err = DeliveryError::from_smtp_response(550, "No such user", SmtpStage::RcptTo);
        let r = RecipientResult::PermanentFailure(err);
        assert!(!r.is_success());
        assert!(r.is_permanent());
        assert!(!r.is_transient());
        assert!(r.error().is_some());
    }

    #[test]
    fn test_delivery_result_aggregates() {
        let mut result = DeliveryResult::new(Some("mx.example.com".to_string()));

        result.add_recipient(
            "alice@example.com".to_string(),
            RecipientResult::Success {
                message: "OK".to_string(),
            },
        );
        result.add_recipient(
            "bob@example.com".to_string(),
            RecipientResult::PermanentFailure(DeliveryError::from_smtp_response(
                550,
                "User unknown",
                SmtpStage::RcptTo,
            )),
        );
        result.add_recipient(
            "carol@example.com".to_string(),
            RecipientResult::TransientFailure(DeliveryError::from_smtp_response(
                451,
                "Try later",
                SmtpStage::RcptTo,
            )),
        );

        assert!(!result.all_succeeded());
        assert!(!result.all_permanent_failures());
        assert!(result.has_transient_failures());

        assert_eq!(result.successful_recipients().len(), 1);
        assert_eq!(result.permanent_failed_recipients().len(), 1);
        assert_eq!(result.transient_failed_recipients().len(), 1);
    }
}
