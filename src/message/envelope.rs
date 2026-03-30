// src/message/envelope.rs
//
// SMTP envelope — the metadata collected during the SMTP transaction
// (MAIL FROM, RCPT TO) that travels *outside* the message body itself.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// The SMTP envelope — distinct from the message headers/body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Queue-id assigned by the MTA.
    pub id: String,
    /// Reverse-path (MAIL FROM address). Empty string = null sender (bounce).
    pub sender: String,
    /// Forward-paths (RCPT TO addresses). At least one required.
    pub recipients: Vec<String>,
    /// Client hostname sent in EHLO/HELO.
    pub client_hostname: Option<String>,
    /// Remote peer address.
    pub peer_addr: Option<String>,
    /// Timestamp when the message was received.
    pub received_at: DateTime<Utc>,
    /// ESMTP parameters from MAIL FROM (e.g. SIZE=..., BODY=...).
    pub mail_parameters: Vec<String>,
}

impl Envelope {
    pub fn new() -> Self {
        Self {
            id: String::new(),
            sender: String::new(),
            recipients: Vec::new(),
            client_hostname: None,
            peer_addr: None,
            received_at: Utc::now(),
            mail_parameters: Vec::new(),
        }
    }

    /// Reset the envelope for a new transaction (RSET).
    pub fn reset(&mut self) {
        self.id.clear();
        self.sender.clear();
        self.recipients.clear();
        self.mail_parameters.clear();
        // Keep client_hostname & peer_addr since the session persists.
    }

    /// Set the reverse-path and optional ESMTP parameters.
    pub fn set_sender(&mut self, address: String, parameters: Vec<String>) {
        self.sender = address;
        self.mail_parameters = parameters;
    }

    /// Add a forward-path recipient.
    pub fn add_recipient(&mut self, address: String) {
        self.recipients.push(address);
    }

    /// Stamp the envelope with a queue-id and current time.
    pub fn stamp(&mut self, queue_id: String) {
        self.id = queue_id;
        self.received_at = Utc::now();
    }

    /// Set connection-level metadata.
    pub fn set_connection_info(&mut self, peer: SocketAddr, client_host: Option<String>) {
        self.peer_addr = Some(peer.to_string());
        self.client_hostname = client_host;
    }

    /// Build a Received header per RFC 5321 §4.4.
    pub fn received_header(&self, our_hostname: &str) -> String {
        let from_part = match &self.client_hostname {
            Some(h) => format!(
                "from {} ({})",
                h,
                self.peer_addr.as_deref().unwrap_or("unknown")
            ),
            None => format!(
                "from {}",
                self.peer_addr.as_deref().unwrap_or("unknown")
            ),
        };
        let date = self.received_at.format("%a, %d %b %Y %H:%M:%S %z");
        format!(
            "Received: {} by {} with ESMTP id {}; {}",
            from_part, our_hostname, self.id, date
        )
    }
}

impl Default for Envelope {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_envelope_is_empty() {
        let env = Envelope::new();
        assert!(env.sender.is_empty());
        assert!(env.recipients.is_empty());
    }

    #[test]
    fn set_sender_and_recipients() {
        let mut env = Envelope::new();
        env.set_sender("alice@example.com".into(), vec!["SIZE=1024".into()]);
        env.add_recipient("bob@example.com".into());
        env.add_recipient("carol@example.com".into());

        assert_eq!(env.sender, "alice@example.com");
        assert_eq!(env.recipients.len(), 2);
        assert_eq!(env.mail_parameters, vec!["SIZE=1024"]);
    }

    #[test]
    fn reset_clears_transaction() {
        let mut env = Envelope::new();
        env.set_sender("a@b.com".into(), vec![]);
        env.add_recipient("c@d.com".into());
        env.client_hostname = Some("client.test".into());

        env.reset();

        assert!(env.sender.is_empty());
        assert!(env.recipients.is_empty());
        // Connection-level info survives reset
        assert_eq!(env.client_hostname, Some("client.test".into()));
    }

    #[test]
    fn received_header_format() {
        let mut env = Envelope::new();
        env.client_hostname = Some("mail.client.com".into());
        env.peer_addr = Some("10.0.0.1:12345".into());
        env.stamp("ABC123".into());

        let hdr = env.received_header("mx.server.com");
        assert!(hdr.starts_with("Received: from mail.client.com"));
        assert!(hdr.contains("mx.server.com"));
        assert!(hdr.contains("ABC123"));
    }
}