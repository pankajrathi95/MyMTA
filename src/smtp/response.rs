// src/smtp/response.rs
//
// SMTP response formatting per RFC 5321 §4.2.
// Supports both single-line and multi-line (EHLO) replies.

/// An SMTP response consisting of a 3-digit status code and one or more text
/// lines.
#[derive(Debug, Clone)]
pub struct SmtpResponse {
    pub code: u16,
    pub messages: Vec<String>,
}

impl SmtpResponse {
    /// Single-line response.
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            messages: vec![message.into()],
        }
    }

    /// Multi-line response (used for EHLO capabilities, etc.).
    pub fn multiline(code: u16, lines: Vec<String>) -> Self {
        assert!(!lines.is_empty(), "response must have at least one line");
        Self {
            code,
            messages: lines,
        }
    }

    /// Serialize to the wire format.
    ///
    /// Multi-line: intermediate lines use `code-text`, the last line uses
    /// `code text` (space separator).
    pub fn to_wire(&self) -> String {
        let mut buf = String::new();
        let last = self.messages.len() - 1;
        for (i, line) in self.messages.iter().enumerate() {
            let sep = if i < last { '-' } else { ' ' };
            buf.push_str(&format!("{}{}{}\r\n", self.code, sep, line));
        }
        buf
    }

    // ── convenience constructors ────────────────────────────────────

    /// 220 greeting
    pub fn greeting(hostname: &str) -> Self {
        Self::new(220, format!("{} ESMTP MyMTA Service ready", hostname))
    }

    /// 221 closing
    pub fn closing(hostname: &str) -> Self {
        Self::new(221, format!("2.0.0 {} closing connection", hostname))
    }

    /// 250 OK
    pub fn ok() -> Self {
        Self::new(250, "2.0.0 OK")
    }

    /// 250 OK with a queue-id after successful DATA
    pub fn ok_queued(queue_id: &str) -> Self {
        Self::new(250, format!("2.0.0 OK queued as {}", queue_id))
    }

    /// 250 multi-line EHLO response with capabilities
    pub fn ehlo(hostname: &str, client_name: &str, max_size: usize) -> Self {
        Self::multiline(
            250,
            vec![
                format!("{} greets {}", hostname, client_name),
                "PIPELINING".into(),
                format!("SIZE {}", max_size),
                "8BITMIME".into(),
                "ENHANCEDSTATUSCODES".into(),
                "HELP".into(),
            ],
        )
    }

    /// 354 start data
    pub fn start_data() -> Self {
        Self::new(354, "Start mail input; end with <CRLF>.<CRLF>")
    }

    /// 500 syntax error / unrecognized
    pub fn command_unrecognized(detail: &str) -> Self {
        Self::new(500, format!("5.5.2 Error: command not recognized: {}", detail))
    }

    /// 501 syntax error in parameters
    pub fn syntax_error(detail: &str) -> Self {
        Self::new(501, format!("5.5.4 {}", detail))
    }

    /// 503 bad sequence
    pub fn bad_sequence(detail: &str) -> Self {
        Self::new(503, format!("5.5.1 {}", detail))
    }

    /// 550 mailbox unavailable
    pub fn mailbox_unavailable(detail: &str) -> Self {
        Self::new(550, format!("5.1.1 {}", detail))
    }

    /// 552 message too large
    pub fn message_too_large(max: usize) -> Self {
        Self::new(
            552,
            format!("5.3.4 Message size exceeds maximum of {} bytes", max),
        )
    }

    /// 452 too many recipients
    pub fn too_many_recipients(max: usize) -> Self {
        Self::new(
            452,
            format!("4.5.3 Too many recipients (max {})", max),
        )
    }

    /// 553 invalid address
    pub fn invalid_address(detail: &str) -> Self {
        Self::new(553, format!("5.1.3 {}", detail))
    }

    /// 214 HELP reply
    pub fn help() -> Self {
        Self::multiline(
            214,
            vec![
                "Commands supported:".into(),
                "  EHLO HELO MAIL RCPT DATA QUIT RSET NOOP VRFY HELP".into(),
                "For more info see RFC 5321".into(),
            ],
        )
    }

    /// 252 VRFY response (deliberately vague for security)
    pub fn vrfy_ambiguous() -> Self {
        Self::new(252, "2.5.2 Cannot VRFY user; will accept message and attempt delivery")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_format() {
        let r = SmtpResponse::new(250, "OK");
        assert_eq!(r.to_wire(), "250 OK\r\n");
    }

    #[test]
    fn multiline_format() {
        let r = SmtpResponse::multiline(250, vec!["first".into(), "second".into(), "last".into()]);
        assert_eq!(r.to_wire(), "250-first\r\n250-second\r\n250 last\r\n");
    }

    #[test]
    fn greeting_format() {
        let r = SmtpResponse::greeting("mx.example.com");
        assert!(r.to_wire().starts_with("220 "));
        assert!(r.to_wire().contains("mx.example.com"));
    }

    #[test]
    fn ehlo_contains_pipelining() {
        let r = SmtpResponse::ehlo("mx.example.com", "client.test", 10_485_760);
        let wire = r.to_wire();
        assert!(wire.contains("PIPELINING"));
        assert!(wire.contains("SIZE 10485760"));
        assert!(wire.contains("8BITMIME"));
        assert!(wire.contains("ENHANCEDSTATUSCODES"));
    }
}