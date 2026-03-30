// src/message/parser.rs
//
// RFC 5322 email message parsing and validation.
// Parses raw DATA content into structured headers + body, validates required
// fields, line lengths, and header syntax.

use chrono::Utc;
use uuid::Uuid;
use std::fmt;

/// Maximum line length per RFC 5322 §2.1.1 (998 chars + CRLF).
const MAX_LINE_LENGTH: usize = 998;

/// A parsed email message.
#[derive(Debug, Clone)]
pub struct ParsedMessage {
    /// Headers in order of appearance (name, value) — values have folding
    /// whitespace unfolded.
    pub headers: Vec<(String, String)>,
    /// Body after the blank line separating headers from body.
    pub body: String,
    /// Raw bytes of the complete message as received.
    pub raw: Vec<u8>,
}

/// Validation warnings/errors.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageError {
    MissingHeader(String),
    InvalidHeader(String),
    LineTooLong { line_number: usize, length: usize },
    EmptyMessage,
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageError::MissingHeader(h) => write!(f, "missing required header: {}", h),
            MessageError::InvalidHeader(h) => write!(f, "invalid header: {}", h),
            MessageError::LineTooLong { line_number, length } => {
                write!(f, "line {} exceeds maximum length ({} > {})", line_number, length, MAX_LINE_LENGTH)
            }
            MessageError::EmptyMessage => write!(f, "empty message body"),
        }
    }
}

impl std::error::Error for MessageError {}

impl ParsedMessage {
    /// Parse raw DATA content (already dot-unstuffed, without the terminating
    /// dot line) into a structured message.
    pub fn parse(raw: &[u8]) -> Result<Self, Vec<MessageError>> {
        let text = String::from_utf8_lossy(raw);
        let mut errors = Vec::new();

        // ── split headers / body at the first blank line ────────────
        let (header_block, body) = match text.find("\r\n\r\n") {
            Some(pos) => (&text[..pos], text[pos + 4..].to_string()),
            None => match text.find("\n\n") {
                Some(pos) => (&text[..pos], text[pos + 2..].to_string()),
                None => (text.as_ref(), String::new()),
            },
        };

        // ── unfold & parse headers ──────────────────────────────────
        let headers = Self::parse_headers(header_block, &mut errors);

        // ── validate line lengths ───────────────────────────────────
        for (i, line) in text.lines().enumerate() {
            let len = line.len();
            if len > MAX_LINE_LENGTH {
                errors.push(MessageError::LineTooLong {
                    line_number: i + 1,
                    length: len,
                });
            }
        }

        // ── validate required headers (RFC 5322 §3.6) ──────────────
        let has = |name: &str| {
            headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
        };
        if !has("From") {
            errors.push(MessageError::MissingHeader("From".into()));
        }
        if !has("Date") {
            errors.push(MessageError::MissingHeader("Date".into()));
        }

        if !errors.is_empty() {
            return Err(errors);
        }

        Ok(ParsedMessage {
            headers,
            body,
            raw: raw.to_vec(),
        })
    }

    /// Parse a header block into `(name, unfolded-value)` pairs.
    fn parse_headers(block: &str, errors: &mut Vec<MessageError>) -> Vec<(String, String)> {
        let mut headers: Vec<(String, String)> = Vec::new();

        for physical_line in block.lines() {
            if physical_line.starts_with(' ') || physical_line.starts_with('\t') {
                // Continuation (folded) line — append to the previous header.
                if let Some(last) = headers.last_mut() {
                    last.1.push(' ');
                    last.1.push_str(physical_line.trim());
                } else {
                    errors.push(MessageError::InvalidHeader(
                        "continuation line with no preceding header".into(),
                    ));
                }
            } else if let Some(colon) = physical_line.find(':') {
                let name = physical_line[..colon].trim().to_string();
                let value = physical_line[colon + 1..].trim().to_string();
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_graphic() && c != ':')
                {
                    errors.push(MessageError::InvalidHeader(format!(
                        "bad header field name: '{}'",
                        name
                    )));
                } else {
                    headers.push((name, value));
                }
            } else if !physical_line.is_empty() {
                errors.push(MessageError::InvalidHeader(format!(
                    "line is not a valid header: '{}'",
                    physical_line
                )));
            }
        }

        headers
    }

    /// Look up the first value of a header by name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Ensure the message has a Message-ID; generate one if absent.
    pub fn ensure_message_id(&mut self, hostname: &str) {
        if self.header("Message-ID").is_none() {
            let mid = format!("<{}.{}@{}>", Uuid::new_v4(), Utc::now().timestamp(), hostname);
            self.headers.push(("Message-ID".into(), mid));
        }
    }

    /// Prepend a Received header (should be added at the top).
    pub fn prepend_received(&mut self, received_line: &str) {
        // "Received" value without the "Received: " prefix
        let value = if received_line.starts_with("Received:") {
            received_line["Received:".len()..].trim().to_string()
        } else {
            received_line.to_string()
        };
        self.headers.insert(0, ("Received".into(), value));
    }

    /// Re-serialize headers + body into wire-format bytes (CRLF line endings).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = String::new();
        for (name, value) in &self.headers {
            buf.push_str(&format!("{}: {}\r\n", name, value));
        }
        buf.push_str("\r\n"); // blank line
        buf.push_str(&self.body);
        buf.into_bytes()
    }
}

// ── unit tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg(text: &str) -> Vec<u8> {
        text.replace('\n', "\r\n").into_bytes()
    }

    #[test]
    fn parse_simple_message() {
        let raw = make_msg(
            "From: alice@example.com\n\
             To: bob@example.com\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\n\
             Subject: Hello\n\
             \n\
             Hello, Bob!\n",
        );
        let msg = ParsedMessage::parse(&raw).unwrap();
        assert_eq!(msg.header("From"), Some("alice@example.com"));
        assert_eq!(msg.header("Subject"), Some("Hello"));
        assert!(msg.body.contains("Hello, Bob!"));
    }

    #[test]
    fn parse_folded_headers() {
        let raw = make_msg(
            "From: alice@example.com\n\
             To: bob@example.com\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\n\
             Subject: This is a very long\n\
             \t subject line that is folded\n\
             \n\
             Body\n",
        );
        let msg = ParsedMessage::parse(&raw).unwrap();
        assert_eq!(
            msg.header("Subject"),
            Some("This is a very long subject line that is folded")
        );
    }

    #[test]
    fn missing_from_header() {
        let raw = make_msg(
            "To: bob@example.com\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\n\
             \n\
             Body\n",
        );
        let errs = ParsedMessage::parse(&raw).unwrap_err();
        assert!(errs.iter().any(|e| matches!(e, MessageError::MissingHeader(h) if h == "From")));
    }

    #[test]
    fn missing_date_header() {
        let raw = make_msg(
            "From: alice@example.com\n\
             \n\
             Body\n",
        );
        let errs = ParsedMessage::parse(&raw).unwrap_err();
        assert!(errs.iter().any(|e| matches!(e, MessageError::MissingHeader(h) if h == "Date")));
    }

    #[test]
    fn line_too_long() {
        let long_line = "X".repeat(1000);
        let raw = format!(
            "From: a@b.com\r\nDate: Mon, 01 Jan 2024 00:00:00 +0000\r\n\r\n{}\r\n",
            long_line
        );
        let errs = ParsedMessage::parse(raw.as_bytes()).unwrap_err();
        assert!(errs.iter().any(|e| matches!(e, MessageError::LineTooLong { .. })));
    }

    #[test]
    fn ensure_message_id_adds_when_missing() {
        let raw = make_msg(
            "From: a@b.com\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\n\
             \n\
             Body\n",
        );
        let mut msg = ParsedMessage::parse(&raw).unwrap();
        assert!(msg.header("Message-ID").is_none());
        msg.ensure_message_id("mx.test.com");
        assert!(msg.header("Message-ID").is_some());
        assert!(msg.header("Message-ID").unwrap().contains("mx.test.com"));
    }

    #[test]
    fn prepend_received_header() {
        let raw = make_msg(
            "From: a@b.com\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\n\
             \n\
             Body\n",
        );
        let mut msg = ParsedMessage::parse(&raw).unwrap();
        msg.prepend_received("Received: from client by server; date");
        assert_eq!(msg.headers[0].0, "Received");
    }

    #[test]
    fn to_bytes_roundtrip() {
        let raw = make_msg(
            "From: a@b.com\n\
             Date: Mon, 01 Jan 2024 00:00:00 +0000\n\
             \n\
             Body text\n",
        );
        let msg = ParsedMessage::parse(&raw).unwrap();
        let serialized = msg.to_bytes();
        let text = String::from_utf8_lossy(&serialized);
        assert!(text.contains("From: a@b.com\r\n"));
        assert!(text.contains("\r\n\r\n"));
        assert!(text.contains("Body text"));
    }

    #[test]
    fn case_insensitive_header_lookup() {
        let raw = make_msg(
            "FROM: a@b.com\n\
             date: Mon, 01 Jan 2024 00:00:00 +0000\n\
             \n\
             Body\n",
        );
        let msg = ParsedMessage::parse(&raw).unwrap();
        assert!(msg.header("from").is_some());
        assert!(msg.header("DATE").is_some());
    }
}