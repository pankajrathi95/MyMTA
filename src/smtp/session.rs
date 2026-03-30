// src/smtp/session.rs
//
// SMTP session state machine per RFC 5321.
//
// Manages the progression through SMTP states (EHLO → MAIL FROM → RCPT TO →
// DATA → message body) and enforces valid transitions.  The session is purely
// synchronous — I/O is handled by the server module.

use std::net::SocketAddr;
use uuid::Uuid;

use crate::message::envelope::Envelope;
use crate::smtp::command::{ParseError, SmtpCommand};
use crate::smtp::response::SmtpResponse;

// ── session state ───────────────────────────────────────────────────

/// The states an SMTP session can be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    /// Connection established; server has sent 220 greeting.
    Connected,
    /// EHLO/HELO accepted; ready for MAIL FROM.
    Ready,
    /// MAIL FROM accepted; waiting for RCPT TO.
    MailFrom,
    /// At least one RCPT TO accepted; may receive more or DATA.
    RcptTo,
    /// DATA command accepted; now receiving message body lines.
    ReceivingData,
    /// QUIT received; connection will close.
    Closing,
}

/// Result of feeding a line while in DATA mode.
pub enum DataResult {
    /// Append the line and keep reading.
    Continue,
    /// End-of-data marker seen — message is complete.
    Done(SmtpResponse),
    /// An error while accumulating data (e.g. message too large).
    Error(SmtpResponse),
}

// ── session struct ──────────────────────────────────────────────────

pub struct SmtpSession {
    pub state: SessionState,
    pub envelope: Envelope,
    hostname: String,
    max_message_size: usize,
    max_recipients: usize,
    data_buffer: Vec<u8>,
    closing: bool,
}

impl SmtpSession {
    pub fn new(
        peer_addr: SocketAddr,
        hostname: &str,
        max_message_size: usize,
        max_recipients: usize,
    ) -> Self {
        let mut envelope = Envelope::new();
        envelope.set_connection_info(peer_addr, None);
        Self {
            state: SessionState::Connected,
            envelope,
            hostname: hostname.to_string(),
            max_message_size,
            max_recipients,
            data_buffer: Vec::new(),
            closing: false,
        }
    }

    // ── public queries ──────────────────────────────────────────────

    /// The 220 greeting to send right after accept().
    pub fn greeting(&self) -> SmtpResponse {
        SmtpResponse::greeting(&self.hostname)
    }

    pub fn is_receiving_data(&self) -> bool {
        self.state == SessionState::ReceivingData
    }

    pub fn is_closing(&self) -> bool {
        self.closing
    }

    /// Return a snapshot of the envelope (used after successful DATA).
    pub fn envelope(&self) -> &Envelope {
        &self.envelope
    }

    /// Consume the accumulated data buffer (called after spooling).
    pub fn take_message_data(&mut self) -> Option<Vec<u8>> {
        if self.data_buffer.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.data_buffer))
        }
    }

    /// Get the current queue id
    pub fn queue_id(&self) -> &str {
        &self.envelope.id
    }

    // ── command processing ──────────────────────────────────────────

    /// Process a single command line (already trimmed of CRLF).
    pub fn process_command(&mut self, line: &str) -> SmtpResponse {
        match SmtpCommand::parse(line) {
            Ok(cmd) => self.handle_command(cmd),
            Err(ParseError::EmptyCommand) => SmtpResponse::new(500, "5.5.2 Error: bad syntax"),
            Err(ParseError::UnrecognizedCommand(verb)) => {
                SmtpResponse::command_unrecognized(&verb)
            }
            Err(ParseError::InvalidSyntax(msg)) => SmtpResponse::syntax_error(&msg),
            Err(ParseError::InvalidAddress(msg)) => SmtpResponse::invalid_address(&msg),
        }
    }

    fn handle_command(&mut self, cmd: SmtpCommand) -> SmtpResponse {
        match cmd {
            SmtpCommand::Ehlo(host) => self.handle_ehlo(host),
            SmtpCommand::Helo(host) => self.handle_helo(host),
            SmtpCommand::MailFrom { address, parameters } => {
                self.handle_mail_from(address, parameters)
            }
            SmtpCommand::RcptTo { address, parameters } => {
                self.handle_rcpt_to(address, parameters)
            }
            SmtpCommand::Data => self.handle_data(),
            SmtpCommand::Quit => self.handle_quit(),
            SmtpCommand::Rset => self.handle_rset(),
            SmtpCommand::Noop => SmtpResponse::ok(),
            SmtpCommand::Vrfy(_) => SmtpResponse::vrfy_ambiguous(),
            SmtpCommand::Help(_) => SmtpResponse::help(),
        }
    }

    // ── individual command handlers ─────────────────────────────────

    fn handle_ehlo(&mut self, client_host: String) -> SmtpResponse {
        self.envelope.reset();
        self.envelope.client_hostname = Some(client_host.clone());
        self.state = SessionState::Ready;
        SmtpResponse::ehlo(&self.hostname, &client_host, self.max_message_size)
    }

    fn handle_helo(&mut self, client_host: String) -> SmtpResponse {
        self.envelope.reset();
        self.envelope.client_hostname = Some(client_host.clone());
        self.state = SessionState::Ready;
        SmtpResponse::new(250, format!("{} greets {}", self.hostname, client_host))
    }

    fn handle_mail_from(
        &mut self,
        address: String,
        parameters: Vec<String>,
    ) -> SmtpResponse {
        match self.state {
            SessionState::Ready => {}
            _ => {
                return SmtpResponse::bad_sequence(
                    "MAIL FROM requires EHLO/HELO first",
                );
            }
        }
        // Check SIZE parameter if present
        for param in &parameters {
            if let Some(size_str) = param.strip_prefix("SIZE=") {
                if let Ok(size) = size_str.parse::<usize>() {
                    if size > self.max_message_size {
                        return SmtpResponse::message_too_large(self.max_message_size);
                    }
                }
            }
        }

        self.envelope.set_sender(address, parameters);
        self.state = SessionState::MailFrom;
        SmtpResponse::ok()
    }

    fn handle_rcpt_to(
        &mut self,
        address: String,
        _parameters: Vec<String>,
    ) -> SmtpResponse {
        match self.state {
            SessionState::MailFrom | SessionState::RcptTo => {}
            _ => {
                return SmtpResponse::bad_sequence(
                    "RCPT TO requires MAIL FROM first",
                );
            }
        }
        if self.envelope.recipients.len() >= self.max_recipients {
            return SmtpResponse::too_many_recipients(self.max_recipients);
        }
        self.envelope.add_recipient(address);
        self.state = SessionState::RcptTo;
        SmtpResponse::ok()
    }

    fn handle_data(&mut self) -> SmtpResponse {
        match self.state {
            SessionState::RcptTo => {}
            SessionState::MailFrom => {
                return SmtpResponse::bad_sequence(
                    "DATA requires at least one RCPT TO",
                );
            }
            _ => {
                return SmtpResponse::bad_sequence(
                    "DATA requires MAIL FROM and RCPT TO first",
                );
            }
        }
        // Generate a queue-id and switch to data-receiving mode
        let queue_id = Self::generate_queue_id();
        self.envelope.stamp(queue_id);
        self.data_buffer.clear();
        self.state = SessionState::ReceivingData;
        SmtpResponse::start_data()
    }

    fn handle_quit(&mut self) -> SmtpResponse {
        self.closing = true;
        self.state = SessionState::Closing;
        SmtpResponse::closing(&self.hostname)
    }

    fn handle_rset(&mut self) -> SmtpResponse {
        self.envelope.reset();
        self.data_buffer.clear();
        // RSET goes back to Ready if we have had EHLO, otherwise Connected
        if self.state != SessionState::Connected {
            self.state = SessionState::Ready;
        }
        SmtpResponse::ok()
    }

    // ── DATA-mode line processing ───────────────────────────────────

    /// Feed one line (including CRLF) while in ReceivingData state.
    ///
    /// Returns `Continue` to keep reading, `Done` when the terminating dot
    /// is seen, or `Error` if the message exceeds the size limit.
    pub fn feed_data_line(&mut self, line: &str) -> DataResult {
        // RFC 5321 §4.1.1.4: a line consisting of only "." terminates DATA.
        let trimmed = line.trim_end_matches(|c| c == '\r' || c == '\n');
        if trimmed == "." {
            // End of data
            self.state = SessionState::Ready;
            let qid = self.envelope.id.clone();
            return DataResult::Done(SmtpResponse::ok_queued(&qid));
        }

        // Dot-unstuffing: if a line starts with "..", strip one leading dot.
        let unstuffed = if trimmed.starts_with("..") {
            &trimmed[1..]
        } else {
            trimmed
        };

        // Append to buffer (with CRLF)
        self.data_buffer.extend_from_slice(unstuffed.as_bytes());
        self.data_buffer.extend_from_slice(b"\r\n");

        // Size check
        if self.data_buffer.len() > self.max_message_size {
            self.data_buffer.clear();
            self.state = SessionState::Ready;
            self.envelope.reset();
            return DataResult::Error(SmtpResponse::message_too_large(self.max_message_size));
        }

        DataResult::Continue
    }

    // ── helpers ─────────────────────────────────────────────────────

    fn generate_queue_id() -> String {
        // Short hex id like Postfix uses
        let u = Uuid::new_v4();
        let bytes = u.as_bytes();
        format!(
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    }
}

// ── unit tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn test_session() -> SmtpSession {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        SmtpSession::new(addr, "mx.test.com", 10_485_760, 100)
    }

    // ── greeting ────────────────────────────────────────────────────

    #[test]
    fn greeting_returns_220() {
        let s = test_session();
        let r = s.greeting();
        assert_eq!(r.code, 220);
    }

    // ── EHLO ────────────────────────────────────────────────────────

    #[test]
    fn ehlo_transitions_to_ready() {
        let mut s = test_session();
        let r = s.process_command("EHLO client.test");
        assert_eq!(r.code, 250);
        assert_eq!(s.state, SessionState::Ready);
        let wire = r.to_wire();
        assert!(wire.contains("PIPELINING"));
    }

    #[test]
    fn helo_transitions_to_ready() {
        let mut s = test_session();
        let r = s.process_command("HELO client.test");
        assert_eq!(r.code, 250);
        assert_eq!(s.state, SessionState::Ready);
    }

    // ── MAIL FROM ───────────────────────────────────────────────────

    #[test]
    fn mail_from_requires_ehlo() {
        let mut s = test_session();
        let r = s.process_command("MAIL FROM:<a@b.com>");
        assert_eq!(r.code, 503);
    }

    #[test]
    fn mail_from_after_ehlo() {
        let mut s = test_session();
        s.process_command("EHLO client.test");
        let r = s.process_command("MAIL FROM:<sender@example.com>");
        assert_eq!(r.code, 250);
        assert_eq!(s.state, SessionState::MailFrom);
        assert_eq!(s.envelope.sender, "sender@example.com");
    }

    // ── RCPT TO ─────────────────────────────────────────────────────

    #[test]
    fn rcpt_to_requires_mail_from() {
        let mut s = test_session();
        s.process_command("EHLO client.test");
        let r = s.process_command("RCPT TO:<a@b.com>");
        assert_eq!(r.code, 503);
    }

    #[test]
    fn rcpt_to_after_mail_from() {
        let mut s = test_session();
        s.process_command("EHLO client.test");
        s.process_command("MAIL FROM:<s@a.com>");
        let r = s.process_command("RCPT TO:<r@b.com>");
        assert_eq!(r.code, 250);
        assert_eq!(s.state, SessionState::RcptTo);
    }

    #[test]
    fn multiple_rcpt_to() {
        let mut s = test_session();
        s.process_command("EHLO client.test");
        s.process_command("MAIL FROM:<s@a.com>");
        s.process_command("RCPT TO:<r1@b.com>");
        s.process_command("RCPT TO:<r2@b.com>");
        assert_eq!(s.envelope.recipients.len(), 2);
    }

    #[test]
    fn too_many_recipients() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let mut s = SmtpSession::new(addr, "mx.test.com", 10_485_760, 2);
        s.process_command("EHLO client.test");
        s.process_command("MAIL FROM:<s@a.com>");
        s.process_command("RCPT TO:<r1@b.com>");
        s.process_command("RCPT TO:<r2@b.com>");
        let r = s.process_command("RCPT TO:<r3@b.com>");
        assert_eq!(r.code, 452);
    }

    // ── DATA ────────────────────────────────────────────────────────

    #[test]
    fn data_requires_rcpt_to() {
        let mut s = test_session();
        s.process_command("EHLO client.test");
        s.process_command("MAIL FROM:<s@a.com>");
        let r = s.process_command("DATA");
        assert_eq!(r.code, 503); // need RCPT TO
    }

    #[test]
    fn data_starts_receiving() {
        let mut s = test_session();
        s.process_command("EHLO client.test");
        s.process_command("MAIL FROM:<s@a.com>");
        s.process_command("RCPT TO:<r@b.com>");
        let r = s.process_command("DATA");
        assert_eq!(r.code, 354);
        assert!(s.is_receiving_data());
    }

    #[test]
    fn data_collection_and_termination() {
        let mut s = test_session();
        s.process_command("EHLO client.test");
        s.process_command("MAIL FROM:<s@a.com>");
        s.process_command("RCPT TO:<r@b.com>");
        s.process_command("DATA");

        assert!(matches!(s.feed_data_line("From: s@a.com\r\n"), DataResult::Continue));
        assert!(matches!(s.feed_data_line("Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n"), DataResult::Continue));
        assert!(matches!(s.feed_data_line("\r\n"), DataResult::Continue));
        assert!(matches!(s.feed_data_line("Hello!\r\n"), DataResult::Continue));

        match s.feed_data_line(".\r\n") {
            DataResult::Done(r) => {
                assert_eq!(r.code, 250);
                assert_eq!(s.state, SessionState::Ready);
            }
            _ => panic!("expected Done"),
        }

        let data = s.take_message_data().unwrap();
        let text = String::from_utf8_lossy(&data);
        assert!(text.contains("Hello!"));
    }

    #[test]
    fn dot_unstuffing() {
        let mut s = test_session();
        s.process_command("EHLO client.test");
        s.process_command("MAIL FROM:<s@a.com>");
        s.process_command("RCPT TO:<r@b.com>");
        s.process_command("DATA");

        s.feed_data_line("From: s@a.com\r\n");
        s.feed_data_line("Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n");
        s.feed_data_line("\r\n");
        s.feed_data_line("..leading dot\r\n");
        s.feed_data_line(".\r\n");

        let data = s.take_message_data().unwrap();
        let text = String::from_utf8_lossy(&data);
        assert!(text.contains(".leading dot"));
        assert!(!text.contains("..leading dot"));
    }

    // ── RSET ────────────────────────────────────────────────────────

    #[test]
    fn rset_returns_to_ready() {
        let mut s = test_session();
        s.process_command("EHLO client.test");
        s.process_command("MAIL FROM:<s@a.com>");
        s.process_command("RCPT TO:<r@b.com>");
        let r = s.process_command("RSET");
        assert_eq!(r.code, 250);
        assert_eq!(s.state, SessionState::Ready);
        assert!(s.envelope.sender.is_empty());
        assert!(s.envelope.recipients.is_empty());
    }

    // ── QUIT ────────────────────────────────────────────────────────

    #[test]
    fn quit_closes() {
        let mut s = test_session();
        let r = s.process_command("QUIT");
        assert_eq!(r.code, 221);
        assert!(s.is_closing());
    }

    // ── NOOP / VRFY / HELP ──────────────────────────────────────────

    #[test]
    fn noop_always_ok() {
        let mut s = test_session();
        assert_eq!(s.process_command("NOOP").code, 250);
    }

    #[test]
    fn vrfy_returns_252() {
        let mut s = test_session();
        assert_eq!(s.process_command("VRFY user").code, 252);
    }

    #[test]
    fn help_returns_214() {
        let mut s = test_session();
        assert_eq!(s.process_command("HELP").code, 214);
    }

    // ── error cases ─────────────────────────────────────────────────

    #[test]
    fn unknown_command_500() {
        let mut s = test_session();
        assert_eq!(s.process_command("XYZZY").code, 500);
    }

    // ── full conversation ───────────────────────────────────────────

    #[test]
    fn full_smtp_transaction() {
        let mut s = test_session();

        let r = s.process_command("EHLO client.example.com");
        assert_eq!(r.code, 250);

        let r = s.process_command("MAIL FROM:<alice@example.com>");
        assert_eq!(r.code, 250);

        let r = s.process_command("RCPT TO:<bob@example.com>");
        assert_eq!(r.code, 250);

        let r = s.process_command("RCPT TO:<carol@example.com>");
        assert_eq!(r.code, 250);

        let r = s.process_command("DATA");
        assert_eq!(r.code, 354);

        s.feed_data_line("From: alice@example.com\r\n");
        s.feed_data_line("To: bob@example.com\r\n");
        s.feed_data_line("Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n");
        s.feed_data_line("Subject: Test\r\n");
        s.feed_data_line("\r\n");
        s.feed_data_line("Hello, World!\r\n");

        match s.feed_data_line(".\r\n") {
            DataResult::Done(r) => {
                assert_eq!(r.code, 250);
                assert!(r.to_wire().contains("queued"));
            }
            _ => panic!("expected Done"),
        }

        // Session is back to Ready — can start another transaction
        assert_eq!(s.state, SessionState::Ready);

        let r = s.process_command("QUIT");
        assert_eq!(r.code, 221);
        assert!(s.is_closing());
    }

    // ── message size limit ──────────────────────────────────────────

    #[test]
    fn message_too_large_during_data() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let mut s = SmtpSession::new(addr, "mx.test.com", 100, 100); // 100 byte limit

        s.process_command("EHLO client.test");
        s.process_command("MAIL FROM:<s@a.com>");
        s.process_command("RCPT TO:<r@b.com>");
        s.process_command("DATA");

        s.feed_data_line("From: s@a.com\r\n");
        s.feed_data_line("Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n");
        s.feed_data_line("\r\n");

        // Push over the limit
        let big = "X".repeat(200);
        match s.feed_data_line(&big) {
            DataResult::Error(r) => assert_eq!(r.code, 552),
            _ => panic!("expected size error"),
        }
    }

    #[test]
    fn size_param_rejected_early() {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 12345);
        let mut s = SmtpSession::new(addr, "mx.test.com", 1000, 100);

        s.process_command("EHLO client.test");
        let r = s.process_command("MAIL FROM:<s@a.com> SIZE=99999");
        assert_eq!(r.code, 552);
    }
}