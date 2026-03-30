// src/smtp/command.rs
//
// SMTP command parsing per RFC 5321.
// Handles: EHLO, HELO, MAIL FROM, RCPT TO, DATA, QUIT, RSET, NOOP, VRFY, HELP.

use std::fmt;

/// Represents a parsed SMTP command.
#[derive(Debug, Clone, PartialEq)]
pub enum SmtpCommand {
    /// EHLO (Extended Hello) — RFC 5321 §4.1.1.1
    Ehlo(String),
    /// HELO — RFC 5321 §4.1.1.1
    Helo(String),
    /// MAIL FROM — RFC 5321 §4.1.1.2
    MailFrom {
        address: String,
        parameters: Vec<String>,
    },
    /// RCPT TO — RFC 5321 §4.1.1.3
    RcptTo {
        address: String,
        parameters: Vec<String>,
    },
    /// DATA — RFC 5321 §4.1.1.4
    Data,
    /// QUIT — RFC 5321 §4.1.1.10
    Quit,
    /// RSET — RFC 5321 §4.1.1.5
    Rset,
    /// NOOP — RFC 5321 §4.1.1.9
    Noop,
    /// VRFY — RFC 5321 §4.1.1.6
    Vrfy(String),
    /// HELP — RFC 5321 §4.1.1.8
    Help(Option<String>),
}

/// Errors returned when parsing an SMTP command line.
#[derive(Debug, Clone, PartialEq)]
pub enum ParseError {
    EmptyCommand,
    UnrecognizedCommand(String),
    InvalidSyntax(String),
    InvalidAddress(String),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::EmptyCommand => write!(f, "empty command"),
            ParseError::UnrecognizedCommand(c) => write!(f, "unrecognized command: {}", c),
            ParseError::InvalidSyntax(m) => write!(f, "syntax error: {}", m),
            ParseError::InvalidAddress(m) => write!(f, "invalid address: {}", m),
        }
    }
}

impl std::error::Error for ParseError {}

impl SmtpCommand {
    /// Parse a raw SMTP command line (without trailing CRLF) into a structured command.
    pub fn parse(input: &str) -> Result<Self, ParseError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ParseError::EmptyCommand);
        }

        // Split into verb and the rest
        let (verb, args) = match input.find(' ') {
            Some(pos) => (&input[..pos], input[pos + 1..].trim()),
            None => (input, ""),
        };

        match verb.to_ascii_uppercase().as_str() {
            "EHLO" => {
                if args.is_empty() {
                    Err(ParseError::InvalidSyntax(
                        "EHLO requires a domain or address literal".into(),
                    ))
                } else {
                    Ok(SmtpCommand::Ehlo(args.to_string()))
                }
            }
            "HELO" => {
                if args.is_empty() {
                    Err(ParseError::InvalidSyntax(
                        "HELO requires a domain or address literal".into(),
                    ))
                } else {
                    Ok(SmtpCommand::Helo(args.to_string()))
                }
            }
            "MAIL" => Self::parse_mail_from(args),
            "RCPT" => Self::parse_rcpt_to(args),
            "DATA" => Ok(SmtpCommand::Data),
            "QUIT" => Ok(SmtpCommand::Quit),
            "RSET" => Ok(SmtpCommand::Rset),
            "NOOP" => Ok(SmtpCommand::Noop),
            "VRFY" => {
                if args.is_empty() {
                    Err(ParseError::InvalidSyntax(
                        "VRFY requires a string parameter".into(),
                    ))
                } else {
                    Ok(SmtpCommand::Vrfy(args.to_string()))
                }
            }
            "HELP" => {
                if args.is_empty() {
                    Ok(SmtpCommand::Help(None))
                } else {
                    Ok(SmtpCommand::Help(Some(args.to_string())))
                }
            }
            _ => Err(ParseError::UnrecognizedCommand(verb.to_string())),
        }
    }

    // ── private helpers ──────────────────────────────────────────────

    fn parse_mail_from(args: &str) -> Result<Self, ParseError> {
        let upper = args.to_ascii_uppercase();
        if !upper.starts_with("FROM:") {
            return Err(ParseError::InvalidSyntax(
                "expected MAIL FROM:<address>".into(),
            ));
        }
        let rest = args[5..].trim(); // skip "FROM:"
        let (address, parameters) = Self::extract_angle_address(rest)?;

        // Validate address (empty = null sender for bounces, which is valid)
        if !address.is_empty() {
            validate_email_address(&address)?;
        }
        Ok(SmtpCommand::MailFrom {
            address,
            parameters,
        })
    }

    fn parse_rcpt_to(args: &str) -> Result<Self, ParseError> {
        let upper = args.to_ascii_uppercase();
        if !upper.starts_with("TO:") {
            return Err(ParseError::InvalidSyntax(
                "expected RCPT TO:<address>".into(),
            ));
        }
        let rest = args[3..].trim(); // skip "TO:"
        let (address, parameters) = Self::extract_angle_address(rest)?;

        if address.is_empty() {
            return Err(ParseError::InvalidAddress(
                "RCPT TO requires a non-empty address".into(),
            ));
        }
        validate_email_address(&address)?;
        Ok(SmtpCommand::RcptTo {
            address,
            parameters,
        })
    }

    /// Extract `<addr>` and optional trailing ESMTP parameters.
    fn extract_angle_address(input: &str) -> Result<(String, Vec<String>), ParseError> {
        let input = input.trim();
        if !input.starts_with('<') {
            return Err(ParseError::InvalidSyntax(
                "address must be enclosed in < >".into(),
            ));
        }
        let close = input.find('>').ok_or_else(|| {
            ParseError::InvalidSyntax("missing closing >".into())
        })?;
        let address = input[1..close].to_string();
        let rest = input[close + 1..].trim();
        let parameters: Vec<String> = if rest.is_empty() {
            Vec::new()
        } else {
            rest.split_whitespace().map(|s| s.to_string()).collect()
        };
        Ok((address, parameters))
    }

    /// Returns `true` when this command may be sent inside a pipelined batch
    /// (RFC 2920 §3.1).
    pub fn is_pipelineable(&self) -> bool {
        matches!(
            self,
            SmtpCommand::MailFrom { .. }
                | SmtpCommand::RcptTo { .. }
                | SmtpCommand::Rset
                | SmtpCommand::Noop
        )
    }
}

// ── email-address validation (simplified RFC 5321) ──────────────────

/// Validate an email address in the form `local@domain`.
pub fn validate_email_address(addr: &str) -> Result<(), ParseError> {
    if addr.is_empty() {
        return Ok(()); // null sender
    }
    let at_pos = addr.rfind('@').ok_or_else(|| {
        ParseError::InvalidAddress(format!("missing '@' in address: {}", addr))
    })?;
    let local = &addr[..at_pos];
    let domain = &addr[at_pos + 1..];

    if local.is_empty() || local.len() > 64 {
        return Err(ParseError::InvalidAddress(
            "local part must be 1-64 characters".into(),
        ));
    }
    if domain.is_empty() || domain.len() > 255 {
        return Err(ParseError::InvalidAddress(
            "domain must be 1-255 characters".into(),
        ));
    }

    // Allow IP-address literals [x.x.x.x]
    if domain.starts_with('[') && domain.ends_with(']') {
        return Ok(());
    }

    // Validate domain labels
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ParseError::InvalidAddress(format!(
                "invalid domain label: '{}'",
                label
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ParseError::InvalidAddress(format!(
                "domain label cannot start/end with hyphen: '{}'",
                label
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ParseError::InvalidAddress(format!(
                "invalid characters in domain label: '{}'",
                label
            )));
        }
    }
    Ok(())
}

// ── unit tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── EHLO / HELO ─────────────────────────────────────────────────

    #[test]
    fn parse_ehlo() {
        let cmd = SmtpCommand::parse("EHLO mail.example.com").unwrap();
        assert_eq!(cmd, SmtpCommand::Ehlo("mail.example.com".into()));
    }

    #[test]
    fn parse_ehlo_case_insensitive() {
        let cmd = SmtpCommand::parse("ehlo MAIL.EXAMPLE.COM").unwrap();
        assert_eq!(cmd, SmtpCommand::Ehlo("MAIL.EXAMPLE.COM".into()));
    }

    #[test]
    fn parse_ehlo_missing_hostname() {
        assert!(SmtpCommand::parse("EHLO").is_err());
    }

    #[test]
    fn parse_helo() {
        let cmd = SmtpCommand::parse("HELO relay.example.com").unwrap();
        assert_eq!(cmd, SmtpCommand::Helo("relay.example.com".into()));
    }

    // ── MAIL FROM ───────────────────────────────────────────────────

    #[test]
    fn parse_mail_from_simple() {
        let cmd = SmtpCommand::parse("MAIL FROM:<user@example.com>").unwrap();
        assert_eq!(
            cmd,
            SmtpCommand::MailFrom {
                address: "user@example.com".into(),
                parameters: vec![],
            }
        );
    }

    #[test]
    fn parse_mail_from_null_sender() {
        let cmd = SmtpCommand::parse("MAIL FROM:<>").unwrap();
        assert_eq!(
            cmd,
            SmtpCommand::MailFrom {
                address: "".into(),
                parameters: vec![],
            }
        );
    }

    #[test]
    fn parse_mail_from_with_size_param() {
        let cmd = SmtpCommand::parse("MAIL FROM:<a@b.com> SIZE=1024").unwrap();
        assert_eq!(
            cmd,
            SmtpCommand::MailFrom {
                address: "a@b.com".into(),
                parameters: vec!["SIZE=1024".into()],
            }
        );
    }

    #[test]
    fn parse_mail_from_case_insensitive() {
        let cmd = SmtpCommand::parse("mail from:<a@b.com>").unwrap();
        assert_eq!(
            cmd,
            SmtpCommand::MailFrom {
                address: "a@b.com".into(),
                parameters: vec![],
            }
        );
    }

    #[test]
    fn parse_mail_from_missing_angle_brackets() {
        assert!(SmtpCommand::parse("MAIL FROM:user@example.com").is_err());
    }

    // ── RCPT TO ─────────────────────────────────────────────────────

    #[test]
    fn parse_rcpt_to() {
        let cmd = SmtpCommand::parse("RCPT TO:<dest@example.com>").unwrap();
        assert_eq!(
            cmd,
            SmtpCommand::RcptTo {
                address: "dest@example.com".into(),
                parameters: vec![],
            }
        );
    }

    #[test]
    fn parse_rcpt_to_empty_rejects() {
        assert!(SmtpCommand::parse("RCPT TO:<>").is_err());
    }

    // ── simple commands ─────────────────────────────────────────────

    #[test]
    fn parse_data() {
        assert_eq!(SmtpCommand::parse("DATA").unwrap(), SmtpCommand::Data);
    }

    #[test]
    fn parse_quit() {
        assert_eq!(SmtpCommand::parse("QUIT").unwrap(), SmtpCommand::Quit);
    }

    #[test]
    fn parse_rset() {
        assert_eq!(SmtpCommand::parse("RSET").unwrap(), SmtpCommand::Rset);
    }

    #[test]
    fn parse_noop() {
        assert_eq!(SmtpCommand::parse("NOOP").unwrap(), SmtpCommand::Noop);
    }

    #[test]
    fn parse_vrfy() {
        let cmd = SmtpCommand::parse("VRFY user").unwrap();
        assert_eq!(cmd, SmtpCommand::Vrfy("user".into()));
    }

    #[test]
    fn parse_help_no_arg() {
        assert_eq!(SmtpCommand::parse("HELP").unwrap(), SmtpCommand::Help(None));
    }

    #[test]
    fn parse_help_with_arg() {
        assert_eq!(
            SmtpCommand::parse("HELP DATA").unwrap(),
            SmtpCommand::Help(Some("DATA".into()))
        );
    }

    // ── error cases ─────────────────────────────────────────────────

    #[test]
    fn parse_empty_line() {
        assert!(SmtpCommand::parse("").is_err());
    }

    #[test]
    fn parse_unrecognized_command() {
        let err = SmtpCommand::parse("XYZZY").unwrap_err();
        assert!(matches!(err, ParseError::UnrecognizedCommand(_)));
    }

    // ── address validation ──────────────────────────────────────────

    #[test]
    fn valid_addresses() {
        assert!(validate_email_address("user@example.com").is_ok());
        assert!(validate_email_address("a@b.c").is_ok());
        assert!(validate_email_address("user+tag@sub.domain.com").is_ok());
    }

    #[test]
    fn invalid_addresses() {
        assert!(validate_email_address("noatsign").is_err());
        assert!(validate_email_address("@domain.com").is_err());
        assert!(validate_email_address("user@").is_err());
        assert!(validate_email_address("user@-bad.com").is_err());
    }

    #[test]
    fn ip_literal_address() {
        assert!(validate_email_address("user@[127.0.0.1]").is_ok());
    }

    // ── pipelining ──────────────────────────────────────────────────

    #[test]
    fn pipelineable_commands() {
        assert!(SmtpCommand::MailFrom {
            address: "a@b.com".into(),
            parameters: vec![]
        }
        .is_pipelineable());
        assert!(SmtpCommand::RcptTo {
            address: "a@b.com".into(),
            parameters: vec![]
        }
        .is_pipelineable());
        assert!(SmtpCommand::Rset.is_pipelineable());
        assert!(SmtpCommand::Noop.is_pipelineable());
    }

    #[test]
    fn non_pipelineable_commands() {
        assert!(!SmtpCommand::Ehlo("x".into()).is_pipelineable());
        assert!(!SmtpCommand::Data.is_pipelineable());
        assert!(!SmtpCommand::Quit.is_pipelineable());
    }
}