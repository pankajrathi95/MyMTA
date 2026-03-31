// src/delivery/mod.rs
//
// Outbound SMTP delivery module - Phase 4 implementation.
//
// This module handles:
// - MX to IP resolution with fallback strategies
// - SMTP client connection establishment
// - SMTP protocol implementation (EHLO, MAIL, RCPT, DATA, QUIT)
// - STARTTLS upgrade
// - Response code classification (permanent vs transient failures)

pub mod client;
pub mod connector;
pub mod error;
pub mod mx_resolve;
pub mod result;

pub use client::SmtpClient;
pub use connector::{ConnectionConfig, SmtpConnector};
pub use error::{DeliveryError, SmtpStage};
pub use mx_resolve::{MxResolver, ResolvedDestination};
pub use result::{DeliveryResult, RecipientResult};
