// examples/delivery_example.rs
//
// Example showing how to use the outbound SMTP delivery module.
//
// Run with:
//   cargo run --example delivery_example

use std::sync::Arc;
use std::time::Duration;

use mymta::delivery::{
    ConnectionConfig, DeliveryError, MxResolver, SmtpClient, SmtpConnector,
};
use mymta::dns::resolver::RealResolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for debug output
    tracing_subscriber::fmt()
        .with_env_filter("mymta=debug")
        .init();

    println!("=== MyMTA Delivery Example ===\n");

    // Example 1: MX Resolution
    println!("1. MX Resolution Example");
    println!("------------------------");
    
    let resolver = Arc::new(RealResolver::new()?);
    let mx_resolver = MxResolver::new(resolver);
    
    // Resolve MX records for a domain
    match mx_resolver.resolve("gmail.com").await {
        Ok(destinations) => {
            println!("Found {} MX destinations for gmail.com:", destinations.len());
            for (i, dest) in destinations.iter().enumerate() {
                println!("  {}. {} (preference: {}, IPs: {:?})",
                    i + 1,
                    dest.exchange,
                    dest.preference,
                    dest.addresses
                );
            }
        }
        Err(e) => {
            println!("Failed to resolve MX: {}", e);
        }
    }
    println!();

    // Example 2: SMTP Client Configuration
    println!("2. SMTP Client Configuration");
    println!("-----------------------------");
    
    let config = ConnectionConfig {
        connect_timeout: Duration::from_secs(30),
        command_timeout: Duration::from_secs(60),
        data_timeout: Duration::from_secs(300),
        enable_starttls: true,
        require_tls: false,
        implicit_tls: false,
        local_hostname: "mymta.example.com".to_string(),
    };
    
    println!("Connection timeouts:");
    println!("  Connect: {:?}", config.connect_timeout);
    println!("  Command: {:?}", config.command_timeout);
    println!("  Data: {:?}", config.data_timeout);
    println!("  STARTTLS: {}", config.enable_starttls);
    println!("  Local hostname: {}", config.local_hostname);
    println!();

    // Example 3: Delivery Result Handling
    println!("3. Delivery Result Handling");
    println!("----------------------------");
    println!("When delivering a message, you'll get a DeliveryResult with:");
    println!("  - Per-recipient status (success, transient failure, permanent failure)");
    println!("  - Whether TLS was used");
    println!("  - Which MX server was used");
    println!();
    println!("Example error handling:");
    println!("  - 4xx errors: Transient (retry later)");
    println!("  - 5xx errors: Permanent (generate bounce)");
    println!("  - Connection failures: Transient (try next MX)");
    println!();

    // Example 4: Error Classification
    println!("4. Error Classification Examples");
    println!("---------------------------------");
    
    use mymta::delivery::{DeliveryError, SmtpStage};
    
    let transient_error = DeliveryError::from_smtp_response(
        451, "Server busy, try later", SmtpStage::RcptTo
    );
    println!("Error: {}", transient_error);
    println!("  Is transient: {} (should retry)", transient_error.is_transient());
    println!("  Is permanent: {}", transient_error.is_permanent());
    println!();
    
    let permanent_error = DeliveryError::from_smtp_response(
        550, "User unknown", SmtpStage::RcptTo
    );
    println!("Error: {}", permanent_error);
    println!("  Is transient: {}", permanent_error.is_transient());
    println!("  Is permanent: {} (generate bounce)", permanent_error.is_permanent());
    println!();

    // Example 5: SMTP Client Usage (commented out - requires real server)
    println!("5. SMTP Client Usage (Example Code)");
    println!("------------------------------------");
    println!("// Create connector and client");
    println!("let connector = SmtpConnector::new(config);");
    println!("let client = SmtpClient::new(connector);");
    println!();
    println!("// Resolve destination");
    println!("let destinations = mx_resolver.resolve(\"example.com\").await?;");
    println!();
    println!("// Deliver message");
    println!("let result = client.delve(");
    println!("    &destinations,");
    println!("    \"sender@example.com\",");
    println!("    &[\"recipient@example.com\".to_string()],");
    println!("    b\"Subject: Hello\\r\\n\\r\\nWorld!\\r\\n\",");
    println!(").await?;");
    println!();
    println!("// Check results");
    println!("for (recipient, status) in &result.recipients {{");
    println!("    match status {{");
    println!("        RecipientResult::Success {{ message }} => {{");
    println!("            println!(\"Delivered to {{}}: {{}}\", recipient, message);");
    println!("        }}");
    println!("        RecipientResult::TransientFailure(e) => {{");
    println!("            println!(\"Transient failure for {{}}: {{}}\", recipient, e);");
    println!("            // Schedule retry");
    println!("        }}");
    println!("        RecipientResult::PermanentFailure(e) => {{");
    println!("            println!(\"Permanent failure for {{}}: {{}}\", recipient, e);");
    println!("            // Generate bounce message");
    println!("        }}");
    println!("    }}");
    println!("}}");
    println!();

    println!("=== Example Complete ===");
    
    Ok(())
}
