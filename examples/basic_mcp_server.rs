//! Basic SIGIL MCP Server example.
//!
//! Run with: `cargo run --example basic_mcp_server`

use sigil::mcp_server::{SigilMcpServer, ToolDef};
use sigil::{AuditEvent, AuditLogger, SensitivityScanner, TrustLevel};
use std::sync::Arc;

// ── Custom Scanner ──────────────────────────────────────────────

struct RegexScanner;

impl SensitivityScanner for RegexScanner {
    fn scan(&self, text: &str) -> Option<String> {
        if text.contains("sk-") || text.contains("sk_") {
            Some("API Key".into())
        } else if text.contains("4242") && text.len() > 12 {
            Some("Credit Card".into())
        } else {
            None
        }
    }
}

// ── Custom Audit Logger ─────────────────────────────────────────

struct ConsoleAudit;

impl AuditLogger for ConsoleAudit {
    fn log(&self, event: &AuditEvent) -> anyhow::Result<()> {
        println!(
            "[SIGIL AUDIT] {:?} | {} | approved={} allowed={}",
            event.event_type,
            event.action.description,
            event.action.approved,
            event.action.allowed,
        );
        Ok(())
    }
}

// ── Main ────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let scanner = Arc::new(RegexScanner);
    let audit = Arc::new(ConsoleAudit);

    let mut server = SigilMcpServer::new("demo-server", "0.1.0", scanner, audit);

    // Register a safe tool (any trust level)
    server.register_tool(ToolDef {
        name: "get_weather".into(),
        description: "Get current weather for a city".into(),
        parameters_schema: serde_json::json!({
            "type": "object",
            "properties": {
                "city": { "type": "string" }
            }
        }),
        handler: Box::new(|args| {
            Box::pin(async move {
                let city = args.get("city")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                Ok(serde_json::json!({
                    "city": city,
                    "temp_c": 22,
                    "condition": "sunny"
                }))
            })
        }),
    });

    // Register a sensitive tool (requires High trust)
    server.register_tool_with_trust(
        ToolDef {
            name: "transfer_funds".into(),
            description: "Transfer money between accounts".into(),
            parameters_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "from": { "type": "string" },
                    "to": { "type": "string" },
                    "amount": { "type": "number" }
                }
            }),
            handler: Box::new(|_args| {
                Box::pin(async move {
                    Ok(serde_json::json!({
                        "status": "completed",
                        "transaction_id": "TX-12345"
                    }))
                })
            }),
        },
        TrustLevel::High,
    );

    println!("=== SIGIL MCP Server Demo ===\n");

    // 1. Initialize
    println!("--- Initialize ---");
    let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let resp = server.handle_request(req, TrustLevel::Low).await;
    println!("Response: {}\n", resp);

    // 2. List tools
    println!("--- List Tools ---");
    let req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
    let resp = server.handle_request(req, TrustLevel::Low).await;
    println!("Response: {}\n", resp);

    // 3. Call safe tool (succeeds)
    println!("--- Call get_weather (Low trust → OK) ---");
    let req = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"Berlin"}}}"#;
    let resp = server.handle_request(req, TrustLevel::Low).await;
    println!("Response: {}\n", resp);

    // 4. Call sensitive tool with Low trust (DENIED)
    println!("--- Call transfer_funds (Low trust → DENIED) ---");
    let req = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"transfer_funds","arguments":{"from":"A","to":"B","amount":100}}}"#;
    let resp = server.handle_request(req, TrustLevel::Low).await;
    println!("Response: {}\n", resp);

    // 5. Call sensitive tool with High trust (OK)
    println!("--- Call transfer_funds (High trust → OK) ---");
    let resp = server.handle_request(req, TrustLevel::High).await;
    println!("Response: {}\n", resp);

    // 6. Call with secret in arguments (SIGIL detects it)
    println!("--- Call with API key in arguments (secret detected) ---");
    let req = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"Berlin","api_key":"sk-live-abc123def456"}}}"#;
    let resp = server.handle_request(req, TrustLevel::Low).await;
    println!("Response: {}\n", resp);

    println!("=== Demo Complete ===");
}
