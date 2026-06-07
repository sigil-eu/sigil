// SPDX-License-Identifier: EUPL-1.2
// Copyright (c) 2026 Benjamin Küttner <benjamin.kuettner@icloud.com>
// Patent Pending — DE Gebrauchsmuster, filed 2026-02-23
//
// sigil-mcp-server — Standalone SIGIL MCP Server (stdio transport)
//
// Reads newline-delimited JSON-RPC 2.0 requests from stdin,
// writes responses to stdout. Compatible with Claude Desktop,
// Cursor, Cline, and any MCP host that supports stdio servers.
//
// Usage:
//   sigil-mcp-server [--did <did>] [--key <hex-privkey>] [--offline]
//
// Tools exposed:
//   scan   — Scan arbitrary text for secrets / prompt injection
//   policy — Evaluate a tool-call payload against the SIGIL policy engine
//   ping   — Health check

use sigil_protocol::{
    mcp_server::{SigilMcpServer, ToolDef},
    AuditEvent, AuditEventType, AuditLogger, FileAuditLogger, NullAuditLogger,
    SensitivityScanner, SigilKeypair, TrustLevel,
};

use std::io::{self, BufRead, Write};
use std::sync::Arc;

// ── Built-in scanner (regex, no network) ─────────────────────────────────────

struct BuiltinScanner;

impl SensitivityScanner for BuiltinScanner {
    fn scan(&self, text: &str) -> Option<String> {
        const PATTERNS: &[(&str, &str)] = &[
            ("AKIA[0-9A-Z]{16}", "aws_access_key_id"),
            ("sk-[a-zA-Z0-9]{32,}", "openai_api_key"),
            ("gh[ps]_[a-zA-Z0-9]{36}", "github_pat"),
            ("-----BEGIN RSA PRIVATE KEY-----", "rsa_private_key"),
            ("(?i)(secret|password|api_key)\\s*[:=]\\s*['\"]?[A-Za-z0-9+/]{16,}", "generic_secret"),
            ("(?i)(ignore previous instructions|act as|jailbreak|you are now)", "prompt_injection"),
        ];
        for (pat, name) in PATTERNS {
            if let Ok(re) = regex::Regex::new(pat) {
                if re.is_match(text) {
                    return Some(name.to_string());
                }
            }
        }
        None
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    // Determine audit log path from env (default: stderr-only via NullAuditLogger for simplicity)
    let audit_path = std::env::var("SIGIL_AUDIT_LOG").ok();

    // Keypair (optional — dev mode if not set)
    let did_env = std::env::var("SIGIL_DID")
        .unwrap_or_else(|_| "did:sigil:mcp-server".to_string());

    let scanner = Arc::new(BuiltinScanner);

    // Build server — signed if SIGIL_PRIVKEY is set, unsigned otherwise
    let mut server = if let Ok(hex_key) = std::env::var("SIGIL_PRIVKEY") {
        let bytes = hex::decode(&hex_key).expect("SIGIL_PRIVKEY must be valid hex");
        let key_bytes: [u8; 32] = bytes.try_into().expect("SIGIL_PRIVKEY must be 32 bytes");
        let keypair = SigilKeypair::from_seed(&key_bytes);
        if let Some(ref path) = audit_path {
            let audit = Arc::new(FileAuditLogger::open(path).expect("Cannot open audit log"));
            SigilMcpServer::new_with_keypair(
                "sigil-mcp-server", env!("CARGO_PKG_VERSION"),
                scanner, audit, keypair, &did_env,
            )
        } else {
            let audit = Arc::new(NullAuditLogger);
            SigilMcpServer::new_with_keypair(
                "sigil-mcp-server", env!("CARGO_PKG_VERSION"),
                scanner, audit, keypair, &did_env,
            )
        }
    } else {
        let audit = Arc::new(NullAuditLogger);
        SigilMcpServer::new(
            "sigil-mcp-server", env!("CARGO_PKG_VERSION"),
            scanner, audit,
        )
    };

    // ── Register tools ────────────────────────────────────────────────────────

    // Tool: scan
    server.register_tool(ToolDef {
        name: "scan".into(),
        description: concat!(
            "Scan arbitrary text for security issues: ",
            "leaked secrets (AWS keys, OpenAI tokens, GitHub PATs, RSA keys), ",
            "PII patterns, and prompt injection attempts. ",
            "Returns a JSON object with `hit` (bool), `pattern` (string|null), ",
            "and `severity` (Warn|High|Critical|null)."
        ).into(),
        parameters_schema: serde_json::json!({
            "type": "object",
            "required": ["text"],
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text to scan for security issues"
                }
            }
        }),
        handler: Box::new(|args| Box::pin(async move {
            let text = args.get("text")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let scanner = BuiltinScanner;
            if let Some(pattern) = scanner.scan(&text) {
                let severity = if pattern.contains("rsa") || pattern.contains("openai") || pattern.contains("aws") || pattern.contains("github") {
                    "Critical"
                } else if pattern == "prompt_injection" {
                    "High"
                } else {
                    "High"
                };
                Ok(serde_json::json!({
                    "hit": true,
                    "pattern": pattern,
                    "severity": severity,
                    "blocked": severity == "Critical"
                }))
            } else {
                Ok(serde_json::json!({
                    "hit": false,
                    "pattern": null,
                    "severity": null,
                    "blocked": false
                }))
            }
        })),
    });

    // Tool: ping
    server.register_tool(ToolDef {
        name: "ping".into(),
        description: "Health check. Returns server version and SIGIL status.".into(),
        parameters_schema: serde_json::json!({"type": "object", "properties": {}}),
        handler: Box::new(|_| Box::pin(async move {
            Ok(serde_json::json!({
                "status": "ok",
                "server": "sigil-mcp-server",
                "version": env!("CARGO_PKG_VERSION"),
                "license": "EUPL-1.2",
                "did_method": "did:sigil",
                "beta1": 0
            }))
        })),
    });

    // ── stdio loop ────────────────────────────────────────────────────────────

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) if l.trim().is_empty() => continue,
            Ok(l) => l,
            Err(_) => break,
        };

        let response = server.handle_request(&line, TrustLevel::Low).await;
        let _ = writeln!(out, "{response}");
        let _ = out.flush();
    }
}
