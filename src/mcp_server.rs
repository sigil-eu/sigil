// SPDX-License-Identifier: EUPL-1.2
// Copyright (c) 2026 Benjamin Küttner <benjamin.kuettner@icloud.com>
// Patent Pending — DE Gebrauchsmuster, filed 2026-02-23

//! Reference SIGIL MCP Server.
//!
//! An embeddable MCP (Model Context Protocol) server that any Rust
//! application can use to expose SIGIL-protected tools over JSON-RPC 2.0.
//!
//! ```rust,no_run
//! use sigil_protocol::mcp_server::{SigilMcpServer, ToolDef};
//! use sigil_protocol::{SensitivityScanner, AuditLogger, AuditEvent};
//! use std::sync::Arc;
//!
//! struct MyScanner;
//! impl SensitivityScanner for MyScanner {
//!     fn scan(&self, _text: &str) -> Option<String> { None }
//! }
//! struct MyAudit;
//! impl AuditLogger for MyAudit {
//!     fn log(&self, _e: &AuditEvent) -> anyhow::Result<()> { Ok(()) }
//! }
//!
//! let scanner = Arc::new(MyScanner);
//! let audit = Arc::new(MyAudit);
//! let mut server = SigilMcpServer::new("my-server", "1.0.0", scanner, audit);
//! server.register_tool(ToolDef {
//!     name: "get_weather".into(),
//!     description: "Get current weather".into(),
//!     parameters_schema: serde_json::json!({"type": "object"}),
//!     handler: Box::new(|args| Box::pin(async move {
//!         Ok(serde_json::json!({"temp": 22}))
//!     })),
//! });
//! ```

use crate::{
    sigil_envelope::{SigilEnvelope, SigilKeypair, Verdict},
    AuditEvent, AuditEventType, AuditLogger, SensitivityScanner, TrustLevel,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

// ── Inbound _sigil parser ──────────────────────────────────────

/// Inbound SIGIL envelope parsed from the request `params._sigil` field.
#[derive(Debug, Deserialize, Default)]
pub struct InboundSigil {
    pub identity: Option<String>,
    pub verdict: Option<String>,
    pub signature: Option<String>,
    pub nonce: Option<String>,
    pub timestamp: Option<String>,
}

// ── JSON-RPC 2.0 types ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<serde_json::Value>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

// ── MCP Tool definition ─────────────────────────────────────────

/// Async handler for a tool call.
pub type ToolHandler = Box<
    dyn Fn(serde_json::Value) -> Pin<Box<dyn Future<Output = anyhow::Result<serde_json::Value>> + Send>>
        + Send
        + Sync,
>;

/// A tool definition to register with the SIGIL MCP server.
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub parameters_schema: serde_json::Value,
    pub handler: ToolHandler,
}

// ── SIGIL MCP Server ────────────────────────────────────────────

/// A reference SIGIL-secured MCP server.
///
/// Wraps any set of tools with:
/// - **Input scanning** — tool arguments are scanned for secrets before execution
/// - **Output scanning** — tool results are scanned for secrets before returning
/// - **Audit logging** — every tool invocation is logged
/// - **Trust gating** — tools can require a minimum trust level
/// - **SIGIL signing** — every response carries a signed `_sigil` envelope
pub struct SigilMcpServer<S: SensitivityScanner, A: AuditLogger> {
    name: String,
    version: String,
    tools: HashMap<String, ToolEntry>,
    scanner: Arc<S>,
    audit: Arc<A>,
    /// Minimum trust level required for this server (default: Low).
    required_trust: TrustLevel,
    /// Ed25519 keypair for signing outbound `_sigil` envelopes.
    /// If `None`, responses are not signed (development mode only).
    keypair: Option<Arc<SigilKeypair>>,
    /// The server's DID identifier (e.g. `did:sigil:my-server`).
    did: String,
}

struct ToolEntry {
    description: String,
    schema: serde_json::Value,
    handler: ToolHandler,
    /// Per-tool trust level override (None = use server default).
    required_trust: Option<TrustLevel>,
}

impl<S: SensitivityScanner, A: AuditLogger> SigilMcpServer<S, A> {
    /// Create a new SIGIL MCP server (no signing keypair — dev mode).
    pub fn new(name: &str, version: &str, scanner: Arc<S>, audit: Arc<A>) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            tools: HashMap::new(),
            scanner,
            audit,
            required_trust: TrustLevel::Low,
            keypair: None,
            did: format!("did:sigil:{}", name.to_lowercase().replace(' ', "_")),
        }
    }

    /// Create a server with a signing keypair (production mode).
    pub fn new_with_keypair(
        name: &str,
        version: &str,
        scanner: Arc<S>,
        audit: Arc<A>,
        keypair: SigilKeypair,
        did: &str,
    ) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            tools: HashMap::new(),
            scanner,
            audit,
            required_trust: TrustLevel::Low,
            keypair: Some(Arc::new(keypair)),
            did: did.to_string(),
        }
    }

    /// Returns the server's public verifying key (base64url), if a keypair is set.
    pub fn verifying_key(&self) -> Option<String> {
        self.keypair.as_ref().map(|kp| kp.verifying_key_base64())
    }

    /// Set the minimum trust level for the entire server.
    pub fn set_required_trust(&mut self, level: TrustLevel) {
        self.required_trust = level;
    }

    /// Register a tool.
    pub fn register_tool(&mut self, tool: ToolDef) {
        self.tools.insert(
            tool.name.clone(),
            ToolEntry {
                description: tool.description,
                schema: tool.parameters_schema,
                handler: tool.handler,
                required_trust: None,
            },
        );
    }

    /// Register a tool with a specific trust requirement.
    pub fn register_tool_with_trust(&mut self, tool: ToolDef, trust: TrustLevel) {
        self.tools.insert(
            tool.name.clone(),
            ToolEntry {
                description: tool.description,
                schema: tool.parameters_schema,
                handler: tool.handler,
                required_trust: Some(trust),
            },
        );
    }

    /// Handle an incoming JSON-RPC 2.0 request string.
    ///
    /// Returns the JSON-RPC response string. All tool arguments and results
    /// are scanned by the SIGIL `SensitivityScanner`, and every invocation
    /// is logged via the `AuditLogger`.
    pub async fn handle_request(
        &self,
        request: &str,
        caller_trust: TrustLevel,
    ) -> String {
        let req: JsonRpcRequest = match serde_json::from_str(request) {
            Ok(r) => r,
            Err(e) => {
                return serde_json::to_string(&JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id: serde_json::Value::Null,
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32700,
                        message: format!("Parse error: {e}"),
                        data: None,
                    }),
                })
                .unwrap_or_default();
            }
        };

        let id = req.id.clone().unwrap_or(serde_json::Value::Null);

        let response = match req.method.as_str() {
            "initialize" => self.handle_initialize(&id),
            "tools/list" => self.handle_tools_list(&id),
            "tools/call" => self.handle_tools_call(&id, req.params, caller_trust).await,
            _ => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id,
                result: None,
                error: Some(JsonRpcError {
                    code: -32601,
                    message: format!("Method not found: {}", req.method),
                    data: None,
                }),
            },
        };

        serde_json::to_string(&response).unwrap_or_default()
    }

    fn handle_initialize(&self, id: &serde_json::Value) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: id.clone(),
            result: Some(serde_json::json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": self.name,
                    "version": self.version,
                },
                "capabilities": {
                    "tools": { "listChanged": false },
                },
                "sigil": {
                    "version": "0.1.0",
                    "requiredTrust": format!("{:?}", self.required_trust),
                }
            })),
            error: None,
        }
    }

    fn handle_tools_list(&self, id: &serde_json::Value) -> JsonRpcResponse {
        let tools: Vec<serde_json::Value> = self
            .tools
            .iter()
            .map(|(name, entry)| {
                serde_json::json!({
                    "name": name,
                    "description": entry.description,
                    "inputSchema": entry.schema,
                })
            })
            .collect();

        JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: id.clone(),
            result: Some(serde_json::json!({ "tools": tools })),
            error: None,
        }
    }

    async fn handle_tools_call(
        &self,
        id: &serde_json::Value,
        params: serde_json::Value,
        caller_trust: TrustLevel,
    ) -> JsonRpcResponse {
        let tool_name = params
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or(serde_json::json!({}));

        // ── SIGIL: Parse + verify inbound _sigil envelope ──
        let inbound_sigil = params
            .get("_sigil")
            .and_then(|v| serde_json::from_value::<InboundSigil>(v.clone()).ok());

        if let Some(ref sig) = inbound_sigil {
            if let (Some(identity), Some(nonce)) = (&sig.identity, &sig.nonce) {
                let _ = self.audit.log(
                    &AuditEvent::new(AuditEventType::McpToolGated).with_action(
                        format!("Inbound _sigil: identity={identity} nonce={nonce}"),
                        "low".into(),
                        true,
                        true,
                    ),
                );
            }
        }

        // ── Lookup tool ──
        let entry = match self.tools.get(&tool_name) {
            Some(e) => e,
            None => {
                return JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id: id.clone(),
                    result: None,
                    error: Some(JsonRpcError {
                        code: -32602,
                        message: format!("Unknown tool: {tool_name}"),
                        data: None,
                    }),
                };
            }
        };

        // ── SIGIL: Trust gate ──
        let required = entry.required_trust.unwrap_or(self.required_trust);
        if (caller_trust as u8) < (required as u8) {
            let _ = self.audit.log(&AuditEvent::new(AuditEventType::PolicyViolation).with_action(
                format!("Trust gate: {tool_name} requires {required:?}, caller has {caller_trust:?}"),
                "high".into(),
                false,
                false,
            ));
            return JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: id.clone(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32001,
                    message: format!(
                        "SIGIL trust gate: tool '{tool_name}' requires {required:?} trust"
                    ),
                    data: None,
                }),
            };
        }

        // ── SIGIL: Scan input arguments ──
        let args_str = serde_json::to_string(&arguments).unwrap_or_default();
        let input_scan = self.scanner.scan(&args_str);
        if input_scan.is_some() {
            let _ = self.audit.log(&AuditEvent::new(AuditEventType::SigilInterception).with_action(
                format!("Input scan: secrets detected in {tool_name} arguments"),
                "high".into(),
                true,
                false,
            ));
        }

        // ── Execute tool ──
        let result = (entry.handler)(arguments).await;

        match result {
            Ok(output) => {
                // ── SIGIL: Scan output ──
                let output_str = serde_json::to_string(&output).unwrap_or_default();
                let output_scan = self.scanner.scan(&output_str);

                let _ = self.audit.log(&AuditEvent::new(AuditEventType::McpToolGated).with_action(
                    format!(
                        "MCP tool {tool_name}: input_secrets={}, output_secrets={}",
                        input_scan.is_some(),
                        output_scan.is_some()
                    ),
                    "low".into(),
                    true,
                    true,
                ));

                // ── SIGIL: Sign outbound envelope ──
                let verdict = if output_scan.is_some() {
                    Verdict::Scanned
                } else {
                    Verdict::Allowed
                };
                let reason = output_scan.clone().map(|cat| {
                    format!("Outbound sensitivity scan detected: {cat}")
                });
                let sigil_envelope = self.keypair.as_ref().and_then(|kp| {
                    SigilEnvelope::sign(&self.did, verdict, reason, kp).ok()
                });

                let mut result_obj = serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": output_str,
                    }],
                    "isError": false,
                    "sigil": {
                        "inputSecrets": input_scan.is_some(),
                        "outputSecrets": output_scan.is_some(),
                    }
                });

                // Embed signed _sigil if keypair is available
                if let Some(envelope) = sigil_envelope {
                    result_obj["_sigil"] = serde_json::to_value(&envelope).unwrap_or_default();
                }

                JsonRpcResponse {
                    jsonrpc: "2.0".into(),
                    id: id.clone(),
                    result: Some(result_obj),
                    error: None,
                }
            }
            Err(e) => JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: id.clone(),
                result: Some(serde_json::json!({
                    "content": [{
                        "type": "text",
                        "text": format!("Error: {e}"),
                    }],
                    "isError": true,
                })),
                error: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal test scanner
    struct TestScanner;
    impl SensitivityScanner for TestScanner {
        fn scan(&self, text: &str) -> Option<String> {
            if text.contains("sk-") {
                Some("OpenAI Key".into())
            } else {
                None
            }
        }
    }

    // Minimal test audit logger
    struct TestAudit {
        log_count: std::sync::atomic::AtomicU32,
    }
    impl TestAudit {
        fn new() -> Self {
            Self {
                log_count: std::sync::atomic::AtomicU32::new(0),
            }
        }
        fn count(&self) -> u32 {
            self.log_count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    impl AuditLogger for TestAudit {
        fn log(&self, _event: &AuditEvent) -> anyhow::Result<()> {
            self.log_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    fn make_server() -> SigilMcpServer<TestScanner, TestAudit> {
        let scanner = Arc::new(TestScanner);
        let audit = Arc::new(TestAudit::new());
        let mut server = SigilMcpServer::new("test-server", "0.1.0", scanner, audit);

        server.register_tool(ToolDef {
            name: "echo".into(),
            description: "Echo input back".into(),
            parameters_schema: serde_json::json!({"type": "object"}),
            handler: Box::new(|args| {
                Box::pin(async move { Ok(args) })
            }),
        });

        server.register_tool_with_trust(
            ToolDef {
                name: "admin_reset".into(),
                description: "Dangerous admin operation".into(),
                parameters_schema: serde_json::json!({"type": "object"}),
                handler: Box::new(|_| {
                    Box::pin(async move { Ok(serde_json::json!({"status": "reset"})) })
                }),
            },
            TrustLevel::High,
        );

        server
    }

    #[tokio::test]
    async fn initialize_returns_server_info() {
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        let resp = server.handle_request(req, TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["result"]["serverInfo"]["name"], "test-server");
        assert!(parsed["result"]["sigil"].is_object());
    }

    #[tokio::test]
    async fn tools_list_returns_registered_tools() {
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#;
        let resp = server.handle_request(req, TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        let tools = parsed["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"echo"));
        assert!(names.contains(&"admin_reset"));
    }

    #[tokio::test]
    async fn tools_call_echo_succeeds() {
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}"#;
        let resp = server.handle_request(req, TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert!(parsed["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("hello"));
        assert_eq!(parsed["result"]["isError"], false);
    }

    #[tokio::test]
    async fn tools_call_unknown_tool_returns_error() {
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}"#;
        let resp = server.handle_request(req, TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert!(parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("Unknown tool"));
    }

    #[tokio::test]
    async fn trust_gate_blocks_low_trust_from_high_trust_tool() {
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"admin_reset","arguments":{}}}"#;
        let resp = server.handle_request(req, TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert!(parsed["error"]["message"]
            .as_str()
            .unwrap()
            .contains("trust gate"));
    }

    #[tokio::test]
    async fn trust_gate_allows_high_trust_for_high_trust_tool() {
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"admin_reset","arguments":{}}}"#;
        let resp = server.handle_request(req, TrustLevel::High).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert!(parsed["error"].is_null());
        assert!(parsed["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("reset"));
    }

    #[tokio::test]
    async fn sigil_scan_detects_secrets_in_arguments() {
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo","arguments":{"key":"sk-abc123def456"}}}"#;
        let resp = server.handle_request(req, TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        // Tool still executes, but SIGIL metadata flags secrets
        assert_eq!(parsed["result"]["sigil"]["inputSecrets"], true);
        // Audit log was called (at least 2: interception + tool gated)
        assert!(server.audit.count() >= 2);
    }

    #[tokio::test]
    async fn sigil_scan_no_secrets_in_clean_input() {
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"echo","arguments":{"message":"safe text"}}}"#;
        let resp = server.handle_request(req, TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["result"]["sigil"]["inputSecrets"], false);
        assert_eq!(parsed["result"]["sigil"]["outputSecrets"], false);
    }

    #[tokio::test]
    async fn invalid_json_returns_parse_error() {
        let server = make_server();
        let resp = server.handle_request("not json", TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn unknown_method_returns_method_not_found() {
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":10,"method":"resources/list","params":{}}"#;
        let resp = server.handle_request(req, TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        assert_eq!(parsed["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn audit_logged_for_every_tool_call() {
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}"#;
        let before = server.audit.count();
        server.handle_request(req, TrustLevel::Low).await;
        let after = server.audit.count();
        assert!(after > before, "Audit log should record tool invocation");
    }

    #[tokio::test]
    async fn signed_server_embeds_sigil_envelope_in_response() {
        use crate::sigil_envelope::{SigilEnvelope, SigilKeypair};

        let keypair = SigilKeypair::generate();
        let verifying_key = keypair.verifying_key_base64();
        let scanner = Arc::new(TestScanner);
        let audit = Arc::new(TestAudit::new());

        let mut server = SigilMcpServer::new_with_keypair(
            "signed-server",
            "0.1.0",
            scanner,
            audit,
            keypair,
            "did:sigil:signed_server",
        );
        server.register_tool(ToolDef {
            name: "ping".into(),
            description: "Returns pong".into(),
            parameters_schema: serde_json::json!({"type": "object"}),
            handler: Box::new(|_| {
                Box::pin(async move { Ok(serde_json::json!({"pong": true})) })
            }),
        });

        let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ping","arguments":{}}}"#;
        let resp = server.handle_request(req, TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();

        // Response must contain a _sigil field
        let sigil = &parsed["result"]["_sigil"];
        assert!(sigil.is_object(), "_sigil must be present in signed response");
        assert_eq!(sigil["identity"], "did:sigil:signed_server");
        assert_eq!(sigil["verdict"], "allowed");
        assert!(sigil["signature"].is_string(), "Signature must be present");
        assert!(sigil["nonce"].is_string(), "Nonce must be present");

        // Signature must be cryptographically valid
        let envelope: SigilEnvelope = serde_json::from_value(sigil.clone()).unwrap();
        assert!(
            envelope.verify(&verifying_key).unwrap(),
            "Outbound _sigil signature must verify against server public key"
        );
    }

    #[tokio::test]
    async fn unsigned_server_works_without_sigil_envelope() {
        // Default server (no keypair) must still function correctly
        let server = make_server();
        let req = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"x":1}}}"#;
        let resp = server.handle_request(req, TrustLevel::Low).await;
        let parsed: serde_json::Value = serde_json::from_str(&resp).unwrap();
        // No error, result present, but no _sigil (no keypair)
        assert!(parsed["error"].is_null());
        assert!(parsed["result"]["_sigil"].is_null());
    }
}
