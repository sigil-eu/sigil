# 6. The Security Handshake Protocol

As part of aligning SIGIL natively with the Model Context Protocol (MCP), a formal security handshake is required during server initialization. This handshake establishes mutual trust, negotiates scanning capabilities, and prevents insecure "Shadow IT" connections.

## 6.1 The Problem

In a standard MCP environment, any Client can connect to any Server if network access allows it. There is no capability to say: *"I will only process your requests if you can cryptographically prove you are an Enterprise Claude Host."* Furthermore, a client doesn't know what scanning capabilities the server provides out-of-the-box.

## 6.2 The `sigil/handshake` Method

SIGIL introduces a dedicated JSON-RPC method that MUST be called immediately after the standard MCP `initialize` request, but BEFORE any `tools/call` requests are accepted.

### 6.2.1 Handshake Request (From Client to Server)

The client proves its identity and declares what security policies it enforces locally.

```json
{
  "jsonrpc": "2.0",
  "method": "sigil/handshake",
  "params": {
    "host_identity": "did:web:claude.ai",
    "host_certificate": "-----BEGIN CERTIFICATE-----\n...",
    "enforced_policies": ["prevent_destructive_writes", "require_human_confirmation"],
    "client_capabilities": {
      "local_vault": true,
      "audit_forwarding": true
    }
  },
  "id": 2
}
```

### 6.2.2 Handshake Response (From Server to Client)

The Server validates the `host_certificate` against its `IdentityProvider`. If successful, the server responds with its own intercept capabilities and the established trust baseline.

```json
{
  "jsonrpc": "2.0",
  "result": {
    "status": "established",
    "maximum_trust_level": "High",
    "active_scanners": ["generic-pii", "aws-secrets", "iban-detector"],
    "server_capabilities": {
      "auto_redact": true,
      "strict_mode": false
    }
  },
  "id": 2
}
```

## 6.3 Handshake Rejection

If a non-SIGIL client connects to a `strict_mode` SIGIL Server and attempts to bypass the `sigil/handshake` by immediately calling `tools/call`, the Server MUST return a standard JSON-RPC error.

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "SIGIL Handshake Required: This server requires cryptographic identity verification.",
    "data": {
      "expected_method": "sigil/handshake"
    }
  },
  "id": 3
}
```

## 6.4 Client-Side Enforcement (Shift-Left)

By negotiating `active_scanners` during the handshake, the Client and Server can avoid redundant scanning. If the Server declares it handles `generic-pii`, the Client can disable its local PII scanner to save compute, trusting the Server's SIGIL outbound gate to intercept the data.

Conversely, if the Server does NOT have an `aws-secrets` scanner, the Client MUST enforce its SDK-level interceptor to guarantee the LLM response is sanitized before being rendered to the user.
