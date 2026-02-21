# 7. The SIGIL Registry

The Model Context Protocol (MCP) achieves exponential growth through its open ecosystem of tools. SIGIL aims to replicate this for **Agent Security** via the SIGIL Registry.

Instead of every organization writing their own regular expressions to detect leaked secrets, or complex policies to prevent destructive actions, the SIGIL Registry crowdsources security primitives.

## 7.1 Core Concepts

The registry distributes two primary artifacts:

1. **Scanners (`SensitivityScanner`)**: Compiled patterns for detecting specific classes of sensitive data.
2. **Policies (`SecurityPolicy`)**: Standardized rules engines for evaluating risk and gating tool execution.

## 7.2 Architecture & Distribution

SIGIL leverages existing package matrices (Crates.io for Rust Servers, NPM for TS/Node Clients) rather than building a proprietary package manager. The "Registry" is a curated namespace and metadata index over these ecosystems.

### 7.2.1 Scanner Packages

Scanners are distributed under the `sigil-scanner-*` namespace.

**Example (Rust Server):**

```bash
cargo add sigil-scanner-financial
cargo add sigil-scanner-health
```

```rust
let mut server = SigilMcpServer::new("my-tools", "1.0", 
    CombinedScanner::new(vec![
        sigil_scanner_financial::IbanScanner::new(),
        sigil_scanner_health::HipaaScanner::new()
    ]),
    audit
);
```

**Example (TypeScript Client Proxy):**

```bash
npm install @sigil-eu/scanner-aws @sigil-eu/scanner-pii
```

```typescript
const secureClient = new SigilProxy(baseClient, {
    scanners: [ AwsSecretScanner, StandardPiiScanner ]
});
```

## 7.3 The Global Index

While packages live on Crates/NPM, `sigil-protocol.org/registry` will host the Global Index. This index serves as the "MCP Inspector" for security.

It provides:

- **Verification Status**: Was this scanner audited by the SIGIL core team? (Prevents malicious scanners that *exfiltrate* secrets instead of vaulting them).
- **Performance Metrics**: Benchmarks on regex execution time (critical to prevent latency on LLM streams).
- **Test Corpus Pass Rate**: What percentage of known leaking formats does this scanner successfully intercept?

## 7.4 Security Considerations for the Registry

A malicious `SensitivityScanner` could act as a keylogger, silently sending intercepted secrets to an offshore server instead of the local `VaultProvider`.

To mitigate this:

1. **Trait Sandboxing**: The `SensitivityScanner` trait in the core protocol is intentionally pure. It takes `&str` and returns `Option<String>` (the matched text). It does **not** have access to the network or async runtime context.
2. **No-HTTP Guarantee**: The reference `SigilMcpServer` ensures scanners execute in a synchronous thread loop without network capabilities.
3. **Audit Dominance**: Every intercept is logged by the `AuditLogger` *before* the scanner returns control. If a scanner crashes or misbehaves, the audit trail captures the discrepancy.
