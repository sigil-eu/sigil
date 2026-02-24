# SIGIL Bridge — Technical Whitepaper

## Source Material: Bridge Core, EURO, FXBridge, ServiceBridge

**Revision:** 0.1 — 2026-02-25
**Status:** Internal / Patent Priority Document
**Authors:** SIGIL Protocol — sigil-protocol.org

---

## 1. Project Overview

The SIGIL Bridge is a family of four cryptographic infrastructure components enabling **sovereign, asset-agnostic, atomic transfers** between distributed ledgers, payment systems, and service contracts. It extends the SIGIL Protocol (Gebrauchsmuster DE, DPMA, filed 2026-02-22) into the domain of value settlement.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        SIGIL BRIDGE ECOSYSTEM                           │
│                                                                         │
│  ┌────────────────┐   ┌──────────────────┐   ┌─────────────────────┐   │
│  │  SIGIL-BRIDGE  │   │   SIGIL-EURO     │   │   SIGIL-FXBRIDGE    │   │
│  │  CORE          │   │   Gateway        │   │   Multi-Hop FX      │   │
│  │  (Protocol)    │◄──│   (eIDAS CBDC)   │   │   (HTLC-Routing)    │   │
│  └───────┬────────┘   └──────────────────┘   └─────────────────────┘   │
│          │                                                               │
│  ┌───────▼────────────────────────────────────────────────────────┐     │
│  │              SIGIL-SERVICEBRIDGE (Service Escrow)              │     │
│  │              Milestone Intents, Dispute, Arbitration           │     │
│  └────────────────────────────────────────────────────────────────┘     │
│                                                                         │
│  All components share: DID Identities · HMAC Audit Chains ·             │
│  Rust type-safety · EUPL-1.2 + Commercial License                       │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. SIGIL-BRIDGE-CORE

### 2.1 Core Abstraction: The Asset

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "asset_class", rename_all = "snake_case")]
pub enum Asset {
    Currency { currency: String, amount_units: u64, display: String },
    Security  { isin: String, quantity: u64, display: String },
    Token     { contract_id: String, token_id: String, amount: u64, chain: String, display: String },
}
```

The `Asset` enum is the **core polymorphic primitive** — the bridge protocol is asset-agnostic. Any digital value can be transferred using the same protocol.

### 2.2 The HTLC Contract

```rust
pub struct HtlcContract {
    pub contract_id:      String,
    pub preimage_hash:    PreimageHash,      // SHA-256(preimage_secret)
    pub locked_asset:     Asset,
    pub holder_did:       Did,               // Party A — locks assets
    pub beneficiary_did:  Did,               // Party B — receives on reveal
    pub locked_at:        i64,
    pub timeout_at:       i64,               // Unix timestamp
    pub state:            HtlcState,
    pub preimage_revealed: Option<Preimage>, // None = pending, Some = settled
}
```

The HTLC invariant: `state == Settled` if and only if the `preimage_revealed` matches `SHA256(preimage_revealed) == preimage_hash`. Settlement is therefore **mathematically atomic**.

### 2.3 The Bridge Audit Chain

Every HTLC event is appended to a `BridgeAuditChain` — an HMAC-chained, append-only log. The chain is initialised with a genesis entry (HMAC seed). Each subsequent entry contains `prev_hmac`, creating a tamper-evident linked structure.

```rust
pub fn verify_chain(entries: &[AuditEntry], hmac_key: &[u8]) -> ChainVerification {
    // For each entry: verify seq monotonically increases, prev_hmac matches prior entry,
    // and entry HMAC is valid. Any deviation = detected tampering.
}
```

---

## 3. SIGIL-EURO — eIDAS Payment Gateway

### 3.1 PaymentIntent

The `PaymentIntent` is the eIDAS-compliant signed primitive for Digital Euro transfers.

```rust
pub struct PaymentIntent {
    pub payment_reference: String,          // SEPA-compatible reference
    pub payer_did:         Did,             // W3C DID of the payer
    pub recipient_hash:    [u8; 32],        // SHA-256(recipient_did) — pseudonymised
    pub amount_cents:      u64,             // Euro cents — avoids float
    pub currency:          String,          // ISO 4217
    pub consent_scope:     ConsentScope,    // SinglePayment | StandingOrder | Limit
    pub trust_level:       TrustLevel,      // Low | High (eIDAS mapping)
    pub payload_hash:      [u8; 32],        // SHA-256 of canonical payload
    pub timestamp:         i64,
    pub signature:         Vec<u8>,         // Ed25519 over payload_hash ‖ recipient_hash ‖ ts ‖ did
    pub aml_flags:         Vec<AmlFlag>,
}
```

**Key invariant:** The recipient is **never stored in plain text** — only `SHA-256(recipient_did)`. This satisfies GDPR Art. 5(1)(c) data minimisation.

### 3.2 Trust Level Enforcement

| Level | Max Amount | Identity Method |
|---|---|---|
| `Low` | ≤ €50.00 | Basic (email, OIDC) |
| `High` | Unlimited | eIDAS qualified electronic signature |

The gateway rejects `Low`-trust intents above €50 with `422 Unprocessable Entity` before any database write occurs.

### 3.3 The AML/CTF Scanner Interface

```rust
pub trait AmlScanner: Send + Sync {
    fn scan(&self, text: &str) -> Vec<AmlFlag>;
}
pub struct AmlFlag {
    pub category:     String,  // "THRESHOLD_EXCEEDED"
    pub severity:     String,  // "LOW" | "MEDIUM" | "HIGH"
    pub content_hash: String,  // SHA-256(triggering_content) — never raw content
}
```

**Critical property:** The scanner receives only structured field concatenation, not raw user input. High-severity AML flags result in hard rejection (`403 Forbidden`). The original content is **never stored in the audit log** — only the category and hash.

### 3.4 Three-Layer Tamper-Evident Audit Trail

```
Layer 1: Per-entry HMAC-SHA256 chain        → Local tamper detection (sub-millisecond)
Layer 2: Merkle tree over HMAC values       → Batch integrity (hourly)
Layer 3: Merkle root on Celestia/Solana     → Operator-neutral public proof
```

**Live evidence (2026-02-24):**

- Celestia Mocha Block: `10221745`
- Merkle Root: `0xfb19a5ff8ba6be900bac09968522577d60e3e4da9e5fe7dda19928dbc0517c64`
- E2E Test: Audit Sequence #15 written — `SIGILEURO-20260224-512a1bcc` for €15.00

### 3.5 Regulatory Compliance Matrix

| Regulation | Mechanism |
|---|---|
| eIDAS 2.0 (EU 2024/1183) | `TrustLevel::High` = eIDAS qualified signature |
| GDPR Art. 5 | `recipient_hash` — no PII in log |
| AMLD 5/6 | AML categories logged, raw in encrypted Vault |
| MiFID II | Full audit chain per transaction |
| EMIR | Tamper-evident settlement record |
| BSI TR-03116 | Ed25519 + HMAC-SHA256 + AES-256-GCM |

---

## 4. SIGIL-FXBRIDGE — Multi-Hop Atomic FX Gateway

### 4.1 FxContext — Rate Documentation

```rust
pub struct FxContext {
    pub source_currency: String,   // "EUR"
    pub dest_currency:   String,   // "USD"
    pub rate:            String,   // "1.0812"
    pub rate_source:     String,   // "ECB Reference Rate"
    pub rate_timestamp:  i64,
    pub valid_until:     i64,      // Rate expires — typically +30s for live FX
}
```

The `valid_until` field is **validated server-side** (`now <= valid_until`). An expired FX context results in `422 Unprocessable Entity`. This prevents rate-staleness exploitation.

### 4.2 MultiHopIntent — Atomic n-Leg Transfer

```rust
pub struct MultiHopIntent {
    pub intent_id:        String,
    pub sender:           Did,
    pub receiver:         Did,
    pub hops:             Vec<HtlcHop>,            // 1 = direct, n≥2 = multi-hop
    pub route_attestation: Option<RouteAttestation>, // Optional signed route proof
    pub created_at:       i64,
}
```

**Timeout Invariant (formally enforced):**  
`hop[i].contract.timeout_at > hop[i+1].contract.timeout_at ∀ i`

This invariant guarantees that the preimage reveal propagates from the terminal hop back to the source before any contract expires — ensuring atomicity.

**Live evidence (2026-02-24):**  
Intent `SIGIL-FX-1771973584-e2e` accepted — EUR→USD, 1 hop, `timeout_invariant_ok: true`

### 4.3 RouteAttestation — Signed Optimality Proof

```rust
pub struct RouteAttestation {
    pub attestation_id:     String,
    pub attesting_service:  Did,           // DID of the routing service
    pub source_currency:    String,
    pub dest_currency:      String,
    pub evaluated_routes:   Vec<RouteOption>, // ALL routes evaluated, for transparency
    pub selected_route_index: usize,
    pub criteria_applied:   RoutingCriteria,
    pub valid_at:           i64,
    pub valid_until:        i64,
    pub proof_bytes:        Vec<u8>,       // Ed25519 of routing service (Phase 2)
}
```

**Novel contribution:** A DID-attributed routing service is **liable for the claim** that the selected route was optimal given documented criteria at time `valid_at`. This gives Alice a permanent cryptographic receipt for "the cheapest compliant route at time T."

### 4.4 Risk Analytics — CUSUM + Realized Volatility

```rust
pub struct BridgeRiskSnapshot {
    pub rv:                   f64,   // Realized Variance: Σ r²_i
    pub bv:                   f64,   // Bipower Variation: jump-robust IV estimator
    pub jump_component:       f64,   // max(0, RV - BV)
    pub realized_vol_annualized: f64,
    pub fpc_scores:           [f64; 5], // L² functional PCA scores
    pub cusum_stat:           f64,   // CUSUM test statistic for regime change
    pub alert_level:          AlertLevel, // green → yellow → orange → red
}
```

Theoretical basis: Andersen, Tan, Todorov, Zhang (2025) — Journal of Econometrics (CUSUM); Tan, Tan, Tang, Zhang (2024) — Journal of Forecasting (Functional PCA).

---

## 5. SIGIL-SERVICEBRIDGE — Service Escrow Gateway

### 5.1 ServiceIntent Architecture

The ServiceBridge manages the lifecycle of a service contract: a buyer locks payment, a provider delivers, the buyer accepts (or disputes). Dispute resolution is handled by a pre-agreed DID-identified arbitrator.

**Endpoints (live on `https://sigil-protocol.org/service/api/...`):**

- `POST /service/intent/submit` — Create escrow intent
- `POST /service/intent/:id/deliver` — Provider marks delivery
- `POST /service/intent/:id/accept` — Buyer accepts → release payment
- `POST /service/intent/:id/dispute` — Buyer opens dispute window
- `POST /service/intent/:id/arbitrate` — Arbitrator resolves

### 5.2 Intent Lifecycle State Machine

```
Pending
  │
  ▼
Locked ──── timeout ──► TimedOut (refund to buyer)
  │
  ▼ /deliver
Delivered
  │
  ├── /accept ──► Settled (payment released to provider)
  │
  └── /dispute ──► Disputed (DisputeWindow open)
                       │
                       └── /arbitrate ──► Settled | Refunded
```

Every state transition produces an HMAC audit entry, creating a full court-admissible record of the service contract lifecycle.

---

## 6. Deployment Architecture

All four gateways are deployed on a single VPS (`194.242.56.119`) behind an NGINX reverse-proxy with:

- **TLS 1.3** (Let's Encrypt, auto-renewed)
- **IP Whitelisting** (Layer 7, `allow`/`deny` in NGINX config)
- **API-Key Authentication** (`X-Sigil-API-Key` header)
- **Rate Limiting** (`sigil_api`, `sigil_read`, `sigil_write` zones)
- **systemd** service management (auto-restart, hardened units)
- **PostgreSQL** database for SIGIL-REGISTRY
- **Celestia Mocha** testnet for SIGIL-EURO Merkle anchoring (cron, hourly)

All Rust services bind only to `127.0.0.1` — not reachable from the public internet directly.

---

## 7. Evidence Chain Summary

| Date | Component | Evidence | Location |
|---|---|---|---|
| 2026-02-22 | SIGIL Protocol | Patent filed (DE Gebrauchsmuster, DPMA) | DPMA, München |
| 2026-02-24 | SIGIL-EURO | Audit Seq #15 — SIGILEURO-20260224-512a1bcc | VPS `/home/admin/sigil-euro/audit/` |
| 2026-02-24 | Celestia | Mocha Block 10221745, Merkle Root 0xfb19a5ff... | Public DA layer |
| 2026-02-24 | SIGIL-FXBRIDGE | MultiHopIntent SIGIL-FX-1771973584-e2e | VPS `/home/admin/SIGIL-FXBRIDGE/` |
| 2026-02-24 | SIGIL-REGISTRY | PostgreSQL operative, HTTP 200 `/health` | `registry.sigil-protocol.org` |
| 2026-02-24 | Security | 4-layer Defense in Depth verified | `docs/security/sigil-security-audit-2026-02-24.md` |

---

*SIGIL Bridge — Technical Whitepaper v0.1 — 2026-02-25*
*Patent Pending — EUPL-1.2 — sigil-protocol.org*
