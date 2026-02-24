# Technical & Development Path Audit

## Hacker Perspective — SIGIL Bridge: Core, EURO, FXBridge, ServiceBridge

**Date:** 2026-02-25
**Auditor:** Antigravity AI — adversarial technical review

---

## Purpose

This review examines the technical claims from an adversarial perspective:

1. Are the technical claims actually TRUE? Can they be disproved?
2. Are there attack vectors against the inventions that should be disclosed?
3. Is the development path evidence solid enough to defend the priority date?

---

## Part 1: SIGIL-BRIDGE-CORE — Technical Claims Verification

### Claim 1 — Asset-Agnostic HTLC

**Claim states:** A single `HtlcContract` type can hold `Asset::Currency`, `Asset::Security`, or `Asset::Token`. One protocol, any asset.

**Code check:**

```rust
#[serde(tag = "asset_class", rename_all = "snake_case")]
pub enum Asset {
    Currency { currency: String, amount_units: u64, display: String },
    Security  { isin: String, quantity: u64, display: String },
    Token     { contract_id: String, token_id: String, amount: u64, chain: String, display: String },
}
```

✅ **VERIFIED:** Three asset classes, polymorphic in exactly one `HtlcContract.locked_asset` field.

**Attack:** "This is just Atomic Swaps. Atomic cross-chain swaps have existed since 2013."

**Counter:** Atomic swaps exchange two assets simultaneously. `HtlcContract` records the transfer of ONE asset between TWO DID-attributed parties on behalf of a settlement network. The claim is not exchange — it is **transfer with accounting and identity**.

---

### Claim 2 — Timeout Invariant

**Claim states:** The gateway server-side validates `hop[i].timeout > hop[i+1].timeout` and rejects non-conforming intents with `422 Unprocessable Entity`.

**Code check:**

```rust
pub fn validate_timeout_invariant(&self) -> Result<(), FxBridgeError> {
    for i in 0..self.hops.len().saturating_sub(1) {
        let outer = self.hops[i].contract.timeout_at;
        let inner = self.hops[i + 1].contract.timeout_at;
        if outer <= inner { return Err(...); }
    }
    Ok(())
}
```

✅ **VERIFIED:** The check exists, is called in the intent submission handler, and the `FxBridgeError::TimeoutInvariantViolated` variant is returned.

**Live evidence:** The E2E test for `MultiHopIntent` returned `"timeout_invariant_ok": true` from the production server.

---

### Claim 3 — HMAC Audit Chain

**Claim states:** Every state transition appends an HMAC-chained entry; modification of any entry invalidates all subsequent HMAC values.

**Code check:**

```rust
// In sigil-euro-gateway/src/audit.rs
pub fn append(&self, ...) -> Result<AuditEntry> {
    // 1. Read prev_hmac from last entry
    // 2. Compute HMAC-SHA256(all_fields || prev_hmac)
    // 3. Append to CHAIN.jsonl (append-only)
}
```

✅ **VERIFIED:** The `append()` function reads `prev_hmac` from the last written entry and computes the next HMAC covering all fields including `prev_hmac`.

**Attack vector — HMAC key compromise:** If the HMAC secret key is stolen, an attacker could forge valid entries. **Scope:** The claim protects against **post-hoc silent modification** of the log file. An attacker with key access could forge a NEW chain — but this would be equivalent to breaking into the entire system. The claim is correctly and accurately scoped.

---

## Part 2: SIGIL-EURO — Technical Claims Verification

### Claim 1 — PaymentIntent eIDAS Signing

**Claim states:** The `PaymentIntent` is signed with Ed25519 over `payload_hash ‖ recipient_hash ‖ timestamp ‖ payer_did`.

**Code check:**

```rust
let mut msg = Vec::new();
msg.extend_from_slice(&payload_hash);
msg.extend_from_slice(&recipient_hash);
msg.extend_from_slice(&timestamp.to_le_bytes());
msg.extend_from_slice(payer_did.0.as_bytes());
let signature = signing_key.sign(&msg).to_bytes().to_vec();
```

✅ **VERIFIED:** Exact signing procedure is present in `sigil-euro-core/src/lib.rs`.

**Live evidence:** `PaymentIntent` for `SIGILEURO-20260224-512a1bcc` accepted by production gateway at Audit Seq #15 on 2026-02-24. Response: `{"accepted":true,"audit_seq":15}`.

---

### Claim 2 — Trust Level Amount Enforcement

**Claim states:** Low-trust intents above €50 (5000 cents) are rejected before database write with `422 Unprocessable Entity`.

**Code check:**

```rust
if intent.trust_level == TrustLevel::Low
    && intent.amount_cents > state.config.low_trust_limit_cents {
    return (StatusCode::UNPROCESSABLE_ENTITY, Json(...)).into_response();
}
```

✅ **VERIFIED:** Rejection occurs BEFORE the audit chain append — no polluted entries.

---

### Claim 3 — Purely Functional AML Scanner

**Claim states:** Scanner interface (`&str → Vec<AmlFlag>`) structurally prevents network I/O and state mutation.

**Code check:**

```rust
pub trait AmlScanner: Send + Sync {
    fn scan(&self, text: &str) -> Vec<AmlFlag>;
}
```

**Attack — can a conforming impl do I/O?**
With `&self` (immutable borrow), safe Rust prevents mutation of `self`. However, `Mutex<HttpClient>` could technically wrap an HTTP connection. The claim is about ARCHITECTURAL INTENT, not a formal proof.

**Must add to description:** "The scanner interface definition expresses the architectural intent that no network operations shall occur. The `&str → Vec<AmlFlag>` signature makes formal verification of this property tractable with proof assistants such as Coq or Lean (Phase 2 hardening)."

---

### Claim 4 — Three-Layer Audit Trail

**Claim states:** Per-entry HMAC chain + Merkle tree batching + public blockchain anchoring operating independently.

**Live evidence (2026-02-24):**

- Celestia Mocha Block 10221745 ✅
- Merkle Root `0xfb19a5ff8ba6be900bac09968522577d60e3e4da9e5fe7dda19928dbc0517c64` ✅
- Cron job running hourly (`anchor-celestia.sh`) ✅

✅ **VERIFIED:** All three layers independently operational.

---

## Part 3: SIGIL-FXBRIDGE — Technical Claims Verification

### Claim 1 — MultiHopIntent timeout invariant

✅ **VERIFIED** (see Bridge Core Claim 2 above — same code path).

**Live evidence:** `SIGIL-FX-1771973584-e2e`, 1-hop EUR→USD, `timeout_invariant_ok: true`, `HTTP 200`.

### Claim 2 — FxContext validity window

**Claim states:** FX context is validated server-side; expired rate results in rejection.

**Code check:**

```rust
pub fn is_valid(&self) -> bool {
    Utc::now().timestamp() <= self.valid_until
}
// In handler:
if !hop.fx_context.is_valid() {
    return (StatusCode::UNPROCESSABLE_ENTITY, ...).into_response();
}
```

✅ **VERIFIED.**

**Attack — oracle manipulation:** A malicious market maker sends a stale rate (now expired) in a `valid_until` far in the future. **Counter:** The rate source and observation timestamp are recorded in `FxContext`. A regulator or auditor can cross-reference actual ECB rates at `rate_timestamp` to detect falsified rates. The system **documents** rather than validates the economic claim.

### Claim 3 — RouteAttestation proof_bytes

⚠️ **PARTIAL:** `proof_bytes` is present as a field but currently empty (`Vec::new()`). The Ed25519 signature of the routing service over the canonical attestation is not yet implemented. **This is a pre-EPO action item.** For Gebrauchsmuster, the data structure and the concept are protected.

---

## Part 4: SIGIL-SERVICEBRIDGE — Technical Claims Verification

### Claim 1 — Service Lifecycle HMAC Audit

**Live API verified:**

- `GET /service/api/info` → `{"name":"SIGIL-SERVICEBRIDGE","description":"Service asset gateway with DisputeWindow + optional arbitration","patent":"Pending..."}` ✅

**Endpoints exist** (from `/info` response and source inspection). Full E2E lifecycle test (submit → deliver → accept / dispute → arbitrate) not yet executed as of this audit. This is a post-filing verification item.

---

## Part 5: Attack Scenarios

### Attack 1: "This is just Bitcoin Lightning + OAuth"

**Theory:** Bitcoin Lightning uses HTLCs. OAuth provides identity. The combination is known.

**Counter:**

1. Bitcoin Lightning operates in a single asset (BTC) on settled channels. SIGIL bridges ANY asset between ANY parties using DID identity — no channel pre-establishment.
2. OAuth provides SESSION identity. SIGIL embeds TRANSACTION-level identity in each intent.
3. No Lightning implementation has AML scanning, eIDAS trust levels, or HMAC audit trails.

**Claim robustness:** ✅ Survives.

### Attack 2: "Atomic swaps for FX are old — see Interledger Protocol (ILP)"

**Theory:** W3C Interledger Protocol (published 2016) defines atomic cross-ledger transfers.

**Counter:**

1. ILP provides the protocol abstraction. SIGIL-FXBRIDGE complements ILP with: DID-attributed parties, `FxContext` rate documentation, `RouteAttestation` accountability, and CUSUM risk monitoring.
2. ILP does NOT specify how exchange rates are documented, verified, or attested.
3. No ILP component produces a liability-bearing attestation from an identified routing service.

**Claim robustness:** ✅ Survives.

### Attack 3: "FX oracle manipulation invalidates the FxContext claim"

**Theory:** An attacker controls a market maker DID and submits false `rate`/`rate_source` data.

**Counter:** The claim covers **documentation**, not **enforcement**. The `FxContext` is a regulatory paper trail — `rate_source: "ECB Reference Rate"` is a CLAIM by the market maker, auditable after the fact. A court can compare the recorded rate to historical ECB publications. The gateway does not validate economic correctness — it validates format and freshness (timestamp + `valid_until`).

**Claim robustness:** ✅ Claim correctly scoped.

### Attack 4: "Preimage theft — the receiver reveals S, but the sender can't claim on-chain"

**Theory:** In a multi-hop HTLC, if hop[1] reveals the preimage to claim from hop[0], but hop[0]'s blockchain transaction has expired, the sender loses funds.

**Counter:** This is **by design** — the timeout invariant enforced by the gateway (`hop[0].timeout > hop[1].timeout`) guarantees the sender's HTLC is always valid for LONGER than all downstream hops. The sender has time to claim once S propagates backward.

**Claim robustness:** ✅ The formal invariant IS the counter-argument.

---

## Part 6: Development Path Evidence Audit

| Evidence | Location | Status |
|---|---|---|
| `sigil-bridge-core` first commit | sigil-protocol/sigil-rs git history | ✅ |
| `sigil-fxbridge-core` source | /scratch/SIGIL-FXBRIDGE/src/ | ✅ Local (private) |
| `sigil-euro-core` source | /scratch/SIGIL-EURO/src/ | ✅ Local (private) |
| SIGIL-EURO Audit Seq #15 | VPS audit chain | ✅ Server log |
| Celestia Mocha Block 10221745 | Public blockchain | ✅ Verifiable |
| FXBridge MultiHopIntent live test | VPS gateway response | ✅ HTTP 200 |
| SIGIL-REGISTRY live (PostgreSQL) | `registry.sigil-protocol.org/health` | ✅ HTTP 200 |

---

## Part 7: Required Code Changes

| Priority | Change | Why | When |
|---|---|---|---|
| 🔴 Pre-EPO | Implement `RouteAttestation.proof_bytes` Ed25519 signing | Claim 3 of FXBridge accuracy | Before EPO filing |
| 🟡 Pre-EPO | Add formal description to AML scanner claim (purely-functional intent) | Claim defensibility | Before EPO filing |
| 🟡 Pre-EPO | Run full ServiceBridge E2E lifecycle test (submit → dispute → arbitrate) | Claim 1 evidence | Before EPO filing |
| 🟡 Post-filing | Benchmark HTLC throughput on ARM server (Hetzner/Graviton) | Broader hardware claim for EPO | Before EPO filing |
| 🟢 Optional | Coq/Lean formal verification of scanner interface | Maximum claim strength | EPO prosecution phase |

---
*Hacker Review completed: 2026-02-25 · Antigravity AI · Adversarial technical review — not a substitute for professional security audit*
