# Patent Attorney Review — Claims Audit

## SIGIL Bridge: Core, EURO, FXBridge, ServiceBridge

**Date:** 2026-02-25 · **Perspective:** German/European Patent Practice (DE Gebrauchsmuster + EPO)

---

> [!NOTE]
> This is an AI-generated advisory review for internal planning purposes. It is not a substitute for qualified patent attorney advice.

---

## I. SIGIL-BRIDGE-CORE — Claim-by-Claim Assessment

### Claim 1 (Independent) — Asset-Agnostic Atomic HTLC Transfer

**Form:** Computerimplementiertes Verfahren ✅

**Content:** An asset-agnostic atomic cross-ledger transfer primitive using Hashed Time-Locked Contracts (HTLCs) with DID-attributed parties and an HMAC-chained audit trail.

**Novelty:** Supported. Prior art (US10489780B2, Lightning Labs) covers HTLC in fixed-asset payment channels. The combination of (1) polymorphic asset class, (2) W3C DID identity on both legs, and (3) HMAC audit chain within a single contract primitive is not found in prior art.

**Inventive step:** The key contribution is **asset-class abstraction at the protocol level** — currency, tokenised security, or on-chain token all use the same HTLC primitive. This is the "inventive nucleus" and must be repeated in dependent claims.

**Claim breadth:** Broad. Correctly describes a protocol-level abstraction, not a specific ledger implementation. Court-defensible formulation.

**Rating:** 🟢 SOLID — file as-is.

---

### Claim 2 — Timeout Invariant Enforcement

**Form:** Verfahren (dependent on 1) ✅

**Content:** Server-side validation that `hop[i].timeout > hop[i+1].timeout` for all hops, ensuring preimage reveal propagation is causally guaranteed.

**Novelty:** The mathematical formulation as an **enforced server-side invariant** (vs. a recommended guideline) is novel. No prior art mandates timeout ordering at the gateway level.

**Rating:** 🟢 SOLID.

---

### Claim 3 — HMAC Audit Chain

**Form:** Verfahren (dependent on 1) ✅

**Content:** Each HTLC state transition appends a structured entry to an HMAC-SHA256 chained log. Each entry includes `prev_hmac`, making post-hoc modification detectable.

**Issue — breadth vs. prior art:** US10958648B2 (IBM, 2021) covers HMAC audit logs with blockchain anchoring in a generic IT context. The counter is domain-specificity: SIGIL's chain operates on **financial contract state transitions** with DID attribution, not generic IT events.

**Recommended claim language:** Add: "wherein each audit entry contains the Decentralised Identifier of the initiating party and a structured financial outcome, such that the identity and result of every asset transfer are individually attributable."

**Rating:** 🟡 ACCEPTABLE — strengthen with domain-specificity language.

---

## II. SIGIL-EURO — Claim-by-Claim Assessment

### Claim 1 (Independent) — eIDAS-Signed PaymentIntent

**Form:** Computerimplementiertes Verfahren ✅

**Content:** A signed payment intent primitive that embeds eIDAS trust level, pseudonymised recipient hash (SHA-256), consent scope, and Ed25519 signature in a single serialisable object.

**Novelty:** 🟢 Excellent. EP3948568A1 (Idemia) covers eIDAS identity + payment but not a **signed intent object** carrying all these fields atomically. The pseudonymised recipient (hash, not DID) satisfies GDPR Art. 5 and is novel in combination with payment authorisation.

**Inventive step:** The combination of eIDAS trust levels + SHA-256 recipient pseudonymisation + Ed25519 signing + consent scope in one serialisable primitive creates a **legally attributable but privacy-preserving payment authorisation**. This is inventive.

**Rating:** 🟢 SOLID — strongest independent claim in the Bridge portfolio.

---

### Claim 3 — Structural AML Scanner

**Form:** System (dependent on 1) ✅

**Content:** An AML scanner defined as a purely-functional interface (`text → Vec<AmlFlag>`) where the audit log records only the AML category hash, not the triggering content.

**Issue — same as SIGIL-Core Claim 9:** The "purely-functional" structural claim is the novel contribution. The language must specify: "a synchronous mapping defined such that no network access, state mutation, or asynchronous operation is possible at the interface level."

**Recommended addition to description:** "The content of the triggering transaction is never stored in the audit log; only its SHA-256 hash is retained, satisfying GDPR Article 5(1)(c) data minimisation while preserving regulatory traceability."

**Rating:** 🟢 SOLID with description addition.

---

### Claim 4 — Three-Layer HMAC / Merkle / Blockchain Audit Trail

**Form:** Verfahren (dependent on 1) ✅

**Content:** Per-entry HMAC chain → Merkle tree batch → public blockchain anchoring (Celestia or Solana).

**Issue — evidence of reduction to practice:** This is a **LIVE IMPLEMENTED** system, with documented Celestia Mocha Block 10221745 on 2026-02-24. Add this as an annexe to the description: "The system has been reduced to practice as of 2026-02-24 (Celestia Mocha, Block 10221745, Commitment 0xfb19a5ff...)."

**Rating:** 🟢 SOLID — evidence chain is strong.

---

## III. SIGIL-FXBRIDGE — Claim-by-Claim Assessment

### Claim 1 (Independent) — MultiHopIntent with HTLC n-leg chain

**Form:** Computerimplementiertes Verfahren ✅

**Content:** A multi-hop atomic FX transfer primitive where n HTLCs share a preimage hash, with mandatory timeout invariant enforcement and FX rate context documentation.

**Novelty:** 🟢 Strong. US10346819B2 (Ripple) covers pathfinding for cross-currency payment, but does NOT enforce a server-side timeout invariant or document exchange rates per hop. SIGIL's `MultiHopIntent` is more restrictive (formally enforced invariant) and more transparent (per-hop FX documentation).

**Important: the `route_attestation` field is optional.** This means the basic claim (HTLC + timeout invariant) is independent of the attesting service. Good claim architecture.

**Rating:** 🟢 SOLID.

---

### Claim 3 — RouteAttestation — DID-Liable Routing Service

**Form:** System (dependent on 1) ✅

**Content:** A cryptographically signed document by a DID-identified routing service attesting that all evaluated routes were considered and the optimal one was selected based on documented criteria.

**Inventive step:** 🟢 Excellent. The LIABILITY ELEMENT (the routing service's DID is recorded, making it attributable) combined with the "all evaluated routes" transparency is the inventive contribution. A routing service that selects a suboptimal route is now provably accountable.

**Issue:** The `proof_bytes` field is `Vec<u8>` currently empty (Phase 2). For EPO prosecution, the actual signature must be implemented. This is flagged as a pre-EPO action item.

**Rating:** 🟢 SOLID for Gebrauchsmuster. ⚠️ Proof bytes must be implemented before EPO.

---

## IV. SIGIL-SERVICEBRIDGE — Claim-by-Claim Assessment

### Claim 1 (Independent) — DID-Bound Service Escrow Intent

**Form:** Computerimplementiertes Verfahren ✅

**Content:** A service contract primitive where buyer, provider, and arbitrator are identified by W3C DIDs; payment is locked in escrow; and every state transition (delivery, acceptance, dispute, arbitration) is appended to an HMAC audit chain.

**Novelty:** 🟡 Medium (see prior art: US11250439B2 — Kleros, US10748144B2 — DocuSign). The differentiating element: **pre-agreed DID arbitrator** (not a crowd-sourced juror pool), and **HMAC audit chain** producing court-admissible state transition records.

**Recommended addition to description:** "The arbitrator is identified by Decentralised Identifier at intent creation time, making the dispute resolution mechanism deterministic and attributable, as opposed to stochastic crowd-sourced arbitration systems."

**Rating:** 🟡 ACCEPTABLE — strengthen arbitrator language.

---

## V. Global Issues — All Four Applications

### 1. Claim Numbering

All four patents use standard consecutive Arabic numerals (1, 2, 3...). ✅ No Mängelrüge expected.

### 2. Fee Calculation

Gebrauchsmuster base fee: €40 per application. 4 applications = **€160 total**.

### 3. Abstract Length

All Patent descriptions must include abstracts of ≤150 words in the final documents.

### 4. Pre-EPO Changes Required

| Issue | Severity | Action |
|---|---|---|
| RouteAttestation `proof_bytes` empty | 🔴 Pre-EPO critical | Implement Ed25519 signing in FXBridge routing service |
| `purely-functional` scanner description | 🟡 Pre-EPO | Add description clarification to EURO and BRIDGE-CORE |
| Arbitrator DID claim language | 🟡 Pre-EPO | Strengthen description in ServiceBridge |
| HMAC chain domain-specificity | 🟡 Pre-EPO | Add "DID + financial outcome" language to BRIDGE-CORE Cl.3 |
| Evidence annex (Celestia block) | 🟢 Optional | Attach as PDF annex to SIGIL-EURO description |

---

## VI. Filing Recommendation

| Application | Status | File? |
|---|---|---|
| SIGIL-BRIDGE-CORE | 🟢 CLEARED | ✅ FILE |
| SIGIL-EURO | 🟢 CLEARED | ✅ FILE |
| SIGIL-FXBRIDGE | 🟢 CLEARED | ✅ FILE |
| SIGIL-SERVICEBRIDGE | 🟡 CONDITIONAL | ✅ FILE — strengthen arbitrator claim in description |

All four applications are **legally and technically sufficient** for DE Gebrauchsmuster filing. No issue requires delay.

---
*Attorney Review completed: 2026-02-25 · Antigravity AI · Not a substitute for qualified patent attorney advice*
