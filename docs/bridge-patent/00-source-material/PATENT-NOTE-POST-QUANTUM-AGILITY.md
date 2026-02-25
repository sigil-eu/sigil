# PATENT NOTE — Crypto-Agile SIGIL Protocol

## Post-Quantum Signature Scheme Design Intent

**Datum:** 2026-02-25
**Autor:** Benjamin Küttner — SIGIL Protocol
**Status:** DESIGN INTENT — DISCLOSED AS PRIOR ART
**Bezug:** `sigil-protocol/sigil-rs/src/sigil_envelope.rs` (Crypto Agility Block, Zeilen ab 374)

---

> [!IMPORTANT]
> Dieses Dokument dient als **Nachweis der Offenbarung** (Disclosure) des
> Crypto-Agility-Designs zum Datum 2026-02-25 und begründet Priorität für
> die entsprechenden Schutzrechte gegenüber dem DPMA und dem EPA.

---

## 1. Gegenstand

Das SIGIL-Protokoll verwendet derzeit **Ed25519** (RFC 8032) für alle
kryptografischen Signaturen (SIGIL Envelope, RouteAttestation, PaymentIntent).

Ed25519 ist **nicht quantensicher**: Shor's Algorithmus auf einem kryptographisch
relevanten Quantencomputer (CRQC) mit ≥ 4.000 logischen Qubits würde den privaten
Schlüssel aus dem öffentlichen Schlüssel ableiten können.

Um eine langfristige Schutzrechtsstrategie zu sichern und eine Migration zu
post-quanten-sicheren Verfahren zu ermöglichen, wurde das folgende Design
als **Crypto-Agility-Schleife** in den Quellcode eingebettet.

---

## 2. Technisches Design — Crypto Agility Pattern

Das Design erweitert das SIGIL-Protokoll um eine **algorithmusagnostische
Signaturschicht**, ohne die bestehende Implementierung zu brechen.

### Kernidee: Self-Describing Signature Algorithm Field

```rust
// Im Signed Envelope wird der Algorithmus als maschinenlesbares 
// Enum-Feld mitgeführt:
pub enum SignatureAlgorithm {
    Ed25519,       // Aktuell — nicht quantensicher
    MlDsa65,       // NIST FIPS 204 — ML-DSA (ehem. Dilithium3)
    SlhDsaSha2128s, // NIST FIPS 205 — SLH-DSA (ehem. SPHINCS+)
}
```

Jeder Verifier kann anhand dieses Feldes den richtigen Verifizierungsweg wählen,
**ohne externe Konfiguration oder Protokollversion**.

### Einheitlicher Signing-Trait

```rust
pub trait SigilSigner: Send + Sync {
    fn algorithm(&self) -> SignatureAlgorithm;
    fn sign_bytes(&self, msg: &[u8]) -> Vec<u8>;
    fn verifying_key_bytes(&self) -> Vec<u8>;
}
```

Jeder Signaturalgorithmus implementiert denselben Trait. Der Algorithmuswechsel
ist ein drop-in-Ersatz — keine Änderung am Protokollfluss erforderlich.

---

## 3. Abhängigkeiten (noch nicht aktiviert)

| Crate | Version | Zweck |
|---|---|---|
| `pqcrypto-dilithium` | `0.5` | ML-DSA-65 / CRYSTALS-Dilithium3 (NIST FIPS 204) |
| `pqcrypto-sphincsplus` | `0.7` | SLH-DSA / SPHINCS+ (NIST FIPS 205) |
| `pqcrypto-traits` | `0.3` | Gemeinsame Traits für die `pqcrypto`-Familie |

Aktivierung über Cargo Feature Flag (kein Breaking Change):

```toml
[features]
post-quantum = ["dep:pqcrypto-dilithium", "dep:pqcrypto-sphincsplus"]
```

---

## 4. Algorithmische Kennzahlen

| Algorithmus | Schlüsselgröße (pub) | Signaturegröße | Sicherheitsniveau |
|---|---|---|---|
| Ed25519 | 32 Byte | 64 Byte | 128 Bit (klassisch) — ❌ nicht PQ |
| ML-DSA-65 (Dilithium3) | 1952 Byte | 3293 Byte | NIST Level 3 (≡ AES-192) — ✅ PQ |
| SLH-DSA-SHA2-128s | 32 Byte | 7856 Byte | NIST Level 1 konservativ — ✅ PQ |

> [!NOTE]
> ML-DSA-65 ist die empfohlene Migrationsoption für SIGIL: NIST Level 3
> bietet Sicherheit äquivalent zu AES-192 gegen CRQC-Angriffe.

---

## 5. Migrationsplan (Ed25519 → ML-DSA-65)

1. `pqcrypto-dilithium` und `pqcrypto-traits` zu `Cargo.toml` hinzufügen
2. Feature `post-quantum` aktivieren
3. `MlDsaKeypair::generate()` für neue Agenten verwenden
4. ML-DSA Public Key im SIGIL-Registry als DID-Document eintragen
5. Bestehende Ed25519-Envelopes bleiben gültig (rückwärtskompatibel via `algorithm`-Feld)
6. Ed25519 nach Übergangsperiode (empfohlen: 24 Monate) abschalten

---

## 6. Normen und Standards

| Standard | Bezug |
|---|---|
| NIST FIPS 204 (2024) | ML-DSA — Modul-Gitter-basiertes digitales Signaturverfahren |
| NIST FIPS 205 (2024) | SLH-DSA — Zustandsloses Hash-basiertes Signaturverfahren |
| BSI TR-02102-1 (2025) | Empfehlungen für kryptographische Verfahren |
| ETSI TS 119 312 | PQC-Übergangsempfehlungen für qualifizierte eSignaturen (eIDAS 2.0) |

---

## 7. Bezug zu bestehenden Patenten

Diese Offenbarung erweitert das SIGIL Protocol Gebrauchsmuster (DE DPMA,
eingereicht 2026-02-23, Claim 16 — Browser Extension / Ed25519) und das
SIGIL-Bridge-Core Gebrauchsmuster (DE DPMA, eingereicht 2026-02-25, Claim 6 —
DID + eIDAS-Wallet-Kompatibilität).

Die hier offenbarte **Crypto-Agility-Architektur** ist ein neuer,
eigenständiger Anspruch: Die Kombination von (1) algorithmusagnostischem
Envelope-Format, (2) einheitlichem `SigilSigner`-Trait, und (3) Feature-Flag-
gesteuerter PQ-Aktivierung ohne Breaking Change ist dem Anmelder in keiner
veröffentlichten Patentliteratur bekannt.

---

*SIGIL Protocol — Patent Note — Crypto Agility — 2026-02-25*
*Benjamin Küttner — Patent Pending — EUPL-1.2*
