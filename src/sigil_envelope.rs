//! SIGIL Envelope — per-message DID-bound cryptographic signing.
//!
//! Implements the `_sigil` envelope as defined in the SIGIL Protocol
//! Specification v1.0.0 (§2–§4). Each MCP JSON-RPC 2.0 tool call carries
//! a `SigilEnvelope` that:
//!
//! 1. Asserts the caller's identity as a Decentralised Identifier (DID).
//! 2. Embeds the real-time policy verdict (`allowed` / `blocked` / `scanned`).
//! 3. Carries an **Ed25519 digital signature** over the canonical form of the
//!    envelope, making the identity + verdict non-repudiable.
//!
//! # Signing
//!
//! ```rust
//! use sigil_protocol::sigil_envelope::{SigilEnvelope, SigilKeypair, Verdict};
//!
//! let keypair = SigilKeypair::generate();
//! let envelope = SigilEnvelope::sign(
//!     "did:sigil:parent_01",
//!     Verdict::Allowed,
//!     None,
//!     &keypair,
//! ).unwrap();
//! assert!(envelope.verify(&keypair.verifying_key_base64()).unwrap());
//! ```

use anyhow::{anyhow, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

// ── Verdict ──────────────────────────────────────────────────────────────────

/// The real-time policy decision for a single MCP tool call.
///
/// Exactly three values are valid per SIGIL Spec §2.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The gateway verified the identity and permitted the call.
    Allowed,
    /// The gateway denied the call. `reason` must be present.
    Blocked,
    /// The call is permitted but the payload was inspected (e.g., for PII).
    Scanned,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Allowed => write!(f, "allowed"),
            Verdict::Blocked => write!(f, "blocked"),
            Verdict::Scanned => write!(f, "scanned"),
        }
    }
}

// ── SigilEnvelope ─────────────────────────────────────────────────────────────

/// The `_sigil` object embedded in every MCP JSON-RPC request's `params`.
///
/// All fields except `reason` are required. The `signature` field is a
/// base64url-encoded Ed25519 signature over the canonical form (§3.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigilEnvelope {
    /// DID of the requesting agent (e.g., `did:sigil:parent_01`).
    pub identity: String,
    /// Policy verdict for this call.
    pub verdict: Verdict,
    /// Signing time, ISO 8601 with millisecond precision (UTC).
    pub timestamp: String,
    /// 16-byte cryptographically random nonce, hex-encoded. Prevents replays.
    pub nonce: String,
    /// Ed25519 signature over the canonical form, base64url-encoded.
    pub signature: String,
    /// Present when verdict is `blocked` or `scanned`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl SigilEnvelope {
    /// Produce the canonical byte string for signing/verifying.
    ///
    /// Per SIGIL Spec §3.1: fields in lexicographic key order, compact JSON,
    /// no whitespace, excluding `signature` and `reason`.
    pub fn canonical_bytes(
        identity: &str,
        verdict: &Verdict,
        timestamp: &str,
        nonce: &str,
    ) -> Vec<u8> {
        // Keys must appear in lexicographic order: identity, nonce, timestamp, verdict
        let canonical = serde_json::json!({
            "identity": identity,
            "nonce": nonce,
            "timestamp": timestamp,
            "verdict": verdict.to_string(),
        });
        // serde_json preserves insertion order — but we need lexicographic order.
        // Build the string manually to guarantee determinism across platforms.
        format!(
            "{{\"identity\":{},\"nonce\":{},\"timestamp\":{},\"verdict\":{}}}",
            serde_json::to_string(identity).unwrap(),
            serde_json::to_string(nonce).unwrap(),
            serde_json::to_string(timestamp).unwrap(),
            serde_json::to_string(&canonical["verdict"]).unwrap(),
        )
        .into_bytes()
    }

    /// Sign a new envelope using the given keypair.
    ///
    /// Generates a fresh nonce and timestamp automatically.
    pub fn sign(
        identity: &str,
        verdict: Verdict,
        reason: Option<String>,
        keypair: &SigilKeypair,
    ) -> Result<Self> {
        if verdict == Verdict::Blocked && reason.is_none() {
            return Err(anyhow!(
                "SIGIL spec §2.3: reason MUST be present when verdict = blocked"
            ));
        }

        let timestamp = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        // 16-byte cryptographically random nonce
        let mut nonce_bytes = [0u8; 16];
        rand_core::RngCore::fill_bytes(&mut OsRng, &mut nonce_bytes);
        let nonce = hex::encode(nonce_bytes);

        let canonical = Self::canonical_bytes(identity, &verdict, &timestamp, &nonce);
        let signature_bytes: Signature = keypair.signing_key.sign(&canonical);
        let signature = Base64UrlUnpadded::encode_string(signature_bytes.to_bytes().as_ref());

        Ok(Self {
            identity: identity.to_string(),
            verdict,
            timestamp,
            nonce,
            signature,
            reason,
        })
    }

    /// Verify the envelope signature against an Ed25519 public key (base64url).
    ///
    /// Returns `Ok(true)` if the signature is valid, `Ok(false)` if invalid,
    /// or `Err` if the public key or signature cannot be decoded.
    pub fn verify(&self, verifying_key_base64: &str) -> Result<bool> {
        // Decode public key
        let key_bytes = Base64UrlUnpadded::decode_vec(verifying_key_base64)
            .map_err(|e| anyhow!("Failed to decode verifying key: {e}"))?;
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow!("Verifying key must be exactly 32 bytes"))?;
        let verifying_key = VerifyingKey::from_bytes(&key_array)
            .map_err(|e| anyhow!("Invalid Ed25519 public key: {e}"))?;

        // Decode signature
        let sig_bytes = Base64UrlUnpadded::decode_vec(&self.signature)
            .map_err(|e| anyhow!("Failed to decode signature: {e}"))?;
        let sig_array: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| anyhow!("Signature must be exactly 64 bytes"))?;
        let signature = Signature::from_bytes(&sig_array);

        // Reconstruct canonical bytes
        let canonical =
            Self::canonical_bytes(&self.identity, &self.verdict, &self.timestamp, &self.nonce);

        Ok(verifying_key.verify(&canonical, &signature).is_ok())
    }
}

// ── SigilKeypair ─────────────────────────────────────────────────────────────

/// An Ed25519 keypair for signing SIGIL envelopes.
///
/// The signing key is kept in memory only. In production, the private key
/// MUST be stored in a secure enclave or OS keychain (SIGIL Spec §11.4).
pub struct SigilKeypair {
    signing_key: SigningKey,
}

impl SigilKeypair {
    /// Generate a new random Ed25519 keypair using the OS random source.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self { signing_key }
    }

    /// Load a keypair from a raw 32-byte seed (private key scalar).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(seed),
        }
    }

    /// Export the public verifying key as base64url (no padding).
    ///
    /// This is the value to store in the DID Document and SIGIL Registry.
    pub fn verifying_key_base64(&self) -> String {
        let vk: VerifyingKey = self.signing_key.verifying_key();
        Base64UrlUnpadded::encode_string(vk.as_bytes())
    }

    /// Export the raw verifying key bytes (32 bytes).
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        *self.signing_key.verifying_key().as_bytes()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keypair() -> SigilKeypair {
        // Fixed seed for deterministic tests
        let seed = [42u8; 32];
        SigilKeypair::from_seed(&seed)
    }

    #[test]
    fn verdict_display() {
        assert_eq!(Verdict::Allowed.to_string(), "allowed");
        assert_eq!(Verdict::Blocked.to_string(), "blocked");
        assert_eq!(Verdict::Scanned.to_string(), "scanned");
    }

    #[test]
    fn verdict_serializes_lowercase() {
        let json = serde_json::to_string(&Verdict::Allowed).unwrap();
        assert_eq!(json, "\"allowed\"");
        let json = serde_json::to_string(&Verdict::Blocked).unwrap();
        assert_eq!(json, "\"blocked\"");
    }

    #[test]
    fn canonical_bytes_are_deterministic() {
        let a = SigilEnvelope::canonical_bytes(
            "did:sigil:parent_01",
            &Verdict::Allowed,
            "2026-02-21T17:54:44.123Z",
            "a3f82c1d9b7e04f5",
        );
        let b = SigilEnvelope::canonical_bytes(
            "did:sigil:parent_01",
            &Verdict::Allowed,
            "2026-02-21T17:54:44.123Z",
            "a3f82c1d9b7e04f5",
        );
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_bytes_are_lexicographically_ordered() {
        let bytes = SigilEnvelope::canonical_bytes(
            "did:sigil:parent_01",
            &Verdict::Allowed,
            "2026-02-21T17:54:44.123Z",
            "a3f82c1d9b7e04f5",
        );
        let s = String::from_utf8(bytes).unwrap();
        // Keys must appear in order: identity, nonce, timestamp, verdict
        let id_pos = s.find("identity").unwrap();
        let nonce_pos = s.find("nonce").unwrap();
        let ts_pos = s.find("timestamp").unwrap();
        let verdict_pos = s.find("verdict").unwrap();
        assert!(id_pos < nonce_pos);
        assert!(nonce_pos < ts_pos);
        assert!(ts_pos < verdict_pos);
    }

    #[test]
    fn sign_and_verify_allowed() {
        let kp = test_keypair();
        let vk = kp.verifying_key_base64();
        let envelope =
            SigilEnvelope::sign("did:sigil:parent_01", Verdict::Allowed, None, &kp).unwrap();

        assert_eq!(envelope.identity, "did:sigil:parent_01");
        assert_eq!(envelope.verdict, Verdict::Allowed);
        assert!(envelope.reason.is_none());
        assert!(envelope.verify(&vk).unwrap(), "Valid signature should verify");
    }

    #[test]
    fn sign_and_verify_blocked_with_reason() {
        let kp = test_keypair();
        let vk = kp.verifying_key_base64();
        let envelope = SigilEnvelope::sign(
            "did:sigil:child_02",
            Verdict::Blocked,
            Some("Insufficient trust level".into()),
            &kp,
        )
        .unwrap();

        assert_eq!(envelope.verdict, Verdict::Blocked);
        assert_eq!(envelope.reason.as_deref(), Some("Insufficient trust level"));
        assert!(envelope.verify(&vk).unwrap());
    }

    #[test]
    fn blocked_without_reason_is_rejected() {
        let kp = test_keypair();
        let result = SigilEnvelope::sign("did:sigil:agent", Verdict::Blocked, None, &kp);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("reason MUST be present"));
    }

    #[test]
    fn tampered_identity_fails_verification() {
        let kp = test_keypair();
        let vk = kp.verifying_key_base64();
        let mut envelope =
            SigilEnvelope::sign("did:sigil:parent_01", Verdict::Allowed, None, &kp).unwrap();

        // Attacker tries to change the identity after signing
        envelope.identity = "did:sigil:attacker".to_string();

        assert!(
            !envelope.verify(&vk).unwrap(),
            "Tampered identity must fail verification"
        );
    }

    #[test]
    fn tampered_verdict_fails_verification() {
        let kp = test_keypair();
        let vk = kp.verifying_key_base64();
        let mut envelope =
            SigilEnvelope::sign("did:sigil:parent_01", Verdict::Allowed, None, &kp).unwrap();

        // Attacker tries to change allowed → blocked (unlikely, but covered)
        // Actually testing allowed → scanned
        envelope.verdict = Verdict::Scanned;

        assert!(
            !envelope.verify(&vk).unwrap(),
            "Tampered verdict must fail verification"
        );
    }

    #[test]
    fn wrong_keypair_fails_verification() {
        let kp1 = SigilKeypair::generate();
        let kp2 = SigilKeypair::generate();

        let envelope =
            SigilEnvelope::sign("did:sigil:parent_01", Verdict::Allowed, None, &kp1).unwrap();

        // Try to verify with a different keypair's public key
        let wrong_vk = kp2.verifying_key_base64();
        assert!(
            !envelope.verify(&wrong_vk).unwrap(),
            "Wrong keypair must fail verification"
        );
    }

    #[test]
    fn nonce_is_16_bytes_hex() {
        let kp = test_keypair();
        let envelope =
            SigilEnvelope::sign("did:sigil:parent_01", Verdict::Allowed, None, &kp).unwrap();
        // 16 bytes = 32 hex characters
        assert_eq!(envelope.nonce.len(), 32);
        assert!(
            envelope.nonce.chars().all(|c| c.is_ascii_hexdigit()),
            "Nonce must be hex-encoded"
        );
    }

    #[test]
    fn nonces_are_unique() {
        let kp = test_keypair();
        let e1 =
            SigilEnvelope::sign("did:sigil:parent_01", Verdict::Allowed, None, &kp).unwrap();
        let e2 =
            SigilEnvelope::sign("did:sigil:parent_01", Verdict::Allowed, None, &kp).unwrap();
        assert_ne!(e1.nonce, e2.nonce, "Each envelope must have a unique nonce");
    }

    #[test]
    fn envelope_roundtrips_json() {
        let kp = test_keypair();
        let vk = kp.verifying_key_base64();
        let original =
            SigilEnvelope::sign("did:sigil:parent_01", Verdict::Scanned, Some("PII detected".into()), &kp)
                .unwrap();

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: SigilEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.identity, original.identity);
        assert_eq!(deserialized.verdict, original.verdict);
        assert_eq!(deserialized.signature, original.signature);
        assert!(deserialized.verify(&vk).unwrap(), "Deserialized envelope must verify");
    }

    #[test]
    fn keypair_from_seed_is_deterministic() {
        let seed = [99u8; 32];
        let kp1 = SigilKeypair::from_seed(&seed);
        let kp2 = SigilKeypair::from_seed(&seed);
        assert_eq!(kp1.verifying_key_base64(), kp2.verifying_key_base64());
    }
}
