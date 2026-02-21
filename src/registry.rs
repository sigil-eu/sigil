//! Remote pattern fetching from the SIGIL community registry.
//!
//! Enabled with `cargo add sigil-protocol --features registry`.
//!
//! This module provides [`RemoteScanner`], a [`SensitivityScanner`] implementation
//! that automatically downloads the latest community-curated patterns from
//! `registry.sigil-protocol.org/patterns/bundle` at startup, and falls back to
//! a set of hardcoded built-in patterns if the registry is unreachable.
//!
//! ## Usage
//!
//! ```rust,no_run
//! # #[cfg(feature = "registry")]
//! # async fn example() -> anyhow::Result<()> {
//! use sigil_protocol::registry::RemoteScanner;
//! use sigil_protocol::SensitivityScanner;
//!
//! // Downloads latest verified community patterns at startup
//! let scanner = RemoteScanner::from_registry().await?;
//!
//! // Use it anywhere a SensitivityScanner is needed
//! if let Some(hit) = scanner.scan("aws sk-ant-api03-...") {
//!     println!("Sensitive content detected: {hit}");
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Offline / custom registry
//!
//! ```rust,no_run
//! # #[cfg(feature = "registry")]
//! # async fn example() -> anyhow::Result<()> {
//! use sigil_protocol::registry::RemoteScanner;
//!
//! // Use a self-hosted registry or a local test server
//! let scanner = RemoteScanner::from_url("http://localhost:3100/patterns/bundle").await?;
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "registry")]
pub use remote::RemoteScanner;

#[cfg(feature = "registry")]
mod remote {
    use crate::scanner::SensitivityScanner;
    use regex::Regex;
    use serde::Deserialize;

    /// The SIGIL public registry bundle endpoint.
    const REGISTRY_BUNDLE_URL: &str =
        "https://registry.sigil-protocol.org/patterns/bundle";

    /// A compiled scanner pattern entry from the registry bundle.
    #[derive(Debug, Deserialize)]
    struct BundleEntry {
        name: String,
        category: String,
        pattern: String,
        severity: String,
        replacement_hint: Option<String>,
    }

    /// The registry bundle response envelope.
    #[derive(Debug, Deserialize)]
    struct Bundle {
        count: usize,
        patterns: Vec<BundleEntry>,
    }

    /// A compiled regex rule ready for scanning.
    #[allow(dead_code)]
    struct CompiledRule {
        name: String,
        category: String,
        severity: String,
        replacement_hint: Option<String>,
        regex: Regex,
    }

    /// A [`SensitivityScanner`] backed by community patterns from the SIGIL registry.
    ///
    /// Fetches the latest verified patterns from `registry.sigil-protocol.org` at
    /// construction time, compiles them, and uses them for all subsequent scans.
    ///
    /// Falls back to built-in hardcoded patterns if the registry is unreachable.
    pub struct RemoteScanner {
        rules: Vec<CompiledRule>,
        source: ScannerSource,
    }

    /// Where the scanner patterns came from.
    #[derive(Debug, Clone, PartialEq)]
    pub enum ScannerSource {
        /// Downloaded from a SIGIL registry instance.
        Registry { url: String, count: usize },
        /// Using built-in fallback patterns (registry was unreachable).
        Fallback { count: usize },
    }

    impl RemoteScanner {
        /// Create a scanner by fetching patterns from the public SIGIL registry.
        ///
        /// Falls back to built-in patterns if the registry is unreachable.
        pub async fn from_registry() -> anyhow::Result<Self> {
            Self::from_url(REGISTRY_BUNDLE_URL).await
        }

        /// Create a scanner by fetching patterns from a custom registry URL.
        ///
        /// Useful for self-hosted registries or offline testing.
        pub async fn from_url(url: &str) -> anyhow::Result<Self> {
            match Self::fetch_and_compile(url).await {
                Ok(scanner) => {
                    tracing::info!(
                        "SIGIL scanner loaded {} patterns from registry: {}",
                        scanner.rules.len(),
                        url
                    );
                    Ok(scanner)
                }
                Err(e) => {
                    tracing::warn!(
                        "SIGIL registry unreachable ({}): {} — falling back to built-in patterns",
                        url,
                        e
                    );
                    Ok(Self::with_fallback())
                }
            }
        }

        /// Return the source of the loaded patterns (for observability).
        pub fn source(&self) -> &ScannerSource {
            &self.source
        }

        /// Return the number of loaded rules.
        pub fn rule_count(&self) -> usize {
            self.rules.len()
        }

        // ── Internal helpers ─────────────────────────────────────────────────

        async fn fetch_and_compile(url: &str) -> anyhow::Result<Self> {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .user_agent(concat!(
                    "sigil-protocol/",
                    env!("CARGO_PKG_VERSION"),
                    " (+https://sigil-protocol.org)"
                ))
                .build()?;

            let bundle: Bundle = client.get(url).send().await?.error_for_status()?.json().await?;

            let count = bundle.count;
            let rules = compile_patterns(bundle.patterns);

            Ok(Self {
                rules,
                source: ScannerSource::Registry {
                    url: url.to_string(),
                    count,
                },
            })
        }

        fn with_fallback() -> Self {
            let entries = builtin_patterns();
            let count = entries.len();
            let rules = compile_patterns(entries);
            Self {
                rules,
                source: ScannerSource::Fallback { count },
            }
        }
    }

    impl SensitivityScanner for RemoteScanner {
        fn scan(&self, text: &str) -> Option<String> {
            for rule in &self.rules {
                if rule.regex.is_match(text) {
                    // Return hint if available, otherwise a descriptive label
                    let label = rule
                        .replacement_hint
                        .clone()
                        .unwrap_or_else(|| format!("[SIGIL: {} ({})]", rule.name, rule.severity));
                    return Some(label);
                }
            }
            None
        }
    }

    fn compile_patterns(entries: Vec<BundleEntry>) -> Vec<CompiledRule> {
        entries
            .into_iter()
            .filter_map(|e| {
                match Regex::new(&e.pattern) {
                    Ok(regex) => Some(CompiledRule {
                        name: e.name,
                        category: e.category,
                        severity: e.severity,
                        replacement_hint: e.replacement_hint,
                        regex,
                    }),
                    Err(err) => {
                        tracing::warn!(
                            "SIGIL registry: skipping pattern '{}' — invalid regex: {}",
                            e.name,
                            err
                        );
                        None
                    }
                }
            })
            .collect()
    }

    /// Hardcoded built-in patterns used when the registry is unreachable.
    /// These mirror the official seed data in migration 0003.
    fn builtin_patterns() -> Vec<BundleEntry> {
        vec![
            BundleEntry {
                name: "aws_access_key_id".into(),
                category: "credential".into(),
                pattern: "(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}".into(),
                severity: "critical".into(),
                replacement_hint: Some("[SIGIL-VAULT: AWS_KEY_ID]".into()),
            },
            BundleEntry {
                name: "openai_api_key_generic".into(),
                category: "credential".into(),
                pattern: r"sk-[a-zA-Z0-9\-_]{40,}".into(),
                severity: "high".into(),
                replacement_hint: Some("[SIGIL-VAULT: OPENAI_KEY]".into()),
            },
            BundleEntry {
                name: "anthropic_api_key".into(),
                category: "credential".into(),
                pattern: r"sk-ant-[a-zA-Z0-9\-_]{40,}".into(),
                severity: "critical".into(),
                replacement_hint: Some("[SIGIL-VAULT: ANTHROPIC_KEY]".into()),
            },
            BundleEntry {
                name: "github_personal_access_token".into(),
                category: "credential".into(),
                pattern: r"gh[pousr]_[0-9a-zA-Z]{36,255}".into(),
                severity: "critical".into(),
                replacement_hint: Some("[SIGIL-VAULT: GITHUB_TOKEN]".into()),
            },
            BundleEntry {
                name: "private_key_pem".into(),
                category: "secret".into(),
                pattern: r"-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----".into(),
                severity: "critical".into(),
                replacement_hint: Some("[SIGIL-VAULT: PRIVATE_KEY]".into()),
            },
            BundleEntry {
                name: "jwt_token".into(),
                category: "credential".into(),
                pattern: r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}".into(),
                severity: "high".into(),
                replacement_hint: Some("[SIGIL-VAULT: JWT]".into()),
            },
            BundleEntry {
                name: "eu_iban".into(),
                category: "financial".into(),
                pattern: r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]{0,16})\b".into(),
                severity: "critical".into(),
                replacement_hint: Some("[SIGIL-VAULT: IBAN]".into()),
            },
            BundleEntry {
                name: "database_connection_url".into(),
                category: "secret".into(),
                pattern: r"(?i)(postgres|mysql|mongodb|redis|mssql)://[^:]+:[^@]+@[a-zA-Z0-9.\-]+(:[0-9]+)?/[a-zA-Z0-9_\-]+".into(),
                severity: "critical".into(),
                replacement_hint: Some("[SIGIL-VAULT: DB_URL]".into()),
            },
        ]
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::scanner::SensitivityScanner;

        fn fallback_scanner() -> RemoteScanner {
            RemoteScanner::with_fallback()
        }

        #[test]
        fn detects_aws_key() {
            let s = fallback_scanner();
            assert!(s
                .scan("key=AKIAIOSFODNN7EXAMPLE")
                .is_some());
        }

        #[test]
        fn detects_openai_key() {
            let s = fallback_scanner();
            let key = format!("sk-{}", "a".repeat(48));
            assert!(s.scan(&key).is_some());
        }

        #[test]
        fn detects_jwt() {
            let s = fallback_scanner();
            assert!(s
                .scan("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
                .is_some());
        }

        #[test]
        fn detects_iban() {
            let s = fallback_scanner();
            assert!(s.scan("Account: DE89370400440532013000").is_some());
        }

        #[test]
        fn passes_safe_text() {
            let s = fallback_scanner();
            assert!(s.scan("Hello, world! This is totally safe content.").is_none());
        }

        #[test]
        fn fallback_source_reported() {
            let s = fallback_scanner();
            assert!(matches!(s.source(), ScannerSource::Fallback { .. }));
        }
    }
}
