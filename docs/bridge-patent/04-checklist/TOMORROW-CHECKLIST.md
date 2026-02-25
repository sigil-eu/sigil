# MORGEN-CHECKLIST — SIGIL Bridge Patent Suite

## Stand: 2026-02-25 | Erstellung: 2026-02-25 00:30 Uhr

---

## 1. Sofortmaßnahmen (Heute/Morgen früh)

### 1.1 Patent-Anmeldung DPMA — 4 Umschläge fertig stellen

- [ ] PATENT-BRIDGE-CORE.md ausdrucken, Adresse eintragen, unterschreiben
- [ ] PATENT-SIGIL-EURO.md ausdrucken, Adresse eintragen, unterschreiben
- [ ] PATENT-SIGIL-FXBRIDGE.md ausdrucken, Adresse eintragen, unterschreiben
- [ ] PATENT-SIGIL-SERVICEBRIDGE.md ausdrucken, Adresse eintragen, unterschreiben
- [ ] 4 × €40 = **€160 Banküberweisung** an Bundeskasse Halle vorbereiten
  - IBAN: `DE84 8600 0000 0086 0010 30`
  - BIC: `MARKDEF1860`
  - Verwendungszweck: jeweils Name + Aktenzeichen (wird nach Eingang mitgeteilt)
- [ ] Alle 4 Umschläge **Einschreiben mit Rückschein** aufgeben
  - **An:** Deutsches Patent- und Markenamt, 80297 München

> [!IMPORTANT]
> Prioritätsdatum ist der Tagesstempel der Post. Das DPMA-Aktenzeichen kommt ca. 4 Wochen nach Eingang. Du musst nichts beibringen — der Eingang beim Amt genügt.

---

### 1.2 ServiceBridge — End-to-End Lebenszyklustest

- [ ] Testdaten für `ServiceIntent` generieren (analog zur FXBridge — Python-Skript oder Rust-Bin)
- [ ] `POST /service/api/intent/submit` → HTTP 200 bestätigen
- [ ] `POST /service/api/intent/:id/deliver` → Zustandswechsel Delivered bestätigen
- [ ] `POST /service/api/intent/:id/dispute` → Zustandswechsel Disputed bestätigen
- [ ] `POST /service/api/intent/:id/arbitrate` → Settled oder Refunded bestätigen
- [ ] Logs auf VPS prüfen: `journalctl -u sigil-servicebridge -n 50`

---

## 2. Diese Woche (Prä-EPO Hardening)

### 2.1 FXBridge — RouteAttestation Signierung implementieren

- [ ] `RouteAttestation.proof_bytes` mit Ed25519-Signatur des Routing-Service füllen
- [ ] Signierung über kanonisches JSON der Attestation implementieren
- [ ] Unit-Test: Attestation verifizieren gegen bekannten Public Key
- [ ] Code committen + VPS deployen

### 2.2 AML-Scanner Beschreibung präzisieren

- [ ] Formalen Kommentar in `AmlScanner` Trait-Definition einfügen:

  ```rust
  /// # Formal purity guarantee
  /// This interface is defined as a synchronous, purely-functional mapping.
  /// Conforming implementations MUST NOT perform network I/O, state mutation,
  /// or asynchronous operations. This makes formal verification tractable.
  ```

- [ ] Code committen + VPS deployen

### 2.3 SIGIL-Registry — Token Rotation & Revocation

- [ ] `/registry/revoke/:did` Endpunkt implementieren (SIGIL-REGISTRY)
- [ ] Revoked-DID-Check im SIGIL-EURO Gateway (Intent ablehnen wenn DID revoked)
- [ ] Doku aktualisieren

---

## 3. Nächste 2 Wochen (Post-Filing Korrekturen)

### 3.1 Auf DPMA-Mängelrüge antworten

- [ ] DPMA-Rückmeldung zum SIGIL Protocol Gebrauchsmuster (2026-02-23) beobachten
- [ ] Falls Mängelrüge zu Claims 8a/8b/8c: Renumerierung einreichen (Frist ~2 Monate)
- [ ] Für die 4 neuen Bridge-Patente: Claims sind korrekt nummeriert (keine Rüge erwartet)

### 3.2 Browser Extension & SDK finalisieren

- [ ] `sigil-ts` SDK: `FXBridgeClient` und `ServiceBridgeClient` Klassen ergänzen
- [ ] Chrome Browser Extension: Live-Endpunkte für alle Gateways konfigurieren
- [ ] Smoke-Test: Browser Extension → SIGIL-EURO Gateway → HTTP 200

---

## 4. EPO/PCT Vorbereitung (bis Feb 2027)

> [!NOTE]
> EPO/PCT-Deadline: 2027-02-25 (12 Monate ab heutigem Prioritätsdatum der Bridge-Patente)

- [ ] Alle GitHub Commit-Log-Seiten als timestampte PDF drucken
- [ ] WHOIS-Einträge für `sigil-protocol.org` und `mymolt.org` archivieren (web.archive.org)
- [ ] ARM Cloud Benchmarks: HTLC throughput auf Hetzner/Graviton
- [ ] `RouteAttestation.proof_bytes` vollständig implementiert und getestet
- [ ] Coq/Lean-Spezifikation für AML-Scanner-Reinheitsbeweis vorbereiten (optional)

---

## 5. Launch-Vorbereitung

- [ ] Entscheiden: Wann werden `sigil-eu` GitHub-Repos mit der Bridge-Dokumentation öffentlich?
- [ ] Whitepaper BRIDGE-TECHNICAL-OVERVIEW.md auf `sigil-protocol.org` veröffentlichen
- [ ] Celestia Mainnet statt Mocha-Testnet konfigurieren (für Produktionsbetrieb)
- [ ] Nginx IP-Whitelist für Launch erweitern (oder auf Key-only + Rate-Limiting umstellen)

---

*MORGEN-CHECKLIST SIGIL Bridge — erstellt: 2026-02-25 — Antigravity AI*
