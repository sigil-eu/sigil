# PATENT — SIGIL CRYPTO-AGILITY

## DE Gebrauchsmuster · Algorithmusagnostische, quantensichere Signaturarchitektur für das SIGIL-Protokoll (Sovereign Identity-Gated Interaction Layer) und dessen Erweiterungen

## GBM-1 der SIGIL-Patentfamilie

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, Garmischerstrasse 46 B, 86163 Augsburg, Deutschland
**Kontakt:** <benjamin.kuettner@icloud.com> · <ben@sigil-protocol.org>
**Priorität / Stammanmeldung:** DE Gebrauchsmuster SIGIL Protocol (GBM-0), eingereicht DPMA 2026-02-23
**Gilt für:** GBM-0 (SIGIL Protocol), GBM-2 (Bridge Core), GBM-3 (EURO), GBM-4 (FXBridge), GBM-5 (ServiceBridge)
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Gebrauchsmusteranmeldung — SIGIL Crypto-Agility (GBM-1)

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster als Erweiterung des SIGIL-Protokolls (GBM-0, DPMA 2026-02-23) für eine **algorithmusagnostische, quantensichere Signatur-Upgrade-Architektur** an. Die Erfindung betrifft das gesamte SIGIL-Protokollfamilie (GBM-0 bis GBM-5) und schützt insbesondere den Mechanismus, mit dem im SIGIL-Protokoll verwendete Signaturverfahren — ohne Protokollbruch, ohne Kompatibilitätsverlust und ohne Serviceunterbrechung — auf post-quanten-sichere Algorithmen nach NIST FIPS 204/205 umgestellt werden können.

Der Quellcode-Nachweis der Offenbarung liegt im SIGIL-Protokoll-Repository vor, Commit `ca10eeb`, 2026-02-25: `sigil_envelope.rs` enthält den vollständig ausgearbeiteten Crypto-Agility-Entwurf als kommentierten Codeblock mit Zeitstempel.

Anliegend: Beschreibung, Ansprüche, Zusammenfassung.

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft ein computerimplementiertes Verfahren zum **unterbrechungsfreien, rückwärtskompatiblen Austausch kryptografischer Signaturalgorithmen** in verteilten Protokollen, insbesondere im SIGIL-Protokoll und seinen Erweiterungen, mit dem Ziel der Quantensicherheit gemäß den NIST-Post-Quantum-Kryptografiestandards FIPS 204 (ML-DSA) und FIPS 205 (SLH-DSA).

### 2.2 Bezug zum Stamm-Schutzrecht (GBM-0)

Das **SIGIL-Protokoll** (ausgesprochen: *Sovereign Identity-Gated Interaction Layer*, GBM-0, DPMA 2026-02-23) schützt einen kryptografisch signierten Identitätsumschlag (`_sigil`-Envelope) mit Ed25519-Signatur. Die Signatur ist dort als festes Verfahren definiert. Die vorliegende Erfindung (GBM-1) erweitert GBM-0 — und alle darauf aufbauenden Schutzrechte — um eine algorithmusagnostische Signaturarchitektur, die auf alle folgenden Protokollschichten anwendbar ist:

- **GBM-0 SIGIL Core:** `SigilEnvelope`, DID-Identitätsnachweis, Browser-Extension-Interception
- **GBM-2 Bridge Core:** `BridgeIntent`, HTLC-Preimage-Hash, HMAC-Audit-Chain
- **GBM-3 SIGIL-EURO:** `PaymentIntent`, eIDAS-qualifizierte Signatur, AML-Scanner-Attestation
- **GBM-4 SIGIL-FXBridge:** `MultiHopIntent`, `RouteAttestation` (Ed25519 → ML-DSA-65 Drop-in), `FxContext`-Signierung
- **GBM-5 SIGIL-ServiceBridge:** `ServiceIntent`, Arbitrator-DID-Binding, Escrow-Zustandsattestationen

Die algorithmusagnostische Architektur (GBM-1) ist auf allen genannten Schichten ohne Protokollbruch aktivierbar und erweitert das ursprüngliche Ed25519-Verfahren (GBM-0) um:

1. den eingesetzten Algorithmus als **maschinenlesbares Selbstbeschreibungsfeld** im Protokolldatensatz führt
2. einen **einheitlichen Signing-Trait** (Interface) definiert, hinter dem beliebige Signaturalgorithmen als auswechselbare Implementierungen fungieren
3. **hybrides Signing** ermöglicht: Ed25519 für latenzkritische Live-Protokolleinträge, ML-DSA für langlebige Archiveinträge und regulatorische Prüfdokumente
4. die Migration **ohne Protokollbruch** durchführbar macht: bestehende Ed25519-Datensätze bleiben dauerhaft valide

### 2.3 Problemstellung — Quantenbedrohung

Ed25519 basiert auf elliptischer-Kurven-Kryptografie. Shor's Algorithmus auf einem kryptografisch relevanten Quantencomputer (CRQC) mit ≥ 4.000 fehlerkorrigierten logischen Qubits kann den privaten Schlüssel aus dem öffentlichen Schlüssel in polynomialer Zeit ableiten. Aktuelle Risikoschätzungen (ETSI, BSI TR-02102) gehen von einer CRQC-Bedrohung im Zeitraum 2030–2035 aus.

NIST hat 2024 drei quantensichere Signaturstandards finalisiert:

- **NIST FIPS 204**: ML-DSA (Module-Lattice Digital Signature Algorithm, früher CRYSTALS-Dilithium)
- **NIST FIPS 205**: SLH-DSA (Stateless Hash-based Signature Algorithm, früher SPHINCS+)
- **NIST FIPS 206**: ML-KEM (für Schlüsselaustausch, für Signaturen nicht direkt relevant)

### 2.4 Stand der Technik und Abgrenzung

Bestehende Protokolle (TLS 1.3, Signal Protocol, PGP, SWIFT MX ISO 20022) verwenden feste Algorithmuskonfigurationen oder verhandeln Algorithmen über externe Handshakes (Cipher Suites). Keines dieser Systeme implementiert:

1. Ein **eingebettetes Selbstbeschreibungsfeld** im Datensatz, das den Algorithmus pro Eintrag individuell festlegt
2. Einen **einheitlichen Signing-Trait**, der sowohl klassische als auch PQ-Algorithmen hinter derselben Schnittstelle kapselt
3. **Hybrides Signing** mit algorithmisch unterschiedlichen Einträgen innerhalb desselben Protokollstroms
4. **DA-Layer-Agnostizismus in Kombination mit PQ-Signing:** `DaProof`-Datensätze tragen den `da_provider`-Bezeichner und den `algorithm`-Bezeichner als unabhängige Selbstbeschreibungsfelder — das System ist damit sowohl DA-Layer-agnostisch (Celestia, Avail, EigenDA) als auch algorithmusagnostisch (Ed25519, ML-DSA, SLH-DSA) ohne externe Konfiguration
5. **Protokollübergreifende Kryptoagilität**: Dieselbe `SigilSigner`-Schnittstelle signiert `BridgeIntent`, `PaymentIntent`, `RouteAttestation`, `ServiceIntent` und DA-Anchoring-Beweise — ein Algorithmustausch wirkt gleichzeitig auf alle 5 Protokollebenen

### 2.5 Offenbarung der Erfindung

**Schritt 1: Algorithmus-Selbstbeschreibung**

Jeder signierte Protokolldatensatz im SIGIL-System enthält ein `algorithm`-Feld mit einem maschinenlesbaren Algorithmus-Identifikator. Dies gilt für alle fünf Protokollebenen:

- **GBM-0/GBM-2:** `SigilEnvelope.algorithm`, `BridgeIntent.algorithm`
- **GBM-3:** `PaymentIntent.algorithm`, `AmlAttestation.algorithm`
- **GBM-4:** `RouteAttestation.algorithm`, `FxContext.algorithm`
- **GBM-5:** `ServiceIntent.algorithm`, `ArbitrationRecord.algorithm`
- **DA-Layer:** `DaProof.algorithm` (unabhängig von `DaProof.da_provider`)

Aktuell definierte Algorithmus-Identifikatoren:

| Wert | Standard | Quantensicher | Signaturegröße | Schlüsselgröße | Empfohlen für |
|---|---|---|---|---|---|
| `Ed25519` | RFC 8032 | ❌ CRQC-angreifbar | 64 Byte | 32 Byte | Live-Transaktionen (< 10 ms) |
| `MlDsa65` | NIST FIPS 204 | ✅ NIST Level 3 | 3.293 Byte | 1.952 Byte | Regulatorische Archiveinträge |
| `SlhDsaSha2128s` | NIST FIPS 205 | ✅ Hash-basiert | 7.856 Byte | 32 Byte | Höchste Konservativität |
| `MlKem768` | NIST FIPS 206 | ✅ (Schlüsselaustausch) | n.a. | 1.184 Byte | Future: PQ Key Encapsulation |

Der Verifier liest das `algorithm`-Feld und wählt den Verifizierungspfad **ohne externe Konfiguration, ohne Versionsnummer, ohne Handshake**.

**Schritt 2: Einheitlicher Signing-Trait**

```
SigilSigner:
  algorithm()           → AlgorithmId
  sign_bytes(msg)       → Bytes
  verifying_key_bytes() → Bytes
```

Jeder Signaturalgorithmus implementiert dieselbe Schnittstelle. Der Algorithmuswechsel ist ein **Drop-in-Ersatz** — keine Änderung der aufrufenden Protokolllogik erforderlich.

**Schritt 3: Hybrides Signing — Performance-Optimierung**

Angesichts der stark unterschiedlichen Signaturgrößen (64 Byte vs. 3.293 Byte) sieht die Erfindung eine **selektive Algorithmuszuweisung** vor:

- **Ed25519**: für Einträge mit Latenzanforderungen < 10 ms (Live-Protokolleinträge, Echtzeittransaktionen)
- **ML-DSA-65**: für Einträge mit langfristiger Beweissicherungspflicht (regulatorische Prüfdokumente, Archiveinträge, Merkle-Root-Verankerungen)
- **SLH-DSA**: für höchste konservative Sicherheitsanforderungen und Hash-basierte Unabhängigkeit

Beide Algorithmustypen koexistieren **im selben Protokollstrom** — ein Verifier prüft jeden Eintrag anhand seines eigenen `algorithm`-Felds.

**Schritt 4: Rückwärtskompatible Migration**

Die Migration erfolgt schrittweise:

1. Neue Agenten erhalten ML-DSA-Schlüsselpaare und erzeugen ML-DSA-Einträge
2. Alte Agenten erzeugen weiterhin Ed25519-Einträge — **keine Änderung erforderlich**
3. Verifier prüfen anhand des `algorithm`-Felds — verarbeiten beide Algorithmen korrekt
4. Nach Ablauf der Übergangsperiode (empfohlen: 24 Monate) werden Ed25519-Einträge im Prüfprotokoll als `legacy` markiert aber nicht abgelehnt

**Quellcode-Nachweis:**

Der vollständige Entwurf ist als dokumentierter Codeblock mit Zeitstempel in `sigil_envelope.rs` des SIGIL-Protokoll-Repositories archiviert (Commit `ca10eeb`, 2026-02-25). Alle 6 Implementierungsschritte (Algorithmus-Enum, agiler Envelope, Signing-Trait, Ed25519-Adapter, ML-DSA-Adapter, generischer Dispatcher) sind dort ausgearbeitet.

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig — Plattformanspruch Kryptoagilität): Computerimplementiertes Verfahren zur algorithmusagnostischen Signierung und Verifizierung von Protokolldatensätzen des **SIGIL-Protokolls (Sovereign Identity-Gated Interaction Layer**, GBM-0, DPMA 2026-02-23) und dessen Erweiterungen (GBM-2 bis GBM-5), dadurch gekennzeichnet, dass:

(a) jeder signierte Protokolldatensatz ein maschinenlesbares Algorithmus-Identifikationsfeld enthält, das den verwendeten Signaturalgorithmus eindeutig benennt;

(b) der Verifier anhand dieses Feldes ohne externe Konfiguration, ohne Versionsnummer und ohne Protokollhandshake den korrekten Verifizierungsalgorithmus auswählt;

(c) der Signaturmechanismus hinter einem einheitlichen Interface implementiert ist, sodass der Austausch des Algorithmus keinen Einfluss auf die aufrufende Protokolllogik hat;

(d) bestehende Protokolldatensätze mit vorherigen Algorithmen dauerhaft valide bleiben, wenn der eingesetzte Algorithmus für neue Datensätze gewechselt wird.

**Anspruch 2** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Algorithmus `ML-DSA-65` gemäß NIST FIPS 204 (Module-Lattice Digital Signature Algorithm, Sicherheitsstufe 3) als erster quantensicherer Signaturalgorithmus im `algorithm`-Feld verwendbar ist, mit einem 1.952-Byte-öffentlichen Schlüssel und einer 3.293-Byte-Signatur, die durch Gitterstruktur-Mathematik gegen Angriffe eines kryptografisch relevanten Quantencomputers abgesichert ist.

**Anspruch 3** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Algorithmus `SLH-DSA-SHA2-128s` gemäß NIST FIPS 205 (Stateless Hash-Based Signature Algorithm) als zweiter quantensicherer Signaturalgorithmus verwendbar ist, dessen Sicherheitsannahmen ausschließlich auf Hash-Funktionen basieren und damit unabhängig von agebröckelten Gitter- oder Faktorisierungsannahmen sind.

**Anspruch 4** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass innerhalb desselben Protokollstroms verschiedene Einträge unterschiedliche Signaturalgorithmen verwenden können (**hybrides Signing**), insbesondere:

- latenzkritische Einträge (Live-Transaktionen, Echtzeit-Protokolleinträge) mit einem klassischen Algorithmus geringer Signaturegröße (`Ed25519`, 64 Byte)
- langlebige Einträge mit regulatorischer Beweissicherungspflicht (Prüfprotokoll-Archiveinträge, Merkle-Root-Verankerungen) mit einem quantensicheren Algorithmus (`MlDsa65`, 3.293 Byte oder `SlhDsaSha2128s`, 7.856 Byte)

wobei ein Verifier jeden Eintrag anhand seines eigenen `algorithm`-Feldes unabhängig korrekt prüft.

**Anspruch 5** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die Migration von einem klassischen zu einem quantensicheren Algorithmus schrittweise und ohne Serviceunterbrechung durchführbar ist, indem neue Signierstellen den quantensicheren Algorithmus verwenden, ältere Signierstellen ohne Konfigurationsänderung klassische Algorithmen verwenden, und alle Verifier beide Algorithmen gleichzeitig korrekt verarbeiten.

**Anspruch 6** (abhängig von 4): Verfahren nach Anspruch 4, dadurch gekennzeichnet, dass die algorithmische Selektion anhand maschinenlesbarer Latenzschwellen oder Archivkennzeichnungen automatisiert erfolgt, ohne dass der Nutzer der Signierschnittstelle den Algorithmus manuell auswählen muss.

**Anspruch 7** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass das Verfahren auf alle Protokolldatensätze der SIGIL-Patentfamilie anwendbar ist:

- GBM-0: `SigilEnvelope` (Sovereign Identity-Gated Interaction Layer Identitätsumschlag)
- GBM-2: `BridgeIntent` (HTLC-Transferprimitive, Asset-agnostisch über 7 Anlageklassen)
- GBM-3: `PaymentIntent` und `AmlAttestation` (eIDAS-konforme Zahlungsanweisung)
- GBM-4: `MultiHopIntent`, `RouteAttestation` und `FxContext` (Devisenübertragung mit kryptografisch attestion Routing-Entscheidung)
- GBM-5: `ServiceIntent` und `ArbitrationRecord` (Dienst-Escrow mit vorbestimmtem DID-Schlichter)
- DA-Layer: `DaProof` (DA-Layer-agnostischer Blockchain-Anker, `da_provider`-Feld unabhängig von `algorithm`-Feld)

ohne dass eine der genannten Datenstrukturen verändert werden muss; der Algorithmustausch ist durch Drop-in-Ersatz der `SigilSigner`-Implementierung möglich.

**Anspruch 8** (abhängig von 1, neu): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass Protokolldatensätze aus verschiedenen Protokollebenen (GBM-0 bis GBM-5) unterschiedliche Signaturalgorithmen tragen können und ein Verifier die korrekte Prüfmethode für jeden Datensatz anhand dessen eigenem `algorithm`-Feld bestimmt, sodass in einem systemweiten Protokollfluss gleichzeitig klassische (Ed25519) und post-quanten-sichere (ML-DSA-65, SLH-DSA) Datensätze koexistieren, ohne dass der Verifier für jeden Datensatztyp gesondert konfiguriert werden muss.

---

## 4. Zusammenfassung (Abstract)

Das Verfahren erweitert das **SIGIL-Protokoll (Sovereign Identity-Gated Interaction Layer**, GBM-0, DPMA 2026-02-23) und alle darauf aufbauenden Schutzrechte (GBM-2–GBM-5) um eine algorithmusagnostische Signatur-Upgrade-Architektur. Jeder Protokolldatensatz — auf allen fünf Protokollebenen sowie im DA-Layer-Anker — trägt ein maschinenlesbares Algorithmus-Identifikationsfeld; der Verifier wählt ohne externe Konfiguration, ohne Protokollhandshake und ohne Versionsnummer den korrekten Prüfalgorithmus. Ein einheitliches `SigilSigner`-Interface kapselt klassische (Ed25519, RFC 8032), gitterbasierte (ML-DSA nach NIST FIPS 204) und Hash-basierte post-quanten-sichere Verfahren (SLH-DSA nach NIST FIPS 205) hinter derselben Schnittstelle. Hybrides Signing ermöglicht Ed25519 für latenzkritische Live-Transaktionen (< 10 ms) und ML-DSA-65 für regulatorische Archiveinträge und `DaProof`-Verankerungen im selben Protokollstrom. Die Migration ist schrittweise, rückwärtskompatibel und ohne Serviceunterbrechung durchführbar. Das Verfahren ist DA-Layer-agnostisch (Celestia, Avail, EigenDA) und protokollübergreifend. Das SIGIL-Protokoll und seine Infrastruktur werden Zentralbanken, Privatpersonen und gemeinnützigen Organisationen dauerhaft kostenlos zur Verfügung gestellt; Einnahmen werden ausschließlich von kommerziellen Finanzintermediären erzielt. (≈ 155 Wörter)

---

## 5. Normen und Standards

| Standard | Relevanz für GBM-1 |
|---|---|
| NIST FIPS 204 (2024) | ML-DSA — Modul-Gitter-basiertes digitales Signaturverfahren (primäre PQ-Migration) |
| NIST FIPS 205 (2024) | SLH-DSA — Zustandsloses Hash-basiertes Signaturverfahren (konservative Fallback-Option) |
| NIST FIPS 206 (2024) | ML-KEM — Schlüsselkapselung (zukünftige Erweiterung für verschlüsselte Kanaleinrichtung) |
| BSI TR-02102-1 (2025) | Empfehlungen für kryptografische Verfahren — ML-DSA als Empfehlung ab 2025 |
| ETSI TS 119 312 v1.4 | PQC-Übergangsempfehlungen für qualifizierte elektronische Signaturen (eIDAS 2.0) |
| eIDAS 2.0 (EU 2024/1183) | Anforderungen an qualifizierte elektronische Signaturen — Kryptoagilität explizit gefordert |
| W3C DID v1.0 | Decentralized Identifier — Basis der SIGIL-Identitätsschicht in GBM-0–5 |
| RFC 8032 (Ed25519) | Aktuell genutztes Signaturverfahren — Migration via GBM-1 vorgesehen |

---

*SIGIL CRYPTO-AGILITY · GBM-1 der SIGIL-Patentfamilie (Sovereign Identity-Gated Interaction Layer) · Erweiterung von GBM-0 · Anmeldedatum 2026-02-25 · Patent Pending · EUPL-1.2*
*Benjamin Küttner · Garmischerstrasse 46 B · 86163 Augsburg, Deutschland · <benjamin.kuettner@icloud.com> · <ben@sigil-protocol.org>*
