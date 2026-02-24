# PATENT — SIGIL-EURO

## DE Gebrauchsmuster — eIDAS-Compliant Digital Euro Payment Gateway

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, [Adresse eintragen]
**Priorität:** Fortführung DE Gebrauchsmuster SIGIL Protocol (2026-02-22) + SIGIL-BRIDGE-CORE (2026-02-25)
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Anmeldung eines Gebrauchsmusters — SIGIL-EURO

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster für ein computerimplementiertes Verfahren zur **eIDAS-konformen Verarbeitung, kryptografischen Signierung und revisionssicheren Protokollierung digitaler Zahlungsanweisungen** an. Die Erfindung ist auf digitale Zentralbankwährungen (CBDC) sowie auf regulierte elektronische Zahlungen in beliebigen ISO-4217-Währungen anwendbar.

Die Erfindung wurde am 2026-02-24 erfolgreich im Echtbetrieb auf einem produktiven Server demonstriert (siehe § 2.5).

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft ein computerimplementiertes Gateway-System zur Verarbeitung kryptografisch signierter, eIDAS-konformer Zahlungsanweisungen mit integrierter AML/CTF-Prüfung und dreischichtigem, tamper-evidentem Prüfprotokoll.

### 2.2 Stand der Technik

Bestehende CBDC-Architekturen (EP4181458A1, Deutsche Bundesbank; EP3850567A1 u.a.) beschreiben Ausstellungsplattformen und Identitätssysteme. Sie spezifizieren keine **signierten Zahlungsanweisungs-Primitive** auf Anwendungsebene, die eIDAS-Vertrauensstufen einbetten, Empfänger-Pseudonymisierung (SHA-256) als DSGVO-Designeigenschaft implementieren und eine dreischichtige kryptografische Prüfkette erzeugen.

Herkömmliche AML-Systeme protokollieren entweder keine Rohdaten (Datenverlust) oder speichern vollständige Transaktionsinhalte (DSGVO-Verstoß). Das SIGIL-EURO-System löst diesen Widerspruch durch rein-funktionale AML-Scanner-Schnittstellen, die ausschließlich Kategorie-Hashes in das Prüfprotokoll schreiben.

### 2.3 Offenbarung der Erfindung

**PaymentIntent-Datenstruktur:**

```rust
pub struct PaymentIntent {
    pub payment_reference: String,       // SEPA-kompatible Referenz
    pub payer_did:         Did,          // W3C-DID des Zahlers
    pub recipient_hash:    [u8; 32],     // SHA-256(Empfänger-DID) — kein Klartext
    pub amount_cents:      u64,          // Euro-Cent (kein Gleitkomma)
    pub currency:          String,       // ISO 4217
    pub consent_scope:     ConsentScope, // SinglePayment | StandingOrder
    pub trust_level:       TrustLevel,   // Low | High (eIDAS-Mapping)
    pub payload_hash:      [u8; 32],     // SHA-256(Canonical Payload)
    pub timestamp:         i64,
    pub signature:         Vec<u8>,      // Ed25519 über payload_hash‖recipient_hash‖ts‖did
    pub aml_flags:         Vec<AmlFlag>,
}
```

**Dreischichtiges Prüfprotokoll:**

```
Schicht 1: HMAC-SHA256 pro Eintrag       → Lokale Manipulationserkennung
Schicht 2: Merkle-Baum-Batch             → Batch-Integrität (stündlich)
Schicht 3: Merkle-Root auf Public-DA     → Betreiberunabhängiger Beweis
```

**Evidenz (2026-02-24):**

- Intent `SIGILEURO-20260224-512a1bcc`, €15,00, Audit Seq #15, HTTP 200 ✅
- Celestia Mocha Block 10221745, Root `0xfb19a5ff...` ✅

Das System hat worden am 2026-02-24 erfolgreich im Echtbetrieb demonstriert, was als Nachweis der Ausführbarkeit dient.

### 2.4 Anwendungsbereich

Das SIGIL-EURO-Primitive ist ohne wesentliche Protokolländerungen auf beliebige ISO-4217-Währungen (USD, GBP, CHF) sowie auf tokenisierte Wertpapiere übertragbar; lediglich die Währungsbezeichnung und die länderspezifischen regulatorischen Einschränkungen müssen angepasst werden.

### 2.5 AML-Scanner-Schnittstelle (Rein-funktionales Design)

```rust
pub trait AmlScanner: Send + Sync {
    fn scan(&self, text: &str) -> Vec<AmlFlag>;
}
```

Die Schnittstelle ist als synchrone, rein-funktionale Abbildung definiert. Die verwendeten Implementierungen führen keine Netzwerkoperationen und keine Zustandsmutation außerhalb des Rückgabewerts durch. Das Prüfprotokoll enthält ausschließlich den SHA-256-Hash des auslösenden Inhalts — nie den Inhalt selbst. Dies erfüllt Art. 5(1)(c) DSGVO (Datenminimierung) bei vollständiger AML-Rückverfolgbarkeit.

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig): Computerimplementiertes Verfahren zur Verarbeitung einer kryptografisch signierten Zahlungsanweisung, dadurch gekennzeichnet, dass es:

(a) eine Zahlungsanweisung (`PaymentIntent`) annimmt, die einen W3C-konformen dezentralen Identifikator des Zahlers, einen SHA-256-Hash des Empfänger-Identifikators, den Betrag in kleinster Währungseinheit, eine ISO-4217-Währungsbezeichnung, eine eIDAS-kompatible Vertrauensstufe, einen Ed25519-Zeitstempel sowie eine Ed25519-Signatur über einen kanonischen Hash aller vorgenannten Felder umfasst;

(b) die Ed25519-Signatur serverseitig gegen den öffentlichen Schlüssel des Zahler-DIDs verifiziert;

(c) die Zahlungsanweisung vor jedem Datenbankschreibvorgang anhand der Vertrauensstufe und des Betrags prüft;

(d) einem integrierten AML/CTF-Scanner übergibt, der als synchrone, rein-funktionale Abbildung implementiert ist und ausschließlich Kategorie-Kennungen in das Prüfprotokoll schreibt.

**Anspruch 2** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass Zahlungsanweisungen mit Vertrauensstufe `Low` über einer konfigurierbaren Schwelle (Standard: 5.000 Cent = €50,00) vor jedem Datenbankschreibvorgang abgewiesen werden, sodass keine abgelehnten Einträge in das Prüfprotokoll gelangen.

**Anspruch 3** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass das AML-Prüfsystem als rein-funktionale Schnittstelle definiert ist, welche eine Zeichenkette auf eine Liste von Markierungen abbildet, wobei das Prüfprotokoll ausschließlich den SHA-256-Hash des auslösenden Inhalts und die Markierungskategorie erfasst, niemals den Klartextinhalt, womit Art. 5(1)(c) DSGVO (Datenminimierung) als Designeigenschaft erfüllt wird.

**Anspruch 4** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass jede angenommene Zahlungsanweisung einen Eintrag in einer dreischichtigen Prüfstruktur erzeugt, bestehend aus: (a) HMAC-SHA256-Verkettung aller Einträge; (b) Merkle-Baum-Aggregation in konfigurierbaren Zeitintervallen; (c) Verankerung des Merkle-Roots in einem öffentlichen Distributed-Ledger, sodass ein Dritter ohne Vertrauen in den Betreiber die Vollständigkeit und Unverändertheit des Prüfprotokolls verifizieren kann.

**Anspruch 5** (abhängig von 4): Verfahren nach Anspruch 4, dadurch gekennzeichnet, dass der Merkle-Root in einem öffentlichen Data-Availability-Layer (Celestia, Solana oder äquivalent) verankert wird, wobei die Übertragung automatisiert über eine konfigurierbare Regelmäßigkeit (z.B. stündlich) ausgeführt wird und die Blocknummer sowie der Transaktions-Hash als maschinenlesbare Quittung im Prüfprotokoll gespeichert werden.

**Anspruch 6** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die eIDAS-Vertrauensstufe genau zwei Werte `Low` und `High` annimmt, wobei `High` einer qualifizierten elektronischen Signatur gemäß eIDAS-Verordnung (EU) Nr. 910/2014 entspricht, und das System durch Erweiterung der Vertrauensstufen-Enumeration auf weitere Regulierungsrahmen (PSD2, MiCA) adaptierbar ist.

**Anspruch 7** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass das Verfahren ohne wesentliche Protokolländerungen auf beliebige ISO-4217-Währungen, auf tokenisierte Wertpapiere mit ISIN-Bezeichner oder auf CBDC-Einheiten beliebiger Zentralbanken anwendbar ist.

**Anspruch 8** (abhängig von 4): System nach Anspruch 4, dadurch gekennzeichnet, dass die HMAC-Prüfkette und die Merkle-Batch-Daten über eine authentifizierte API-Schnittstelle für regulatorische Behörden (BaFin, EZB) exportierbar sind, einschließlich vollständiger Merkle-Inklusions-Beweise für einzelne Transaktionen.

---

## 4. Zusammenfassung (Abstract)

Ein computerimplementiertes Verfahren nimmt kryptografisch signierte, eIDAS-konforme Zahlungsanweisungen entgegen. Die Identität des Zahlers wird durch einen W3C Decentralised Identifier nachgewiesen, der Empfänger wird ausschließlich als SHA-256-Hash gespeichert (DSGVO-Designkonformität). Ein rein-funktionaler AML-Scanner prüft jede Transaktion ohne Netzwerkzugriff. Angenommene Transaktionen werden in einer dreischichtigen Prüfstruktur aus per-Eintrag-HMAC-Verkettung, Merkle-Batch-Aggregation und öffentlicher DA-Layer-Verankerung protokolliert. Das Verfahren ist ohne Protokolländerungen auf beliebige Währungen (USD, GBP, CHF) und Finanzwerte übertragbar. (≈ 100 Wörter)

---

*SIGIL-EURO Patent — 2026-02-25 — Patent Pending — EUPL-1.2*
