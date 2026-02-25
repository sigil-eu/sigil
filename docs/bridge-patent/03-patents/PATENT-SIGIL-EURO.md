# PATENT — SIGIL-EURO

## DE Gebrauchsmuster · Offenes, eIDAS-konformes Zahlungsprotokoll für alle Teilnehmerklassen

## GBM-3 der SIGIL-Patentfamilie

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, Garmischerstrasse 46 B, 86163 Augsburg
**Priorität / Stammanmeldungen:**

- GBM-0: DE Gebrauchsmuster SIGIL Protocol, eingereicht DPMA 2026-02-23
- GBM-1: DE Gebrauchsmuster SIGIL Crypto-Agility, eingereicht 2026-02-25 (gleichzeitig)
- GBM-2: DE Gebrauchsmuster SIGIL-Bridge-Core, eingereicht 2026-02-25 (gleichzeitig)
**EPO-Frist:** 2027-02-23
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Gebrauchsmusteranmeldung — SIGIL-EURO (GBM-3)

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster für ein computerimplementiertes, vollständig offenes Zahlungsprotokoll an, das auf dem SIGIL-Protokoll (GBM-0) und dem SIGIL-Bridge-Core (GBM-2) aufbaut. Das Protokoll ist bewusst für **alle Klassen von Zahlungsmarktteilnehmern** konzipiert: Zentralbanken als CBDC-Aussteller, Geschäftsbanken und Sparkassen, Broker und Payment Service Provider, Unternehmen, sowie Privatpersonen. Es integriert sich vollständig in bestehende Zahlungsinfrastrukturen (SEPA, SWIFT, T2, ISO 20022) und erweitert diese um kryptografische Nicht-Repudierbarkeit, eIDAS-konforme Identitätsbindung, DSGVO-konforme Empfänger-Pseudonymisierung und dreischichtiges regulatorisch verwertbares Prüfprotokoll.

Die Erfindung wurde am 2026-02-24 im Echtbetrieb demonstriert: Audit Sequence #15, Betrag €15,00, Merkle-Root verankert in öffentlichem DA-Layer.

Anliegend: Beschreibung, Ansprüche, Zusammenfassung.

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft ein computerimplementiertes Zahlungsprotokoll für kryptografisch signierte, eIDAS-konforme Zahlungsanweisungen mit:

- integrierter AML/CTF-Prüfung durch rein-funktionale Scanschnittstelle
- DSGVO-konformer Empfänger-Pseudonymisierung als Designeigenschaft
- dreischichtigem tamper-evidentem Prüfprotokoll
- offener Teilnahme für alle Klassen von Zahlungsmarktteilnehmern

Aufgebaut auf GBM-0 (Identitäts- und Prüfprotokollrahmen), GBM-1 (Kryptoagilität) und GBM-2 (Transfer-Intent-Primitiv).

### 2.2 Offenheit des Systems — Alle Teilnehmerklassen

Das Protokoll diskriminiert nicht nach Teilnehmerklasse. Jede Partei, die einen W3C-DID-konformen Identifikator vorlegt und den erforderlichen eIDAS-Vertrauensstufenanforderungen entspricht, kann als Zahler oder Empfänger teilnehmen:

| Teilnehmerklasse | Typische eIDAS-Vertrauensstufe | Beispiel-Anwendungsfall |
|---|---|---|
| Zentralbanken | Hoch (qualifiziert) | CBDC-Ausgabe und -Rücknahme |
| Geschäftsbanken und Sparkassen | Hoch (qualifiziert) | Interbanken-Settlement, Kundenüberweisungen |
| Payment Service Provider (Broker) | Hoch oder Substantiell | Zahlungsabwicklung im Auftrag |
| Unternehmen (juristische Personen) | Substantiell oder Hoch | B2B-Zahlungen, Lieferketten |
| Privatpersonen (natürliche Personen) | Niedrig bis Hoch (je Betragsschwelle) | Endnutzer-Zahlungen |
| KI-Agenten (im Kontext von GBM-0) | Delegiert aus übergeordnetem DID | Autonome Zahlungsausführung |

Die Vertrauensstufe ist ein enumerierbares, maschinenlesbares Feld im Zahlungsvertrag — kein Konfigurationsparameter außerhalb des Protokolls.

### 2.3 Kompatibilität mit bestehenden Währungssystemen

Das Protokoll ist komplementär zu bestehenden Zahlungsinfrastrukturen, nicht konkurrierend:

- **ISO 20022 / SWIFT**: Zahlungsanweisungen können in ISO-20022-Nachrichten eingebettet oder aus diesen generiert werden; jede Transaktion kann mit einer ISO-20022-Transaktion-ID referenziert werden.
- **SEPA Credit Transfer / Instant**: Kompatibel als ergänzende kryptografische Signaturschicht über SEPA-Zahlungen.
- **T2 / TARGET (EZB)**: CBDC-Interbankentransfers auf dem SIGIL-Protokoll nutzen dieselbe Teilnehmer-ID-Infrastruktur wie T2-RTGS-Konten.
- **PSD2 / Open Banking**: Das DID-System des SIGIL-Protokolls kann als Open-Banking-API-Authentifizierungsschicht fungieren, ohne eigene Kontoverwaltung vorzuhalten.
- **MiCA (Markets in Crypto-Assets)**: Tokenisierte Währungsrepräsentationen sind als Asset-Typ in GBM-2 abdeckbar; das Auditsystem erfüllt die RTS-Anforderungen für Crypto-Asset-Dienstleister.

Das Protokoll setzt keine bestehende Infrastruktur außer Dienst, sondern fügt eine standardisierte kryptografische Attestationsschicht hinzu.

### 2.4 Bezug zu den Stamm-Schutzrechten

**GBM-0**: Identitätsinfrastruktur (W3C-DID, Ed25519-Signatur), HMAC-Prüfkette (hier Schicht 1 des 3-Schicht-Audits), rein-funktionale Scanschnittstelle.
**GBM-1**: Kryptoagilität — der Zahlungsvertrag erbt automatisch den Quantensicher-Upgrade-Pfad.
**GBM-2**: Transfer-Intent-Primitiv — die Zahlungsanweisung ist ein spezialisierter BridgeIntent für Fiat-Währungen und CBDC.

### 2.5 Stand der Technik und Abgrenzung

CBDC-Architekturen (EP4181458A1, EP3850567A1) und PSD2-konforme API-Gateways beschreiben keine **signed Zahlungsanweisungs-Primitive** auf Anwendungsebene, die alle vier folgenden Eigenschaften gleichzeitig aufweisen:

1. eIDAS-Vertrauensstufe als strukturiertes Enum-Feld (nicht Policy-Metadaten)
2. SHA-256-Empfänger-Pseudonymisierung als Typklasseneigenschaft (nicht Policy)
3. Rein-funktionale AML-Scanner-Schnittstelle (exfiltrationssicher durch Typsystem)
4. Dreischichtiges Prüfprotokoll (HMAC + Merkle + öffentlicher DA-Layer)

### 2.6 Offenbarung der Erfindung

**Zahlungsanweisung (PaymentIntent) als spezialisierter GBM-2-BridgeIntent:**

| Feld | Typ | Bedeutung |
|---|---|---|
| `trust_level` | eIDAS-Enum | Niedriger / Substanzieller / Hoher Vertrauensgrad |
| `currency` | ISO-4217-Code | Währungsbezeichner |
| `amount_minimal` | Integer | Betrag in kleinster Einheit (cent, Satoshi, etc.) — kein Gleitkomma |
| `recipient_hash` | SHA-256 | Hash des Empfänger-DID — nie der Klartext |
| `consent_scope` | Enum | EinzelZahlung / Dauerauftrag / Lastschrift |
| `aml_flags` | Liste | Kategorie-Hashes (nie Klartextinhalt) |
| `signature` | Bytes | Gemäß GBM-0 / GBM-1 über alle vorgenannten Felder |

**Formale Reinheitseigenschaft des AML-Scanners:**

```
AmlScanner: (&self: unveränderliche Selbstreferenz, text: &str) → Vec<AmlFlag>
```

Die Schnittstelle ist als synchrone, seiteneffektfreie Abbildung spezifiziert. In sicherem Rust erzwingt die unveränderliche Selbstreferenz das Fehlen von Netzwerkkommunikation und externer Zustandsmutation auf Typebene — formal nachweisbar, nicht nur durch Richtlinien gesichert. AML-Protokolleinträge enthalten ausschließlich den SHA-256-Hash des auslösenden Inhalts (DSGVO Art. 5 Abs. 1 lit. c als Designeigenschaft).

**Dreischichtiges Prüfprotokoll:**

- Schicht 1 (GBM-0): HMAC-SHA256 pro Eintrag — lokale append-only Kette
- Schicht 2: Merkle-Baum über konfigurierbare Zeitintervalle
- Schicht 3: Verankerung des Merkle-Root in öffentlichem DA-Layer mit blockbasiertem Verweis

**Live-Evidenz (Reducing to Practice, 2026-02-24):**

- Zahlungsanweisung `SIGILEURO-20260224-512a1bcc`, €15,00, Audit Seq #15, HTTP 200 ✅
- Merkle-Root `0xfb19a5ff...` in öffentlichem DA-Layer verankert *(beispielhaft realisiert mit Celestia Mocha, Block 10221745 — das Verfahren ist DA-Layer-agnostisch)* ✅

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig — offenes Zahlungsprotokoll): Computerimplementiertes Protokoll zur Verarbeitung einer kryptografisch signierten Zahlungsanweisung unter Verwendung des SIGIL-Protokolls (GBM-0, DPMA 2026-02-23), des SIGIL-Bridge-Core-Transferprimitivs (GBM-2, 2026-02-25) und der Identitätsinfrastruktur für alle Klassen von Zahlungsmarktteilnehmern — Zentralbanken, Geschäftsbanken, Payment Service Provider, Unternehmen und Privatpersonen — dadurch gekennzeichnet, dass es:

(a) eine Zahlungsanweisung entgegennimmt, die enthält: eine eIDAS-kompatible Vertrauensstufe als maschinenlesbares Enum-Feld, den Betrag in kleinster Währungseinheit als ganzzahligen Wert, eine ISO-4217-Währungsidentifikation sowie einen SHA-256-Hash des Empfänger-Identifikators (nie den Klartext);

(b) die kryptografische Signatur gemäß dem Signaturrahmen von GBM-0 und GBM-1 verifiziert;

(c) die Vertrauensstufe und den Betrag vor jedem Datenbankschreibvorgang prüft und Zahlungsanweisungen, die die Anforderungen nicht erfüllen, vollständig ohne Protokolleintrag abweist;

(d) die Anweisung einer rein-funktionalen, seiteneffektfreien AML/CTF-Prüfschnittstelle übergibt, die ausschließlich Kategorie-Hashes protokolliert;

(e) einen dreischichtigen Prüfeintrag gemäß § 2.6 erstellt.

**Anspruch 2** (abhängig von 1 — Teilnehmer-Offenheit): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass jeder Zahlungsmarktteilnehmer — unabhängig von institutioneller Zugehörigkeit, Registrierungsland oder Teilnehmerklasse — als Zahler oder Empfänger teilnehmen kann, sofern er einen W3C-DID-konformen Identifikator vorhält und der erforderlichen eIDAS-Vertrauensstufe entspricht, ohne dass eine gesonderte Zulassung durch den Systembetreiber erforderlich ist.

**Anspruch 3** (abhängig von 1 — Kompatibilität mit bestehenden Systemen): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass Zahlungsanweisungen mit bestehenden Zahlungsinfrastrukturen verknüpft werden können, insbesondere durch: (a) Einbettung in ISO-20022-konforme Nachrichtenformate oder Referenzierung durch ISO-20022-Transaktions-ID; (b) Nutzung als kryptografische Attestationsschicht über SEPA-Credit-Transfer- und SEPA-Instant-Zahlungen; (c) Verwendung von T2-RTGS-kompatiblen Teilnehmer-IDs als Basis für DID-Konstruktion.

**Anspruch 4** (abhängig von 1 — DSGVO Pseudonymisierung): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Empfänger-Identifikator ausschließlich als SHA-256-Hash gespeichert wird, niemals als Klartext, womit Art. 5 Abs. 1 lit. c DSGVO als Designeigenschaft des Protokolls erfüllt wird und nicht durch Konfiguration umgehbar ist.

**Anspruch 5** (abhängig von 1 — rein-funktionale AML-Schnittstelle): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die AML/CTF-Prüfschnittstelle als synchrone, rein-funktionale Abbildung spezifiziert ist, deren unveränderliche Selbstreferenz in typgesicherten Implementierungsumgebungen Netzwerkkommunikation und externe Zustandsmutation strukturell verhindert, und dass das Prüfprotokoll ausschließlich Kategorie-Hashes enthält.

**Anspruch 6** (abhängig von 1 — dreischichtiges Prüfprotokoll): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass das Prüfprotokoll aus drei unabhängig verifizierbaren Schichten besteht: (a) HMAC-Kette von GBM-0 als lokale Manipulationserkennung; (b) Merkle-Baum über konfigurierbare Zeitintervalle; (c) Verankerung des Merkle-Root in einem öffentlichen Distributed-Ledger, der ohne Genehmigung lesbar, nach Aufnahme unveränderlich und mit maschinenlesbarem Blockverweis abfragbar ist.

**Anspruch 7** (abhängig von 6 — trustless Verifikation): Verfahren nach Anspruch 6, dadurch gekennzeichnet, dass ein Dritter ohne Vertrauen in den Systembetreiber, allein durch Kenntnis des Merkle-Root-Blockverweises im öffentlichen DA-Layer, die Vollständigkeit und Unverändertheit des vollständigen Zahlungs-Prüfprotokolls verifizieren kann.

**Anspruch 8** (abhängig von 1 — Kryptoagilität): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Signaturmechanismus gemäß GBM-1 (SIGIL Crypto-Agility, 2026-02-25) implementiert ist und der Wechsel auf ML-DSA (NIST FIPS 204) ohne Änderung der Zahlungsanweisungs-Datenstruktur durchführbar ist.

---

## 4. Zusammenfassung (Abstract)

Aufbauend auf GBM-0, GBM-1 und GBM-2 implementiert das Protokoll ein offenes, eIDAS-konformes Zahlungssystem für alle Teilnehmerklassen — Zentralbanken, Geschäftsbanken, Broker, Unternehmen und Privatpersonen — ohne gesonderte Zulassung. Kompatibilität mit ISO 20022, SEPA, T2 und PSD2 ist durch Referenzierungs-Standards sichergestellt. Eine eIDAS-Vertrauensstufe als maschinenlesbares Enum-Feld wird vor jedem Datenbankschreibvorgang erzwungen. Der Empfänger wird als SHA-256-Hash pseudonymisiert (DSGVO Art. 5 als Designeigenschaft). Eine rein-funktionale AML-Schnittstelle schreibt ausschließlich Kategorie-Hashes. Das dreischichtige Prüfprotokoll (HMAC + Merkle + öffentlicher DA-Layer) ist trustless durch Dritte verifizierbar. Das Verfahren ist DA-Layer-agnostisch und kryptoagil. (≈ 110 Wörter)

---

## 5. Englische Zusammenfassung / English Summary

**GBM-3 — SIGIL-EURO · Open, eIDAS-Compliant Payment Protocol for All Participant Classes**

Building on GBM-0, GBM-1, and GBM-2, this protocol implements an open, eIDAS-compliant payment system for all participant classes — central banks, commercial banks, brokers, payment service providers, corporates and private individuals — without requiring individual authorisation by the system operator. Compatibility with ISO 20022, SEPA, T2-RTGS, PSD2, and MiCA is ensured through reference standards. An eIDAS trust level (Low / Substantial / High) is specified as a machine-readable enum field and enforced before every database write. The recipient is represented exclusively as its SHA-256 hash — GDPR Art. 5(1)(c) data minimisation as a design property, not a configuration option. A purely-functional, side-effect-free AML/CTF scanner interface writes only category hashes to the audit log. The three-layer audit trail (HMAC chain + Merkle tree + public DA-layer anchoring) is trustlessly verifiable by any third party. Demonstrated in live operation on 2026-02-24: €15.00 payment, Merkle root anchored in Celestia Mocha Block 10221745. The protocol is DA-layer-agnostic and inherits quantum-resistance from GBM-1.

---

*SIGIL-EURO · GBM-3 der SIGIL-Patentfamilie (Sovereign Identity-Gated Interaction Layer) · Anmeldedatum 2026-02-25 · Patent Pending · EUPL-1.2*
*Benjamin Küttner · Garmischerstrasse 46 B · 86163 Augsburg, Deutschland · <benjamin.kuettner@icloud.com> · <ben@sigil-protocol.org>*
