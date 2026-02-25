# PATENT — SIGIL-EURO

## DE Gebrauchsmuster · eIDAS-konformes Zahlungsgateway auf SIGIL-Bridge-Basis

## GBM-3 der SIGIL-Patentfamilie

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, [Adresse eintragen]
**Priorität / Stammanmeldungen:**

- GBM-0: DE Gebrauchsmuster SIGIL Protocol, eingereicht 2026-02-23
- GBM-1: DE Gebrauchsmuster SIGIL Crypto-Agility, eingereicht 2026-02-25 (gleichzeitig)
- GBM-2: DE Gebrauchsmuster SIGIL-Bridge-Core, eingereicht 2026-02-25 (gleichzeitig)
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Gebrauchsmusteranmeldung — SIGIL-EURO (GBM-3)

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster für ein computerimplementiertes eIDAS-konformes Zahlungsgateway an, das auf dem SIGIL-Protokoll (GBM-0) und dem SIGIL-Bridge-Core (GBM-2) aufbaut. Die Erfindung wurde am 2026-02-24 im Echtbetrieb erfolgreich demonstriert (Audit Sequence #15; Verankerung des Merkle-Root in einem öffentlichen Distributed-Ledger nachgewiesen, beispielhaft mittels Celestia Mocha, Block 10221745).

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft ein computerimplementiertes Zahlungsgateway für eIDAS-konforme, kryptografisch signierte Zahlungsanweisungen mit integrierter AML/CTF-Prüfung, DSGVO-konformer Empfänger-Pseudonymisierung und dreischichtigem, tamper-evidentem Prüfprotokoll — aufgebaut auf dem SIGIL-Protokoll (GBM-0) und dem SIGIL-Bridge-Core-Transferprimiti (GBM-2).

### 2.2 Bezug zu den Stamm-Schutzrechten

**GBM-0** liefert die Identitätsinfrastruktur (W3C-DID, Ed25519-Signatur), die rein-funktionale Prüfschnittstelle und den HMAC-Prüfprotokollrahmen, den SIGIL-EURO als Schicht 1 seines dreischichtigen Prüfprotokolls verwendet.

**GBM-2** liefert das Transfer-Intent-Primitiv und die Atomaritätsgarantie, auf der die Zahlungsanweisung (`PaymentIntent`) als spezialisierter Transfer-Intent für Fiat-Währungen und CBDCs aufsetzt.

Die vorliegende Erfindung fügt gegenüber GBM-0 und GBM-2 hinzu:

- eIDAS-Vertrauensstufen-Enforcement vor jedem Datenbankschreibvorgang
- DSGVO-konforme Empfänger-Pseudonymisierung als Designeigenschaft (nicht Richtlinie)
- Rein-funktionale AML-Scanner-Schnittstelle mit formalem Reinheitsnachweis
- Merkle-Tree-Batch-Aggregation + Public-DA-Verankerung (Schichten 2 und 3)

### 2.3 Stand der Technik und Abgrenzung

Bestehende CBDC-Architekturen (EP4181458A1, EP3850567A1) beschreiben Ausstellungsplattformen und Identitätssysteme, spezifizieren jedoch keine **signierten Zahlungsanweisungs-Primitive** auf Anwendungsebene, die alle vier folgenden Eigenschaften vereinen:

1. eIDAS-Vertrauensstufe als strukturiertes Datenfeld (nicht Policy-Metadaten)
2. SHA-256-Empfänger-Pseudonymisierung als DSGVO-Designeigenschaft
3. Rein-funktionale (seiteneffektfreie) AML-Scanner-Schnittstelle
4. Dreischichtiges kryptografisches Prüfprotokoll mit Public-DA-Verankerung

### 2.4 Offenbarung der Erfindung

**Zahlungsanweisung (`PaymentIntent`) — erweiterter Transfer-Intent:**

Alle Felder von GBM-2 BridgeIntent plus:

- eIDAS-Vertrauensstufe (`Low` / `High`) — gemäß eIDAS-VO (EU) Nr. 910/2014
- ISO-4217-Währungsbezeichner
- SHA-256-Hash des Empfänger-DID (niemals der Klartext-DID)
- Betrag in kleinster Währungseinheit (kein Gleitkomma)
- Einwilligungsumfang (`EinzelZahlung` / `Dauerauftrag`)
- AML-Markierungsliste (Kategorie-Hashes, nie Klartextinhalte)

**Formale Reinheitseigenschaft des AML-Scanners:**

```
AmlScanner: &str → Vec<AmlFlag>
```

Die Schnittstelle ist als **synchrone, rein-funktionale Abbildung** definiert. Das `&self` (unveränderliche Ausleihe) erzwingt in sicherem Rust das Fehlen von Zustandsmutation außerhalb des Rückgabewerts. Konforme Implementierungen dürfen keine Netzwerkkommunikation, keine Datenbankschreiboperationen und keine Hintergrundaufgaben ausführen. Das Prüfprotokoll enthält ausschließlich den SHA-256-Hash des auslösenden Inhalts, nie den Inhalt selbst. Damit erfüllt das System Art. 5 Abs. 1 lit. c DSGVO (Datenminimierung) als **Designeigenschaft**, nicht als Richtlinie — formal nachweisbar und für Beweisassistenten (Coq, Lean) geeignet.

**Dreischichtiges Prüfprotokoll:**

- Schicht 1 (GBM-0): HMAC-SHA256 pro Eintrag — lokale Manipulationserkennung
- Schicht 2 (neu): Merkle-Baum-Aggregation über konfigurierbare Zeitintervalle
- Schicht 3 (neu): Verankerung des Merkle-Root in einem öffentlichen DA-Layer

**Live-Evidenz (Prioritätsdokument):**

- Zahlungsanweisung `SIGILEURO-20260224-512a1bcc`, €15,00, Audit Seq #15, HTTP 200 ✅
- Merkle-Root `0xfb19a5ff...` in öffentlichem DA-Layer verankert, Timestamp 2026-02-24 ✅
  *(beispielhaft realisiert mit: Celestia Mocha, Block 10221745 — austauschbar gegen jeden kompatiblen DA-Layer)*

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig, aufbauend auf GBM-0 und GBM-2): Computerimplementiertes Verfahren zur eIDAS-konformen Verarbeitung einer kryptografisch signierten Zahlungsanweisung unter Verwendung des SIGIL-Protokolls (GBM-0, 2026-02-23) und des SIGIL-Bridge-Core-Transferprimitivs (GBM-2, 2026-02-25), dadurch gekennzeichnet, dass es:

(a) eine Zahlungsanweisung entgegennimmt, die neben den Pflichtfeldern des GBM-2 BridgeIntent zusätzlich eine eIDAS-kompatible Vertrauensstufe, einen SHA-256-Hash des Empfänger-Identifikators (nicht den Klartext), den Betrag in kleinster Währungseinheit, eine ISO-4217-Währungsbezeichnung und eine digitale Signatur gemäß GBM-0 über alle vorgenannten Felder umfasst;

(b) die digitale Signatur gemäß dem Signaturrahmen von GBM-0 verifiziert;

(c) die Vertrauensstufe und den Betrag **vor jedem Datenbankschreibvorgang** prüft und Zahlungsanweisungen, die die Vertrauensstufenanforderung nicht erfüllen, vollständig abweist — ohne Anlage eines Protokolleintrags — sodass keine abgelehnten Einträge die Prüfkette verunreinigen;

(d) die Zahlungsanweisung einer rein-funktionalen AML/CTF-Prüfschnittstelle übergibt, die als synchrone, seiteneffektfreie Abbildung implementiert ist und ausschließlich Kategorie-Hashes in das Prüfprotokoll schreibt;

(e) einen vollständigen dreischichtigen Prüfeintrag gemäß § 2.4 erzeugt.

**Anspruch 2** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die Vertrauensstufe `Hoch` einer qualifizierten elektronischen Signatur gemäß eIDAS-Verordnung (EU) Nr. 910/2014 entspricht und das System durch Erweiterung der Vertrauensstufen-Enumeration auf PSD2, MiCA oder beliebige weitere regulatorische Rahmen adaptierbar ist.

**Anspruch 3** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Empfänger-Identifikator ausschließlich als SHA-256-Hash gespeichert wird, niemals als Klartext, womit Art. 5 Abs. 1 lit. c DSGVO (Datenminimierung) als Designeigenschaft des Systems erfüllt wird; der Berechtigte kann bei Kenntnis des Klartext-Identifikators die Zugehörigkeit zu einer Transaktion berechnen, ohne dass der Systembetreiber den Klartextidentifikator kennen muss.

**Anspruch 4** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die rein-funktionale AML-Prüfschnittstelle durch das Typsystem der Implementierungssprache strukturell erzwungen wird (unveränderliche Selbstreferenz, kein Netzwerkzugriff, keine Zustandsmutation), sodass die Datenschutzeigenschaft für formale Verifikationswerkzeuge zugänglich ist.

**Anspruch 5** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass das dreischichtige Prüfprotokoll aus (a) der HMAC-Kette von GBM-0 als Schicht 1, (b) einem Merkle-Baum über alle HMAC-Werte eines konfigurierbaren Zeitintervalls als Schicht 2, und (c) der Verankerung des Merkle-Root in einem öffentlichen Distributed-Ledger oder Data-Availability-Layer, der die folgenden Eigenschaften aufweist: (i) öffentlich lesbar ohne Genehmigung, (ii) unveränderlich nach Aufnahme, (iii) mit maschinenlesbarem Blockverweis abfragbar, als Schicht 3 besteht, wobei der Blockverweis und der Transaktions-Hash als maschinenlesbare Quittung im Prüfprotokoll gespeichert werden.

**Anspruch 6** (abhängig von 5): Verfahren nach Anspruch 5, dadurch gekennzeichnet, dass ein Dritter ohne Vertrauen in den Systembetreiber, allein durch Kenntnis der Merkle-Root-Quittung und des öffentlichen DA-Layers, die Vollständigkeit und Unverändertheit des gesamten Zahlungsprüfprotokolls verifizieren kann.

**Anspruch 7** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass das Verfahren ohne wesentliche Protokolländerungen auf beliebige ISO-4217-Währungen, auf tokenisierte Wertpapiere (ISIN) oder auf CBDC-Einheiten beliebiger Zentralbanken anwendbar ist — gemäß der Assetklassen-Agnostik von GBM-2 Anspruch 3.

**Anspruch 8** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Signaturmechanismus die Kryptoagilität von GBM-1 (SIGIL Crypto-Agility, 2026-02-25) erbt und der Wechsel auf ML-DSA (NIST FIPS 204) ohne Änderung der Zahlungsanweisungs-Datenstruktur möglich ist.

---

## 4. Zusammenfassung (Abstract)

Aufbauend auf dem SIGIL-Protokoll (GBM-0) und dem SIGIL-Bridge-Core-Transferprimiti (GBM-2) nimmt das Verfahren eIDAS-konforme Zahlungsanweisungen entgegen. Die Vertrauensstufe und der Betrag werden vor jedem Datenbankschreibvorgang erzwungen; abgelehnte Anweisungen hinterlassen keinen Protokolleintrag. Der Empfänger wird strukturell als SHA-256-Hash pseudonymisiert (DSGVO Art. 5 als Designeigenschaft). Eine rein-funktionale AML-Schnittstelle schreibt ausschließlich Kategorie-Hashes. Das dreischichtige Prüfprotokoll (HMAC + Merkle + öffentlicher DA-Layer mit blockbasiertem Verweis) wurde am 2026-02-24 in Produktion nachgewiesen. Das Verfahren ist DA-Layer-agnostisch, währungsagnostisch und kryptoagil. (≈ 100 Wörter)

---

*SIGIL-EURO · GBM-3 · 2026-02-25 · Patent Pending · EUPL-1.2*
