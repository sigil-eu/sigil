# PATENT — SIGIL-BRIDGE-CORE

## DE Gebrauchsmuster · Erweiterung des SIGIL-Protokolls auf Wertübertragung

## GBM-1 der SIGIL-Patentfamilie

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, [Adresse eintragen]
**Priorität / Stammanmeldung:** DE Gebrauchsmuster SIGIL Protocol, eingereicht 2026-02-23 (Aktenzeichen ausstehend) — **GBM-0 der SIGIL-Patentfamilie**
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Gebrauchsmusteranmeldung — SIGIL-BRIDGE-CORE (GBM-1)

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster als Weiterentwicklung des SIGIL-Protokolls (GBM-0, eingereicht 2026-02-23) an. Die vorliegende Erfindung erweitert das dort geschützte Identitäts- und Prüfprotokoll auf den Bereich der **atomaren Übertragung digitaler Vermögenswerte** zwischen verteilten Ledgern. Die SIGIL-Bridge-Core-Architektur bildet die Plattformbasis für alle spezialisierten SIGIL-Bridge-Anwendungen (SIGIL-EURO, SIGIL-FXBRIDGE, SIGIL-SERVICEBRIDGE), die als abhängige Gebrauchsmuster GBM-2 bis GBM-4 gleichzeitig angemeldet werden.

Anliegend übersenden wir: Beschreibung, Ansprüche und Zusammenfassung.

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft computerimplementierte Verfahren zur kryptografisch gesicherten, atomaren Übertragung digitaler Vermögenswerte zwischen unabhängigen Ledgersystemen, unter Verwendung kryptografischer Hash-Präimage-Sperren (HTLC), dezentraler Identifikatoren (DID) und HMAC-verketteter Prüfprotokolle.

### 2.2 Bezug zum Stamm-Schutzrecht (GBM-0)

Das SIGIL-Protokoll (GBM-0) schützt ein allgemeines Sicherheitsrahmenwerk für KI-Agenten-Interaktionen, bestehend aus einem signierten Identitätsumschlag (`_sigil`-Envelope), einer rein-funktionalen Inhaltsprüfschnittstelle, einer HMAC-verketteten Prüfprotokollkette und einem Tresorsystem. GBM-0 definiert die **Identitätsinfrastruktur** (W3C-Decentralised Identifiers, Ed25519-Signaturen) und die **Prüfprotokollarchitektur**, auf der GBM-1 aufbaut.

Die vorliegende Erfindung überträgt diese Infrastruktur auf einen neuen Anwendungsbereich: **die Übertragung von Werten statt Informationen**.

### 2.3 Stand der Technik

Bestehende Lösungen (Bitcoin Lightning Network, Interledger Protocol, Ripple/XRP) bieten atomare Transfers für spezifische Asset-Klassen oder homogene Netzwerke. Keine dieser Lösungen kombiniert:

1. **Assetklassenagnostische** Vertragsprimitive in einem einheitlichen Format (Währung, Wertpapier, Token)
2. **W3C-DID-Attribution** beider Vertragsparteien in jedem Transfervertrag
3. **HMAC-verkettete Prüfkette** direkt aus dem SIGIL-Protokoll-Prüfprotokollrahmen
4. **Algorithmusagnostisches Design** für den Wechsel auf post-quanten-sichere Signaturverfahren

### 2.4 Offenbarung der Erfindung

**Kernprimitive — Asset-agnostischer Transfer-Vertrag:**

Ein `BridgeIntent`-Datensatz enthält:

- einen SHA-256-Hash eines geheimen Preimage (kryptografische Sperre)
- einen digitalen Vermögenswert einer polymorphen Assetklasse (Währung, Wertpapier, On-Chain-Token, oder eine zukünftige Erweiterungsklasse)
- dezentrale Identifikatoren (W3C DID) beider Vertragsparteien (Halter und Begünstigter)
- ein Unix-Timeout-Feld

**Atomaritätsgarantie:**

Der Zustand `Erledigt` (`Settled`) wird ausschließlich durch die Offenbarung eines Geheimwerts `S` herbeigeführt, für den gilt: `SHA-256(S) = PreimageHash`. Es existiert kein Systemzustand, in dem eine Vertragspartei den Vermögenswert erhält, ohne dass die Gegenseite den kryptografischen Nachweis offenbart hat.

**HMAC-Prüfkette (Erweiterung von GBM-0):**

Jeder Zustandsübergang des `BridgeIntent` erzeugt einen Eintrag in der HMAC-verketteten Prüfkette gemäß GBM-0. Jeder Eintrag enthält DID der auslösenden Partei, das finanzielle Ergebnis sowie den HMAC-SHA256-Wert des Vorgängereintrags. Die Unverändertheit der gesamten Kette ist durch Merkle-Root-Verankerung in einem öffentlichen Distributed-Ledger nachweisbar.

**Timeout-Invariante bei verketteten Transfers:**

Bei n aufeinanderfolgenden `BridgeIntent`-Verträgen mit demselben Preimage-Hash wird serverseitig geprüft, dass `Timeout[i] > Timeout[i+1]` für alle `i`. Diese Invariante garantiert die kausalsichere rückwärtige Preimage-Propagation: Kein Zwischenprovider kann die Auszahlung erzwingen, ohne das Preimage zu offenbaren.

**Kryptoagile Signaturarchitektur (PATENT NOTE 2026-02-25):**

Der Signaturmechanismus ist hinter einem algorithmisch neutralen Signing-Interface implementiert, das den eingesetzten Signaturalgorithmus (`Ed25519`, `ML-DSA-65` nach NIST FIPS 204, oder künftige Verfahren) als maschinenlesbares Feld im Protokolleintrag führt. Ein Verifier wählt den Verifizierungspfad anhand dieses Feldes, ohne externe Konfiguration. Der Wechsel auf post-quanten-sichere Verfahren (z.B. CRYSTALS-Dilithium3) ist ohne Protokolländerung möglich.

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig — Plattformanspruch): Computerimplementiertes Verfahren zur atomaren Übertragung eines digitalen Vermögenswerts zwischen zwei durch dezentrale Identifikatoren (DID) gemäß W3C-Standard identifizierten Parteien unter Verwendung des SIGIL-Protokolls (DE Gebrauchsmuster GBM-0, 2026-02-23), dadurch gekennzeichnet, dass es:

(a) einen Transfer-Intent-Datensatz erzeugt, welcher einen kryptografischen Hash eines geheimen Preimage, einen digitalen Vermögenswert einer polymorphen Assetklasse, die DID-Identifikatoren von Halter und Begünstigtem sowie ein Timeout-Feld umfasst;

(b) den Vermögenswert einfriert und den Intent in den Zustand `Gesperrt` versetzt, sobald der Halter ihn bereitstellt;

(c) den Zustand `Erledigt` ausschließlich durch die Offenbarung eines Preimage herbeiführt, dessen kryptografischer Hash mit dem gespeicherten Hashwert übereinstimmt — mathematisch atomar, ohne jeden Zwischenzustand, in dem nur eine Partei den Wert erhalten hat;

(d) bei Ablauf des Timeout-Felds ohne Preimage-Offenbarung den Vermögenswert an den Halter zurückführt und den Intent als `Abgelaufen` markiert;

(e) jeden Zustandsübergang gemäß dem SIGIL-Prüfprotokollrahmen (GBM-0) in einer HMAC-SHA256-verketteten, append-only Prüfkette protokolliert, wobei jeder Eintrag den DID der auslösenden Partei sowie den HMAC-Wert des Vorgängereintrags enthält.

**Anspruch 2** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass bei einer Kette von n Transfer-Intents mit demselben Preimage-Hash vor jedem Schreibvorgang serverseitig geprüft wird, dass der Timeout-Wert jedes äußeren Intents denjenigen des nächsten inneren Intents übersteigt, und dass eine Verletzung dieser Invariante die Annahme des Intents verhindert.

**Anspruch 3** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die polymorphe Assetklasse ohne Protokolländerung um neue Vermögenswerttypen erweiterbar ist und mindestens die Typen (a) Fiat-Währung oder Zentralbankgeld (CBDC), identifiziert durch ISO-4217-Code, (b) Wertpapier, identifiziert durch ISIN, und (c) On-Chain-Token, identifiziert durch Contract-Adresse und Chain-Bezeichner umfasst.

**Anspruch 4** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die HMAC-Prüfkette periodisch durch Berechnung eines Merkle-Baums über alle Eintragsauthentifizierungswerte und Verankerung des resultierenden Merkle-Roots in einem öffentlichen Distributed-Ledger extern verifizierbar gemacht wird, sodass ein Dritter ohne Vertrauen in den Systembetreiber die Vollständigkeit und Unverändertheit des Prüfprotokolls nachweisen kann.

**Anspruch 5** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Signaturmechanismus hinter einem algorithmisch neutralen Signing-Interface implementiert ist, das den eingesetzten Signaturalgorithmus als maschinenlesbares Identifikationsfeld im Protokolldatensatz führt, sodass der eingesetzte Algorithmus — insbesondere durch Modul-Gitter-basierte Signaturverfahren (ML-DSA) gemäß NIST FIPS 204 — ohne Protokolländerung ausgetauscht werden kann (Kryptoagilität).

**Anspruch 6** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die dezentralen Identifikatoren gemäß W3C DID Core 1.0 spezifiziert sind und mit eIDAS-2.0-konformen Wallets und qualifizierten elektronischen Signaturträgern kompatibel sind, sodass das Verfahren ohne Schnittstellenänderung in regulierte europäische Finanzinfrastrukturen integriert werden kann.

---

## 4. Zusammenfassung (Abstract)

Ein computerimplementiertes Verfahren erweitert das SIGIL-Protokoll (GBM-0, 2026-02-23) auf die atomare Übertragung digitaler Vermögenswerte zwischen DID-identifizierten Parteien. Vermögenswerte der Klassen Währung, Wertpapier und On-Chain-Token werden durch ein einheitliches Transfer-Intent-Primitiv mit kryptografischer Hash-Präimage-Sperre und konfigurierbarem Timeout übertragen. Jeder Zustandsübergang wird in der HMAC-verketteten Prüfkette des SIGIL-Prüfprotokollrahmens dokumentiert; periodisch wird ein Merkle-Root in einem öffentlichen Distributed-Ledger verankert. Bei verketteten Transfers wird eine Timeout-Invariante serverseitig erzwungen. Der Signaturmechanismus ist kryptoagil: ein algorithmisches Identifikationsfeld im Protokoll ermöglicht den Wechsel auf post-quanten-sichere Verfahren (ML-DSA, NIST FIPS 204) ohne Protokolländerung. Das Verfahren bildet die Plattformbasis für SIGIL-EURO (GBM-2), SIGIL-FXBRIDGE (GBM-3) und SIGIL-SERVICEBRIDGE (GBM-4). (≈ 120 Wörter)

---

*SIGIL-BRIDGE-CORE · GBM-1 · 2026-02-25 · Patent Pending · EUPL-1.2*
