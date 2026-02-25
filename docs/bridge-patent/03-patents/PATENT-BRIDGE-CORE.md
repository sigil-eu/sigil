# PATENT — SIGIL-BRIDGE-CORE

## DE Gebrauchsmuster · Universelles kryptografisches Übertragungsprotokoll für materielle und immaterielle Vermögenswerte

## GBM-2 der SIGIL-Patentfamilie

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, Garmischerstrasse 46 B, 86163 Augsburg
**Priorität / Stammanmeldungen:**

- GBM-0: DE Gebrauchsmuster SIGIL Protocol, eingereicht DPMA 2026-02-23
- GBM-1: DE Gebrauchsmuster SIGIL Crypto-Agility, eingereicht 2026-02-25 (gleichzeitig)
**EPO-Frist:** 2027-02-23
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Gebrauchsmusteranmeldung — SIGIL-BRIDGE-CORE (GBM-2)

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster als grundlegende Plattformerweiterung des SIGIL-Protokolls (GBM-0, DPMA 2026-02-23) an. Die vorliegende Erfindung überträgt die im SIGIL-Protokoll geschützte Identitäts- und Prüfprotokollinfrastruktur auf einen neuen, wesentlich breiteren Anwendungsbereich: die **atomare, kryptografisch gesicherte Übertragung von Vermögenswerten beliebiger Art** zwischen DID-identifizierten Parteien über beliebige Netzwerkgrenzen.

Der Abstraktionsgrad ist dabei bewusst maximal: Das Protokoll ist agnostisch gegenüber der Natur des Vermögenswerts (materiell oder immateriell, fungibel oder nicht-fungibel), dem Netzwerktyp (Blockchain, traditionelle Finanzinfrastruktur, Registry-System) und der Implementierungssprache. Es definiert ausschließlich die kryptografischen Invarianten, die eine atomare Einigung zwischen zwei DID-identifizierten Parteien ohne vertrauenswürdige Dritte ermöglichen.

Die Bridge-Core-Architektur dient als Plattformbasis für SIGIL-EURO (GBM-3), SIGIL-FXBRIDGE (GBM-4) und SIGIL-SERVICEBRIDGE (GBM-5), die als abhängige Gebrauchsmuster gleichzeitig angemeldet werden.

Anliegend übersenden wir: Beschreibung, Ansprüche und Zusammenfassung.

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft ein computerimplementiertes Protokoll zur kryptografisch garantierten, atomaren Übertragung von Vermögenswerten zwischen zwei durch dezentrale Identifikatoren (DID) identifizierten Parteien. Das Protokoll ist universell einsetzbar für:

**Materielle Vermögenswerte:**

- Fiat-Währungen (EUR, USD, CHF, alle ISO-4217-Währungen)
- Zentralbankgeld (CBDC) beliebiger Zentralbanken
- Wertpapiere (Aktien, Anleihen, ETFs — identifiziert durch ISIN, CUSIP, LEI)
- Immobilien und Grundstücke (identifiziert durch Grundbuchnummer oder vergleichbare Registry-IDs)
- Rohstoffe und Waren (Gold, CO₂-Zertifikate, RECs — identifiziert durch standardisierte Bezeichner)

**Immaterielle Vermögenswerte:**

- On-Chain-Token (fungibel: ERC-20 und Äquivalente; nicht-fungibel: ERC-721 und Äquivalente)
- Geistige Eigentumsrechte (Lizenzen, identifiziert durch UUID oder DOI)
- Nutzungsrechte und Zugriffstoken (API-Schlüssel, Subskriptionen)
- Digitale Kunstwerke und Medienrechte
- Emissionszertifikate und Umweltgutschriften

Das Protokoll trifft keine Annahmen über die technische Natur des Vermögenswerts — es definiert ausschließlich die kryptografischen Invarianten des Übertragungsvorgangs.

### 2.2 Bezug zu den Stamm-Schutzrechten

**GBM-0 (SIGIL Protocol, DPMA 2026-02-23)** schützt das Sicherheitsrahmenwerk für KI-Agenten-Interaktionen mit fünf Schnittstellen: Identitätsprovider, Inhaltsscanner, Tresorsystem, Prüfprotokoll und Sicherheitsregel. GBM-0 definiert insbesondere:

- W3C-konforme Decentralised Identifiers als Parteiidentität
- HMAC-SHA256-verkettete Prüfprotokollar­chitektur
- Ed25519-Signaturrahmen (durch GBM-1 um Kryptoagilität erweitert)

Die vorliegende Erfindung (GBM-2) nutzt diese Infrastruktur als Fundament und überträgt sie auf Werttransfers. Die Prüfprotokollarchitektur von GBM-0 wird direkt als Schicht 1 im dreischichtigen SIGIL-Prüfprotokoll wiederverwendet.

**GBM-1 (SIGIL Crypto-Agility, 2026-02-25)** stellt das Signatur-Upgrade-Interface bereit. GBM-2 erbt damit automatisch Quantensicherheit ohne eigene Implementierung.

### 2.3 Stand der Technik und Neuheit

**Bekannte Lösungen:**

- Bitcoin HTLC (2015): Nur BTC, keine DID-Attribution, keine Prüfkette
- Interledger Protocol (2016): Netzwerkagnostisch, aber ohne DID, ohne HMAC-Prüfkette
- Polkadot XCM (2022): Nur innerhalb des Polkadot-Ökosystems
- Atomic Swaps: Nur kryptonative Assets, keine regulatorische Prüfbarkeit

**Abgrenzung der Erfindung — neuartige Merkmalskombination:**

1. **Universelle Asset-Abstraktion**: Ein einheitliches Transfer-Intent-Format für alle Vermögenswerttypen — von Fiat-Währungen bis Immobilienrechten — ohne Protokollanpassung
2. **DID-Attribution beider Parteien**: W3C-konforme Identifikatoren im Vertrag, keine Account-Adressen, keine zentralen Registries
3. **Direkte HMAC-Prüfketten-Integration**: Lückenlose regulatorisch verwertbare Prüfprotokolldokumentation als Designeigenschaft
4. **Kryptoagilität via GBM-1**: Quantensicherer Upgrade-Pfad ohne Protokolländerung

Diese Merkmalskombination ist in keiner veröffentlichten Patentliteratur oder technischen Spezifikation bekannt.

### 2.4 Technische Beschreibung der Erfindung

**Kernprimitive — Universeller Transfer-Intent:**

Ein `BridgeIntent`-Datensatz ist ein minimal-spezifizierter Vertrag mit folgenden Feldern:

| Feld | Typ | Bedeutung |
|---|---|---|
| `preimage_hash` | SHA-256-Hash | Kryptografische Sperre: H(S) = dieser Wert |
| `asset` | Polymorphe Assetklasse | Vermögenswert beliebiger Art |
| `holder_did` | W3C-DID | Dezentraler Identifikator des Halters |
| `beneficiary_did` | W3C-DID | Dezentraler Identifikator des Begünstigten |
| `timeout_unix` | Unix-Timestamp | Verfallszeit der Sperre |
| `amount` | Dezimalstring | Betrag ohne Gleitkomma-Ungenauigkeit |

Die Assetklasse ist eine geschlossene Typenaufzählung, die ohne Protokolländerung durch neue Varianten erweiterbar ist. Die Mindestvarianten umfassen Fiat-Währungen (ISO 4217), Wertpapiere (ISIN), On-Chain-Token (Contract-Adresse + Chain-ID) und einen generischen Erweiterungstyp für beliebige zukünftige Assetklassen.

**Atomaritätsgarantie — kryptografischer Beweis:**

Der Zustand `Settled` (Erledigt) ist ausschließlich durch Offenbarung eines Preimage-Werts `S` erreichbar, für den gilt: `SHA-256(S) = preimage_hash`. SHA-256 ist eine Einwegfunktion gemäß NIST FIPS 180-4 — eine Fälschung von `S` ohne Kenntnis von `S` ist bei aktuellem Stand der Wissenschaft nicht möglich. Es existiert daher kein Systemzustand, in dem eine Partei den Vermögenswert erhält, ohne dass die Gegenseite `S` zuvor offenbart hat.

**Integration in GBM-0 HMAC-Prüfkette:**

Jeder Zustandsübergang (`Pending → Locked → Settled / Expired`) erzeugt einen HMAC-SHA256-Prüfketteneintrag gemäß GBM-0. Eintragstruktur:

```
entry_n = { did, state_transition, asset_amount, hmac: HMAC-SHA256(key, entry_{n-1}) }
```

Eine nachträgliche Modifikation eines beliebigen Eintrags falsifiziert alle Folgeeinträge.

**Performanz-Eigenschaften (Orientierungswerte):**

- Ed25519-Signaturerstellung: ~0,1 ms auf modernen 64-Bit-Systemen
- SHA-256-Preimage-Verifikation: < 0,01 ms
- HMAC-Ketteneintrag: < 0,5 ms
- Gesamtlatenz eines Settlement-Vorgangs ohne Netzwerk: typisch < 5 ms

*Hinweis: Diese Werte dienen der industriellen Anwendbarkeit (§ 1 PatG). Die Ansprüche sind nicht leistungsabhängig — jede konforme Implementierung ist geschützt, unabhängig von Performanz.*

**Timeout-Invariante für verkettete Transfers:**

Bei n aufeinanderfolgenden BridgeIntents mit demselben Preimage-Hash wird serverseitig vor Aufnahme geprüft: `timeout[i] > timeout[i+1]` für alle i = 1..n. Diese Invariante garantiert, dass kein Zwischenprovider eine Auszahlung erzwingen kann, ohne das Preimage zu offenbaren (kausalitätssichere Preimage-Propagation rückwärts durch die Kette).

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig — universeller Plattformanspruch): Computerimplementiertes Verfahren zur atomaren Übertragung eines Vermögenswerts zwischen zwei durch dezentrale Identifikatoren (W3C DID) identifizierten Parteien unter Verwendung der Identitäts- und Prüfprotokollinfrastruktur des SIGIL-Protokolls (GBM-0, DPMA 2026-02-23), dadurch gekennzeichnet, dass es:

(a) einen Transfer-Intent-Datensatz erzeugt, welcher enthält: (i) den SHA-256-Hash eines geheimen Preimage, (ii) einen Vermögenswert einer polymorphen Assetklasse, die materielle Werte (Fiat-Währungen, Wertpapiere, Immobilienrechte, Rohstoffzertifikate) und immaterielle Werte (On-Chain-Token, Lizenzen, Nutzungsrechte, Digitalrechte) gleichbehandelt, (iii) die W3C-DID-Identifikatoren von Halter und Begünstigtem, (iv) ein Timeout-Feld;

(b) den Vermögenswert einfriert und den Intent in den Zustand `Gesperrt` versetzt, sobald der Halter ihn bereitstellt;

(c) den Zustand `Erledigt` ausschließlich durch Offenbarung eines Preimage herbeiführt, dessen SHA-256-Hash mit dem gespeicherten Wert übereinstimmt — mathematisch atomar ohne jeden Zwischenzustand, in dem nur einer der Beteiligten den Vermögenswert hält;

(d) bei Ablauf des Timeout-Felds ohne Preimage-Offenbarung den Vermögenswert an den Halter zurückführt und den Intent als `Abgelaufen` kennzeichnet;

(e) jeden Zustandsübergang in einer HMAC-SHA256-verketteten, append-only Prüfkette gemäß den Prüfprotokoll-Anforderungen von GBM-0 erfasst, wobei jeder Eintrag den DID der auslösenden Partei und den HMAC-Wert des Vorgängereintrags enthält.

**Anspruch 2** (abhängig von 1 — Timeout-Ketteninvariante): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass bei einer Kette von n Transfer-Intents mit demselben Preimage-Hash vor jeder Aufnahme serverseitig die Bedingung `timeout[i] > timeout[i+1]` für alle i geprüft und bei Verletzung die Aufnahme verhindert wird.

**Anspruch 3** (abhängig von 1 — Assetklassen-Vollständigkeit): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die polymorphe Assetklasse ohne Protokollversion-Änderung um neue Vermögenswerttypen erweiterbar ist, mindestens umfassend:

- Fiat-Währungen und CBDC, identifiziert durch ISO-4217-Währungscode und ausgebende Zentralbank;
- Wertpapiere (Aktien, Anleihen, Fonds, Derivate), identifiziert durch ISIN, CUSIP oder LEI;
- Immobilieneigentum und Grundstücksrechte, identifiziert durch Grundbuchbezeichner oder äquivalente nationale Registry-ID;
- Rohstoffzertifikate, CO₂-Emissionsrechte und Umweltgutschriften, identifiziert durch standardisierte Handelbezeichner;
- Fungible On-Chain-Token (ERC-20 und Äquivalente) und nicht-fungible Token (ERC-721 und Äquivalente), identifiziert durch Contract-Adresse und Chain-ID;
- Lizenzen und Nutzungsrechte an geistigem Eigentum, identifiziert durch UUID, DOI oder vergleichbare persistente Bezeichner;
- einen generischen Erweiterungstyp für bisher nicht klassifizierte Vermögenswerte.

**Anspruch 4** (abhängig von 1 — externe Verifikation): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die HMAC-Prüfkette durch Berechnung eines Merkle-Baums und Verankerung des Merkle-Roots in einem öffentlichen Distributed-Ledger, der die Anforderungen (i) ohne Genehmigung lesbar, (ii) nach Aufnahme unveränderlich, (iii) mit maschinenlesbarem Blockverweis abfragbar erfüllt, extern verifizierbar gemacht wird.

**Anspruch 5** (abhängig von 1 — Kryptoagilität via GBM-1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Signaturmechanismus gemäß dem SIGIL-Crypto-Agility-Verfahren (GBM-1, 2026-02-25) implementiert ist, sodass der eingesetzte Algorithmus ohne Protokolländerung auf quantensichere Verfahren (ML-DSA nach NIST FIPS 204) umgestellt werden kann.

**Anspruch 6** (abhängig von 1 — regulatorische Kompatibilität): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die W3C-DID-Identifikatoren mit eIDAS-2.0-konformen Wallets, qualifizierten elektronischen Signaturträgern (QES) und nationalen Identitätssystemen der EU-Mitgliedstaaten kompatibel sind, sodass das Verfahren ohne Schnittstellenänderung in regulierte Finanzinfrastrukturen integriert werden kann.

**Anspruch 7** (abhängig von 3 — Nicht-finanzielle Vermögenswerte): Verfahren nach Anspruch 3, dadurch gekennzeichnet, dass das Verfahren ohne algorithmische Änderung auf nicht-finanzielle Vermögenswerte (Immobilien, Kunstwerke, geistiges Eigentum, Umweltzertifikate) anwendbar ist, wenn der Vermögenswert durch einen standardisierten Bezeichner eindeutig identifizierbar und in einem Registry-System sperrbar ist.

---

## 4. Zusammenfassung (Abstract)

Ein computerimplementiertes Protokoll erweitert das SIGIL-Protokoll (GBM-0, DPMA 2026-02-23) auf die universelle atomare Übertragung von Vermögenswerten beliebiger Art zwischen W3C-DID-identifizierten Parteien. Das Protokoll behandelt materielle Werte (Fiat-Währungen, CBDC, Wertpapiere ISIN, Immobilien, Rohstoffzertifikate, CO₂-Rechte) und immaterielle Werte (On-Chain-Token, Lizenzen, Nutzungsrechte, Digitalrechte) durch ein einziges polymorphes Transfer-Intent-Primitiv mit kryptografischer Hash-Präimage-Sperre. Jeder Zustandsübergang wird in der HMAC-Prüfkette von GBM-0 dokumentiert; eine Timeout-Ketteninvariante sichert mehrstufige Transfers kausal ab. Signaturmechanismus ist kryptoagil via GBM-1. Das Protokoll bildet die implementierungssprach- und netzwerkagnostische Plattformbasis für SIGIL-EURO (GBM-3), SIGIL-FXBRIDGE (GBM-4) und SIGIL-SERVICEBRIDGE (GBM-5). (≈ 110 Wörter)

---

*SIGIL-BRIDGE-CORE · GBM-2 · 2026-02-25 · Patent Pending · EUPL-1.2*
