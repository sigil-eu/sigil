# PATENT — SIGIL-FXBRIDGE

## DE Gebrauchsmuster · Atomarer Mehrfach-Devisentransfer mit haftender Routing-Attestation

## GBM-3 der SIGIL-Patentfamilie

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, [Adresse eintragen]
**Priorität / Stammanmeldungen:**

- GBM-0: DE Gebrauchsmuster SIGIL Protocol, eingereicht 2026-02-23
- GBM-1: DE Gebrauchsmuster SIGIL-Bridge-Core, eingereicht 2026-02-25 (gleichzeitig)
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Gebrauchsmusteranmeldung — SIGIL-FXBRIDGE (GBM-3)

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster für ein computerimplementiertes System zur atomaren Mehrfach-Devisenübertragung an, das auf dem SIGIL-Protokoll (GBM-0) und dem SIGIL-Bridge-Core-Transferprimiti (GBM-1) aufbaut. Die hervorgehobene Neuheit dieser Erfindung gegenüber GBM-0 und GBM-1 ist die kryptografisch signierte Routing-Optimalitätsbestätigung durch einen DID-identifizierten, haftenden Routing-Dienst.

Die Erfindung wurde am 2026-02-24 im Echtbetrieb nachgewiesen (MultiHopIntent EUR→USD, HTTP 200, Timeout-Invariante verifiziert). Darüber hinaus wurde am 2026-02-25 die Ed25519-Signierung der Routing-Attestation implementiert und durch einen automatisierten Fälschungstest abgesichert (8/8 Tests bestanden).

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft ein computerimplementiertes System zur atomaren Übertragung von Währungsbeträgen über eine Kette von Liquiditätsprovider-Hops, mit dokumentiertem Wechselkurskontext pro Hop, serverseitig erzwungener Timeout-Invariante und kryptografisch signierter, haftungserzeugende Routing-Optimalitätsbestätigung.

### 2.2 Bezug zu den Stamm-Schutzrechten

**GBM-0** liefert das SIGIL-Identitätssystem (DID, Ed25519) sowie den HMAC-Prüfprotokollrahmen. **GBM-1** liefert das Transfer-Intent-Primitiv, die Atomaritätsgarantie und die Timeout-Invariante für Kettentransfers.

Die vorliegende Erfindung (GBM-3) fügt gegenüber GBM-0 und GBM-1 hinzu:

- Wechselkurskontext (`FxContext`) als verpflichtender Dokumentationsbestandteil jedes Hop
- Mehrfach-Hop-Transfer-Intent (`MultiHopIntent`) als Erweiterung des BridgeIntent
- Kryptografisch signierte Routing-Optimalitätsbestätigung durch einen DID-haftenden Routing-Dienst (`RouteAttestation`)
- Online-Volatilitätsmonitoring des Transaktionsstroms (CUSUM + Realized Variance)

### 2.3 Stand der Technik und Abgrenzung

Interledger Protocol, Ripple/XRP (US10346819B2): Pfadsuche ohne DID-haftende Routing-Attestation. Keine serverseitige Timeout-Invariantenerzwingung. Kein dokumentierter Wechselkurskontext pro Hop. Kein eingebettetes Volatilitätsmonitoring.

Die Kombination aller vier Merkmale ist in keiner veröffentlichten Patentliteratur bekannt.

### 2.4 Offenbarung der Erfindung

**Mehrfach-Hop-Transfer-Intent:**

Ein `MultiHopIntent`-Datensatz enthält:

- Sequenz von BridgeIntents (GBM-1) mit jeweils einem Liquiditätsprovider-DID und einem `FxContext`
- Optionale `RouteAttestation`
- DID-Identifikatoren von Sender und Empfänger (GBM-0)

**Wechselkurskontext (FxContext):**

Pro Hop: Quellwährung, Zielwährung, Kurs (Dezimalzeichenkette), Kursquelle, Zeitpunkt der Kursermittlung, Gültigkeitsende. Ermöglicht vollständige MiFID II / EMIR-Dokumentation für jeden Hop.

**Routing-Attestation — implementiert und kryptografisch gesichert (Stand 2026-02-25):**

```
Canonical Form = JSON({
  attestation_id, attesting_service, dest_currency,
  selected_route_index, source_currency, valid_at, valid_until
})
proof_bytes = Ed25519_Sign(routing_service_sk, canonical_bytes)
```

Ein DID-identifizierter Routing-Dienst bestätigt kryptografisch, dass (a) alle bewerteten Routen betrachtet wurden und (b) die ausgewählte Route nach dokumentierten Kriterien zum Zeitpunkt `valid_at` optimal war. Die Attestation verbleibt on-side beim Sender. Bei Streit (»zu hohe Gebühren«) beweist sie, dass keine günstigere konforme Route existierte. Der Routing-Dienst ist durch seinen DID haftbar.

**Verifizierungsgarantie:**

Tampering-Test (automatisierter Einheitentest, 2026-02-25):

- Signierte Attestation verifiziert korrekt → `Ok(())`
- Attestation mit modifiziertem Feld → `Err(InvalidSignature)`
- Attestation ohne Signatur → `Err(MissingSignature)`

**Online-Volatilitätsmonitoring:**

- Realized Variance: `RV = Σ r²ᵢ` — konsistente Integralvarianzschätzung
- Bipower Variation: BV nach Barndorff-Nielsen & Shephard — sprung-robust
- CUSUM-Statistik nach Andersen, Tan, Todorov, Zhang (2025) — Journal of Econometrics
- Funktionale HKA nach Tan, Tan, Tang, Zhang (2024) — Journal of Forecasting

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig, aufbauend auf GBM-0 und GBM-1): Computerimplementiertes Verfahren zur atomaren Übertragung eines Währungsbetrags über eine oder mehrere Liquiditätsprovider-Hops unter Verwendung des SIGIL-Protokolls (GBM-0, 2026-02-23) und des SIGIL-Bridge-Core-Transferprimitivs (GBM-1, 2026-02-25), dadurch gekennzeichnet, dass es:

(a) einen Mehrfach-Hop-Transfer-Intent entgegennimmt, der eine geordnete Sequenz von BridgeIntents (GBM-1) enthält, wobei jeder BridgeIntent mit dem DID-Identifikator des jeweiligen Liquiditätsproviders und einem dokumentierten Wechselkurskontext (Quellwährung, Zielwährung, Kurs, Kursquelle, Zeitpunkt, Gültigkeitsende) versehen ist;

(b) serverseitig für alle aufeinanderfolgenden Hop-Paare prüft, dass der Timeout des äußeren BridgeIntents denjenigen des nächstinneren übersteigt — gemäß GBM-1 Anspruch 2, jedoch auf den mehrsprachigen Devisenkontext erweitert;

(c) für jeden Hop prüft, dass der Wechselkurskontext zum Zeitpunkt der Entgegennahme noch gültig ist;

(d) den Mehrfach-Hop-Transfer-Intent bei bestandener Prüfung als Ganzes atomar registriert.

**Anspruch 2** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Mehrfach-Hop-Transfer-Intent optional eine kryptografisch signierte Routing-Optimalitätsbestätigung trägt, welche den DID des bestätigenden Routing-Dienstes, alle bewerteten Routenoptionen, den Index der ausgewählten Route, die angewandten Auswahlkriterien und den Gültigkeitszeitraum enthält, und dass die Signatur als Ed25519-Signatur (oder algorithmisch äquivalentes Verfahren gemäß der Kryptoagilität von GBM-1 Anspruch 5) über eine kanonische, deterministische Serialisierung der identitätskritischen Attestationsfelder gebildet wird.

**Anspruch 3** (abhängig von 2): Verfahren nach Anspruch 2, dadurch gekennzeichnet, dass der empfangende Verifier die Korrektheit der Routing-Attestation durch Rekonstruktion der kanonischen Serialisierung und Prüfung der Signatur gegen den im DID-Dokument des Routing-Dienstes gespeicherten öffentlichen Schlüssel verifizieren kann, und dass eine Modifikation eines einzelnen Attestationsfelds nach der Signierung die Verifikation fehlschlagen lässt.

**Anspruch 4** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Wechselkurskontext die für MiFID II und EMIR erforderlichen Dokumentationsfelder enthält, sodass für jede Transaktionsstufe ein vollständiger Prüfpfad des verwendeten Wechselkurses im SIGIL-Prüfprotokoll (GBM-0 Schicht 1) archiviert wird.

**Anspruch 5** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass ein integriertes Online-Monitoringsystem aus dem Transaktionsstrom Realized Variance und Bipower Variation nach Barndorff-Nielsen und Shephard berechnet, eine CUSUM-Teststatistik zur Erkennung von Regimewechseln im Wechselkursprozess anwendet und bei Überschreitung konfigurierter Schwellen regulatorische Warnmeldungen erzeugt.

**Anspruch 6** (abhängig von 5): Verfahren nach Anspruch 5, dadurch gekennzeichnet, dass das Online-Monitoring zusätzlich eine funktionale Hauptkomponentenzerlegung des intraday-Volatilitätsprofils durchführt und den Abstand des aktuellen Profils von der empirischen Mittelkurve als weiteres Anomalieerkennungsmerkmal verwendet.

---

## 4. Zusammenfassung (Abstract)

Aufbauend auf dem SIGIL-Protokoll (GBM-0) und dem SIGIL-Bridge-Core (GBM-1) ermöglicht das Verfahren die atomare Übertragung von Währungsbeträgen über eine beliebige Anzahl von DID-identifizierten Liquiditätsprovider-Hops. Pro Hop wird ein BridgeIntent (GBM-1) mit dokumentiertem Wechselkurskontext (MiFID II / EMIR-konform) verbunden. Eine Timeout-Invariante (GBM-1 Anspruch 2) wird auf den Mehrfach-Hop-Kontext erweitert. Optional trägt der Intent eine kryptografisch signierte Routing-Optimalitätsbestätigung eines haftenden, DID-identifizierten Routing-Dienstes, deren Korrektheit durch Fälschungstest automatisiert nachgewiesen ist (Stand 2026-02-25). Ein integriertes Online-Monitoring berechnet Realized Variance, Bipower Variation und CUSUM-Statistiken. Der Signaturmechanismus erbt die Kryptoagilität von GBM-1 Anspruch 5. (≈ 115 Wörter)

---

*SIGIL-FXBRIDGE · GBM-3 · 2026-02-25 · Patent Pending · EUPL-1.2*
