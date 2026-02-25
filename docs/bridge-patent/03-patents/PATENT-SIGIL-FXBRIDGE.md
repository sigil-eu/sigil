# PATENT — SIGIL-FXBRIDGE

## DE Gebrauchsmuster · Offenes atomares Mehrfach-Devisentransferprotokoll mit kryptografisch haftender Routing-Attestation

## GBM-4 der SIGIL-Patentfamilie

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

Betreff: Gebrauchsmusteranmeldung — SIGIL-FXBRIDGE (GBM-4)

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster für ein computerimplementiertes System zur atomaren Devisenübertragung über beliebige Liquiditätsprovider-Ketten an. Die Erfindung ist bewusst offen konzipiert: Als Liquiditätsprovider kommt jeder DID-identifizierte Teilnehmer mit ausreichender Liquiditätszusage infrage — Zentralbanken, Geschäftsbanken, Broker, Market Maker, Fintech-Plattformen oder automatisierte Liquiditätspools. Das System ist kompatibel mit bestehenden Devisenhandelssystemen (CLS, FX Spot, FX Forward, Korrespondentbanken-Netzwerke) und ergänzt diese um kryptografische Nicht-Repudierbarkeit je Routing-Hop.

Die Kernerfindung gegenüber GBM-0 bis GBM-2 ist die **kryptografisch signierte Routing-Optimalitätsbestätigung (RouteAttestation)** durch einen haftenden, DID-identifizierten Routing-Dienst. Implementiert und durch automatisierten Fälschungstest abgesichert, 2026-02-25.

Anliegend: Beschreibung, Ansprüche, Zusammenfassung.

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft ein computerimplementiertes System zur atomaren Übertragung von Währungsbeträgen über eine oder mehrere Liquiditätsprovider-Hops mit dokumentiertem Wechselkurskontext pro Hop, serverseitig erzwungener Timeout-Ketteninvariante (GBM-2 Anspruch 2) und kryptografisch signierter, haftungserzeugender Routing-Optimalitätsbestätigung.

### 2.2 Offenheit des Systems — Alle Liquiditätsprovider-Klassen

Das Protokoll ist vollständig offen für die Integration beliebiger Liquiditätsprovider und bestehender Devisen-Handelsinfrastrukturen:

| Liquiditätsprovider-Klasse | Identifikation | Integration |
|---|---|---|
| Zentralbanken und Währungsbehörden | W3C-DID + qualifiziertes Zertifikat | CBDC-Interoperabilität |
| Geschäftsbanken und Landesbanken | W3C-DID + LEI | Korrespondentbanken-Netzwerk |
| FX-Broker und Market Maker | W3C-DID + regulatorische ID | FX Spot, FX Forward |
| Automatisierte Liquiditätspools (AMM) | W3C-DID + Contract-Adresse | DeFi-Interoperabilität |
| Fintech-Plattformen und PSPs | W3C-DID + PSD2-Lizenz-ID | Open Banking |

Jede Entität, die einen gültigen W3C-DID-Identifikator vorlegt und eine Liquiditätszusage für den angeforderten Betrag und die angeforderte Währung vorhält, kann als Hop-Provider teilnehmen.

### 2.3 Kompatibilität mit bestehenden Devisensystemen

- **CLS (Continuous Linked Settlement)**: SIGIL-FXBridge kann als Attestationsschicht über CLS-Settlements integriert werden; der CLS-Settlement-Identifier kann als Referenz im FxContext gespeichert werden.
- **SWIFT FIN (MT 300, MT 202C)**: Devisenbestätigungsnachrichten können mit SIGIL-RouteAttestation referenziert werden.
- **FX Spot / FX Forward**: Der FxContext-Datensatz enthält Kurs, Kursquelle, Valutadatum und Gültigkeitszeitfenster — MiFID-II-konform dokumentiert.
- **Korrespondentbanken-Netzwerke**: Jeder Hop in der BridgeIntent-Kette repräsentiert eine Korrespondentbankbeziehung, jetzt mit kryptografischer Nachweisbarkeit des vereinbarten Wechselkurses.
- **ISO 20022 / FX Confirmation (fxtr.014–016)**: FxContext ist mit dem ISO-20022-FX-Bestätigungsschema kompatibel.

### 2.4 Bezug zu den Stamm-Schutzrechten

**GBM-0**: DID-Identitätssystem, Ed25519-Signaturrahmen, HMAC-Prüfkette.
**GBM-1**: Kryptoagilität — RouteAttestation erbt automatisch den PQ-Upgrade-Pfad.
**GBM-2**: BridgeIntent-Sequenz als Bauprimitive jedes Hops; Timeout-Ketteninvariante (Anspruch 2) direkt übernommen.

### 2.5 Offenbarung der Erfindung

**Mehrfach-Hop-Transfer-Intent:**

- Geordnete Sequenz von GBM-2-BridgeIntents mit je einem Liquiditätsprovider-DID
- Optionale RouteAttestation eines DID-identifizierten Routing-Dienstes
- Sender- und Empfänger-DID des Gesamttransfers

**Wechselkurskontext (FxContext) pro Hop:**

| Feld | Inhalt |
|---|---|
| `source_currency` | ISO-4217 Quellwährung |
| `dest_currency` | ISO-4217 Zielwährung |
| `rate` | Kurs als Dezimalzeichenkette (Gleitkomma-frei) |
| `rate_source` | Kursquelle (EZB-Referenzkurs, Bloomberg, etc.) |
| `determined_at` | Zeitstempel der Kursermittlung |
| `valid_until` | Gültigkeitsende (MiFID II RTS 27/28) |

**RouteAttestation — kryptografisch signiert (Stand 2026-02-25 implementiert):**

```
canonical_input = JSON({
  attestation_id, attesting_service_did, dest_currency,
  selected_route_index, source_currency, valid_at, valid_until
})
proof_bytes = Sign(routing_service_sk, canonical_input)
```

Der Routing-Dienst bestätigt kryptografisch: alle bewerteten Routen wurden berücksichtigt, die ausgewählte war nach dokumentierten Kriterien zum Zeitpunkt `valid_at` optimal. Tampering-Test bestanden (2026-02-25): Modifikation eines Felds → `InvalidSignature`.

**Integriertes Volatilitätsmonitoring:**

- Realized Variance (RV = Σ rᵢ²) und Bipower Variation — sprungrobust
- CUSUM-Statistik nach Andersen, Tan, Todorov, Zhang (J. Econometrics 2025)
- Funktionale HKA nach Tan, Tan, Tang, Zhang (J. Forecasting 2024)

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig — offenes Multi-Hop-FX-Protokoll): Computerimplementiertes Verfahren zur atomaren Übertragung eines Währungsbetrags über eine oder mehrere durch W3C-DID-Identifikatoren benannte Liquiditätsprovider-Hops unter Verwendung des SIGIL-Protokolls (GBM-0, DPMA 2026-02-23) und des SIGIL-Bridge-Core-Transferprimitivs (GBM-2, 2026-02-25), offen für alle Klassen von Liquiditätsprovidern — Zentralbanken, Geschäftsbanken, Broker, automatisierte Liquiditätspools und Fintech-Plattformen — dadurch gekennzeichnet, dass es:

(a) einen Mehrfach-Hop-Transfer-Intent entgegennimmt, der eine geordnete Sequenz von BridgeIntents (GBM-2) enthält, wobei jeder BridgeIntent mit dem DID des Liquiditätsproviders und einem vollständigen Wechselkurskontext versehen ist;

(b) serverseitig für alle aufeinanderfolgenden Hop-Paare prüft, dass der Timeout des äußeren BridgeIntents denjenigen des nächstinneren übersteigt (Timeout-Ketteninvariante, GBM-2 Anspruch 2), erweitert auf den Devisenkontext;

(c) für jeden Hop prüft, dass der Wechselkurskontext zum Zeitpunkt der Entgegennahme noch gültig ist;

(d) den Mehrfach-Hop-Transfer-Intent bei bestandener Prüfung als Ganzes atomar registriert.

**Anspruch 2** (abhängig von 1 — MiFID-II-konformer Wechselkurskontext): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Wechselkurskontext pro Hop mindestens enthält: Quellwährung, Zielwährung, Kurs als Dezimalzeichenkette ohne Gleitkommadarstellung, identifizierte Kursquelle, Zeitstempel der Kursermittlung und Gültigkeitsende — konform zu MiFID II (EU) 2014/65 RTS 27/28 für Best-Execution-Nachweise.

**Anspruch 3** (abhängig von 1 — kryptografische Routing-Attestation): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Mehrfach-Hop-Transfer-Intent optional eine Routing-Optimalitätsbestätigung trägt, die enthält: den DID des Routing-Dienstes, alle bewerteten Routenoptionen, den Index der ausgewählten Route, angewandte Auswahlkriterien und Gültigkeitszeitraum; und dass die Bestätigung als kryptografische Signatur (gemäß GBM-0 / GBM-1) über eine kanonische Serialisierung der entscheidungsrelevanten Felder gebildet wird.

**Anspruch 4** (abhängig von 3 — Fälschungssicherheit): Verfahren nach Anspruch 3, dadurch gekennzeichnet, dass die Modifikation eines einzigen Felds der Routing-Optimalitätsbestätigung nach der Signierung die Verifikation fehlschlagen lässt, nachgewiesen durch automatisierten Fälschungstest (2026-02-25).

**Anspruch 5** (abhängig von 1 — Systemoffenheit): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass jede Entität, die einen W3C-DID-konformen Identifikator vorlegt und eine Liquiditätszusage für den angeforderten Betrag vorhält, als Liquiditätsprovider-Hop teilnehmen kann, ohne gesonderte Zulassung durch den Systembetreiber — kompatibel mit CLS, SWIFT FIN MT 300/202C, ISO 20022 FX (fxtr.014–016) und DeFi-AMM-Systemen.

**Anspruch 6** (abhängig von 1 — Online-Volatilitätsmonitoring): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass ein integriertes Monitoring aus dem Transaktionsstrom Realized Variance, Bipower Variation und eine CUSUM-Statistik berechnet und bei Überschreitung konfigurierter Schwellen Warnmeldungen erzeugt.

---

## 4. Zusammenfassung (Abstract)

Aufbauend auf GBM-0, GBM-1 und GBM-2 ermöglicht das Verfahren die atomare Übertragung von Währungsbeträgen über eine beliebige Kette von DID-identifizierten Liquiditätsprovidern (Zentralbanken, Geschäftsbanken, Broker, AMM, Fintech). Pro Hop wird ein BridgeIntent (GBM-2) mit MiFID-II-konformem Wechselkurskontext verknüpft. Die Timeout-Ketteninvariante (GBM-2 Anspruch 2) wird auf den Devisenkontext erweitert. Optional trägt der Intent eine kryptografisch signierte Routing-Optimalitätsbestätigung eines haftenden, DID-identifizierten Routing-Dienstes — Fälschungssicherheit durch automatisierten Test nachgewiesen (2026-02-25). Systemoffenheit: jeder DID-identifizierte Liquiditätsprovider teilnahmefähig, kompatibel mit CLS, SWIFT, ISO 20022 FX. Kryptoagil via GBM-1. (≈ 110 Wörter)

---

*SIGIL-FXBRIDGE · GBM-4 · 2026-02-25 · Patent Pending · EUPL-1.2*
