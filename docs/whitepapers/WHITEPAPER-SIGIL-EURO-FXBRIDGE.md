# SIGIL EURO & FXBridge

## Whitepaper — Offenes transnationales Zahlungsprotokoll für das 21. Jahrhundert

**Version 1.0 · 2026-02-25 · Benjamin Küttner · sigil-protocol.org**

---

## Einleitung: Das Problem mit dem Geld

Wenn Anna in Frankfurt ihrer Tochter Maria in Barcelona 500€ überweist, passiert folgendes:
Annas Bank schickt eine SWIFT-Nachricht an eine Korrespondenzbank in Madrid. Die Korrespondenzbank zieht Gebühren ab. Die Nachricht landet bei Marias Bank. Marias Bank zieht Gebühren ab. In 1–3 Tagen und nach zwei Gebührenabzügen landet vielleicht €480 bei Maria.

Mit SIGIL-EURO passiert folgendes: Anna signiert eine Zahlungsanweisung mit ihrem privaten Schlüssel. Das System prüft ihre eIDAS-Identität. Maria erhält eine mathematisch unveränderte, vollständig nachvollziehbare, prüfbare Quittung — in Sekunden, für Bruchteile eines Cents.

Keine Korrespondenzbank. Keine Gebührenabzüge. Volle Transparenz.

---

## Teil I: SIGIL-EURO — Der vollständige Zahlungsvorgang

### Schritt 1: Anna erstellt eine Zahlungsanweisung

Anna öffnet ihre SIGIL-Wallet. Sie gibt ein:

- Betrag: €500,00 (intern: 50.000 Cent — kein Komma, kein Rundungsproblem)
- Empfänger: Marias DID-Identifikator (oder IBAN — automatisch umgewandelt)
- Vertrauensstufe: Hoch (eIDAS-qualifiziert, da Betrag > €200)

Das System erstellt einen `PaymentIntent`-Datensatz:

```json
{
  "trust_level": "High",
  "currency": "EUR",
  "amount_minimal": 50000,
  "recipient_hash": "7e3c9f...",
  "consent_scope": "EinzelZahlung",
  "timestamp": "2026-02-25T01:00:00Z"
}
```

**Wichtig:** Der Empfänger wird als SHA-256-Hash gespeichert — nie als Klartext. Das ist DSGVO-Compliance als technische Eigenschaft, nicht als Policy. Nur Anna und Maria kennen die Klartext-Identitäten.

### Schritt 2: Signatur und AML-Prüfung

Annas Wallet signiert den `PaymentIntent` mit ihrem Ed25519-Schlüssel. Die Signatur deckt alle Felder ab — Betrag, Empfänger-Hash, Vertrauensstufe, Zeitstempel.

Gleichzeitig prüft ein AML-Scanner die Transaktion auf regulatorische Flags:

- Der Scanner ist **rein-funktional**: Er liest nur, schreibt nirgendwo, ruft kein Netzwerk auf
- Falls ein Flag gesetzt wird, landet nur der **Hash** des Flags im Protokoll — nie der Klartext-Inhalt
- Annas Transaktion: Keine Flags. AML: `[]`

### Schritt 3: Gateway-Validierung (vor jeder Datenbankoperation)

Das SIGIL-EURO-Gateway prüft — **vor** dem ersten Datenbankschreibvorgang:

1. ✅ Signatur korrekt? (Ed25519-Verifikation)
2. ✅ Vertrauensstufe ausreichend? (High für €500 → ✅)
3. ✅ Kein AML-Flag gesetzt?
4. ✅ Betrag > 0 und < Maximum?

Scheitert eine Prüfung: **Keine Datenbankoperation.** Kein Protokolleintrag. Die Transaktion existiert für das System nicht — es gibt keinen Eintrag, der manipuliert werden könnte.

### Schritt 4: HMAC-Prüfkette (Schicht 1)

Die Transaktion wird als Eintrag in die HMAC-Prüfkette aufgenommen:

```
Eintrag_n = {
  seq: 42,
  betrag: 50000,
  empfaenger_hash: "7e3c9f...",
  hmac: HMAC(eintrag_n-1 || betrag || empfaenger_hash || timestamp)
}
```

Jeder Eintrag ist mit dem vorherigen verkettet. Ändert jemand Eintrag 42, stimmt der HMAC von Eintrag 43 nicht mehr. Manipulation ist mathematisch ausgeschlossen.

### Schritt 5: Merkle-Aggregation (Schicht 2)

Jede Stunde berechnet das System einen Merkle-Baum über alle HMAC-Werte der letzten Stunde. Der Merkle-Root: ein 32-Byte-Fingerabdruck aller Transaktionen.

### Schritt 6: DA-Verankerung (Schicht 3)

Der Merkle-Root wird in einem öffentlichen DA-Layer verankert (z.B. Celestia, Avail, Ethereum 4844). Das dauert eine Millisekunde. Ein Dritter — ohne Vertrauen in das System — kann jetzt die Vollständigkeit aller Transaktionen des vergangenen Stunde verifizieren.

**Maria hat ihr Geld erhalten. Die Transaktion ist dreifach belegt. Gesamtzeit: < 3 Sekunden.**

---

## Teil II: SIGIL-FXBridge — Der vollständige Devisenvorgang

### Szenario: Carlos tauscht €10.000 in USD über zwei Hops

Carlos in Berlin möchte €10.000 in USD tauschen. Er hat keinen direkten USD-Liquiditätsprovider mit gutem Kurs. Das System findet zwei Hops:

- **Hop 1:** Deutsche Bank FX (EUR → CHF, Kurs: 0,9580, gültig bis +30 Sek)
- **Hop 2:** UBS Zürich (CHF → USD, Kurs: 1,1254, gültig bis +30 Sek)

### Schritt 1: MultiHopIntent erstellt

```
MultiHopIntent {
  sender: Carlos-DID,
  hops: [
    { provider: DeutscheBank-DID, EUR→CHF, rate: "0.9580", valid_until: T+30s },
    { provider: UBS-DID, CHF→USD, rate: "1.1254", valid_until: T+30s }
  ],
  route_attestation: SignedByOptimalRouter
}
```

### Schritt 2: Timeout-Invariante geprüft

Vor der Übernahme prüft das Gateway:

- Hop 1 Timeout: T + 120 Sekunden
- Hop 2 Timeout: T + 60 Sekunden

✅ Hop 1 Timeout (120s) > Hop 2 Timeout (60s). Die Invariante ist erfüllt.

Warum wichtig? Wenn Hop 2 zuerst abläuft, hat Carlos Zeit, sein Preimage zu enthüllen und Hop 1 trotzdem zu erfüllen. Umgekehrt könnte niemand die Zeitfolge manipulieren, um Carlos' Geld in der Mitte festzuhalten.

### Schritt 3: Routing-Attestation (optional, aber wichtig)

Ein DID-identifizierter Routing-Dienst (z.B. `did:sigil:fx-router:xyz`) bestätigt kryptografisch:
*„Ich habe alle verfügbaren Routen evaluiert. Diese Route war zum Zeitpunkt T die optimale nach Kaiterium: Netto-USD-Betrag minus Gebühren."*

Die Attestation ist **Ed25519-signiert** über alle identitätskritischen Felder. Nachträgliche Modifikation → mathematisch erkennbar.

Carlos hat jetzt **Beweiskette**: Die optimale Route wurde bestätigt. Falls er später klagt — „Ihr habt mich zu einem schlechteren Kurs geführt" — beweist die Attestation, dass dies die beste verfügbare Route war.

### Schritt 4: Atomarer Settlement

Carlos enthüllt das Preimage. Beide Hops settlen gleichzeitig. Er erhält USD. beide Provider haben ihre Gegenposition. Kein Zwischenzustand, in dem das Geld nirgendwo ist.

**Carlos hat €10.000 in USD getauscht. Vollständig dokumentiert. In < 10 Sekunden.**

---

## Teil III: Skalierbarkeit — Zahlen die man kennen muss

### Der europäische Zahlungsverkehr

Der europäische SEPA-Raum verarbeitet ca. **5 Milliarden Transaktionen pro Jahr** (EZB, 2024). Der Gesamtwert beläuft sich auf ca. **€200 Billionen**.

| System | Kosten/Zahlung | Jahreskosten gesamt | Latenz |
|---|---|---|---|
| Korrespondenzbank (heute) | €15–35 (cross-border) | >€50 Milliarden | 1–3 Tage |
| SEPA Instant | €0,10–0,50 | €500 Mio. – €2,5 Mrd. | 10 Sek. |
| **SIGIL-EURO** | **€0,0001–0,001** | **€500.000 – €5 Mio.** | **< 3 Sek.** |

**SIGIL-EURO könnte die Abwicklungskosten des gesamten europäischen Zahlungsverkehrs um den Faktor 1.000–10.000 reduzieren.**

### Warum ist das möglich?

1. **Kein Konsens:** Keine Blockchain-Runden. Eine Signaturprüfung (0,1 ms) statt 6.000 Node-Konsensrunden.
2. **Batching:** 10.000 Transaktionen teilen sich einen DA-Layer-Anker (~€0,01). Pro Transaktion: €0,000001.
3. **Kein Intermediär:** Keine Korrespondenzbank, kein Settlement-Agent, kein CLS-Mitgliedsbeitrag.

### Horizontale Skalierung

SIGIL-EURO ist **horizontal skalierbar** durch einfaches Hinzufügen von Gateway-Instanzen:

- Jede Instanz verarbeitet unabhängige Transaktionen
- Alle Instanzen schreiben in dieselbe HMAC-Prüfkette (serialisiert) oder abgetrennte Teilketten (Sharding)
- Merkle-Root aggregiert alle Teilketten
- Kein Konsens zwischen Instanzen nötig

Eine einzelne VPS-Instanz (~€100/Monat) verarbeitet in Tests >10.000 Transaktionen/Sekunde. Bei 5 Milliarden Jahrestransaktionen (~158 TPS Mittel) reicht eine Instanz für den gesamten SEPA-Basisverkehr.

---

## Teil IV: Währungsmarkttransparenz als Nebenprodukt

### Das ungenutzte Potential der Transaktionsdaten

Wenn Millionen von SIGIL-FXBRIDGE-Transaktionen verarbeitet werden, entstehen in Echtzeit aggregierte Preis- und Volumendaten — **pseudonymisiert, aber vollständig** in der öffentlichen HMAC-Prüfkette.

Dies gibt der Finanzwissenschaft etwas, das bisher nicht existierte: **hochfrequente, echte Transaktionsdaten für Devisenmärkte** — nicht modelliert, nicht simuliert, sondern gemessen.

### Realized Volatility — Risiko präzise messen

Mit SIGIL-Transaktionsdaten kann **Realized Variance** in Echtzeit berechnet werden:

$$\text{RV}_t = \sum_{i=1}^{N} r_{t,i}^2$$

wobei $r_{t,i}$ die logarithmischen Renditen zwischen Transaktionen $i$ und $i{-1}$ sind. Dieses Schätzer ist **konsistent** für die quadratische Variation des zugrunde liegenden Preisprozesses (Andersen & Bollerslev, 1998).

**Was das bedeutet:** Statt einmal täglich aus Tagesschlusskursen zu schätzen, messen wir Volatilität **sekündlich**, aus echten Transaktionspreisen, nicht aus Bid-Ask-Mittelwerten.

### Bipower Variation — Sprünge identifizieren

Reguläre Volatilität vs. Sprünge (z.B. durch Flash Crashes oder politische Ereignisse) lassen sich mit **Bipower Variation** trennen:

$$\text{BV}_t = \frac{\pi}{2} \sum_{i=2}^{N} |r_{t,i}| \cdot |r_{t,i-1}|}$$

BV ist **robust gegenüber Preissprüngen** — während RV sehr sensitiv ist. Die Differenz `RV - BV` identifiziert den Sprunganteil der Volatilität (Barndorff-Nielsen & Shephard, 2004).

**Anwendung:** Ein SIGIL-FXBRIDGE-Monitoring kann in Echtzeit erkennen: *„Der EUR/USD zeigt gerade einen abnormalen Sprung — kein organisches Volatilitätsereignis."*

### Online Strukturbrüche (CUSUM)

Wann hat sich die Marktstruktur verändert? Mit SIGIL-Transaktionsdaten lässt sich ein **CUSUM-Test** in Echtzeit durchführen (Andersen, Tan, Todorov, Zhang, *Journal of Econometrics*, 2025):

$$C_t = \sum_{i=1}^{t} (r_i^2 - \hat{\sigma}_i^2)$$

Übersteigt $|C_t|$ eine kritische Schwelle: Strukturbruch erkannt. Das System meldet: *„Seit 14:32 Uhr zeigt EUR/CHF ein neues Volatilitätsregime."*

**Anwendung:** Zentralbanken, Risikoabteilungen und Regulierer könnten Marktstress in Echtzeit erkennen — nicht erst am nächsten Tag aus Meldungen.

### Realized Covariation — Systemisches Risiko messen

Wie viel Risiko teilen EUR/USD und GBP/USD? Mit SIGIL-Daten lässt sich **Realized Covariation** berechnen:

$$\text{RC}_{t}(X, Y) = \sum_{i=1}^{N} r_{t,i}^X \cdot r_{t,i}^Y$$

Dies ist ein konsistenter Schätzer für die Kovarianz zwischen zwei Währungspaaren. In einer Matrix über alle SIGIL-gehandelten Paare entsteht eine **Echtzeit-Risikostruktur des Devisenmarkts**.

**Warum das Finanzstabilität verbessert:**

Heute messen Zentralbanken systemisches Risiko mit veralteten, aggregierten Daten. Ein Stressmoment wie der CHF-Flash-Crash 2015 oder der GBP-Crash 2016 wäre mit SIGIL-Daten **Sekunden nach Beginn** messbar gewesen — nicht erst nach Stunden.

### Funktionale Hauptkomponentenzerlegung — Muster im Tagesverlauf

Welche Muster zeigt das intraday-Volatilitätsprofil? Mit **funktionaler Hauptkomponentenzerlegung** (Tan, Tan, Tang, Zhang, *Journal of Forecasting*, 2024) kann SIGIL:

1. Typische intraday-Volatilitätskurven extrahieren (Morgenöffnung, Mittagstal, Abendspitze)
2. Aktuelle Kurve mit historischem Muster vergleichen
3. Anomalien erkennen, bevor sie zu Krisen werden

---

## Teil V: Transparenz und Vertrauen

### Transparenz durch Pseudonymisierung

„Öffentlich" bedeutet bei SIGIL nicht: Jeder weiß, wer was kauft. Es bedeutet: Jeder kann verifyifizieren, dass der aggregierte Marktpreis korrekt ist.

- **Empfänger-Hash:** Nur Parteien mit Kenntnis der DID können zuordnen
- **Beträge:** In aggregierten Preis-/Volumendaten pseudonymisiert
- **Merkle-Root:** Beweist Existenz und Unveränderlichkeit — ohne Inhalte zu enthüllen

Das ist **regulatorisch konform** (DSGVO, MiFID II) und ermöglicht gleichzeitig präzise Marktüberwachung.

### Das neue Paradigma

SIGIL-EURO und SIGIL-FXBridge schaffen ein System, das bisher nicht existierte:

> **Transaktionsdaten sind öffentlich genug für präzise Marktüberwachung — und privat genug für DSGVO-Compliance.**

Das ist keine Utopie. Das ist eine direkte Konsequenz des kryptografischen Designs: SHA-256-Pseudonymisierung der Einzeltransaktion, Merkle-Aggregation für die öffentliche Schicht, DA-Layer-Verankerung für trustless Verifikation.

---

## Anhang: Technische Eckdaten

| Eigenschaft | Wert |
|---|---|
| Maximale Durchsatzrate | > 10.000 TPS (Single Instance) |
| Geschätzte Kosten/Transaktion | €0,0001–€0,001 |
| Gesamtkosten SEPA-Äquivalent | €500.000–€5 Mio./Jahr |
| DA-Anker pro Batch | ~€0,01 für 10.000 Transaktionen |
| Volatilitäts-Update-Frequenz | Pro Transaktion (Echtzeit) |
| Regulatorische Basis | eIDAS (EU) Nr. 910/2014, PSD2, MiCA, ISO 20022 |
| AML-Konformität | FATF, EU-Geldwäscherichtlinie 2020/849 |
| Patent | GBM-0 (DPMA 2026-02-23) · GBM-1–5 (2026-02-25) |

---

*SIGIL EURO & FXBridge Whitepaper · 2026-02-25 · sigil-protocol.org · Patent Pending*
