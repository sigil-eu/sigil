# PATENT — SIGIL-FXBRIDGE

## DE Gebrauchsmuster — Atomic Multi-Hop FX Transfer with Route Attestation

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, [Adresse eintragen]
**Priorität:** Fortführung DE Gebrauchsmuster SIGIL Protocol (2026-02-22) + SIGIL-BRIDGE-CORE (2026-02-25)
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Anmeldung eines Gebrauchsmusters — SIGIL-FXBRIDGE

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster für ein computerimplementiertes Verfahren zur **atomaren, mehrschrittig verketteten Devisenübertragung mit kryptografisch signierter Routing-Attestation und Online-Volatilitätsüberwachung** an.

Die Erfindung wurde am 2026-02-24 im Echtbetrieb auf einem produktiven Server demonstriert — ein `MultiHopIntent` für EUR→USD wurde erfolgreich angenommen, die Timeout-Invariante wurde serverseitig verifiziert.

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft ein computerimplementiertes System zur atomaren Übertragung von Währungsbeträgen über mehrere Liquiditätsprovider hinweg, mit dokumentiertem Wechselkurskontext pro Hop, serverseitig erzwungener Timeout-Invariante und kryptografisch signierter Routing-Optimalitätsbestätigung durch einen identifizierten Routing-Dienst.

### 2.2 Stand der Technik

Das W3C Interledger Protocol (ILP) beschreibt atomare Cross-Ledger-Transfers auf Protokollebene, spezifiziert jedoch nicht: (1) die Dokumentation des Wechselkurses pro Hop, (2) die serverseitige Erzwingung von Timeout-Invarianten, (3) eine haftungserzeugende, kryptografisch signierte Routing-Optimalitätsbestätigung, oder (4) CUSUM-basiertes Online-Volatiliätsmonitoring des Transaktionsstroms. Ripple/XRP (US10346819B2) implementiert Pfadsuche, erzeugt aber keine attributierten Attestationen durch identifizierte Dienste.

### 2.3 Offenbarung der Erfindung

**MultiHopIntent-Struktur:**

```rust
pub struct MultiHopIntent {
    pub intent_id:         String,
    pub sender:            Did,
    pub receiver:          Did,
    pub hops:              Vec<HtlcHop>,
    pub route_attestation: Option<RouteAttestation>,
    pub created_at:        i64,
}

pub struct HtlcHop {
    pub contract:   HtlcContract,  // HTLC gemäß SIGIL-BRIDGE-CORE
    pub fx_provider: Did,          // DID des Liquiditätsproviders
    pub fx_context: FxContext,     // Dokumentierter Wechselkurs
    pub label:      String,
}
```

**FxContext (Wechselkursdokumentation):**

```rust
pub struct FxContext {
    pub source_currency: String,   // "EUR"
    pub dest_currency:   String,   // "USD"
    pub rate:            String,   // "1.0812"
    pub rate_source:     String,   // "ECB Reference Rate"
    pub rate_timestamp:  i64,      // Zeitpunkt der Kursermittlung
    pub valid_until:     i64,      // Kurs gültig bis (z.B. +30 Sek)
}
```

Die Timeout-Invariante `timeout[i] > timeout[i+1]` für alle i wird serverseitig erzwungen. Ein Intent, der diese Invariante verletzt, wird vor jedem Schreibzugriff mit `422 Unprocessable Entity` abgewiesen.

**Live-Evidenz (2026-02-24):**

- Intent `SIGIL-FX-1771973584-e2e` (EUR→USD, 1 Hop) angenommen
- `{"accepted":true,"hop_count":1,"is_direct":true,"timeout_invariant_ok":true}`

### 2.4 RouteAttestation — Haftende Routing-Optimalitätsbestätigung

```rust
pub struct RouteAttestation {
    pub attestation_id:      String,
    pub attesting_service:   Did,           // DID des Routing-Dienstes (haftend)
    pub evaluated_routes:    Vec<RouteOption>, // ALLE bewerteten Routen (transparent)
    pub selected_route_index: usize,
    pub criteria_applied:    RoutingCriteria,
    pub valid_at:            i64,
    pub valid_until:         i64,
    pub proof_bytes:         Vec<u8>,       // Ed25519 des Routing-Dienstes (Phase 2)
}
```

Der entscheidende Erfindungsaspekt: Ein DID-identifizierter Routing-Dienst bestätigt kryptografisch, dass alle bewerteten Routen betrachtet wurden und die ausgewählte zum Zeitpunkt `valid_at` nach dokumentierten Kriterien optimal war. Die Bestätigung verbleibt dauerhaft bei Alice als Nachweis dafür, dass zum Transferzeitpunkt keine günstigere konforme Route existierte.

### 2.5 Online-Volatilitätsmonitoring (CUSUM + Realized Variance)

Das System überwacht den Zahlungsintent-Datenstrom mit:

- **Realized Variance (RV):** `∑ r²_i` — konsistente Schätzung für integrierte Varianz
- **Bipower Variation (BV):** Sprung-robuster Schätzer nach Barndorff-Nielsen & Shephard
- **CUSUM-Statistik** nach Andersen, Tan, Todorov, Zhang (2025) — Journal of Econometrics
- **Funktionale Hauptkomponentenanalyse** nach Tan, Tan, Tang, Zhang (2024) — Journal of Forecasting

Überschreitet die CUSUM-Statistik konfigurierbare Schwellen (Yellow/Orange/Red), erzeugt das System automatisch regulatorische Warnmeldungen.

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig): Computerimplementiertes Verfahren zur atomaren Übertragung eines Währungsbetrags über eine oder mehrere Liquiditätsprovider-Hops, dadurch gekennzeichnet, dass es:

(a) einen `MultiHopIntent`-Datensatz entgegennimmt, der eine geordnete Liste von HTLC-Hops mit je einem Hashed-Time-Locked-Contract, dem dezentralen Identifikator des Liquiditätsproviders und einem dokumentierten Wechselkurskontext umfasst;

(b) serverseitig für alle aufeinanderfolgenden Hop-Paare (i, i+1) prüft, dass `hop[i].contract.timeout_at > hop[i+1].contract.timeout_at` gilt, und bei Verletzung die Einreichung mit `422 Unprocessable Entity` abweist;

(c) für jeden Hop serverseitig prüft, dass der Wechselkurskontext zum Zeitpunkt der Entgegennahme noch gültig ist (`jetzt ≤ valid_until`), und abgelaufene Kontexte ablehnt;

(d) die Transaktion bei erfolgreicher Prüfung als `MultiHopIntent` in einem persistenten Datenspeicher registriert und als "atomic settlement pending" bestätigt.

**Anspruch 2** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Wechselkurskontext die Felder Quellwährung, Zielwährung, Kurs (als Dezimalzeichenkette), Kursquelle, Zeitpunkt der Kursermittlung und Gültigkeitsende umfasst, womit für Regulierungszwecke (MiFID II, EMIR) für jede Hop-Stufe ein vollständiger dokumentarischer Nachweis des verwendeten Wechselkurses vorliegt.

**Anspruch 3** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass eine optionale kryptografisch signierte Routing-Optimalitätsbestätigung entgegengenommen werden kann, welche den dezentralen Identifikator des attestierenden Routing-Dienstes, alle bewerteten Routenoptionen, die Indexnummer der ausgewählten Route, die angewandten Auswahlkriterien sowie den Gültigkeitszeitraum der Bestätigung umfasst; wobei der Routing-Dienst durch seinen DID-Identifikator für die Korrektheit der Bestätigung haftbar gemacht werden kann.

**Anspruch 4** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Zahlungsintent-Datenstrom durch ein Online-Monitoringsystem ausgewertet wird, das (a) realisierte Varianz und Bipower Variation der Transaktions-Log-Renditen berechnet, (b) eine CUSUM-Teststatistik zur Erkennung von Regimewechseln im Wechselkursprozess anwendet, und (c) bei Überschreitung konfigurierter Schwellen automatisch Warnmeldungen der Stufen Gelb/Orange/Rot erzeugt.

**Anspruch 5** (abhängig von 4): Verfahren nach Anspruch 4, dadurch gekennzeichnet, dass die Online-Volatilätsanalyse eine funktionale Hauptkomponentenzerlegung des intraday-Volatilitätsprofils durchführt und den Abstand des aktuellen Profils von der empirischen Mittelkurve als weiteres Anomalieerkennungsmerkmal verwendet.

**Anspruch 6** (abhängig von 1): System nach Anspruch 1, dadurch gekennzeichnet, dass der Zahlungsintent mit einem n=1-Hop (direkte Übertragung) äquivalent zu einer einfachen Cross-Ledger-Übertragung ist und das System somit nahtlos in bestehende Bridge-Core-Implementierungen integriert werden kann, die nur Einzelhops benötigen.

---

## 4. Zusammenfassung (Abstract)

Ein computerimplementiertes Verfahren ermöglicht die atomare Übertragung von Währungsbeträgen über eine beliebige Anzahl von Liquiditätsprovider-Hops. Für jeden Hop wird ein HTLC-Vertrag mit dokumentiertem Wechselkurskontext (Kurs, Quelle, Zeitfenster) erzeugt. Serverseitig wird eine Timeout-Invariante erzwungen, die die rückwärtige Preimage-Propagation kausalsicher garantiert. Optional kann eine kryptografisch signierte Routing-Optimalitätsbestätigung eines DID-identifizierten Routing-Dienstes beigefügt werden, der für die Korrektheit seiner Bewertung haftbar ist. Ein integriertes Online-Monitoring berechnet realisierte Varianz, Bipower-Variation und CUSUM-Statistiken aus dem Transaktionsstrom für regulatorische Echtzeitüberwachung. (≈ 105 Wörter)

---

*SIGIL-FXBRIDGE Patent — 2026-02-25 — Patent Pending — EUPL-1.2*
