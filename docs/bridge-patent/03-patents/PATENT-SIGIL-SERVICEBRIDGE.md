# PATENT — SIGIL-SERVICEBRIDGE

## DE Gebrauchsmuster — Service-Asset-Treuhand mit Schlichter-Disputing und HMAC-Protokollkette

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, [Adresse eintragen]
**Priorität:** Fortführung DE Gebrauchsmuster SIGIL Protocol (2026-02-22) + SIGIL-BRIDGE-CORE (2026-02-25)
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Anmeldung eines Gebrauchsmusters — SIGIL-SERVICEBRIDGE

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster für ein computerimplementiertes Verfahren zur **treuhandgesicherten, meilensteinbasierten Verwaltung von Dienstleistungsverträgen** an. Das Verfahren setzt auf DID-identifizierten Parteien und Schlichtern auf und erzeugt für jeden Vertragsschritt eine kryptografisch gesicherte Protokollkette mit Prüfwert.

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft ein computerimplementiertes Treuhandgateway, das eine Zahlungsanweisung für Dienstleistungen in gesicherte Verwahrung nimmt, den Vertragslebenszyklus (Einreichung, Lieferung, Abnahme, Streitigkeit, Schlichtung) als HMAC-verkettete Ereigniskette protokolliert und Zahlungen ausschließlich durch kryptografisch verifizierbare Ereignisse freigibt oder zurückführt.

### 2.2 Stand der Technik

Bestehende Dienstleistungs-Treuhandsysteme wie US11250439B2 (Kleros) verwenden tokenbasierte Jurorenpools für die Schlichtung — der Schlichter ist nicht im Vorhinein identifiziert. US10748144B2 (DocuSign) verwendet traditionelle elektronische Signaturen ohne HMAC-Audit-Kette und ohne CBDC-Integration. Keine bekannte Lösung kombiniert: (1) vorab festgelegten DID-Schlichter, (2) HMAC-verkettete Lebenszyklusprotokolle, und (3) Integration mit eIDAS-konformen CBDC-Zahlungen.

### 2.3 Offenbarung der Erfindung

**Intent-Lebenszyklus-State-Machine:**

```
Pending ──► Locked ──── timeout ──► TimedOut (Rückerstattung)
                │
                ▼ /deliver
           Delivered
                │
                ├── /accept ──► Settled (Zahlung freigegeben)
                │
                └── /dispute ──► Disputed (Streitfenster offen)
                                      │
                                      └── /arbitrate ──► Settled | Refunded
```

Der **Schlichter (DID)** wird zum Zeitpunkt der Intent-Erstellung bindend festgelegt. Eine stochastische Schlichterauswahl existiert nicht. Dies macht die Streitbeilegung **deterministisch und zurechenbar** — für Unternehmensverträge, B2B-Software-SLAs und regulierte Branchen entscheidend.

**Live-Status (2026-02-24):**

- Gateway `https://sigil-protocol.org/service/api/info` erreichbar: HTTP 200 ✅
- Alle Endpunkte (`/submit`, `/deliver`, `/accept`, `/dispute`, `/arbitrate`) vorhanden ✅

### 2.4 Beschreibung der API-Endpunkte

| Endpunkt | HTTP | Auslöser | Zustandsübergang |
|---|---|---|---|
| `/service/intent/submit` | POST | Käufer | Pending → Locked |
| `/service/intent/:id/deliver` | POST | Anbieter | Locked → Delivered |
| `/service/intent/:id/accept` | POST | Käufer | Delivered → Settled |
| `/service/intent/:id/dispute` | POST | Käufer | Delivered → Disputed |
| `/service/intent/:id/arbitrate` | POST | Schlichter | Disputed → Settled / Refunded |

Jeder Zustandsübergang erzeugt einen HMAC-verketteten Eintrag in der Prüfkette — eine lückenlose, gerichtsverwertbare Dokumentation des Vertragslebenswegs.

### 2.5 Integration mit SIGIL-EURO

Die Zahlungskomponente der `ServiceBridge` kann native SIGIL-EURO `PaymentIntent`-Primitive verwenden, sodass jede Zahlung eIDAS-konform, pseudonymisiert und dreischichtig protokolliert abläuft.

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig): Computerimplementiertes Verfahren zur treuhandgesicherten Verwaltung eines Dienstleistungsvertrags, dadurch gekennzeichnet, dass es:

(a) eine Dienstleistungsanweisung (`ServiceIntent`) entgegennimmt, die die dezentralen Identifikatoren von Käufer, Anbieter und Schlichter, eine Zahlungsmenge in einer definierten Währungseinheit, eine Liste von Liefermeilensteinen und ein Timeout-Datum umfasst;

(b) die Zahlung des Käufers in gesicherter Verwahrung einfriert und den Intent in den Zustand `Locked` versetzt;

(c) bei Eingang einer vom Anbieter unterzeichneten Lieferungsmeldung den Intent in den Zustand `Delivered` versetzt;

(d) bei Eingang einer Abnahme des Käufers den Intent in `Settled` versetzt und die Zahlung an den Anbieter freigibt;

(e) bei Ablauf des Timeouts ohne Lieferungsmeldung die Zahlung an den Käufer zurückführt und den Intent als `TimedOut` markiert.

**Anspruch 2** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Käufer innerhalb eines konfigurierbaren Streitfensters nach einer Lieferungsmeldung eine Streitigkeit eröffnen kann, der Intent in den Zustand `Disputed` wechselt und ein vorab im Intent hinterlegter, DID-identifizierter Schlichter exklusiv berechtigt ist, die Streitigkeit durch eine Schlichtungsentscheidung zu beenden, die entweder in die Freigabe der Zahlung an den Anbieter (`Settled`) oder in die Rückerstattung an den Käufer (`Refunded`) mündet.

**Anspruch 3** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass jeder Zustandsübergang des Intent-Lebenszyklus (Einreichung, Lieferung, Abnahme, Streitigkeit, Schlichtung) einen authentifizierten Eintrag an eine HMAC-SHA256-verkettete Prüfkette anhängt; wobei jeder Eintrag den dezentralen Identifikator der auslösenden Partei, den neuen Zustand, den Zeitstempel und den HMAC-Wert des vorangehenden Eintrags enthält, sodass die vollständige Vertragshistorie unveränderlich und gerichtsverwertbar nachgewiesen werden kann.

**Anspruch 4** (abhängig von 2): Verfahren nach Anspruch 2, dadurch gekennzeichnet, dass der Schlichter zum Zeitpunkt der Intent-Erstellung durch seinen dezentralen Identifikator bindend festgelegt wird und nicht durch eine stochastische Schlichterauswahl (z.B. tokenbasierte Jurorenpools) bestimmt werden kann, wodurch die Streitbeilegung deterministisch und zurechenbar ist.

**Anspruch 5** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die Zahlungskomponente als SIGIL-EURO-`PaymentIntent`-Primitiv gemäß dem SIGIL-EURO-Gebrauchsmuster (ko-angemeldet 2026-02-25) implementiert werden kann, sodass die Dienstleistungszahlung eIDAS-konform, SHA-256-pseudonymisiert und dreischichtig protokolliert abläuft.

**Anspruch 6** (abhängig von 3): Verfahren nach Anspruch 3, dadurch gekennzeichnet, dass die HMAC-Prüfkette aller Zustandsübergänge eines Intent über eine authentifizierte API-Schnittstelle exportierbar ist, einschließlich vollständiger Meilenstein-Protokolle für Gerichts-, Steuer- oder Regulierungszwecke.

---

## 4. Zusammenfassung (Abstract)

Ein computerimplementiertes Verfahren verwaltet Dienstleistungsverträge als treuhandgesicherten Intent-Lebenszyklus. Käufer, Anbieter und Schlichter werden durch W3C Decentralised Identifiers identifiziert. Die Zahlung wird bei Intent-Einreichung eingefroren und nach Abnahme oder Schlichtungsentscheidung freigegeben. Jeder Zustandsübergang (Pending, Locked, Delivered, Settled, Disputed, Refunded) wird in einer HMAC-SHA256-Prüfkette protokolliert. Der Schlichter wird zum Erstellungszeitpunkt deterministisch und zurechenbar festgelegt. Das System lässt sich direkt mit dem SIGIL-EURO-Zahlungsgateway verbinden. (≈ 85 Wörter)

---

*SIGIL-SERVICEBRIDGE Patent — 2026-02-25 — Patent Pending — EUPL-1.2*
