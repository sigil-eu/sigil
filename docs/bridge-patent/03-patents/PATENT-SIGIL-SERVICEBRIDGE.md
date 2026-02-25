# PATENT — SIGIL-SERVICEBRIDGE

## DE Gebrauchsmuster · DID-gebundener Dienstleistungs-Treuhand mit deterministischer Schlichtung

## GBM-5 der SIGIL-Patentfamilie

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, Garmischerstrasse 46 B, 86163 Augsburg, Deutschland
**Kontakt:** <benjamin.kuettner@icloud.com> · <ben@sigil-protocol.org>
**Priorität / Stammanmeldungen:**

- GBM-0: DE Gebrauchsmuster SIGIL Protocol (Sovereign Identity-Gated Interaction Layer), eingereicht DPMA 2026-02-23
- GBM-1: DE Gebrauchsmuster SIGIL Crypto-Agility, eingereicht 2026-02-25 (gleichzeitig)
- GBM-2: DE Gebrauchsmuster SIGIL-Bridge-Core, eingereicht 2026-02-25 (gleichzeitig)
**EPO-Frist:** 2027-02-23
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Gebrauchsmusteranmeldung — SIGIL-SERVICEBRIDGE (GBM-5)

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster für ein computerimplementiertes Treuhandgateway für Dienstleistungsverträge an, das auf dem SIGIL-Protokoll (GBM-0, DPMA 2026-02-23) und dem SIGIL-Bridge-Core-Transferprimiti (GBM-2, 2026-02-25) aufbaut. Die wesentliche Neuheit gegenüber GBM-0 und GBM-2 liegt in der deterministischen, zurechenbaren Streitschlichtung durch einen zum Zeitpunkt der Vertragsschließung bindend festgelegten DID-identifizierten Schlichter sowie in der HMAC-verketteten Lebenszyklusprüfkette aller Zustandsübergänge.

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft ein computerimplementiertes Gateway, das digitale Zahlungen für Dienstleistungsverträge in meilensteingebundener Treuhand verwaltet, einen HMAC-verketteten Lebenszyklusverlauf protokolliert und Streitigkeiten durch einen vorab festgelegten, kryptografisch identifizierten Schlichter deterministisch und zurechenbar auflöst.

### 2.2 Bezug zu den Stamm-Schutzrechten

**GBM-0 (DPMA 2026-02-23)** liefert das DID-Identitätssystem (Käufer, Anbieter, Schlichter), die Ed25519-Signaturinfrastruktur und den HMAC-Prüfprotokollrahmen. **GBM-2 (2026-02-25)** liefert das Transfer-Intent-Primitiv als Zahlungskomponente des Treuhandvertrags sowie die Atomaritätsgarantie für die Zahlungsfreigabe.

Die vorliegende Erfindung (GBM-5) fügt hinzu:

- Meilensteinbasiertes Lebenszyklusmodell (Pending → Locked → Delivered → Settled / Disputed → Refunded)
- Vorab festgelegter, DID-gebundener Schlichter als deterministischer Konfliktlösungsmechanismus
- HMAC-verkettete Protokollierung aller Zustandsübergänge für gerichtsverwertbare Nachweise
- Konfigurierbare Streitfrist nach Lieferungsmeldung

### 2.3 Stand der Technik und Abgrenzung

**US11250439B2 (Kleros, Tokenbasierte Jurorenpools):** Schlichter wird durch stochastische Tokengewichtung zufällig ausgewählt — nicht deterministisch, nicht vor Vertragsschluss vorhersehbar, nicht namentlich attributierbar. **US10748144B2 (DocuSign, Elektronische Signaturen):** Keine HMAC-Audit-Kette. Kein CBDC-Transfer-Primitiv. Kein Schlichtungsmechanismus.

Keine bekannte Lösung kombiniert: (1) vorab festgelegten DID-Schlichter, (2) HMAC-verkettete Lebenszyklusprüfkette, (3) Integration mit dem SIGIL-Bridge-Core-Transferprimiti.

### 2.4 Offenbarung der Erfindung

**Dienstleistungsanweisung (ServiceIntent) als spezialisierter BridgeIntent:**

Eine `ServiceIntent`-Datenstruktur enthält:

- DID von Käufer, Anbieter und Schlichter (GBM-0-Identitätssystem)
- Zahlungsbetrag und -währung als GBM-2-BridgeIntent-Komponente
- Geordnete Meilensteinliste als Lieferungsnachweis
- Streitigkeitsfenster (konfigurierbare Dauer nach Lieferungsmeldung)
- Timeout-Feld für Gesamtvertragslaufzeit (GBM-2 Atomaritätsmechanismus)

**Lebenszyklusautomat:**

```
Pending ──► Locked ───── Timeout ──► TimedOut  (Rückerstattung)
                │
             /deliver
                ▼
           Delivered ──── /accept ──► Settled   (Zahlung freigegeben)
                │
             /dispute (innerhalb Streitfrist)
                ▼
           Disputed ───── /arbitrate ──► Settled | Refunded
                                         (Schlichter: DID-attributiert)
```

Jeder Zustandsübergang erzeugt einen HMAC-verketteten Eintrag gemäß GBM-0. Der Schlichter-DID ist im ServiceIntent unveränderlich festgelegt — keine nachträgliche Änderung, keine stochastische Auswahl möglich.

**Deterministische Schlichtung als Kernanspruch:**

Der Schlichter ist durch seinen W3C-DID-Identifikator eindeutig identifiziert. Die Schlichtungsentscheidung (`Erledigt` oder `Erstattet`) ist durch seinen DID vollständig attributiert — rechtlich zurechenbar, forensisch nachvollziehbar. Das Schlichtungsprotokoll verbleibt als HMAC-verketteter Eintrag unveränderlich im Prüfprotokoll.

**Integration mit SIGIL-EURO (GBM-3):**

Als optionale Erweiterung kann die Zahlungskomponente des ServiceIntent als SIGIL-EURO-PaymentIntent (GBM-3) implementiert werden, sodass die Dienstleistungszahlung eIDAS-konform, pseudonymisiert und dreischichtig protokolliert wird.

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig, aufbauend auf GBM-0 und GBM-2): Computerimplementiertes Verfahren zur Verwaltung eines meilensteinbasierten Dienstleistungsvertrags unter Verwendung des SIGIL-Protokolls (GBM-0, DPMA 2026-02-23) und des SIGIL-Bridge-Core-Transferprimitivs (GBM-2, 2026-02-25), dadurch gekennzeichnet, dass es:

(a) eine Dienstleistungsanweisung entgegennimmt, die neben den Feldern des GBM-2-BridgeIntent die WC3-DID-Identifikatoren von Käufer, Anbieter und einem vorab festgelegten Schlichter, eine geordnete Meilensteinliste und ein Streitfristfeld umfasst;

(b) den Zahlungsbetrag in gesicherter Verwahrung einfriert und den Intent in den Zustand `Gesperrt` versetzt, sobald der Käufer bereitstellt;

(c) nach Eingang einer vom Anbieter unterzeichneten Lieferungsmeldung den Intent in den Zustand `Geliefert` versetzt und eine konfigurierbare Streitfrist startet;

(d) bei Eingang der Abnahme durch den Käufer innerhalb der Streitfrist den Zahlungsbetrag an den Anbieter freigibt und den Intent als `Erledigt` markiert;

(e) bei Ablauf des Gesamttimeouts ohne Lieferungsmeldung den Zahlungsbetrag an den Käufer zurückführt gemäß dem Atomaritätsmechanismus von GBM-2 Anspruch 1(d);

(f) jeden Zustandsübergang in der HMAC-verketteten Prüfkette des SIGIL-Prüfprotokollrahmens (GBM-0) protokolliert, wobei jeder Eintrag den DID der auslösenden Partei, den neuen Zustand und den HMAC-Wert des Vorgängereintrags enthält.

**Anspruch 2** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Käufer innerhalb der konfigurierbaren Streitfrist nach Eingang der Lieferungsmeldung eine Streitigkeit eröffnen kann, woraufhin ausschließlich der zum Zeitpunkt der Vertragsschließung im ServiceIntent hinterlegte, DID-identifizierte Schlichter berechtigt ist, durch eine unterzeichnete Entscheidung die Streitigkeit durch Zahlungsfreigabe (`Erledigt`) oder Rückerstattung (`Erstattet`) zu beenden.

**Anspruch 3** (abhängig von 2): Verfahren nach Anspruch 2, dadurch gekennzeichnet, dass der Schlichter bindend zum Zeitpunkt der Einreichung des ServiceIntent und nicht nachträglich bestimmt wird, sodass die Schlichtungszuständigkeit für alle Vertragsparteien vor Vertragsschluss vorhersehbar, eindeutig attributierbar und nicht durch stochastische Auswahl oder Nachverhandlung veränderbar ist.

**Anspruch 4** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die HMAC-verkettete Prüfkette aller Zustandsübergänge über eine authentifizierte Schnittstelle für Gerichts-, Steuer- oder Regulierungszwecke exportierbar ist und die lückenlose Vertragshistorie einschließlich Meilensteinprotokollen nachweist.

**Anspruch 5** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die Zahlungskomponente des ServiceIntent als SIGIL-EURO-Zahlungsanweisung (GBM-3, 2026-02-25) implementiert werden kann, sodass Dienstleistungsverträge eIDAS-konform, mit SHA-256-pseudonymisiertem Empfänger und dreischichtigem Prüfprotokoll abgewickelt werden.

**Anspruch 6** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass der Signaturmechanismus die Kryptoagilität von GBM-1 (SIGIL Crypto-Agility, 2026-02-25) erbt, sodass der Wechsel auf ML-DSA (NIST FIPS 204) für alle am Vertrag beteiligten DID-Identitäten ohne Strukturänderung des ServiceIntent durchführbar ist.

---

## 4. Zusammenfassung (Abstract)

Aufbauend auf dem SIGIL-Protokoll (GBM-0, DPMA 2026-02-23) und dem SIGIL-Bridge-Core (GBM-2, 2026-02-25) verwaltet das Verfahren Dienstleistungsverträge als meilensteingebundene Treuhand. Käufer, Anbieter und Schlichter werden durch W3C-DIDs identifiziert; der Schlichter wird bindend vor Vertragsschluss festgelegt. Jeder Zustandsübergang (Pending → Locked → Delivered → Settled | Disputed → Refunded) wird HMAC-verkettet protokolliert. Bei Streitigkeit entscheidet ausschließlich der vorab festgelegte, kryptografisch authentifizierte Schlichter — deterministisch, zurechenbar, nicht stochastisch. Die Zahlung kann als SIGIL-EURO-Intent (GBM-3) eIDAS-konform abgewickelt werden. Der Signaturmechanismus erbt die Kryptoagilität von GBM-2. (≈ 100 Wörter)

---

## 5. Englische Zusammenfassung / English Summary

**GBM-5 — SIGIL-ServiceBridge · DID-Bound Service Escrow with Deterministic Arbitration**

Building on the SIGIL Protocol (GBM-0, Sovereign Identity-Gated Interaction Layer) and the SIGIL-Bridge-Core transfer primitive (GBM-2), this procedure manages service contracts as milestone-bound escrow. Buyer, provider, and arbitrator are identified by W3C DIDs; the arbitrator is bindingly designated at contract inception — not stochastically selected. Every lifecycle transition (Pending → Locked → Delivered → Settled | Disputed → Refunded) is HMAC-chained and append-only. In the event of a dispute, only the pre-agreed, cryptographically authenticated arbitrator may issue a binding decision — deterministic, attributable, non-stochastic. Payment may optionally be processed as a SIGIL-EURO intent (GBM-3) with eIDAS-compliant pseudonymisation and three-layer audit trail. The signature mechanism inherits crypto-agility from GBM-1.

---

*SIGIL-SERVICEBRIDGE · GBM-5 der SIGIL-Patentfamilie (Sovereign Identity-Gated Interaction Layer) · Anmeldedatum 2026-02-25 · Patent Pending · EUPL-1.2*
*Benjamin Küttner · Garmischerstrasse 46 B · 86163 Augsburg, Deutschland · <benjamin.kuettner@icloud.com> · <ben@sigil-protocol.org>*
