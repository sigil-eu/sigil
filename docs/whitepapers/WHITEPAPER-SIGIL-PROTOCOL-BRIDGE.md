# SIGIL Protocol & Bridge Core

## Whitepaper — Vertrauensarchitektur für das digitale Zeitalter

**Version 1.0 · 2026-02-25 · Benjamin Küttner · sigil-protocol.org**

---

## Präambel: Vertrauen ist ein Brief, kein Ledger

Im Jahr 1723 überwies ein Kaufmann in Amsterdam Geld nach Venedig. Er schickte keinen Boten mit einem Sack Münzen. Er schrieb einen Brief. Der Brief enthielt seine Signatur, den Betrag, den Namen des Empfängers, und das Datum. Der Bank in Venedig genügte das: Sie zahlte aus.

Das Geheimnis war nicht die Bank. Es war die **Signatur** — der kryptografische Beweis, dass dieser Brief von diesem Menschen stammt und unterwegs nicht verändert wurde.

Dreihundert Jahre später bauen wir Milliarden-Dollar-Infrastrukturen für Blockchain-Ledger, weil wir vergessen haben, was Vertrauen wirklich bedeutet: **Es ist kein Buch. Es ist ein Brief.**

Das SIGIL-Protokoll erinnert uns daran.

---

## Teil I: Das SIGIL-Protokoll

### Was ist SIGIL?

SIGIL steht für **Sovereign Identity-Gated Interaction Layer** — eine kryptografische Infrastruktur, die drei Fragen mit mathematischer Sicherheit beantwortet:

1. **Wer hat das gesagt?** — Durch dezentrale Identifikatoren (W3C DID) und Ed25519-Signaturen
2. **Wurde es verändert?** — Durch HMAC-SHA256-verkettete Prüfprotokolle
3. **Gilt es noch?** — Durch Zeitstempel und konfigurierbare Ablaufregeln

Das sind die drei Grundfragen des Vertrauens — und SIGIL beantwortet sie ohne Blockchain, ohne Konsensrunden, ohne Proof-of-Work.

### Die Oma-Analogie: Was ist eine digitale Signatur?

Stell dir vor, deine Oma bäckt Kuchen und deponiert das Rezept in einem Tresor. Den Tresorschlüssel behält sie. Eine öffentliche Kopie des Schlosses hängt an ihrer Haustür.

Jeder kann das Schloss anschauen. Nur sie kann damit Rezepte versiegeln. Wenn du ein Rezept siehst, das mit ihrem Schloss versiegelt ist, weißt du: Das hat Oma gemacht. Niemand sonst.

Ed25519 funktioniert genauso — nur mit Mathematik statt Metall. Dein **privater Schlüssel** ist Omas Tresorschlüssel. Dein **öffentlicher Schlüssel** ist das Schloss an der Tür. Die **Signatur** ist der Abdruck dieses Schlosses auf dem Dokument.

### Was ist eine HMAC-Prüfkette?

Stefan ist Buchhalter. Jeden Tag fügt er einen Eintrag zum Kassenbuch hinzu. Unter jeden Eintrag schreibt er eine spezielle Summe: den HMAC. Der HMAC wird aus **dem aktuellen Eintrag + dem HMAC des Vorgängers** berechnet.

Das Resultat: Wenn jemand nachts Eintrag 47 ändert, stimmt der HMAC von Eintrag 48 nicht mehr — und alle nachfolgenden HMACs auch nicht. Jede Manipulation ist sofort und mathematisch beweisbar.

Das hat keinen Unterschied zu einem Blockchain-Ledger — außer dass es **100× schneller**, **ohne Konsens** und **ohne Energieverbrauch** funktioniert.

---

## Teil II: SIGIL vs. Blockchain

### Der fundamentale Unterschied

| | Blockchain | SIGIL |
|---|---|---|
| **Vertrauensmodel** | Vertraue dem Netzwerk (Mehrheit) | Vertraue der Signatur (Mathematik) |
| **Konsens** | Tausende Nodes einigen sich | Keine Einigung nötig |
| **Latenz** | Sekunden bis Minuten | Millisekunden |
| **Energie** | Proof-of-Work: Megawatt | HMAC + Ed25519: Mikrowatt |
| **Skalierung** | 7–30 TPS (Bitcoin/Ethereum) | 10.000+ TPS |
| **Datenschutz** | Alles öffentlich | GDPR-Design: Pseudonymisierung |
| **Regulatorisch** | Unsicherheit | eIDAS, ISO 20022, SEPA-konform |

**Kernthese:** In 95% aller Anwendungsfälle **ersetzt SIGIL die Blockchain vollständig** — schneller, günstiger, regulatorisch sicherer. In den verbleibenden 5% wirkt SIGIL als **hocheffizienter Wrapper**, der die Blockchain um ein Vielfaches effizienter macht.

### Wann braucht man überhaupt noch Blockchain?

Blockchain löst ein spezifisches Problem: **Wie beweise ich einem Fremden, dem ich gar nicht traue, dass ein Dokument zu einem bestimmten Zeitpunkt existiert hat — ohne eine dritte Partei?**

Das ist ein legitimes Problem. Aber es ist selten. Die meisten Transaktionen haben mindestens eine vertrauenswürdige Partei (Bank, Notar, Regulierer). Für die braucht man keine Blockchain.

**Für die verbleibenden 5%** — öffentliche Beweisbarkeit ohne Drittpartei — verwendete SIGIL **Data-Availability-Layer** wie Celestia als externen Anker. Hier wird lediglich ein **Merkle-Root** (ein 32-Byte-Fingerabdruck Tausender Transaktionen) in der Blockchain verankert. Das kostet eine Millisekunde und ein paar Cent — statt einer eigenen Blockchain zu betreiben.

### Die Zitaretten-Metapher

Stell dir einen Tauschmarkt vor: Manche tauschen Äpfel gegen Birnen. Manche tauschen Gedichte gegen Bücher. Manche tauschen — nun ja — Zigaretten gegen Zigaretten.

Eine Blockchain dokumentiert jeden einzelnen Tausch öffentlich auf einem unveränderlichen Ledger. Das Netzwerk prüft jeden Tausch einzeln. Das dauert. Das kostet.

SIGIL dokumentiert jeden Tausch in einem signierten Brief. Einmal täglich wird eine Zusammenfassung aller Briefe (ein Merkle-Tree-Root) öffentlich verankert. 10.000 Tauschvorgänge kosten denselben Anker-Preis wie einer.

Das ist **Batching** — und es macht SIGIL in der Praxis nicht 10× effizienter als Blockchain, sondern **10.000×**.

---

## Teil III: SIGIL Bridge Core

### Das Tauschproblem ohne Vertrauen

Luisa in München möchte ihrer Kusine Sofia in Mailand 200€ schicken. Sie haben keine gemeinsame Bank. Wie funktioniert der Tausch, ohne dass eine von beiden zuerst zahlt und betrogen werden kann?

Das klassische Dilemma: Wenn Luisa zuerst überweist, könnte Sofia nicht liefern. Wenn Sofia zuerst liefert, könnte Luisa nicht zahlen.

**Lösung:** Ein HTLC — Hash Time Locked Contract, der atomare Tausch.

### Der atomare Tausch — Schritt für Schritt

**Szene 1: Luisa generiert ein Geheimnis**

Luisa würfelt eine zufällige Zahl: `S = a4f8b...`. Davon berechnet sie den SHA-256-Hash: `H = SHA256(S) = 7e3c9...`. `H` schickt sie an Sofia. `S` behält sie geheim.

**Szene 2: Sofia sperrt**

Sofia sperrt €200 auf ihrem Konto mit der Bedingung: *„Wer `S` bei Wert `H = SHA-256(S)` vorweisen kann, bekommt die €200. Wenn niemand es innerhalb von 24 Stunden tut, komme ich zurück."*

**Szene 3: Luisa enthüllt**

Luisa sieht, dass Sofia gesperrt hat. Jetzt enthüllt sie `S`. Sie erhält Sofias €200. Und da `S` jetzt öffentlich ist, weiß Sofia: Luisa muss bezahlt haben. Sie kann ihre eigene Gegensperrung auflösen.

**Das Ergebnis:** Entweder tauschen beide — oder keine tauscht. Es gibt keinen Zwischenzustand, in dem eine Partei beide Werte hat.

Das ist mathematische Atomarität. Ohne Bank. Ohne Vertrauen. Nur Mathematik.

### Welche Assets kann SIGIL-Bridge übertragen?

Alles, was einen eindeutigen Bezeichner hat und in einem Registry-System sperrbar ist:

- **Fiat-Währungen & CBDC** (EUR, USD, Digital Euro) — identifiziert durch ISO-4217-Code
- **Wertpapiere** (Aktien, Anleihen, ETFs) — identifiziert durch ISIN
- **Immobilien** (Wohnungen, Grundstücke, Anteile) — identifiziert durch Grundbuchnummer
- **Rohstoffe & CO₂-Zertifikate** — identifiziert durch Handelbezeichner (EU-ETS, VCS)
- **Digitale Kunstwerke & Medienrechte** — identifiziert durch UUID / DOI
- **Lizenzen & Nutzungsrechte** — identifiziert durch Lizenz-UUID
- **On-Chain-Token** (ERC-20, ERC-721) — identifiziert durch Contract-Adresse + Chain-ID
- **Alles andere** — über generischen Erweiterungstyp mit freiem Metadatenfeld

Ein einziges Protokoll. Beliebige Assets. Keine Protokolländerung nötig.

### Der Übersetzer: DID als universelle Identität

Der Übersetzer sitzt zwischen zwei Parteien, die verschiedene Sprachen sprechen. SIGIL-DIDs sind ähnlich: Sie übersetzen identische Personen zwischen verschiedenen Systemen.

Luisa hat in Deutschland eine IBAN. In der EU hat sie eine eIDAS-Identität. In Web3 hat sie eine Wallet-Adresse. Das sind drei verschiedene Sprachen für dieselbe Person.

Ihr **W3C-DID** — z.B. `did:sigil:ed25519:xyz123` — ist der Übersetzer: eine einzige, kryptografisch verankerte Identität, die in allen drei Systemen gilt. Kein Intermediär nötig. Die Identität liegt bei Luisa.

---

## Teil IV: SIGIL Services (ServiceBridge)

### Der faire Dienst-Treuhänder

Der Klempner hat das Rohr repariert. Der Auftraggeber sagt: „Ich finde das nicht gut gemacht." Wer hat Recht?

Heute: Anwalt, Gericht, Monate. Morgen mit SIGIL:

1. **Vertragsschluss:** Betrag gesperrt, Schlichter DID = `did:sigil:schlichter:xyz` — festgelegt *vor* Vertragsschluss, nicht danach
2. **Lieferung:** Klempner meldet: „Fertig." 7-Tage-Streitfenster öffnet sich
3. **Keine Einigung:** Schlichter `did:sigil:schlichter:xyz` entscheidet — kryptografisch signiert, sofort vollstreckbar
4. **Prüfprotokoll:** Jeder Schritt HMAC-verkettet, unveränderlich, exportierbar für Steuerbehörden

Der Schlichter ist nicht stochastisch ausgewählt (wie bei Kleros). Er ist **vorher bekannt benannt**. Niemand kann ihn nachträglich wechseln. Das ist Rechtssicherheit als Designeigenschaft.

---

## Anhang: Technische Eckdaten

| Eigenschaft | Wert |
|---|---|
| Signaturalgorithmus | Ed25519 (64 Byte Signatur) / ML-DSA-65 für PQ-Schutz |
| Preimage-Hash | SHA-256 (NIST FIPS 180-4) |
| Prüfkette | HMAC-SHA256, append-only |
| DA-Anker | Merkle-Root in öffentlichem DA-Layer (agnostisch) |
| Latenz Settlement | < 5 ms (ohne Netzwerk) |
| Throughput | > 10.000 TPS |
| Lizenz | EUPL-1.2 (Open Source) + Kommerzielle Lizenz |
| Patent | GBM-0 (DPMA, 2026-02-23) · GBM-1..5 (2026-02-25) |

---

*SIGIL Protocol Whitepaper · 2026-02-25 · sigil-protocol.org · Patent Pending*
