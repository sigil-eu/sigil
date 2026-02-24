# PATENT — SIGIL-BRIDGE-CORE

## DE Gebrauchsmuster — Atomic Asset-Agnostic Cross-Ledger Transfer

**Anmeldedatum:** 2026-02-25
**Anmelder:** Benjamin Küttner, [Adresse eintragen]
**Priorität:** Fortführung und Erweiterung DE Gebrauchsmuster SIGIL Protocol (eingereicht 2026-02-22)
**Lizenz:** EUPL-1.2 + Kommerzielle Lizenz

---

## 1. Anschreiben (Cover Letter)

**An:** Deutsches Patent- und Markenamt, 80297 München

Betreff: Anmeldung eines Gebrauchsmusters — SIGIL Bridge Core

Sehr geehrte Damen und Herren,

hiermit melden wir ein Gebrauchsmuster für eine computerimplementierte Methode zur **assetklassenagnostischen, atomaren Übertragung digitaler Vermögenswerte zwischen verteilten Ledgern** an. Die vorliegende Erfindung erweitert das SIGIL-Protokoll (DE Gebrauchsmuster, eingereicht 2026-02-22) auf den Bereich der Wertübertragung und Finanzinfrastruktur.

Anliegend übersenden wir: Beschreibung, Ansprüche und Zusammenfassung.

Mit freundlichen Grüßen
Benjamin Küttner

---

## 2. Beschreibung (Description)

### 2.1 Technisches Gebiet

Die Erfindung betrifft computerimplementierte Verfahren zur kryptografisch gesicherten, atomaren Übertragung digitaler Vermögenswerte zwischen unabhängigen Ledgersystemen unter Verwendung von Hashed Time-Locked Contracts (HTLCs), dezentralen Identifikatoren (DID) und HMAC-verketteten Prüfprotokollen.

### 2.2 Stand der Technik

Bestehende Lösungen wie Bitcoin Lightning Network (HTLC in homogenen Netzwerken) und Interledger Protocol (ILP) bieten atomare Transfers für spezifische Asset-Typen. Keines dieser Systeme kombiniert:

1. **Assetklassenagnostische** HTLC-Primitive (Währung, Wertpapier, Token in einem Vertrag)
2. **W3C-DID-Attribution** beider Vertragsparteien
3. **HMAC-SHA256-Prüfkette** für jeden Zustandsübergang

Eine solche Kombination ist weder als Patentliteratur noch als veröffentlichte Referenzimplementierung auffindbar.

### 2.3 Offenbarung der Erfindung

Die Erfindung beschreibt das `HtlcContract`-Primitiv und die `BridgeAuditChain`:

**Asset-Typen (polymorphe Klasse):**

```rust
pub enum Asset {
    Currency { currency: String, amount_units: u64, display: String },
    Security  { isin: String, quantity: u64, display: String },
    Token     { contract_id: String, token_id: String, amount: u64, chain: String },
}
```

**HTLC-Vertrag:**

```rust
pub struct HtlcContract {
    pub contract_id:      String,
    pub preimage_hash:    PreimageHash,
    pub locked_asset:     Asset,
    pub holder_did:       Did,
    pub beneficiary_did:  Did,
    pub locked_at:        i64,
    pub timeout_at:       i64,
    pub state:            HtlcState,
    pub preimage_revealed: Option<Preimage>,
}
```

Settlement ist **mathematisch atomar**: `state = Settled` genau dann, wenn `SHA256(preimage_revealed) == preimage_hash`. Es existiert kein Zustand, in dem eine Seite den Wert erhält, ohne dass die Gegenseite den kryptografischen Nachweis offenbart.

Jeder Zustandsübergang erzeugt einen Eintrag in der `BridgeAuditChain`, einer HMAC-SHA256-verketteten, append-only Protokolldatei. Jeder Eintrag enthält den HMAC des Vorgängers (`prev_hmac`), sodass jegliche nachträgliche Änderung eines Eintrags alle nachfolgenden HMAC-Werte invalidiert.

### 2.4 Vorteilhafte Ausführungsformen

- Die Assetklasse kann ohne Protokolländerung erweitert werden (z.B. um NFT, CO2-Zertifikat).
- DID-Attribution erfolgt gemäß W3C DID Core 1.0 — kompatibel mit eIDAS 2.0 Wallets.
- Die Prüfkette kann periodisch in einem öffentlichen Data-Availability-Layer verankert werden (z.B. Celestia, Solana).

---

## 3. Ansprüche (Claims)

**Anspruch 1** (unabhängig): Computerimplementiertes Verfahren zur atomaren Übertragung eines digitalen Vermögenswerts zwischen zwei mittels dezentralem Identifikator (DID) identifizierten Parteien, dadurch gekennzeichnet, dass es:

(a) einen `HtlcContract`-Datensatz erzeugt, welcher einen SHA-256-Hash eines geheimen Preimage, einen digitalen Vermögenswert einer polymorphen Assetklasse, die dezentralen Identifikatoren von Halter und Begünstigtem sowie ein Timeout-Feld umfasst;

(b) den Vertrag in den Zustand `Locked` versetzt, sobald der Halter den Vermögenswert bereitstellt;

(c) den Zustand `Settled` ausschließlich durch die Offenbarung eines Preimage `S` herbeiführt, für das gilt: `SHA256(S) == preimage_hash`;

(d) bei Ablauf des Timeouts ohne Preimage-Offenbarung den Zustand `TimedOut` aktiviert und den Vermögenswert an den Halter zurückführt.

**Anspruch 2** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass bei einer Kette von n HTLCs mit demselben Preimage-Hash serverseitig geprüft wird, dass `timeout[i] > timeout[i+1]` für alle i gilt, und bei Verletzung dieser Invariante die Intent-Einreichung mit Fehlercode `422 Unprocessable Entity` abgewiesen wird.

**Anspruch 3** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass jeder Zustandsübergang einen strukturierten Eintrag an eine append-only `BridgeAuditChain` anhängt, wobei jeder Eintrag den HMAC-SHA256-Wert des vorangehenden Eintrags (`prev_hmac`) einschließt, sodass eine nachträgliche Änderung eines Eintrags alle nachfolgenden Einträge invalidiert, und wobei jeder Eintrag den dezentralen Identifikator der initiierenden Partei sowie das finanzielle Ergebnis des Zustandsübergangs enthält.

**Anspruch 4** (abhängig von 1): Verfahren nach Anspruch 1, dadurch gekennzeichnet, dass die polymorphe Assetklasse mindestens die Typen Währung (CBDC/Fiatgeldäquivalent), Wertpapier (mittels ISIN-Code identifiziert) und On-Chain-Token (mittels Contract-ID und Chain-Bezeichner identifiziert) umfasst.

**Anspruch 5** (abhängig von 3): Verfahren nach Anspruch 3, dadurch gekennzeichnet, dass periodisch ein Merkle-Baum über die HMAC-Werte aller ausstehenden `BridgeAuditChain`-Einträge berechnet wird und der Merkle-Root in einem öffentlichen Distributed-Ledger verankert wird, sodass ein Dritter ohne Vertrauen in den Systembetreiber die Integrität des gesamten Prüfprotokolls verifizieren kann.

**Anspruch 6** (abhängig von 1): System nach Anspruch 1, dadurch gekennzeichnet, dass die Parteien durch Decentralised Identifiers gemäß W3C DID Core 1.0 identifiziert werden, die mit eIDAS-2.0-konformen Wallets kompatibel sind.

---

## 4. Zusammenfassung (Abstract)

Ein computerimplementiertes Verfahren ermöglicht die atomare, kryptografisch gesicherte Übertragung digitaler Vermögenswerte — Währungen, Wertpapiere oder Token — zwischen unabhängigen Ledgern, ohne eine zentrale Verrechnungsstelle. Das Verfahren verwendet Hashed Time-Locked Contracts (HTLCs), bei denen Halter und Begünstigter durch W3C-konforme dezentrale Identifikatoren (DID) identifiziert werden. Jeder Zustandsübergang wird in einer HMAC-SHA256-Prüfkette protokolliert. Bei mehreren Hops wird eine Timeout-Invariante erzwungen, die die rückwärtige Preimage-Propagation garantiert. Das System ist assetklassenagnostisch und damit ohne Protokolländerungen auf neue Vermögenswertklassen erweiterbar. (≈ 90 Wörter)

---

*SIGIL-BRIDGE-CORE Patent — 2026-02-25 — Patent Pending — EUPL-1.2*
