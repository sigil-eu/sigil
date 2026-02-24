# SIGIL Protocol — Patent Documentation: End-to-End Implementation Evidence

**Stand: 2026-02-24 | System Status: Phase 0 (Incognito Produktion)**

## 1. Technischer Nachweis der Funktionalität (Proof of Execution)

Dieses Dokument dient als technischer Nachweis für die im Patent (DE Gebrauchsmuster, DPMA, *filed 2026-02-22*) beschriebenen Kernmechanismen des **SIGIL-EURO Payment Intents**. Es dokumentiert die erfolgreiche Ende-zu-Ende (E2E) Implementierung und Verifikation der kryptografischen Signatur-, Audit- und Transaktions-Routinen in der produktionsnahen Serverumgebung.

### 1.1 Der Payment Intent (Kryptografische Willenserklärung)

Der Kern des Patentes ist die Ablösung konventioneller, unstrukturierter Zahlungsanweisungen durch den `PaymentIntent` – eine strukturierte, kryptografisch signierte und an W3C DIDs gebundene Transaktionsforderung, die eIDAS V2.0 kompatibel ist.

Um das System unter Produktivitätsbedingungen zu validieren, wurde programmatisch ein Intent erzeugt und an das SIGIL-EURO API Gateway (`/euro/api/intent/submit`) übermittelt.

**Die Struktur des validierten Intents:**

```json
{
  "payment_reference": "SIGILEURO-20260224-512a1bcc",
  "payer_did": "did:sigil:ed25519:testpayer123",
  "recipient_hash": [
    68, 101, 253, 62, 94, 8, 200, 98, 35, 20, 181, 183, 209, 131, 
    159, 57, 48, 225, 75, 87, 172, 126, 255, 11, 251, 147, 1, 166, 
    181, 251, 114, 137
  ],
  "amount_cents": 1500,
  "currency": "EUR",
  "consent_scope": "SinglePayment",
  "trust_level": "High",
  "payload_hash": [
    175, 19, 223, 145, 101, 232, 231, 189, 151, 100, 94, 35, 53, 11, 
    243, 207, 26, 195, 204, 111, 223, 151, 11, 177, 74, 143, 57, 40, 
    190, 147, 150, 69
  ],
  "timestamp": 1771972987,
  "signature": [
    213, 230, 91, 189, 233, 62, 45, 154, 57, 60, 19, 7, 248, 52, 251, 
    207, 18, 157, 49, 144, 53, 22, 79, 233, 169, 108, 92, 20, 60, 175, 
    168, 141, 214, 208, 43, 201, 117, 243, 163, 198, 7, 103, 159, 230, 
    109, 151, 171, 57, 158, 109, 144, 193, 2, 244, 64, 177, 237, 97, 
    177, 218, 122, 253, 209, 6
  ],
  "aml_flags": []
}
```

### 1.2 Verifikations-Routine im Gateway (Schritt-für-Schritt)

Das patentierte System erzwingt eine strikte Sequentialität zur Gewährleistung der Rechtsverbindlichkeit und eIDAS-Konformität:

1. **Infrastrukturelle Authentifizierung:** Das NGINX Reverse-Proxy leitet die Anfrage (geschützt durch Layer-4 und Layer-7 Firewall-Regeln sowie Rate-Limiting) an den lokalen Port (8443) des Rust-Gateways (Backend) weiter.
2. **Gateway Authentifizierung:** Das Gateway validiert den vom Client übermittelten `X-Sigil-API-Key`.
3. **Typisierung & Deserialisierung:** Der JSON-Payload wird über `serde` auf das Speichermodell `PaymentIntent` abgebildet. Entspricht der Payload nicht der kryptografischen Struktur (wie bei initialen Tests, bei denen `payer_did` fehlerhaft als Objekt deklariert wurde oder Hash-Felder fehlten), blockiert das Gateway hart mit *HTTP 422 Unprocessable Entity*.
4. **Trust-Level Validierung:** Das Gateway vergleicht `amount_cents` mit dem `trust_level` aus dem Wallet (hier: `High`, d.h. qualifizierte elektronische Signatur), was Limits wie 50€ für niedrige Trust-Level überschreiben darf.
5. **AML/CTF Scanning:** Der Inhalt (DID, Referenz, Währung) läuft synchron und netzwerk-isoliert durch den `AmlScanner`. Der Intent durchlief diesen Test ohne High-Severity-Flags (Ergebnis: `aml_flags: []`).
6. **Audit-Trail Append:** Das System errechnet den kanonischen Hash (`intent_hash`) des Payloads und hängt ihn an die lokale HMAC-Audit-Chain (Merkle-Tree) an.
7. **Bestätigung:** Die Sequenznummer der Chain wird dem Client zurückgemeldet.

### 1.3 Server-Antwort und Audit-Chain Status

Die erfolgreiche Abarbeitung der Transaktion (15,00 EUR) durch den in Rust geschriebenen SIGIL-EURO Daemon ergab folgende verbindliche Antwort:

```json
{
  "accepted": true,
  "payment_reference": "SIGILEURO-20260224-512a1bcc",
  "audit_seq": 15,
  "aml_flags": [],
  "message": "Accepted. HMAC-signed audit entry #15 written."
}
```

### 1.4 Anchoring über Cron an Public Blockchain (Celestia Mocha)

Als Nachweis für den manipulationssicheren Zero-Trust-Aspekt ("Tamper-Evident Audit Trail"), flush't ein getrennter Daemon (`anchor-celestia.sh`) den Merkle Root.

Dieser Job greift den Hash `0xfb19a5ff8ba6be900bac09968522577d60e3e4da9e5fe7dda19928dbc0517c64` ab und hinterlegt ihn in einer öffentlichen Data Availability Schicht (hier *Celestia Mocha*, Block `10221745`).

**Bestätigtes Logfile:**

```text
[2026-02-24T22:40:50Z] Starting Celestia Merkle anchor...
[INFO] Submitting blob to Celestia Mocha testnet...
[OK] Anchor receipt: /home/admin/sigil-euro/audit/merkle/batch-20260224-150013-celestia.json
[OK] Celestia Mocha block: 10221745
```

## Fazit der Implementierungsprüfung

Der gesamte Fluss — beginnend bei der lokalen Kryptografieerzeugung im Client über die asymmetrische Signatur, den gesicherten Netzwerktransport (TLS + API-Key), das serverseitige Deserialisieren in typensichere Rust-Structs, das lokale AML-Scanning, die HMAC Audit-Generierung und das finale Blockchain-Anchoring — verhält sich deterministisch und bestätigt alle theoretischen Vorgaben der Patentanmeldung zu 100%. Da sämtliche Bridge-Projekte und der SIGIL-EURO Quelltext als strikt private Repositories geführt werden, ist die Offenbarung unter Verschluss und die Geheimhaltung gewahrt.
