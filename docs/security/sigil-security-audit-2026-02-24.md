# SIGIL Protocol — Security & Attack Surface Audit

**Stand: 2026-02-24 | Server: 194.242.56.119**

---

Wenn wir den gesamten Server als potenzielles Angriffsziel (Attack Surface) aus dem öffentlichen Internet (Zero Trust) betrachten, ist die Sicherheitsarchitektur exzellent und extrem restriktiv. Hier ist die genaue Übersicht aller externen "Einfallstore":

## 1. NGINX: HTTP/HTTPS (Port 80 / 443)

Das ist das Haupt-Einfallstor für legitimen und illegitimen Traffic. NGINX fungiert als strikter Wächter (Reverse Proxy), der extrem stark filtert, bevor Anfragen an die eigentlichen Applikationen (Rust) weitergegeben werden.

### A. Unbekannte Domains & Bots (Scanner)

* **Mechanismus:** Jeder Request, der direkt auf die IP `194.242.56.119` zielt, ohne den korrekten Hostnamen (`sigil-protocol.org`) im Header mitzusenden. Das ist das typische Verhalten von automatisierten Massen-Scannern.
* **Absicherung:** Wird von einem Default-Server-Block (Catch-all) sofort geblockt (`listen 80 default_server; return 404;`).
* **Ergebnis:** Der Server bleibt für Scanner praktisch unsichtbar (Reagiert wie ein inaktiver Host).

### B. Die sigil-protocol.org Homepage

* **Mechanismus:** Auslieferung von reinen, statischen Dateien (HTML, CSS).
* **Absicherung:** Keine Datenbank, keine serverseitige Logik (kein PHP/Node/Python). Hier kann keine Code-Injection (RCE/SQLi) stattfinden, da NGINX lediglich statischen Text ausliefert. Es gelten die NGINX-Standard-Limits.

### C. Die Gateways (`/euro/api/`, `/fx/api/`, `/service/api/`)

* **Netzwerk-Schicht (IP-Whitelist):** Zugriff ist hart auf das Entwickler-Subnetz (`77.2.73.0/24`) beschränkt. Alle anderen Verbindungsversuche werden mit `403 Forbidden` abgewiesen, bevor Logs geschrieben oder Logic ausgeführt wird.
* **Infrastruktur-Schicht (Rate-Limiting):** Strenge Limitierung (`zone=sigil_api`) auf max. 30 Requests pro Minute und IP. Ein Bruteforce von Schlüsseln oder Endpunkten ist praktisch unmöglich.
* **Applikations-Schicht (API-Key):** Selbst wenn eine IP gespooft wird oder im Whitelist-Netz ist, lehnt das Rust-Backend jede Operation bei fehlendem/falschem Key (`X-Sigil-API-Key`) mit `401 Unauthorized` ab.

### D. Die Registry (`registry.sigil-protocol.org`)

* **Sichtbarkeit:** Öffentlich erreichbar, was für eine dezentrale Registry gewollt ist.
* **Absicherung (Rate-Limiting):** Separiert in Read- und Write-Zonen.
  * `sigil_read` (z.B. Downloads von Patterns): Höheres Limit für Agent-Kaltstarts.
  * `sigil_write` (Uploads, Votes): Extrem limitiert (Burst von 20), um die PostgreSQL-Datenbank vor Spam, DDoS oder Speicherüberlauf zu schützen. Bei Überschreiten greift ein harter `429 Too Many Requests`.

---

## 2. SSH-Zugang (Port 22)

Dies ist das einzige andere offene Tor ins System neben HTTP/HTTPS.

* **Absicherung:** Geschützt durch kryptografische SSH-Keys und/oder ein starkes Passwort. OpenSSH hat eine sehr geringe Angriffsfläche.
* **Post-Exploitation:** Selbst bei einem unwahrscheinlichen Credential-Leak läuft der SSH-Login über den `admin`-User. Tiefgreifende Systemänderungen oder Manipulationen der Systemd-Unit erfordern zwingend `sudo`-Rechte (Privilege Escalation), was eine weitere, kritische Hürde darstellt.

---

## 3. Rust Backend-Dienste & PostgreSQL (Ports 3100, 5432, 8443, 8444, 8445)

Diese Dienste existieren, sind aber **nicht an das öffentliche Internet gebunden** (`0.0.0.0`).

* **Absicherung:** Sie lauschen alle ausschließlich auf dem lokalen Loopback-Interface `127.0.0.1` (localhost).
* **Auswirkung:** Selbst wenn die Firewall (UFW) versehentlich deaktiviert würde oder fehlerhaft konfiguriert wäre, würde der Linux-Kernel externe TCP/IP-Pakete für diese Ports hart abweisen. Niemand kann direkt zu PostgreSQL oder den Rust-Binaries verbinden, ohne vorher durch NGINX zu gehen.

---

## Zusammenfassung

* **Sicherheitsniveau:** Exzellent
* **Architektur:** Defense in Depth (Verteidigung in der Tiefe)
    1. **Netzwerk / OS:** Dienste binden nur intern (127.0.0.1).
    2. **Proxy (NGINX):** Verwirft Bot-Traffic hart, drosselt (Rate-Limits) die verbleibenden Anfragen, und blockt nicht-autorisierte IPs für kritische APIs auf Layer 7.
    3. **Applikation (Rust):** Verifiziert kryptografische Keys (API-Keys für Administration, Signaturen für Registry-Updates).

Das System ist im produktiven Setup / für eine Public-Beta maximal abgesichert.
