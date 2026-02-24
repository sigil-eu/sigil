# SIGIL Protocol — Ops-Notiz: Security Setup & Gateway-Infrastruktur

**Stand: 2026-02-24 | Server: 194.242.56.119**

---

## Laufende Services (alle autostart-enabled)

| Service | Port | Beschreibung | systemd unit |
|---|---|---|---|
| `sigil-euro` | 8443 | SIGIL-EURO Gateway (Audit, AML) | `/etc/systemd/system/sigil-euro.service` |
| `sigil-fxbridge` | 8444 | FXBridge Gateway (Multi-Hop FX) | `/etc/systemd/system/sigil-fxbridge.service` |
| `sigil-servicebridge` | 8445 | ServiceBridge Gateway (DisputeWindow) | `/etc/systemd/system/sigil-servicebridge.service` |
| `nginx` | 80/443 | Reverse Proxy + TLS | System-default |

**Nach Reboot starten alle automatisch.** Keine manuelle Intervention nötig.

---

## Sicherheitsarchitektur (2 Schichten)

```
Internet
   │
   ▼
[ nginx ]  ──── Layer 1: IP-Whitelist (allow/deny)
   │             Erlaubt nur: 77.2.73.0/24 + 194.242.56.119
   │
   ▼
[ Gateway ]  ── Layer 2: X-Sigil-API-Key Header
                Ohne gültigen Key: 401 Unauthorized
                Mit gültigem Key:  200 OK + Response
```

### Nginx-Routen (sites-available + sites-enabled)

> ⚠️ **WICHTIG:** `sites-enabled/sigil-protocol.org` war eine **statische Kopie** (kein Symlink).
> Änderungen in `sites-available/` müssen immer auch in `sites-enabled/` landen:
>
> ```bash
> sudo cp /etc/nginx/sites-available/sigil-protocol.org /etc/nginx/sites-enabled/sigil-protocol.org
> sudo nginx -t && sudo nginx -s reload
> ```

Routen (alle mit `^~` Modifier für garantiertes Location-Matching):

| Öffentliche URL | Intern | Gateway |
|---|---|---|
| `https://sigil-protocol.org/euro/api/*` | `http://127.0.0.1:8443/` | sigil-euro |
| `https://sigil-protocol.org/fx/api/*` | `http://127.0.0.1:8444/` | sigil-fxbridge |
| `https://sigil-protocol.org/service/api/*` | `http://127.0.0.1:8445/` | sigil-servicebridge |

---

## API-Key

Alle Gateways verwenden **denselben API-Key**:

```bash
# Key lesen (auf VPS):
grep SIGIL_API_KEY /home/admin/sigil-euro/.env
grep FXBRIDGE_API_KEY /home/admin/SIGIL-FXBRIDGE/.env
grep SERVICEBRIDGE_API_KEY /home/admin/SIGIL-SERVICEBRIDGE/.env
```

Key-Prefix: `07ef37c0...` (48 Zeichen hex)

### Verwendung in curl

```bash
KEY="07ef37c0..." # vollständiger Key
curl -H "X-Sigil-API-Key: $KEY" https://sigil-protocol.org/euro/api/health
curl -H "X-Sigil-API-Key: $KEY" https://sigil-protocol.org/fx/api/health
curl -H "X-Sigil-API-Key: $KEY" https://sigil-protocol.org/service/api/health
```

---

## Gateway-Binaries und .env Dateien

| Gateway | Binary | .env | Env-Variable |
|---|---|---|---|
| sigil-euro | `/home/admin/sigil-euro/bin/sigil-euro-gateway` | `/home/admin/sigil-euro/.env` | `SIGIL_API_KEY` |
| sigil-fxbridge | `/home/admin/SIGIL-FXBRIDGE/bin/sigil-fxbridge-gateway` | `/home/admin/SIGIL-FXBRIDGE/.env` | `FXBRIDGE_API_KEY` |
| sigil-servicebridge | `/home/admin/SIGIL-SERVICEBRIDGE/bin/sigil-servicebridge-gateway` | `/home/admin/SIGIL-SERVICEBRIDGE/.env` | `SERVICEBRIDGE_API_KEY` |

---

## IP-Whitelist anpassen

Wenn sich deine IP ändert, in `/etc/nginx/sites-available/sigil-protocol.org` alle `allow`-Zeilen anpassen:

```bash
# Aktuelle IP prüfen:
curl https://api.ipify.org

# nginx-Config bearbeiten:
sudo nano /etc/nginx/sites-available/sigil-protocol.org
# → Zeile "allow 77.2.73.0/24;" auf neue IP/Range ändern

# In sites-enabled kopieren + reload:
sudo cp /etc/nginx/sites-available/sigil-protocol.org /etc/nginx/sites-enabled/sigil-protocol.org
sudo nginx -t && sudo nginx -s reload
```

---

## Update-Workflow (neue Binary deployen)

```bash
# 1. Lokal bauen (auf Mac):
rsync -avz --exclude target ./src/sigil-fxbridge-gateway/ admin@194.242.56.119:/home/admin/SIGIL-FXBRIDGE/src/sigil-fxbridge-gateway/

# 2. Auf VPS bauen:
ssh admin@194.242.56.119
source ~/.cargo/env
cd /home/admin/SIGIL-FXBRIDGE/src && cargo build --release --package sigil-fxbridge-gateway

# 3. Binary deployen:
cp src/target/release/sigil-fxbridge-gateway bin/sigil-fxbridge-gateway.new
mv bin/sigil-fxbridge-gateway.new bin/sigil-fxbridge-gateway

# 4. Restart via systemd (braucht sudo):
sudo systemctl restart sigil-fxbridge
```

---

## Monitoring

```bash
# Live-Logs aller Gateways:
journalctl -u sigil-euro -f
journalctl -u sigil-fxbridge -f
journalctl -u sigil-servicebridge -f

# Schnell-Status:
systemctl status sigil-euro sigil-fxbridge sigil-servicebridge nginx

# Health-Check (von lokal):
curl -H "X-Sigil-API-Key: $(grep SIGIL_API_KEY /home/admin/sigil-euro/.env | cut -d= -f2)" http://localhost:8443/health
curl -H "X-Sigil-API-Key: $(grep FXBRIDGE_API_KEY /home/admin/SIGIL-FXBRIDGE/.env | cut -d= -f2)" http://localhost:8444/health
curl -H "X-Sigil-API-Key: $(grep SERVICEBRIDGE_API_KEY /home/admin/SIGIL-SERVICEBRIDGE/.env | cut -d= -f2)" http://localhost:8445/health
```

---

## Bekannte Fallstricke

1. **`sites-enabled` ≠ `sites-available`:** nginx liest aus `sites-enabled/`. Bei Änderungen immer `sudo cp sites-available/... sites-enabled/...` und reload.
2. **Dynamische IP:** Wenn deine ISP-IP wechselt, bist du ausgesperrt. Neue IP in `allow`-Zeilen eintragen.
3. **Binary-Update:** `cp` auf laufende Binary schlägt mit "Text file busy" fehl → `.new` Datei kopieren, dann `mv` (atomar).
4. **Sudo ohne TTY:** `sudo` in nicht-interaktiven SSH-Sessions kann Passwort-Prompt nicht anzeigen → interaktive SSH-Session öffnen.
