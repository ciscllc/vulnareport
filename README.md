# Vulnerability Report

Open-Source-Tool zur automatisierten Prüfung **selbst registrierter** Domains
auf bekannte Information-Disclosure- und Fehlkonfigurations-Probleme
(offene `phpinfo()`, ungeschützte phpMyAdmin/Railo/ColdFusion-Adminpfade,
verdächtige CMS-Admin-Bereiche, zu ausführliche Server-Header) — mit
automatischem Mailversand an die hinterlegten Domain-Kontakte, einem
Statistik-Dashboard und einem Plugin-System für weitere Prüfungen.

## Wichtig: Scope

Es werden **ausschließlich Domains gescannt, die im System als `verified`
markiert sind**. Es findet **kein** Scannen des offenen Internets oder
beliebiger fremder Domains statt. Eine Domain gilt erst nach erfolgreicher
Verifizierung als scanbar:

1. **E-Mail-Verifizierung** – Bestätigungslink an admin@/webmaster@/hostmaster@
   der Domain sowie optional an den WHOIS-Kontakt.
2. **Datei-Upload-Nachweis** – Zufallstoken als Datei unter
   `/.well-known/vulnreport-verify-<token>.txt` ablegen.
3. **Manuelle Prüfung** – Domain landet in einer Warteschlange, ein
   Systemadministrator des Vulnerability-Report-Systems schaltet sie
   manuell frei.

Sysadmins können ihre eigenen Domains jederzeit **blacklisten**, um sie
dauerhaft vom Scanning auszuschließen, und eine Infoseite mit allen für ihre
Domain gefundenen Hinweisen einsehen.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# .env anpassen (SMTP-Zugangsdaten, SECRET_KEY, etc.)

python run.py
```

Der erste registrierte Nutzer (`/register`) wird automatisch Admin.

## Architektur

```
app/
├── models.py              # User, Domain, VerificationToken, Plugin, ScanResult, MailLog
├── auth.py                 # Login/Registrierung
├── verification/           # 3 Verifizierungswege
├── scanner/
│   ├── engine.py            # Scan-Orchestrierung, Dedup, Mail-Trigger
│   ├── plugin_base.py       # VulnPlugin-Basisklasse, Finding-Dataclass
│   └── plugin_loader.py     # Dynamisches Laden mit Checksum-Prüfung
├── plugins/                 # Basis-Plugins (siehe unten)
├── mailer.py                 # SMTP-Versand
└── web/
    ├── sysadmin_panel/       # Domain eintragen, verifizieren, blacklisten, Findings ansehen
    └── admin_panel/          # Statistik-Dashboard, Domain-Freigabe, Plugin-Verwaltung, Mail-Log
```

## Mitgelieferte Plugins

| Plugin | Prüft auf |
|---|---|
| `phpinfo_disclosure` | Öffentlich erreichbare `phpinfo()`-Ausgaben |
| `default_configs` | Unveränderte phpMyAdmin/Railo/ColdFusion-Adminpfade |
| `open_admin_panels` | CMS-Adminpfade ohne erkennbares Login-Formular (Hinweis, keine Bestätigung) |
| `server_header_leaks` | Zu ausführliche `Server`/`X-Powered-By`-Header |

Findings werden per SHA-256-Hash aus `domain+plugin+pfad` dedupliziert, damit
nicht bei jedem Lauf erneut gemailt wird.

## Eigene Plugins schreiben

```python
# app/plugins/mein_plugin.py
from app.scanner.plugin_base import Finding, VulnPlugin

class Plugin(VulnPlugin):
    name = "mein_plugin"
    version = "1.0"
    description = "Kurzbeschreibung"
    default_severity = "medium"
    report_title_template = "Vulnerability Report: {domain}"

    def check(self, domain: str, http_client) -> list[Finding]:
        findings = []
        r = http_client.get(f"https://{domain}/irgendein-pfad")
        if r is not None and r.status_code == 200 and "marker" in r.text:
            findings.append(Finding(path="/irgendein-pfad", evidence="..."))
        return findings
```

Im Admin-Panel unter **Plugins → Hochladen** einreichen, Code prüfen, dann
aktivieren. Nach Aktivierung wird die Datei-Checksumme gespeichert; ändert
sich die Datei danach auf der Platte, wird das Plugin beim nächsten Lauf
automatisch übersprungen, bis ein Admin es erneut bestätigt.

Zusätzliche Methoden in eigenen Plugins sind erlaubt – der Loader ruft
zwingend nur `check()` auf, alles andere (eigene Report-Formatierung,
Hilfsfunktionen) steht frei.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
