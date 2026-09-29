from app.scanner.plugin_base import Finding, VulnPlugin

# Pfad -> (Erkennungsmerkmal im Body, Beschreibung)
CHECKS = {
    "/phpmyadmin/": ("phpmyadmin", "phpMyAdmin-Login ohne erkennbaren Zugriffsschutz erreichbar."),
    "/pma/": ("phpmyadmin", "phpMyAdmin-Login (Alias /pma/) ohne erkennbaren Zugriffsschutz erreichbar."),
    "/railo-context/admin/web.cfm": ("railo", "Railo Web-Admin-Interface öffentlich erreichbar."),
    "/railo-context/admin/server.cfm": ("railo", "Railo Server-Admin-Interface öffentlich erreichbar."),
    "/CFIDE/administrator/index.cfm": ("coldfusion", "ColdFusion Administrator-Login öffentlich erreichbar."),
    "/CFIDE/adminapi/": ("coldfusion", "ColdFusion Admin-API-Pfad öffentlich erreichbar."),
}


class Plugin(VulnPlugin):
    name = "default_configs"
    version = "1.0"
    description = "Findet unveränderte Standard-Adminpfade für phpMyAdmin, Railo, ColdFusion."
    default_severity = "high"
    report_title_template = "Exposed Admin Interface on {domain}"

    def check(self, domain: str, http_client) -> list[Finding]:
        findings = []
        for path, (marker, description) in CHECKS.items():
            try:
                r = http_client.get(f"https://{domain}{path}")
            except Exception:
                continue
            if r is None or r.status_code not in (200, 401, 403):
                continue
            body_lower = r.text.lower() if r.text else ""
            if r.status_code == 200 and marker in body_lower:
                findings.append(
                    Finding(path=path, evidence=description, severity=self.default_severity)
                )
        return findings
