from app.scanner.plugin_base import Finding, VulnPlugin

PATHS = ["/phpinfo.php", "/info.php", "/test.php", "/i.php", "/php_info.php"]


class Plugin(VulnPlugin):
    name = "phpinfo_disclosure"
    version = "1.0"
    description = "Findet öffentlich erreichbare phpinfo()-Ausgaben."
    default_severity = "medium"
    report_title_template = "Information Disclosure on {domain}"

    def check(self, domain: str, http_client) -> list[Finding]:
        findings = []
        for path in PATHS:
            try:
                r = http_client.get(f"https://{domain}{path}")
            except Exception:
                continue
            if r is not None and r.status_code == 200 and "phpinfo()" in r.text.lower():
                findings.append(
                    Finding(
                        path=path,
                        evidence="phpinfo()-Ausgabe öffentlich erreichbar (enthält u.a. Serverpfade, "
                        "geladene Module, evtl. Umgebungsvariablen).",
                        severity=self.default_severity,
                    )
                )
        return findings
