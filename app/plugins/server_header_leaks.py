import re

from app.scanner.plugin_base import Finding, VulnPlugin

# Erkennt zu detaillierte Server/X-Powered-By Header, z.B.
# "Apache/2.4.41 (Ubuntu) PHP/7.4.3" statt nur "Apache"
VERSION_PATTERN = re.compile(r"\d+\.\d+")


class Plugin(VulnPlugin):
    name = "server_header_leaks"
    version = "1.0"
    description = "Findet zu ausführliche Server/X-Powered-By Header (Versionsangaben)."
    default_severity = "low"
    report_title_template = "Information Disclosure on {domain}"

    def check(self, domain: str, http_client) -> list[Finding]:
        findings = []
        try:
            r = http_client.get(f"https://{domain}/")
        except Exception:
            return findings
        if r is None:
            return findings

        for header_name in ("Server", "X-Powered-By"):
            value = r.headers.get(header_name)
            if value and VERSION_PATTERN.search(value):
                findings.append(
                    Finding(
                        path="/",
                        evidence=f"{header_name}-Header gibt Versionsdetails preis: '{value}'",
                        severity=self.default_severity,
                    )
                )
        return findings
