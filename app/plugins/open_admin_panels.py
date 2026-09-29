from app.scanner.plugin_base import Finding, VulnPlugin

# Standard-CMS Admin-Pfade. Ein "Fund" ist nur ein Hinweis (Pfad antwortet
# 200 ohne Redirect zu einer Login-Seite und ohne typische Login-Formular-
# Merkmale) - kein Nachweis fehlender Auth, daher niedrige/mittlere Severity
# und klarer Hinweis im Report, dass eine manuelle Prüfung nötig ist.
CMS_ADMIN_PATHS = [
    "/wp-admin/",
    "/administrator/",  # Joomla
    "/admin/",
    "/typo3/",
    "/umbraco/",
    "/user/login",  # Drupal
]

LOGIN_MARKERS = ["password", "login", "benutzername", "username", "anmelden"]


class Plugin(VulnPlugin):
    name = "open_admin_panels"
    version = "1.0"
    description = (
        "Findet erreichbare CMS-Admin-Pfade, die weder per HTTP-Auth noch "
        "erkennbar per Login-Formular geschützt wirken."
    )
    default_severity = "low"
    report_title_template = "Potentially Unprotected Admin Area on {domain}"

    def check(self, domain: str, http_client) -> list[Finding]:
        findings = []
        for path in CMS_ADMIN_PATHS:
            try:
                r = http_client.get(f"https://{domain}{path}", allow_redirects=False)
            except Exception:
                continue
            if r is None or r.status_code != 200:
                continue
            body_lower = (r.text or "").lower()
            looks_like_login = any(marker in body_lower for marker in LOGIN_MARKERS)
            if not looks_like_login:
                findings.append(
                    Finding(
                        path=path,
                        evidence=(
                            "Adminbereich antwortet mit HTTP 200, ohne erkennbares "
                            "Login-Formular oder Redirect. Bitte manuell prüfen, ob "
                            "hier tatsächlich ungeschützter Zugriff besteht."
                        ),
                        severity=self.default_severity,
                    )
                )
        return findings
