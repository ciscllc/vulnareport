"""
Basisklasse für Vulnerability-Plugins.

Ein Plugin prüft eine verifizierte Domain auf ein bestimmtes Merkmal
(offene phpinfo-Seite, freie Admin-Config, etc.) und liefert eine Liste
von Finding-Objekten zurück. Plugins können zusätzlich beliebige weitere
Funktionen bereitstellen (z.B. eigene Report-Formatierung, Hooks), indem
sie zusätzliche Methoden definieren - der Loader ruft nur die hier
definierte Schnittstelle zwingend auf.
"""
from dataclasses import dataclass, field


@dataclass
class Finding:
    path: str | None
    evidence: str
    severity: str = "medium"  # low, medium, high, critical
    extra: dict = field(default_factory=dict)


class VulnPlugin:
    # Von jedem Plugin zu überschreiben:
    name: str = "unnamed_plugin"
    version: str = "1.0"
    description: str = ""
    default_severity: str = "medium"
    report_title_template: str = "Information Disclosure on {domain}"

    def check(self, domain: str, http_client) -> list[Finding]:
        """Muss von Subklassen implementiert werden."""
        raise NotImplementedError

    def report_title(self, domain: str) -> str:
        return self.report_title_template.format(domain=domain)

    def report_body(self, domain: str, finding: Finding) -> str:
        """Kann überschrieben werden für individuellen Mailtext."""
        return (
            f"Auf der Domain {domain} wurde ein Hinweis auf "
            f"'{self.name}' gefunden.\n\n"
            f"Pfad: {finding.path or '(nicht zutreffend)'}\n"
            f"Detail: {finding.evidence}\n\n"
            f"Empfehlung: Bitte prüfen und den Zugriff auf diese Ressource "
            f"einschränken oder die Datei entfernen.\n\n"
            f"-- Vulnerability Report (automatisierte Meldung)"
        )
