"""
Orchestriert den Scanlauf: iteriert nur über Domains mit status=verified
(Blacklist und Pending werden nie gescannt), führt alle aktivierten Plugins
aus, dedupliziert Findings per Hash und stößt bei neuen Findings den
Mailversand an den hinterlegten Domain-Kontakt an.
"""
from datetime import datetime

import requests
from flask import current_app

from app.extensions import db
from app.mailer import send_mail
from app.models import Domain, DomainStatus, MailLog, ScanResult, Severity
from app.scanner.plugin_loader import load_enabled_plugins


class ScopedHttpClient:
    """Wrapper um requests, der User-Agent und Timeout zentral setzt und
    Exceptions abfängt, statt Plugins damit zu belasten."""

    def __init__(self, timeout: int, user_agent: str):
        self.timeout = timeout
        self.headers = {"User-Agent": user_agent}

    def get(self, url: str, allow_redirects: bool = True):
        try:
            return requests.get(
                url, headers=self.headers, timeout=self.timeout, allow_redirects=allow_redirects
            )
        except requests.RequestException:
            return None


def run_scan_for_domain(domain: Domain, plugin_pairs, http_client) -> list[ScanResult]:
    new_results = []
    for plugin_record, plugin_instance in plugin_pairs:
        try:
            findings = plugin_instance.check(domain.fqdn, http_client)
        except Exception:
            continue

        for finding in findings:
            dedup_hash = ScanResult.make_dedup_hash(domain.fqdn, plugin_instance.name, finding.path)
            existing = ScanResult.query.filter_by(dedup_hash=dedup_hash, resolved_at=None).first()
            if existing:
                continue  # bereits gemeldet und nicht als behoben markiert

            result = ScanResult(
                domain_id=domain.id,
                plugin_id=plugin_record.id,
                severity=Severity(finding.severity),
                title=plugin_instance.report_title(domain.fqdn),
                path=finding.path,
                detail=finding.evidence,
                dedup_hash=dedup_hash,
            )
            db.session.add(result)
            db.session.flush()  # id verfügbar machen für MailLog
            new_results.append((result, plugin_instance, finding))

    domain.last_scanned_at = datetime.utcnow()
    db.session.commit()
    return new_results


def notify_domain_owner(domain: Domain, result: ScanResult, plugin_instance, finding):
    recipient = domain.contact_email or domain.owner.email
    subject = plugin_instance.report_title(domain.fqdn)
    body = plugin_instance.report_body(domain.fqdn, finding)

    success, error = send_mail(to=recipient, subject=subject, body=body)

    log = MailLog(
        domain_id=domain.id,
        scan_result_id=result.id,
        recipient=recipient,
        subject=subject,
        status="sent" if success else "failed",
        error=error,
        sent_at=datetime.utcnow() if success else None,
    )
    db.session.add(log)
    if success:
        result.mailed_at = datetime.utcnow()
    db.session.commit()


def run_full_scan(app):
    """Einstiegspunkt für den Scheduler. Läuft im App-Context."""
    with app.app_context():
        from app.models import Plugin as PluginModel

        plugin_records = PluginModel.query.filter_by(enabled=True).all()
        plugin_pairs = load_enabled_plugins(plugin_records)
        if not plugin_pairs:
            return

        http_client = ScopedHttpClient(
            timeout=current_app.config["HTTP_TIMEOUT"],
            user_agent=current_app.config["USER_AGENT"],
        )

        domains = Domain.query.filter_by(status=DomainStatus.VERIFIED).all()
        for domain in domains:
            new_results = run_scan_for_domain(domain, plugin_pairs, http_client)
            for result, plugin_instance, finding in new_results:
                notify_domain_owner(domain, result, plugin_instance, finding)
