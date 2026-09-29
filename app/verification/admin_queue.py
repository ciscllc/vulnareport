"""
Admin-Queue: Domain wird eingetragen und bleibt im Status PENDING, bis ein
Systemadministrator sie im Admin-Panel manuell prüft und freischaltet.
Dient als Fallback, wenn weder E-Mail- noch Datei-Verifizierung möglich sind
(z.B. Subdomain ohne eigenen Mailserver, Legacy-System ohne Upload-Zugriff).
"""
from datetime import datetime

from app.extensions import db
from app.models import Domain, DomainStatus


def enqueue_for_admin_review(domain: Domain, note: str = ""):
    domain.status = DomainStatus.PENDING
    domain.admin_note = note
    db.session.commit()


def approve_domain(domain: Domain, reviewer_note: str = ""):
    domain.status = DomainStatus.VERIFIED
    domain.verified_at = datetime.utcnow()
    if reviewer_note:
        domain.admin_note = (domain.admin_note or "") + f"\n[Admin] {reviewer_note}"
    db.session.commit()


def reject_domain(domain: Domain, reviewer_note: str = ""):
    domain.status = DomainStatus.REJECTED
    if reviewer_note:
        domain.admin_note = (domain.admin_note or "") + f"\n[Admin] {reviewer_note}"
    db.session.commit()
