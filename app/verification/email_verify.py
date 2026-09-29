"""
E-Mail-Verifizierung: Bestätigungslink wird an Standard-Adressen der Domain
(admin@, webmaster@, hostmaster@) sowie optional an die im WHOIS hinterlegte
Kontaktadresse geschickt. Erst nach Klick auf den Link gilt die Domain als
verifiziert und wird in den Scan-Pool aufgenommen.
"""
from datetime import datetime

import whois
from flask import current_app, url_for

from app.extensions import db
from app.mailer import send_mail
from app.models import Domain, DomainStatus, VerificationMethod, VerificationToken

STANDARD_LOCALPARTS = ["admin", "webmaster", "hostmaster"]


def candidate_addresses(fqdn: str) -> list[str]:
    """Liste möglicher Verifizierungs-Empfänger: Standard-Adressen + WHOIS-Kontakt."""
    addresses = [f"{lp}@{fqdn}" for lp in STANDARD_LOCALPARTS]
    try:
        w = whois.whois(fqdn)
        whois_email = w.get("emails")
        if whois_email:
            if isinstance(whois_email, list):
                addresses.extend(whois_email)
            else:
                addresses.append(whois_email)
    except Exception:
        # WHOIS-Lookup ist best-effort, kein harter Fehler
        pass
    # Duplikate entfernen, Reihenfolge erhalten
    seen = set()
    unique = []
    for a in addresses:
        a_lower = a.lower()
        if a_lower not in seen:
            seen.add(a_lower)
            unique.append(a)
    return unique


def start_email_verification(domain: Domain, chosen_address: str) -> VerificationToken:
    token = VerificationToken(
        domain_id=domain.id,
        method=VerificationMethod.EMAIL,
        target_email=chosen_address,
    )
    db.session.add(token)
    db.session.commit()

    confirm_url = url_for("sysadmin.confirm_email_verification", token=token.token, _external=True)
    send_mail(
        to=chosen_address,
        subject=f"Vulnerability Report: Domainbestätigung für {domain.fqdn}",
        body=(
            f"Jemand hat die Domain {domain.fqdn} bei Vulnerability Report zur "
            f"Sicherheitsüberprüfung eingetragen.\n\n"
            f"Falls das autorisiert ist, bestätige bitte über folgenden Link:\n"
            f"{confirm_url}\n\n"
            f"Der Link ist {current_app.config['VERIFY_TOKEN_TTL_HOURS']} Stunden gültig.\n"
            f"Falls dies nicht von dir veranlasst wurde, ignoriere diese Mail."
        ),
    )
    return token


def confirm_email_token(token_value: str) -> tuple[bool, str]:
    token = VerificationToken.query.filter_by(token=token_value, method=VerificationMethod.EMAIL).first()
    if not token:
        return False, "Token nicht gefunden."
    if token.is_expired():
        return False, "Token abgelaufen. Bitte erneut anfordern."
    if token.is_confirmed():
        return True, "Bereits bestätigt."

    token.confirmed_at = datetime.utcnow()
    domain = token.domain
    domain.status = DomainStatus.VERIFIED
    domain.verified_at = datetime.utcnow()
    db.session.commit()
    return True, "Domain erfolgreich verifiziert."
