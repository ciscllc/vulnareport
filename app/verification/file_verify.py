"""
Datei-Upload-Verifizierung: Nutzer legt eine Datei mit Zufallstoken unter
/.well-known/vulnreport-verify-<token>.txt ab. Kein DNS-Zugriff nötig,
nur Kontrolle über den Webserver-Inhalt reicht als Nachweis.
"""
from datetime import datetime

import requests
from flask import current_app

from app.extensions import db
from app.models import Domain, DomainStatus, VerificationMethod, VerificationToken


def start_file_verification(domain: Domain) -> VerificationToken:
    token = VerificationToken(domain_id=domain.id, method=VerificationMethod.FILE)
    db.session.add(token)
    db.session.commit()
    return token


def expected_file_url(domain: Domain, token: VerificationToken) -> str:
    path = current_app.config["FILE_VERIFY_PATH"].format(token=token.token)
    return f"https://{domain.fqdn}/{path}"


def check_file_verification(token: VerificationToken) -> tuple[bool, str]:
    if token.is_expired():
        return False, "Token abgelaufen. Bitte erneut anfordern."

    domain = token.domain
    url = expected_file_url(domain, token)
    headers = {"User-Agent": current_app.config["USER_AGENT"]}

    try:
        # https zuerst, http als Fallback
        for scheme_url in (url, url.replace("https://", "http://", 1)):
            r = requests.get(scheme_url, headers=headers, timeout=current_app.config["HTTP_TIMEOUT"])
            if r.status_code == 200 and token.token in r.text:
                token.confirmed_at = datetime.utcnow()
                domain.status = DomainStatus.VERIFIED
                domain.verified_at = datetime.utcnow()
                db.session.commit()
                return True, "Domain erfolgreich verifiziert."
    except requests.RequestException as e:
        return False, f"Datei konnte nicht abgerufen werden: {e}"

    return False, "Token in der Datei nicht gefunden. Bitte Inhalt und Pfad prüfen."
