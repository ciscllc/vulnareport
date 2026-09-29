import smtplib
from email.mime.text import MIMEText

from flask import current_app


def send_mail(to: str, subject: str, body: str) -> tuple[bool, str | None]:
    """Sendet eine Mail über den konfigurierten SMTP-Server.
    Gibt (erfolg, fehlermeldung) zurück statt zu werfen, damit Aufrufer
    das im MailLog vermerken können, ohne den Scan-Lauf abzubrechen."""
    cfg = current_app.config
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = cfg["MAIL_FROM"]
    msg["To"] = to

    try:
        with smtplib.SMTP(cfg["MAIL_SERVER"], cfg["MAIL_PORT"], timeout=10) as server:
            if cfg["MAIL_USE_TLS"]:
                server.starttls()
            if cfg["MAIL_USERNAME"]:
                server.login(cfg["MAIL_USERNAME"], cfg["MAIL_PASSWORD"])
            server.sendmail(cfg["MAIL_FROM"], [to], msg.as_string())
        return True, None
    except Exception as e:
        return False, str(e)
