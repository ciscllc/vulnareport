import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", f"sqlite:///{os.path.join(BASE_DIR, 'vulnreport.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Mailversand
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "localhost")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD", "")
    MAIL_FROM = os.environ.get("MAIL_FROM", "vulnreport@example.org")

    # Scan-Verhalten
    SCAN_INTERVAL_HOURS = int(os.environ.get("SCAN_INTERVAL_HOURS", 168))  # wöchentlich
    HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", 8))
    USER_AGENT = os.environ.get(
        "USER_AGENT",
        "VulnReportBot/1.0 (+https://example.org/vulnreport-info; nur verifizierte Domains)",
    )

    # Verifizierung
    VERIFY_TOKEN_TTL_HOURS = int(os.environ.get("VERIFY_TOKEN_TTL_HOURS", 24))
    FILE_VERIFY_PATH = ".well-known/vulnreport-verify-{token}.txt"

    PLUGIN_DIR = os.path.join(BASE_DIR, "app", "plugins")
