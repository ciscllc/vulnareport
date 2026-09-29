from flask import Flask

from app.extensions import db, login_manager, scheduler
from config import Config


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    from app.auth import auth_bp
    from app.web.sysadmin_panel.routes import sysadmin_bp
    from app.web.admin_panel.routes import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(sysadmin_bp)
    app.register_blueprint(admin_bp)

    with app.app_context():
        db.create_all()

    if not scheduler.running:
        from app.scanner.engine import run_full_scan

        scheduler.add_job(
            func=lambda: run_full_scan(app),
            trigger="interval",
            hours=app.config["SCAN_INTERVAL_HOURS"],
            id="periodic_scan",
            replace_existing=True,
        )
        scheduler.start()

    return app
