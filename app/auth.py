from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import db
from app.models import Role, User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if User.query.filter_by(email=email).first():
            flash("E-Mail bereits registriert.", "error")
            return redirect(url_for("auth.register"))

        # Erster registrierter Nutzer wird automatisch Admin
        is_first_user = User.query.count() == 0
        user = User(email=email, role=Role.ADMIN if is_first_user else Role.SYSADMIN)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        flash("Registrierung erfolgreich.", "success")
        return redirect(url_for("sysadmin.dashboard"))

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user)
            next_url = request.args.get("next")
            return redirect(next_url or url_for("sysadmin.dashboard"))

        flash("Login fehlgeschlagen.", "error")

    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))
