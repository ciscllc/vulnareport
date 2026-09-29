from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.models import Domain, DomainStatus, VerificationMethod
from app.verification.admin_queue import enqueue_for_admin_review
from app.verification.email_verify import candidate_addresses, confirm_email_token, start_email_verification
from app.verification.file_verify import check_file_verification, expected_file_url, start_file_verification

sysadmin_bp = Blueprint("sysadmin", __name__, url_prefix="/sysadmin")


@sysadmin_bp.route("/")
@login_required
def dashboard():
    domains = current_user.domains.order_by(Domain.added_at.desc()).all()
    return render_template("sysadmin/dashboard.html", domains=domains)


@sysadmin_bp.route("/domains/add", methods=["GET", "POST"])
@login_required
def add_domain():
    if request.method == "POST":
        fqdn = request.form["fqdn"].strip().lower()
        method = request.form["verification_method"]

        if Domain.query.filter_by(fqdn=fqdn).first():
            flash("Diese Domain ist bereits registriert.", "error")
            return redirect(url_for("sysadmin.add_domain"))

        domain = Domain(
            fqdn=fqdn,
            owner_id=current_user.id,
            verification_method=VerificationMethod(method),
            status=DomainStatus.PENDING,
        )
        db.session.add(domain)
        db.session.commit()

        if method == VerificationMethod.EMAIL.value:
            return redirect(url_for("sysadmin.choose_email_address", domain_id=domain.id))
        elif method == VerificationMethod.FILE.value:
            token = start_file_verification(domain)
            return redirect(url_for("sysadmin.file_verification_instructions", token=token.token))
        else:
            enqueue_for_admin_review(domain, note=request.form.get("admin_note", ""))
            flash("Domain zur manuellen Prüfung eingereicht.", "success")
            return redirect(url_for("sysadmin.dashboard"))

    return render_template("sysadmin/add_domain.html")


@sysadmin_bp.route("/domains/<int:domain_id>/email-address", methods=["GET", "POST"])
@login_required
def choose_email_address(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    if domain.owner_id != current_user.id:
        flash("Nicht berechtigt.", "error")
        return redirect(url_for("sysadmin.dashboard"))

    if request.method == "POST":
        address = request.form["address"]
        start_email_verification(domain, address)
        flash(f"Bestätigungsmail an {address} gesendet.", "success")
        return redirect(url_for("sysadmin.dashboard"))

    addresses = candidate_addresses(domain.fqdn)
    return render_template("sysadmin/choose_email.html", domain=domain, addresses=addresses)


@sysadmin_bp.route("/verify/email/<token>")
def confirm_email_verification(token):
    success, message = confirm_email_token(token)
    flash(message, "success" if success else "error")
    return redirect(url_for("auth.login"))


@sysadmin_bp.route("/verify/file/<token>", methods=["GET", "POST"])
@login_required
def file_verification_instructions(token):
    from app.models import VerificationToken

    vt = VerificationToken.query.filter_by(token=token).first_or_404()
    domain = vt.domain

    if request.method == "POST":
        success, message = check_file_verification(vt)
        flash(message, "success" if success else "error")
        if success:
            return redirect(url_for("sysadmin.dashboard"))

    file_url = expected_file_url(domain, vt)
    return render_template(
        "sysadmin/file_verification.html", domain=domain, token=vt.token, file_url=file_url
    )


@sysadmin_bp.route("/domains/<int:domain_id>/blacklist", methods=["POST"])
@login_required
def blacklist_domain(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    if domain.owner_id != current_user.id:
        flash("Nicht berechtigt.", "error")
        return redirect(url_for("sysadmin.dashboard"))

    domain.blacklist()
    db.session.commit()
    flash(f"{domain.fqdn} wurde blacklistet und wird nicht mehr gescannt.", "success")
    return redirect(url_for("sysadmin.dashboard"))


@sysadmin_bp.route("/domains/<int:domain_id>/findings")
@login_required
def domain_findings(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    if domain.owner_id != current_user.id:
        flash("Nicht berechtigt.", "error")
        return redirect(url_for("sysadmin.dashboard"))

    findings = [f for f in domain.findings if f.resolved_at is None]
    return render_template("sysadmin/findings.html", domain=domain, findings=findings)
