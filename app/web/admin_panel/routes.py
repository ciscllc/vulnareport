import os

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app.extensions import db
from app.models import Domain, DomainStatus, MailLog, Plugin, ScanResult
from app.scanner.plugin_loader import file_checksum, load_plugin_module
from app.verification.admin_queue import approve_domain, reject_domain

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def require_admin():
    if not current_user.is_authenticated or not current_user.is_admin:
        abort(403)


@admin_bp.before_request
@login_required
def check_admin():
    require_admin()


@admin_bp.route("/")
def dashboard():
    total_domains = Domain.query.count()
    verified = Domain.query.filter_by(status=DomainStatus.VERIFIED).count()
    pending = Domain.query.filter_by(status=DomainStatus.PENDING).count()
    blacklisted = Domain.query.filter_by(status=DomainStatus.BLACKLISTED).count()

    total_findings = ScanResult.query.count()
    open_findings = ScanResult.query.filter_by(resolved_at=None).count()

    total_mails = MailLog.query.count()
    sent_mails = MailLog.query.filter_by(status="sent").count()
    failed_mails = MailLog.query.filter_by(status="failed").count()

    findings_by_plugin = (
        db.session.query(Plugin.name, db.func.count(ScanResult.id))
        .join(ScanResult, ScanResult.plugin_id == Plugin.id)
        .group_by(Plugin.name)
        .all()
    )

    recent_findings = ScanResult.query.order_by(ScanResult.found_at.desc()).limit(20).all()

    return render_template(
        "admin/dashboard.html",
        total_domains=total_domains,
        verified=verified,
        pending=pending,
        blacklisted=blacklisted,
        total_findings=total_findings,
        open_findings=open_findings,
        total_mails=total_mails,
        sent_mails=sent_mails,
        failed_mails=failed_mails,
        findings_by_plugin=findings_by_plugin,
        recent_findings=recent_findings,
    )


@admin_bp.route("/domains")
def domains():
    status_filter = request.args.get("status")
    query = Domain.query
    if status_filter:
        query = query.filter_by(status=DomainStatus(status_filter))
    domain_list = query.order_by(Domain.added_at.desc()).all()
    return render_template("admin/domains.html", domains=domain_list, status_filter=status_filter)


@admin_bp.route("/domains/<int:domain_id>/approve", methods=["POST"])
def approve(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    approve_domain(domain, reviewer_note=request.form.get("note", ""))
    flash(f"{domain.fqdn} freigegeben.", "success")
    return redirect(url_for("admin.domains"))


@admin_bp.route("/domains/<int:domain_id>/reject", methods=["POST"])
def reject(domain_id):
    domain = Domain.query.get_or_404(domain_id)
    reject_domain(domain, reviewer_note=request.form.get("note", ""))
    flash(f"{domain.fqdn} abgelehnt.", "success")
    return redirect(url_for("admin.domains"))


@admin_bp.route("/plugins")
def plugins():
    plugin_list = Plugin.query.order_by(Plugin.uploaded_at.desc()).all()
    return render_template("admin/plugins.html", plugins=plugin_list)


@admin_bp.route("/plugins/upload", methods=["GET", "POST"])
def upload_plugin():
    if request.method == "POST":
        file = request.files.get("plugin_file")
        if not file or not file.filename.endswith(".py"):
            flash("Bitte eine .py-Datei hochladen.", "error")
            return redirect(url_for("admin.upload_plugin"))

        filename = secure_filename(file.filename)
        dest_path = os.path.join(current_app.config["PLUGIN_DIR"], filename)
        file.save(dest_path)

        try:
            instance = load_plugin_module(filename)
        except Exception as e:
            os.remove(dest_path)
            flash(f"Plugin konnte nicht geladen werden: {e}", "error")
            return redirect(url_for("admin.upload_plugin"))

        existing = Plugin.query.filter_by(name=instance.name).first()
        checksum = file_checksum(dest_path)

        if existing:
            existing.module_path = filename
            existing.checksum = checksum
            existing.version = instance.version
            existing.description = instance.description
            existing.uploaded_by_id = current_user.id
        else:
            record = Plugin(
                name=instance.name,
                version=instance.version,
                description=instance.description,
                module_path=filename,
                checksum=checksum,
                enabled=False,
                uploaded_by_id=current_user.id,
            )
            db.session.add(record)

        db.session.commit()
        flash(f"Plugin '{instance.name}' hochgeladen. Bitte zur Aktivierung prüfen und aktivieren.", "success")
        return redirect(url_for("admin.plugins"))

    return render_template("admin/upload_plugin.html")


@admin_bp.route("/plugins/<int:plugin_id>/toggle", methods=["POST"])
def toggle_plugin(plugin_id):
    plugin = Plugin.query.get_or_404(plugin_id)
    plugin.enabled = not plugin.enabled
    db.session.commit()
    flash(f"Plugin '{plugin.name}' {'aktiviert' if plugin.enabled else 'deaktiviert'}.", "success")
    return redirect(url_for("admin.plugins"))


@admin_bp.route("/mail-log")
def mail_log():
    logs = MailLog.query.order_by(MailLog.created_at.desc()).limit(200).all()
    return render_template("admin/mail_log.html", logs=logs)
