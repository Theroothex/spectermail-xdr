import logging
import uuid

from flask import Blueprint, current_app, render_template, request, send_file

from app.analyzer.email_parser import parse_eml
from app.analyzer.engine import analyze_email
from app.analyzer.ioc_export import generate_ioc_report
from app.analyzer.pdf_report import _build_fallback_pdf, generate_pdf_report
from app.analyzer.risk_engine import RISK_LEVELS
from app.models import ScanHistory
from app.report_store import load_result, reports_dir, save_result
from app.security import (
    enforce_rate_limit,
    ensure_child_path,
    safe_upload_name,
    validate_csrf,
)


home_bp = Blueprint("home", __name__)
security_logger = logging.getLogger("spectermail.security")
audit_logger = logging.getLogger("spectermail.audit")


@home_bp.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        validate_csrf()
        enforce_rate_limit()

        uploaded_file = request.files.get("email_file")
        submitted_text = request.form.get("email_content", "").strip()
        raw_filename = (uploaded_file.filename or "").strip() if uploaded_file else ""
        analysis_id = uuid.uuid4().hex
        metadata = {"analysis_id": analysis_id}
        email_content = ""

        if raw_filename:
            try:
                safe_filename = safe_upload_name(
                    raw_filename,
                    current_app.config["UPLOAD_EXTENSIONS"],
                )
            except Exception:
                security_logger.warning(
                    "Rejected upload filename=%r remote=%s",
                    raw_filename,
                    request.remote_addr,
                )
                return render_template(
                    "index.html",
                    error="Unsupported file format. Please upload a valid .eml or .txt email file.",
                )

            upload_name = f"{analysis_id}_{safe_filename}"
            save_path = ensure_child_path(current_app.config["UPLOAD_DIR"], upload_name)
            uploaded_file.save(save_path)
            metadata["filename"] = safe_filename

            try:
                if save_path.suffix.lower() == ".eml":
                    parsed_email = parse_eml(save_path)
                    metadata.update(parsed_email)
                    metadata["filename"] = safe_filename
                    email_content = parsed_email.get("raw") or parsed_email.get("body", "")
                else:
                    with open(save_path, "r", encoding="utf-8", errors="replace") as file:
                        email_content = file.read()
            except Exception:
                current_app.logger.exception("Failed to parse uploaded email")
                return render_template(
                    "index.html",
                    error="Unable to parse this email safely. Please verify the file and try again.",
                )
        else:
            email_content = submitted_text
            metadata["filename"] = "manual-submission"

        if not email_content.strip():
            return render_template(
                "index.html",
                error=(
                    "Invalid email content. Please upload a valid email file or paste "
                    "email headers, email body, or raw email source."
                ),
            )

        try:
            result = analyze_email(email_content, metadata=metadata)
        except Exception:
            current_app.logger.exception("Email analysis failed")
            return render_template(
                "index.html",
                error="Unable to analyze this email safely. Please verify the content and try again.",
            )

        try:
            result = save_result(result)
        except Exception:
            current_app.logger.exception("Failed to persist analysis report")
        audit_logger.info(
            "analysis_id=%s filename=%s status=%s risk=%s remote=%s",
            result["analysis_id"],
            result.get("filename"),
            result.get("analysis_status"),
            result.get("risk"),
            request.remote_addr,
        )

        return render_template("result.html", result=result)

    return render_template("index.html")


@home_bp.route("/download-report")
@home_bp.route("/download-report/<analysis_id>")
def download_report(analysis_id=None):
    latest_result = load_result(analysis_id)
    if not latest_result:
        return "No report available. Please analyze an email first.", 404

    safe_analysis_id = latest_result.get("analysis_id") or analysis_id or "latest"
    report_name = f"{safe_analysis_id}_intelligence_report.pdf"
    pdf_path = ensure_child_path(str(reports_dir()), report_name)
    try:
        generate_pdf_report(latest_result, pdf_path)
    except Exception:
        current_app.logger.exception("PDF generation failed")
        _build_fallback_pdf(pdf_path, latest_result, "PDF generation failed")

    if not pdf_path.exists():
        return "Unable to generate report safely.", 500

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name="email_intelligence_report.pdf",
    )


@home_bp.route("/export-ioc")
@home_bp.route("/export-ioc/<analysis_id>")
def export_ioc(analysis_id=None):
    latest_result = load_result(analysis_id)
    if not latest_result:
        return "Analyze an email first.", 404

    safe_analysis_id = latest_result.get("analysis_id") or analysis_id or "latest"
    txt_name = f"{safe_analysis_id}_ioc_report.txt"
    txt_path = ensure_child_path(str(reports_dir()), txt_name)
    try:
        generate_ioc_report(latest_result.get("ioc_findings", {}), txt_path)
    except Exception:
        current_app.logger.exception("IOC export failed")
        with open(txt_path, "w", encoding="utf-8") as file:
            file.write("IOC EXTRACTION REPORT\n")
            file.write("=" * 40 + "\n\n")
            file.write("Unable to export IOC details safely for this report.\n")

    return send_file(
        txt_path,
        as_attachment=True,
        download_name="ioc_report.txt",
    )


@home_bp.route("/history")
def history():
    try:
        scans = ScanHistory.query.order_by(ScanHistory.id.desc()).all()
    except Exception:
        current_app.logger.exception("Failed to load scan history")
        scans = []
    return render_template("history.html", scans=scans)


@home_bp.route("/dashboard")
def dashboard():
    risk_counts = {level: 0 for level in RISK_LEVELS}
    try:
        total_scans = ScanHistory.query.count()
        for level in RISK_LEVELS:
            risk_counts[level] = ScanHistory.query.filter_by(risk=level).count()
    except Exception:
        current_app.logger.exception("Failed to load dashboard metrics")
        total_scans = 0
        risk_counts = {level: 0 for level in RISK_LEVELS}

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        risk_counts=risk_counts,
    )
