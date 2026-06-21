from flask import Blueprint, render_template

from app.report_store import load_result


report_bp = Blueprint("report", __name__)


@report_bp.route("/report")
@report_bp.route("/latest-report")
def latest_report():

    latest_result = load_result()

    if not latest_result:
        return render_template(
            "index.html",
            error="No latest report available. Please analyze an email first."
        )

    return render_template(
        "result.html",
        result=latest_result
    )


@report_bp.route("/report/<analysis_id>")
def report_by_id(analysis_id):

    result = load_result(analysis_id)

    if not result:
        return render_template(
            "index.html",
            error="Report not found. Please re-run analysis for this email."
        ), 404

    return render_template(
        "result.html",
        result=result
    )
