import json
import logging
import re
from pathlib import Path

from flask import current_app

from app.analyzer.risk_engine import format_risk_level
from app.models import ScanHistory
from app.security import ensure_child_path


logger = logging.getLogger("spectermail.app")
REPORT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
IOC_KEYS = ("ips", "ipv4", "ipv6", "domains", "emails", "hashes", "md5", "sha1", "sha256", "urls")
ANALYSIS_STATUS_COMPLETED = "Completed"
LEGACY_VERDICT_RISK_MAP = {
    "GENUINE": "INFORMATIONAL",
    "LIKELY LEGITIMATE": "LOW",
    "SUSPICIOUS": "MEDIUM",
    "PHISHING": "HIGH",
    "MALICIOUS": "CRITICAL",
}


def _json_default(value):
    return str(value)


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _as_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_report_id(value):
    candidate = str(value or "").strip()
    if REPORT_ID_PATTERN.fullmatch(candidate):
        return candidate
    return ""


def _migrate_legacy_fields(result):
    if result.get("analysis_status"):
        return result

    legacy_verdict = str(result.get("verdict") or "").upper()
    if legacy_verdict in LEGACY_VERDICT_RISK_MAP and not result.get("risk"):
        result["risk"] = LEGACY_VERDICT_RISK_MAP[legacy_verdict]

    result["analysis_status"] = result.get("analysis_status") or ANALYSIS_STATUS_COMPLETED
    result["analyst_summary"] = (
        result.get("analyst_summary")
        or result.get("analyst_verdict")
        or ""
    )
    result["observed_findings"] = _as_list(
        result.get("observed_findings") or result.get("summary_reasons")
    )
    result["indicator_count"] = _as_int(
        result.get("indicator_count"),
        len(result["observed_findings"]),
    )
    result.pop("verdict", None)
    result.pop("assessment", None)
    result.pop("analyst_verdict", None)
    result.pop("trust_score", None)
    return result


def reports_dir():
    path = Path(current_app.config["REPORT_DIR"])
    path.mkdir(parents=True, exist_ok=True)
    return path


def empty_iocs():
    return {key: [] for key in IOC_KEYS}


def normalize_result(result, analysis_id=None):
    result = _migrate_legacy_fields(dict(_as_dict(result)))
    report_id = _safe_report_id(result.get("analysis_id")) or _safe_report_id(analysis_id)
    if not report_id:
        report_id = "latest"

    iocs = empty_iocs()
    iocs.update({
        key: _as_list(value)
        for key, value in _as_dict(result.get("ioc_findings")).items()
        if key in iocs
    })
    if not iocs["ips"]:
        iocs["ips"] = iocs["ipv4"] + iocs["ipv6"]
    if not iocs["hashes"]:
        iocs["hashes"] = iocs["md5"] + iocs["sha1"] + iocs["sha256"]

    score = _as_int(result.get("score", result.get("threat_score")), 0)
    confidence = _as_int(result.get("confidence"), 0)
    risk = str(result.get("risk") or "UNKNOWN").upper()
    observed_findings = _as_list(result.get("observed_findings"))
    indicator_count = _as_int(result.get("indicator_count"), len(observed_findings))

    normalized = {
        "analysis_id": report_id,
        "filename": result.get("filename") or "N/A",
        "sender": result.get("sender") or result.get("sender_email") or "N/A",
        "sender_email": result.get("sender_email") or "",
        "subject": result.get("subject") or "",
        "keywords": _as_list(result.get("keywords")),
        "language_profile": _as_dict(result.get("language_profile")),
        "urls": _as_list(result.get("urls")),
        "risk": risk,
        "risk_level": result.get("risk_level") or format_risk_level(risk),
        "score": score,
        "threat_score": score,
        "confidence": confidence,
        "analysis_status": result.get("analysis_status") or ANALYSIS_STATUS_COMPLETED,
        "indicator_count": indicator_count,
        "observed_findings": observed_findings,
        "domain": result.get("domain") or "",
        "domain_findings": _as_list(result.get("domain_findings")),
        "mitre_techniques": _as_list(result.get("mitre_techniques")),
        "header_findings": _as_list(result.get("header_findings")),
        "attachment_findings": _as_list(result.get("attachment_findings")),
        "ioc_findings": iocs,
        "ioc_count": _as_int(
            result.get("ioc_count"),
            sum(len(iocs[key]) for key in ("ipv4", "ipv6", "domains", "emails", "md5", "sha1", "sha256")),
        ),
        "summary_reasons": _as_list(result.get("summary_reasons")),
        "recommendations": _as_list(result.get("recommendations")),
        "threat_summary": _as_list(result.get("threat_summary") or result.get("summary_reasons")),
        "sender_reputation": result.get("sender_reputation") or "Unknown",
        "reputation_findings": _as_list(result.get("reputation_findings")),
        "brand_findings": _as_list(result.get("brand_findings")),
        "url_reputation_findings": _as_list(result.get("url_reputation_findings")),
        "score_breakdown": _as_dict(result.get("score_breakdown")),
        "security_scorecard": _as_dict(result.get("security_scorecard")),
        "analyst_summary": result.get("analyst_summary") or "",
        "domain_age_findings": _as_list(result.get("domain_age_findings")),
        "domain_age_risk": _as_list(result.get("domain_age_risk")),
        "shortener_findings": _as_list(result.get("shortener_findings")),
        "tld_findings": _as_list(result.get("tld_findings")),
        "total_urls": _as_int(result.get("total_urls"), len(_as_list(result.get("urls")))),
        "unique_domains": _as_int(result.get("unique_domains"), len(iocs["domains"])),
    }
    if not normalized["threat_summary"]:
        normalized["threat_summary"] = ["No report summary available."]
    if not normalized["analyst_summary"]:
        normalized["analyst_summary"] = (
            "Analysis summary unavailable for this report."
        )
    return normalized


def save_result(result):
    result = normalize_result(result)
    report_dir = reports_dir()
    json_path = ensure_child_path(str(report_dir), f"{result['analysis_id']}.json")
    latest_path = ensure_child_path(str(report_dir), "latest_result.json")

    for path in (json_path, latest_path):
        with open(path, "w", encoding="utf-8") as file:
            json.dump(result, file, indent=4, default=_json_default)
    return result


def _load_json(path, analysis_id=None):
    try:
        with open(path, "r", encoding="utf-8") as file:
            return normalize_result(json.load(file), analysis_id=analysis_id)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        logger.exception("Unable to load report JSON from %s", path)
        return None


def result_from_scan(scan):
    if not scan:
        return None
    try:
        mitre_techniques = json.loads(scan.mitre_techniques or "[]")
    except (TypeError, ValueError):
        mitre_techniques = []
    return normalize_result({
        "analysis_id": scan.analysis_id,
        "filename": scan.filename,
        "sender": scan.sender,
        "subject": scan.subject,
        "domain": scan.domain,
        "risk": scan.risk,
        "score": scan.threat_score,
        "confidence": scan.confidence,
        "analysis_status": getattr(scan, "analysis_status", None) or ANALYSIS_STATUS_COMPLETED,
        "ioc_count": scan.ioc_count,
        "mitre_techniques": mitre_techniques,
        "threat_summary": [
            "Stored JSON report was not found. Showing scan-history metadata only."
        ],
        "recommendations": [
            "Re-run analysis if full report details are required."
        ],
    }, analysis_id=scan.analysis_id)


def _load_scan_report(scan):
    if not scan:
        return None
    if scan.report_path:
        try:
            path = ensure_child_path(str(reports_dir()), scan.report_path)
            if path.exists():
                loaded = _load_json(path, analysis_id=scan.analysis_id)
                if loaded:
                    return loaded
        except Exception:
            logger.exception("Ignoring invalid report_path for analysis_id=%s", scan.analysis_id)
    return result_from_scan(scan)


def load_result(analysis_id=None):
    report_dir = reports_dir()
    report_id = _safe_report_id(analysis_id) if analysis_id else ""
    if analysis_id and not report_id:
        return None

    filename = f"{report_id}.json" if report_id else "latest_result.json"
    path = ensure_child_path(str(report_dir), filename)
    if path.exists():
        loaded = _load_json(path, analysis_id=report_id)
        if loaded:
            return loaded

    if report_id:
        scan = ScanHistory.query.filter_by(analysis_id=report_id).first()
        return _load_scan_report(scan)

    scan = ScanHistory.query.order_by(ScanHistory.id.desc()).first()
    return _load_scan_report(scan)
