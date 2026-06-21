import json
import logging
import uuid
import ipaddress
from urllib.parse import urlparse

from app.analyzer.analyst_summary import generate_analyst_summary
from app.analyzer.attachment_scanner import scan_attachments
from app.analyzer.brand_verifier import verify_brand
from app.analyzer.domain_age_checker import check_domain_age
from app.analyzer.domain_checker import analyze_domain
from app.analyzer.domain_utils import domain_from_url, is_trusted_domain
from app.analyzer.header_analyzer import analyze_headers
from app.analyzer.ioc_extractor import extract_iocs
from app.analyzer.keyword_detector import analyze_language, detect_keywords
from app.analyzer.mitre_mapper import map_mitre_techniques
from app.analyzer.recommendation_engine import generate_recommendations
from app.analyzer.reputation_engine import check_sender_reputation
from app.analyzer.risk_engine import (
    calculate_confidence_score,
    calculate_risk,
    format_risk_level,
)
from app.analyzer.summary_engine import (
    generate_observed_findings,
    generate_summary_context,
)
from app.analyzer.tld_checker import check_suspicious_tlds
from app.analyzer.url_analyzer import analyze_urls
from app.analyzer.url_extractor import extract_urls
from app.analyzer.url_reputation import analyze_url_reputation
from app.analyzer.url_shortener_checker import check_url_shorteners
from app.models import ScanHistory, db


analysis_logger = logging.getLogger("spectermail.analysis")
ANALYSIS_STATUS_COMPLETED = "Completed"


def _count_iocs(ioc_findings):
    return sum(
        len(ioc_findings.get(key, []))
        for key in ("ipv4", "ipv6", "domains", "emails", "md5", "sha1", "sha256")
    )


def _risk_ioc_count(ioc_findings):
    count = sum(
        len(ioc_findings.get(key, []))
        for key in ("md5", "sha1", "sha256")
    )
    for key in ("ipv4", "ipv6"):
        for value in ioc_findings.get(key, []):
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if not (
                address.is_private
                or address.is_loopback
                or address.is_reserved
                or address.is_link_local
                or address.is_multicast
            ):
                count += 1
    return count


def _first_domain(urls, sender_email=""):
    if sender_email and "@" in sender_email:
        return sender_email.rsplit("@", 1)[1].lower()
    for url in urls:
        parsed = urlparse(url)
        if parsed.hostname:
            return parsed.hostname.lower()
    return ""


def _domain_age_score(domain_age_risk):
    if "HIGH" in domain_age_risk:
        return 7
    if "MEDIUM" in domain_age_risk:
        return 4
    return 0


def _positive_auth_count(header_findings):
    return sum(1 for finding in header_findings if "Passed" in finding)


def _auth_passed_all(header_findings):
    required = ("SPF", "DKIM", "DMARC")
    return all(
        any(finding.startswith(method) and "Passed" in finding for finding in header_findings)
        for method in required
    )


def _has_auth_failure(header_findings):
    return any(
        "Failed" in finding or "mismatch" in finding
        for finding in header_findings
    )


def _domain_age_days(domain_age_findings):
    for finding in domain_age_findings:
        if finding.startswith("Age:"):
            parts = finding.split()
            for part in parts:
                if part.isdigit():
                    return int(part)
    return 0


def _is_established_domain(domain_age_findings, domain_age_risk):
    return (
        _domain_age_days(domain_age_findings) >= 365
        or "LOW" in " ".join(domain_age_risk)
    )


def _security_scorecard(threat_score, header_score, domain_score, url_rep_score, attachment_findings):
    return {
        "Authentication": max(0, 100 - min(max(header_score, 0), 100)),
        "Domain Reputation": max(0, 100 - min(max(domain_score, 0), 100)),
        "Content Indicators": max(0, 100 - min(threat_score, 100)),
        "URL Analysis": max(0, 100 - min(max(url_rep_score, 0), 100)),
        "Attachment Review": 70 if attachment_findings else 100,
    }


def analyze_email(content, metadata=None):
    metadata = metadata or {}
    analysis_id = metadata.get("analysis_id") or uuid.uuid4().hex
    headers = metadata.get("headers") or content
    sender_email = metadata.get("sender_email", "")
    subject = metadata.get("subject", "")
    filename = metadata.get("filename", "")

    language_profile = analyze_language(content)
    keywords = detect_keywords(content)
    urls = extract_urls(content)
    ioc_findings = extract_iocs(content)
    attachment_findings = scan_attachments(content)

    for attachment in metadata.get("attachments", []):
        name = attachment.get("filename", "unnamed")
        content_type = attachment.get("content_type", "unknown")
        if content_type or name:
            attachment_findings.append(
                f"Attachment present ({name}, {content_type})"
            )

    domain_findings = []
    domain_score = 0
    checked_domains = set()
    domain_age_findings = []
    domain_age_risk = []

    unique_url_domains = {}
    for url in urls:
        domain = domain_from_url(url)
        if domain and domain not in unique_url_domains:
            unique_url_domains[domain] = url

    for domain, url in unique_url_domains.items():
        findings, score = analyze_domain(url)
        for finding in findings:
            if finding not in domain_findings:
                domain_findings.append(finding)
        domain_score += score

        if domain and domain not in checked_domains:
            checked_domains.add(domain)
            age_findings, age_risk = check_domain_age(domain)
            domain_age_findings.extend(age_findings)
            domain_age_risk.append(age_risk)

    sender_reputation, reputation_findings = check_sender_reputation(urls)
    brand_findings, brand_score = verify_brand(urls)
    url_reputation_findings, url_rep_score = analyze_url_reputation(urls)
    shortener_findings, shortener_score = check_url_shorteners(urls)
    tld_findings, tld_score = check_suspicious_tlds(urls)
    url_stats, url_findings = analyze_urls(urls)
    header_findings, header_score = analyze_headers(headers)

    ioc_count = _count_iocs(ioc_findings)
    risk_ioc_count = _risk_ioc_count(ioc_findings)
    credential_score = len(language_profile.get("credential_theft", [])) * 4
    urgency_score = len(language_profile.get("urgency", [])) * 3
    domain_age_total = _domain_age_score(" ".join(domain_age_risk))
    primary_domain = _first_domain(urls, sender_email)
    auth_pass_all = _auth_passed_all(header_findings)
    positive_auth_count = _positive_auth_count(header_findings)
    trusted_domain = (
        any("Trusted Domain" in finding for finding in domain_findings)
        or sender_reputation == "Trusted"
        or is_trusted_domain(primary_domain)
    )
    established_domain = _is_established_domain(domain_age_findings, domain_age_risk)
    strong_auth = positive_auth_count >= 2 and not _has_auth_failure(header_findings)
    trusted_context = trusted_domain and (strong_auth or established_domain)
    legitimacy_score = 0
    if auth_pass_all:
        legitimacy_score += 30
    elif positive_auth_count:
        legitimacy_score += min(positive_auth_count * 8, 20)
    if trusted_domain:
        legitimacy_score += 14
    if sender_reputation == "Trusted":
        legitimacy_score += 6
    if established_domain:
        legitimacy_score += 8

    risk, threat_score, breakdown = calculate_risk(
        keywords,
        len(urls),
        domain_score,
        header_score,
        brand_score,
        url_rep_score,
        ioc_count=risk_ioc_count,
        shortener_score=shortener_score,
        tld_score=tld_score,
        credential_score=credential_score,
        urgency_score=urgency_score,
        domain_age_score=domain_age_total,
        legitimacy_score=legitimacy_score,
        trusted_context=trusted_context,
    )

    hard_negative_evidence = (
        _has_auth_failure(header_findings)
        or brand_score > 0
        or domain_score >= 25
        or tld_score > 0
        or url_rep_score >= 15
    )
    if strong_auth and trusted_domain and established_domain and not hard_negative_evidence:
        threat_score = min(threat_score, 14)
        risk = "INFORMATIONAL" if threat_score < 15 else "LOW"

    observed_findings = generate_observed_findings(
        header_findings,
        domain_findings,
        attachment_findings,
        keywords,
        brand_findings,
        tld_findings,
        shortener_findings,
        url_reputation_findings,
        language_profile=language_profile,
        urls=urls,
    )
    indicator_count = len(observed_findings)

    evidence_count = (
        len(keywords)
        + len(domain_findings)
        + len(header_findings)
        + len(attachment_findings)
        + ioc_count
    )
    confidence = calculate_confidence_score(evidence_count)

    mitre_techniques = map_mitre_techniques(
        keywords,
        urls,
        domain_findings,
        header_findings=header_findings,
        attachment_findings=attachment_findings,
        language_profile=language_profile,
    )

    summary_reasons = generate_summary_context(risk, observed_findings)
    if url_findings:
        summary_reasons.extend(url_findings)

    recommendations = generate_recommendations(
        risk,
        header_findings,
        domain_findings,
        attachment_findings,
        keywords,
        urls,
        language_profile=language_profile,
    )

    analyst_summary = generate_analyst_summary(
        risk,
        observed_findings,
        indicator_count,
    )

    result = {
        "analysis_id": analysis_id,
        "filename": filename,
        "sender": metadata.get("sender", sender_email),
        "sender_email": sender_email,
        "subject": subject,
        "keywords": keywords,
        "language_profile": language_profile,
        "urls": urls,
        "risk": risk,
        "risk_level": format_risk_level(risk),
        "score": threat_score,
        "threat_score": threat_score,
        "confidence": confidence,
        "analysis_status": ANALYSIS_STATUS_COMPLETED,
        "indicator_count": indicator_count,
        "observed_findings": observed_findings,
        "domain": primary_domain,
        "domain_findings": domain_findings,
        "mitre_techniques": mitre_techniques,
        "header_findings": header_findings,
        "attachment_findings": list(dict.fromkeys(attachment_findings)),
        "ioc_findings": ioc_findings,
        "ioc_count": ioc_count,
        "summary_reasons": summary_reasons,
        "recommendations": recommendations,
        "threat_summary": summary_reasons,
        "sender_reputation": sender_reputation,
        "reputation_findings": reputation_findings,
        "brand_findings": brand_findings,
        "url_reputation_findings": url_reputation_findings,
        "score_breakdown": breakdown,
        "security_scorecard": _security_scorecard(
            threat_score,
            header_score,
            domain_score,
            url_rep_score,
            attachment_findings,
        ),
        "analyst_summary": analyst_summary,
        "domain_age_findings": domain_age_findings,
        "domain_age_risk": domain_age_risk,
        "shortener_findings": shortener_findings,
        "tld_findings": tld_findings,
        "total_urls": url_stats["total_urls"],
        "unique_domains": url_stats["unique_domains"],
    }

    scan = ScanHistory(
        analysis_id=analysis_id,
        filename=filename,
        sender=result["sender"],
        subject=subject,
        domain=primary_domain,
        ioc_count=ioc_count,
        confidence=confidence,
        analysis_status=ANALYSIS_STATUS_COMPLETED,
        risk=risk,
        threat_score=threat_score,
        mitre_techniques=json.dumps(mitre_techniques),
        report_path=f"{analysis_id}.json",
    )

    try:
        db.session.add(scan)
        db.session.commit()
    except Exception:
        db.session.rollback()
        analysis_logger.exception(
            "Failed to persist scan history for analysis_id=%s",
            analysis_id,
        )
    analysis_logger.info(
        "analysis_id=%s status=%s risk=%s score=%s indicator_count=%s",
        analysis_id,
        ANALYSIS_STATUS_COMPLETED,
        risk,
        threat_score,
        indicator_count,
    )
    return result
