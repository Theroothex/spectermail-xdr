def _cap(value, maximum):
    return max(0, min(int(value), maximum))


RISK_LEVELS = ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

RISK_LEVEL_DISPLAY = {
    "INFORMATIONAL": "Informational",
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CRITICAL": "Critical",
}


def format_risk_level(risk):
    return RISK_LEVEL_DISPLAY.get(str(risk or "").upper(), str(risk or "Unknown"))


def calculate_risk(
    keywords,
    url_count,
    domain_score,
    header_score,
    brand_score=0,
    url_reputation_score=0,
    ioc_count=0,
    shortener_score=0,
    tld_score=0,
    credential_score=0,
    urgency_score=0,
    domain_age_score=0,
    legitimacy_score=0,
    trusted_context=False,
):
    url_count_score = _cap(max(url_count - 8, 0) // 3, 5)
    ioc_density_score = _cap(max(ioc_count - 4, 0), 6)
    keyword_score = _cap(len(keywords), 5)

    if trusted_context:
        url_count_score = _cap(max(url_count - 20, 0) // 5, 2)
        ioc_density_score = _cap(max(ioc_count - 10, 0), 3)
        keyword_score = _cap(len(keywords) // 2, 2)
        credential_score = min(credential_score, 6)
        urgency_score = min(urgency_score, 4)

    breakdown = {
        "Header Authentication": _cap(header_score, 28),
        "Suspicious Domains": _cap(domain_score, 18),
        "Brand Impersonation": _cap(brand_score, 16),
        "Credential Theft Language": _cap(credential_score, 12),
        "Urgency Language": _cap(urgency_score, 8),
        "IOC Density": ioc_density_score,
        "Suspicious TLDs": _cap(tld_score, 8),
        "Shortened URLs": _cap(shortener_score, 5),
        "URL Reputation": _cap(url_reputation_score, 12),
        "Domain Age": _cap(domain_age_score, 7),
        "URL Count": url_count_score,
        "Keyword Indicators": keyword_score,
    }

    adjustment = _cap(legitimacy_score, 50)
    if adjustment:
        breakdown["Legitimacy Adjustment"] = -adjustment

    score = _cap(sum(breakdown.values()), 100)

    if score >= 80:
        risk = "CRITICAL"
    elif score >= 55:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    elif score >= 15:
        risk = "LOW"
    else:
        risk = "INFORMATIONAL"

    return risk, score, breakdown


def calculate_confidence_score(evidence_count, parser_warnings=0):
    confidence = 45 + min(evidence_count * 6, 45) - min(parser_warnings * 5, 20)
    return _cap(confidence, 100)
