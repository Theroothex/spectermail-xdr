def generate_observed_findings(
    header_findings,
    domain_findings,
    attachment_findings,
    keywords,
    brand_findings,
    tld_findings,
    shortener_findings,
    url_reputation_findings,
    language_profile=None,
    urls=None,
):
    findings = []
    language_profile = language_profile or {}

    for finding in header_findings or []:
        normalized = _normalize_finding(finding)
        if normalized:
            findings.append(normalized)

    for finding in domain_findings or []:
        if "Trusted Domain" in finding:
            continue
        normalized = _normalize_finding(finding)
        if normalized:
            findings.append(normalized)

    for finding in brand_findings or []:
        normalized = _normalize_finding(finding)
        if normalized:
            findings.append(normalized)

    for finding in tld_findings or []:
        normalized = _normalize_finding(finding)
        if normalized:
            findings.append(normalized)

    for finding in shortener_findings or []:
        normalized = _normalize_finding(finding)
        if normalized:
            findings.append(normalized)

    for finding in url_reputation_findings or []:
        normalized = _normalize_finding(finding)
        if normalized:
            findings.append(normalized)

    for finding in attachment_findings or []:
        normalized = _normalize_finding(finding)
        if normalized:
            findings.append(normalized)

    if language_profile.get("credential_theft"):
        findings.append("Credential-Related Language Detected")

    if language_profile.get("urgency"):
        findings.append("Urgency-Related Language Detected")

    for keyword in keywords or []:
        label = f"Keyword Indicator: {keyword}"
        if label not in findings:
            findings.append(label)

    if urls:
        findings.append("External URL Present")

    return list(dict.fromkeys(findings))


def _normalize_finding(finding):
    text = str(finding or "").strip()
    if not text:
        return ""

    replacements = {
        "SPF Authentication Failed": "SPF Failed",
        "SPF Authentication Passed": "SPF Passed",
        "DKIM Authentication Failed": "DKIM Failed",
        "DKIM Authentication Passed": "DKIM Passed",
        "DMARC Authentication Failed": "DMARC Failed",
        "DMARC Authentication Passed": "DMARC Passed",
        "Suspicious Domain Detected": "Suspicious Domain Detected",
        "Suspicious TLD Detected": "Suspicious TLD Detected",
    }
    for source, target in replacements.items():
        if source in text:
            return target

    if "missing" in text.lower() or "not found" in text.lower():
        return text

    if "fail" in text.lower() or "suspicious" in text.lower():
        return text

    if "detected" in text.lower() or "mismatch" in text.lower():
        return text

    return text


def generate_summary_context(risk, observed_findings):
    reasons = list(observed_findings or [])
    risk_upper = str(risk or "").upper()

    if not reasons:
        if risk_upper in {"INFORMATIONAL", "LOW"}:
            reasons.append(
                "No significant suspicious indicators were observed."
            )
        elif risk_upper == "MEDIUM":
            reasons.append("Some indicators were identified during analysis.")
        elif risk_upper == "HIGH":
            reasons.append(
                "Multiple indicators were identified during analysis."
            )
        else:
            reasons.append(
                "Numerous indicators were identified during analysis."
            )

    return reasons
