def generate_recommendations(
    risk,
    header_findings,
    domain_findings,
    attachment_findings,
    keywords,
    urls,
    language_profile=None,
):
    recommendations = []
    language_profile = language_profile or {}
    header_text = " ".join(header_findings or []).lower()
    domain_text = " ".join(domain_findings or []).lower()

    if "spf" in header_text and "fail" in header_text:
        recommendations.append(
            "Verify sender authenticity through trusted channels."
        )
    if "dkim" in header_text and "fail" in header_text:
        recommendations.append(
            "Verify sender authenticity through trusted channels."
        )
    if "dmarc" in header_text and "fail" in header_text:
        recommendations.append(
            "Verify sender authenticity through trusted channels."
        )
    if any(
        term in header_text
        for term in ("spf missing", "dkim missing", "dmarc missing", "not found")
    ):
        recommendations.append(
            "Verify sender authenticity through trusted channels."
        )

    if any(
        term in domain_text
        for term in ("suspicious", "impersonation", "untrusted", "reputation")
    ):
        recommendations.append("Review domain ownership and reputation.")

    if language_profile.get("urgency") or any(
        term in " ".join(keywords or []).lower()
        for term in ("urgent", "immediately", "act now", "deadline")
    ):
        recommendations.append("Validate request before taking action.")

    if urls:
        recommendations.append(
            "Exercise caution before visiting referenced resources."
        )

    if attachment_findings:
        recommendations.append(
            "Review attachments in a controlled environment before opening."
        )

    risk_upper = str(risk or "").upper()
    if risk_upper in {"HIGH", "CRITICAL"}:
        recommendations.append(
            "Consider escalating to the SOC team for further review."
        )
    elif risk_upper == "MEDIUM":
        recommendations.append("Verify sender identity before responding.")

    seen = set()
    unique = []
    for item in recommendations:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique
