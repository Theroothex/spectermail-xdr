def calculate_trust_score(
    header_findings,
    domain_findings,
    attachment_findings,
    keywords,
    urls
):

    score = 100

    for finding in header_findings:

        finding = finding.lower()

        if (
            "spf fail" in finding
            or "dkim fail" in finding
            or "dmarc fail" in finding
            or "authentication failed" in finding
        ):
            score -= 25

        elif (
            "suspicious" in finding
            or "anomaly" in finding
        ):
            score -= 10

        elif "reply-to" in finding:
            score -= 5

    for finding in domain_findings:

        finding = finding.lower()

        if "trusted domain" in finding:
            continue

        elif "impersonation" in finding:
            score -= 30

        elif "suspicious tld" in finding:
            score -= 20

        elif "ip-based url" in finding:
            score -= 15

        elif "shortener" in finding:
            score -= 5

        else:
            score -= 5

    for finding in attachment_findings:

        finding = finding.lower()

        if "executable" in finding:
            score -= 30

        elif "double extension" in finding:
            score -= 25

        elif "macro" in finding:
            score -= 20

        else:
            score -= 10

    suspicious_keywords = {
        "verify",
        "password",
        "login",
        " confirm identity",
        "account suspended",
        "click here",
        "bank account",
        "urgent action",
        "reset password"
    }

    matches = 0

    for keyword in keywords:

        if keyword.lower() in suspicious_keywords:
            matches += 1

    score -= (matches * 5)

    if len(urls) > 20:
        score -= 15

    elif len(urls) > 15:
        score -= 10

    elif len(urls) > 10:
        score -= 5

    score = max(
        0,
        min(score, 100)
    )

    return score


def calculate_confidence(score):

    if score >= 95:
        return 99

    elif score >= 90:
        return 98

    elif score >= 75:
        return 90

    elif score >= 50:
        return 80

    elif score >= 25:
        return 70

    return 60
