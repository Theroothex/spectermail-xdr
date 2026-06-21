def generate_analyst_summary(risk, observed_findings, indicator_count):
    findings = observed_findings or []
    count = indicator_count if indicator_count is not None else len(findings)
    risk_upper = str(risk or "").upper()

    if risk_upper in {"INFORMATIONAL", "LOW"} and count == 0:
        return (
            "No significant suspicious indicators were observed during "
            "automated analysis."
        )

    if risk_upper in {"INFORMATIONAL", "LOW"}:
        return (
            "Limited indicators were identified during automated analysis. "
            "Independent verification may be performed if required."
        )

    if risk_upper == "MEDIUM":
        return (
            "Several indicators commonly associated with phishing activity "
            "were identified during automated analysis. Independent "
            "verification is recommended before acting on requests "
            "contained within the message."
        )

    if risk_upper == "HIGH":
        return (
            "Multiple authentication and reputation anomalies were detected "
            "during automated analysis. Exercise caution and validate sender "
            "identity and referenced resources through trusted channels."
        )

    return (
        "Multiple high-risk indicators were identified during automated "
        "analysis. Independent verification is strongly recommended before "
        "interacting with links, attachments, or requests contained within "
        "the message."
    )
