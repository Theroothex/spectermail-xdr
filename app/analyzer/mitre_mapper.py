def map_mitre_techniques(
    keywords,
    urls,
    domain_findings,
    header_findings=None,
    attachment_findings=None,
    language_profile=None
):
    header_findings = header_findings or []
    attachment_findings = attachment_findings or []
    language_profile = language_profile or {}
    techniques = []
    keyword_set = {keyword.lower() for keyword in keywords}

    credential_evidence = language_profile.get("credential_theft", [])
    phishing_evidence = (
        credential_evidence
        + language_profile.get("urgency", [])
        + language_profile.get("call_to_action", [])
    )
    if (
        credential_evidence and (len(phishing_evidence) >= 2 or urls)
    ) or len(phishing_evidence) >= 3:
        techniques.append({
            "id": "T1566",
            "name": "Phishing",
            "tactic": "Initial Access",
            "confidence": min(95, 55 + len(phishing_evidence) * 10 + len(urls) * 5),
            "evidence": phishing_evidence[:6],
        })

    impersonation_evidence = [
        finding
        for finding in domain_findings
        if "impersonation" in finding.lower() or "homograph" in finding.lower()
    ]
    if impersonation_evidence:
        techniques.append({
            "id": "T1036",
            "name": "Masquerading",
            "tactic": "Defense Evasion",
            "confidence": min(95, 70 + len(impersonation_evidence) * 8),
            "evidence": impersonation_evidence[:5],
        })

    execution_evidence = [
        keyword
        for keyword in keyword_set
        if keyword in {
            "open attachment",
            "download file",
            "enable macros",
            "run attachment",
            "click here",
            "install update",
            "download now",
        }
    ] + attachment_findings
    if execution_evidence:
        techniques.append({
            "id": "T1204",
            "name": "User Execution",
            "tactic": "Execution",
            "confidence": min(90, 60 + len(execution_evidence) * 10),
            "evidence": execution_evidence[:5],
        })

    auth_evidence = [
        finding
        for finding in header_findings
        if "failed" in finding.lower() or "mismatch" in finding.lower()
    ]
    if auth_evidence:
        techniques.append({
            "id": "T1585",
            "name": "Establish Accounts",
            "tactic": "Resource Development",
            "confidence": min(80, 45 + len(auth_evidence) * 8),
            "evidence": auth_evidence[:5],
        })

    return techniques
