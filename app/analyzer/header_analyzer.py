import re
from email import policy
from email.parser import Parser
from email.utils import parseaddr

from app.analyzer.domain_utils import same_organization


AUTH_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|neutral|none)\b", re.I)


def _domain(address):
    parsed = parseaddr(address or "")[1].lower()
    if "@" not in parsed:
        return ""
    return parsed.rsplit("@", 1)[1]


def _parse_headers(raw_headers):
    header_text = (raw_headers or "").split("\n\n", 1)[0]
    try:
        return Parser(policy=policy.default).parsestr(header_text)
    except Exception:
        return Parser().parsestr(header_text)


def _auth_pass_count(auth_results):
    return sum(
        1
        for method in ("spf", "dkim", "dmarc")
        if auth_results.get(method) == "pass"
    )


def analyze_headers(raw_headers):
    findings = []
    score = 0
    msg = _parse_headers(raw_headers)
    has_structured_headers = any(
        msg.get_all(header)
        for header in (
            "From",
            "Received",
            "Authentication-Results",
            "Received-SPF",
            "DKIM-Signature",
            "Return-Path",
            "Reply-To",
        )
    )

    if not has_structured_headers:
        return ["Email headers not available for authentication checks"], 0

    auth_headers = "\n".join(msg.get_all("Authentication-Results", []))
    received_spf = "\n".join(msg.get_all("Received-SPF", []))
    auth_blob = f"{auth_headers}\n{received_spf}".lower()

    auth_results = {
        method.lower(): result.lower()
        for method, result in AUTH_PATTERN.findall(auth_blob)
    }

    for method in ("spf", "dkim", "dmarc"):
        result = auth_results.get(method)
        label = method.upper()
        if result in {"fail", "softfail"}:
            findings.append(f"{label} Authentication Failed ({result})")
            score += {"spf": 18, "dkim": 18, "dmarc": 24}[method]
        elif result in {"neutral", "none"}:
            findings.append(f"{label} Authentication Not Proven ({result})")
            score += {"spf": 8, "dkim": 8, "dmarc": 12}[method]
        elif result == "pass":
            findings.append(f"{label} Authentication Passed")
        else:
            findings.append(f"{label} Authentication Missing")
            score += {"spf": 3, "dkim": 3, "dmarc": 5}[method]

    from_domain = _domain(msg.get("From", ""))
    reply_domain = _domain(msg.get("Reply-To", ""))
    return_path_domain = _domain(msg.get("Return-Path", ""))

    if reply_domain and from_domain and not same_organization(reply_domain, from_domain):
        findings.append(
            f"Reply-To domain mismatch ({reply_domain} vs {from_domain})"
        )
        score += 10 if _auth_pass_count(auth_results) >= 2 else 15
    elif reply_domain:
        findings.append("Reply-To aligned with From organization")

    if (
        return_path_domain
        and from_domain
        and not same_organization(return_path_domain, from_domain)
    ):
        if _auth_pass_count(auth_results) >= 2:
            findings.append("Return-Path uses authenticated sender infrastructure")
        else:
            findings.append(
                f"Return-Path domain mismatch ({return_path_domain} vs {from_domain})"
            )
            score += 10
    elif return_path_domain and from_domain:
        findings.append("Return-Path aligned with From organization")

    suspicious_tlds = (".ru", ".tk", ".xyz", ".top", ".gq", ".cf")
    if from_domain.endswith(suspicious_tlds):
        findings.append(f"Suspicious sender TLD ({from_domain})")
        score += 12

    if len(msg.get_all("Received", [])) > 8:
        findings.append("Unusually long Received header chain")
        score += 5

    return findings, min(score, 100)
