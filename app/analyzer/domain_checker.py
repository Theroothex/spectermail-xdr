import ipaddress
import re
from urllib.parse import urlparse

from app.analyzer.domain_utils import (
    TRUSTED_ORG_DOMAINS,
    is_brand_associated_domain,
    is_subdomain_of,
    normalize_domain,
)


def analyze_domain(url):

    findings = []
    score = 0

    parsed = urlparse(url)

    domain = normalize_domain(parsed.hostname or parsed.netloc)

    if not domain:
        findings.append("Invalid internationalized domain encoding")
        return findings, 30

    if domain.startswith("xn--") or ".xn--" in domain:
        findings.append(f"Punycode/Homograph Domain Detected ({domain})")
        score += 25

    # -------------------------
    # Trusted Domains
    # -------------------------

    trusted_domains = sorted(TRUSTED_ORG_DOMAINS)

    for trusted in trusted_domains:

        if is_subdomain_of(domain, trusted):

            findings.append(
                f"Trusted Domain Detected ({trusted})"
            )

            return findings, 0

    # -------------------------
    # Suspicious TLD Detection
    # -------------------------

    suspicious_tlds = [

        ".ru",
        ".xyz",
        ".top",
        ".tk",
        ".gq",
        ".cf",
        ".click",
        ".work",
        ".loan",
        ".shop"

    ]

    for tld in suspicious_tlds:

        if domain.endswith(tld):

            findings.append(
                f"Suspicious TLD Detected ({tld})"
            )

            score += 15

    # -------------------------
    # IP Based URL
    # -------------------------

    try:
        ipaddress.ip_address(domain.split(":")[0])
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:

        findings.append(
            "IP-Based URL Detected"
        )

        score += 25

    # -------------------------
    # Brand Impersonation
    # -------------------------

    suspicious_keywords = [

        "paypal",
        "amazon",
        "microsoft",
        "google",
        "youtube",
        "github",
        "linkedin",
        "flipkart",
        "apple",
        "netflix",

    ]

    for keyword in suspicious_keywords:

        if keyword in domain:

            if not is_brand_associated_domain(keyword, domain):

                findings.append(
                    f"Possible Brand Impersonation ({keyword})"
                )

                score += 40

    # -------------------------
    # URL Shorteners
    # -------------------------

    shorteners = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "rb.gy",
        "cutt.ly",
        "is.gd",
        "ow.ly",
        "c.gle"

    ]

    if domain in shorteners:

        findings.append(
            f"URL Shortener Detected ({domain})"
        )

        # informational only
        score += 5

    return findings, score
