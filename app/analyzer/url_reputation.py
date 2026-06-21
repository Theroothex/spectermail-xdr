from urllib.parse import urlparse

from app.analyzer.domain_utils import is_trusted_domain


def analyze_url_reputation(urls):

    findings = []
    score = 0

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "cutt.ly",
        "is.gd",
        "t.co",
        "goo.gl"
    ]

    detected_shorteners = set()
    untrusted_http_domains = set()

    for url in urls:

        try:

            parsed = urlparse(url)

            domain = (
                parsed.hostname or ""
            ).lower().replace("www.", "")

            # URL Shortener Detection
            if domain in shorteners:
                detected_shorteners.add(domain)

            # Unsecured HTTP Detection
            if (
                parsed.scheme == "http"
                and domain
                and not is_trusted_domain(domain)
            ):
                untrusted_http_domains.add(domain)

        except Exception:
            continue

    # =====================================
    # URL SHORTENERS
    # =====================================

    if detected_shorteners:

        findings.append(
            f"Detected {len(detected_shorteners)} URL shortener domain(s)"
        )

        score += min(
            len(detected_shorteners) * 5,
            10
        )

    # =====================================
    # HTTP URLS
    # =====================================

    if untrusted_http_domains:

        findings.append(
            f"Detected {len(untrusted_http_domains)} unsecured HTTP domain(s)"
        )

        score += min(
            len(untrusted_http_domains) * 2,
            6
        )

    return findings, score