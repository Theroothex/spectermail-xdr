from urllib.parse import urlparse

from app.analyzer.domain_utils import is_trusted_domain


def analyze_urls(urls):

    findings = []

    unique_domains = set()

    https_count = 0

    http_count = 0
    untrusted_http_domains = set()

    malformed_urls = 0

    # -------------------------
    # URL Processing
    # -------------------------

    for url in urls:

        try:

            parsed = urlparse(url)

            domain = (parsed.hostname or "").lower().replace("www.", "")

            if not domain:

                malformed_urls += 1

                continue

            unique_domains.add(
                domain
            )

            if parsed.scheme == "https":

                https_count += 1

            elif parsed.scheme == "http":

                http_count += 1
                if not is_trusted_domain(domain):
                    untrusted_http_domains.add(domain)

        except Exception:

            malformed_urls += 1

    # -------------------------
    # URL Statistics
    # -------------------------

    total_urls = len(urls)

    unique_domain_count = len(
        unique_domains
    )

    # -------------------------
    # Risk Indicators
    # -------------------------

    if total_urls > 25 and unique_domain_count > 8:

        findings.append(
            "High URL Count Detected"
        )

    if untrusted_http_domains:

        findings.append(
            "Non-Encrypted HTTP URLs Detected"
        )

    if malformed_urls > 0:

        findings.append(
            "Malformed URLs Detected"
        )

    # -------------------------
    # Statistics Object
    # -------------------------

    statistics = {

        "total_urls":
            total_urls,

        "unique_domains":
            unique_domain_count,

        "https_urls":
            https_count,

        "http_urls":
            http_count,

        "malformed_urls":
            malformed_urls,

        "domains":
            sorted(
                unique_domains
            )

    }

    return (
        statistics,
        findings
    )
