from urllib.parse import urlparse

from app.analyzer.domain_utils import TRUSTED_ORG_DOMAINS, domain_from_url, is_subdomain_of


def check_sender_reputation(urls):

    trusted_domains = TRUSTED_ORG_DOMAINS | {"c.gle"}

    suspicious_tlds = {

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

    }

    findings = []

    reputation = "Unknown"

    unique_domains = set()

    reported_trusted_domains = set()

    suspicious_found = False

    trusted_found_global = False

    # -------------------------
    # Extract Unique Domains
    # -------------------------

    for url in urls:

        try:

            domain = domain_from_url(url)

            if domain:

                unique_domains.add(
                    domain
                )

        except Exception:

            pass

    # -------------------------
    # Reputation Analysis
    # -------------------------

    for domain in unique_domains:

        trusted_found = False

        for trusted in trusted_domains:

            if (

                is_subdomain_of(domain, trusted)

            ):

                if trusted == "c.gle":

                    if "c.gle" not in reported_trusted_domains:

                        findings.append(
                            "Google URL Shortening Service Identified"
                        )

                        reported_trusted_domains.add(
                            "c.gle"
                        )

                else:

                    if trusted not in reported_trusted_domains:

                        findings.append(
                            f"Trusted Domain Detected ({trusted})"
                        )

                        reported_trusted_domains.add(
                            trusted
                        )

                trusted_found = True
                trusted_found_global = True

                break

        if trusted_found:

            continue

        for tld in suspicious_tlds:

            if domain.endswith(tld):

                findings.append(
                    f"Suspicious Domain Detected ({domain})"
                )

                suspicious_found = True

                break

    # -------------------------
    # Reputation Classification
    # -------------------------

    if trusted_found_global:

        reputation = "Trusted"

    elif suspicious_found:

        reputation = "Suspicious"

    else:

        reputation = "Unknown"

    # -------------------------
    # No Findings
    # -------------------------

    if not findings:

        findings.append(
            "No reputation intelligence available"
        )

    return (
        reputation,
        findings
    )
