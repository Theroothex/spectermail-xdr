from urllib.parse import urlparse

from app.analyzer.domain_utils import domain_from_url


SUSPICIOUS_TLDS = {

    ".xyz",
    ".top",
    ".click",
    ".work",
    ".shop",
    ".loan",
    ".gq",
    ".tk"

}


def check_suspicious_tlds(urls):

    findings = []

    score = 0

    reported = set()

    for url in urls:

        domain = domain_from_url(url)

        for tld in SUSPICIOUS_TLDS:

            if domain.endswith(tld) and domain not in reported:

                findings.append(

                    f"Suspicious TLD Detected ({domain})"

                )

                score += 15
                reported.add(domain)

    return findings, score
