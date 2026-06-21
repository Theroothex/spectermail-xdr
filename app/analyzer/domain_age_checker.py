import whois

from datetime import (
    datetime,
    timezone
)


def check_domain_age(domain):

    findings = []

    risk = "UNKNOWN"

    try:

        info = whois.whois(domain)

        creation_date = info.creation_date

        # Some WHOIS servers return a list
        if isinstance(
            creation_date,
            list
        ):

            creation_date = creation_date[0]

        # Creation date not found
        if not creation_date:

            findings.append(
                "Creation date unavailable"
            )

            return findings, risk

        # Fix timezone mismatch
        if creation_date.tzinfo is None:

            creation_date = (
                creation_date.replace(
                    tzinfo=timezone.utc
                )
            )

        current_time = datetime.now(
            timezone.utc
        )

        age_days = (
            current_time -
            creation_date
        ).days

        age_years = round(
            age_days / 365,
            1
        )

        findings.append(
            f"Domain: {domain}"
        )

        findings.append(
            f"Created: {creation_date.strftime('%Y-%m-%d')}"
        )

        findings.append(
            f"Age: {age_days} days ({age_years} years)"
        )

        # Risk classification
        if age_days < 30:

            risk = "HIGH"

            findings.append(
                "Risk: High (Recently Registered Domain)"
            )

        elif age_days < 180:

            risk = "MEDIUM"

            findings.append(
                "Risk: Medium (New Domain)"
            )

        else:

            risk = "LOW"

            findings.append(
                "Risk: Low (Established Domain)"
            )

    except Exception:

        findings.append(
            "No WHOIS data available."
        )

    return findings, risk