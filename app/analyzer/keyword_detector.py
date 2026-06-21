import re


SUSPICIOUS_KEYWORDS = {
    "urgency": [
        "urgent",
        "immediately",
        "within 24 hours",
        "final warning",
        "action required",
        "security alert",
        "account suspended",
    ],
    "credential_theft": [
        "verify",
        "password reset",
        "login immediately",
        "confirm identity",
        "update your password",
        "sign in to restore",
        "validate your account",
    ],
    "financial": [
        "payment required",
        "refund pending",
        "invoice attached",
        "bank account",
        "wire transfer",
        "billing failed",
    ],
    "execution": [
        "enable macros",
        "open attachment",
        "download file",
        "install update",
        "run attachment",
    ],
    "call_to_action": [
        "click here",
        "open the link",
        "review now",
        "download now",
    ],
    "brand": [
        "paypal",
        "amazon",
        "microsoft",
        "google",
        "github",
        "linkedin",
        "apple",
        "netflix",
    ],
}


def analyze_language(content):
    lowered = (content or "").lower()
    profile = {}
    for category, indicators in SUSPICIOUS_KEYWORDS.items():
        matches = [
            indicator
            for indicator in indicators
            if re.search(rf"(?<!\w){re.escape(indicator)}(?!\w)", lowered)
        ]
        profile[category] = list(dict.fromkeys(matches))
    return profile


def detect_keywords(content):
    profile = analyze_language(content)
    findings = []
    for category, matches in profile.items():
        if category == "brand":
            continue
        findings.extend(matches)
    return list(dict.fromkeys(findings))
