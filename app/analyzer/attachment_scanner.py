SUSPICIOUS_EXTENSIONS = [

    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".docm"

]

def scan_attachments(content):

    findings = []

    lower_content = content.lower()

    # Dangerous Extensions
    for ext in SUSPICIOUS_EXTENSIONS:

        if ext in lower_content:

            findings.append(
                f"Suspicious Attachment Detected ({ext})"
            )

    # Double Extension Detection
    double_extensions = [

        ".pdf.exe",
        ".doc.exe",
        ".xls.exe"

    ]

    for ext in double_extensions:

        if ext in lower_content:

            findings.append(
                f"Double Extension File Detected ({ext})"
            )

    # Suspicious ZIP
    if ".zip" in lower_content:

        findings.append(
            "Compressed Attachment Detected (.zip)"
        )

    return findings