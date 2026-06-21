from app.analyzer.header_analyzer import analyze_headers
from app.analyzer.ioc_extractor import extract_iocs
from app.analyzer.risk_engine import calculate_risk, format_risk_level
from app.analyzer.url_extractor import extract_urls


def test_defanged_and_hxxp_urls_are_normalized():
    urls = extract_urls("Visit hxxps://evil[.]com/login and www.bad-example.xyz")

    assert "https://evil.com/login" in urls
    assert "http://www.bad-example.xyz" in urls


def test_ioc_extractor_rejects_invalid_ipv4_and_separates_hashes():
    content = (
        "999.999.999.999 8.8.8.8 "
        "44d88612fea8a8f36de82e1278abb02f "
        "3395856ce81f2b7382dee72602f798b642f14140 "
        "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    )
    iocs = extract_iocs(content)

    assert "999.999.999.999" not in iocs["ipv4"]
    assert "8.8.8.8" in iocs["ipv4"]
    assert len(iocs["md5"]) == 1
    assert len(iocs["sha1"]) == 1
    assert len(iocs["sha256"]) == 1


def test_header_analysis_uses_headers_not_body_spoofing():
    content = (
        "From: Security <security@example.com>\n"
        "Reply-To: attacker@evil.com\n"
        "Authentication-Results: mx; spf=fail smtp.mailfrom=evil.com; "
        "dkim=none; dmarc=fail\n\n"
        "This body says spf=pass dkim=pass dmarc=pass."
    )
    findings, score = analyze_headers(content)

    assert score >= 40
    assert any("SPF Authentication Failed" in finding for finding in findings)
    assert any("Reply-To domain mismatch" in finding for finding in findings)


def test_weighted_risk_caps_score_and_returns_critical_level():
    risk, score, breakdown = calculate_risk(
        keywords=["urgent", "verify", "password reset", "click here"],
        url_count=12,
        domain_score=100,
        header_score=100,
        brand_score=100,
        url_reputation_score=100,
        ioc_count=20,
        shortener_score=20,
        tld_score=20,
        credential_score=30,
        urgency_score=20,
        domain_age_score=20,
    )

    assert risk == "CRITICAL"
    assert score == 100
    assert format_risk_level(risk) == "Critical"
    assert breakdown["Header Authentication"] <= 28


def test_trusted_authenticated_marketing_signals_stay_informational_or_low():
    risk, score, breakdown = calculate_risk(
        keywords=["security alert", "verify", "review now", "refund pending"],
        url_count=24,
        domain_score=0,
        header_score=0,
        brand_score=0,
        url_reputation_score=20,
        ioc_count=28,
        shortener_score=0,
        tld_score=0,
        credential_score=8,
        urgency_score=6,
        legitimacy_score=40,
        trusted_context=True,
    )

    assert score < 35
    assert risk in {"INFORMATIONAL", "LOW", "MEDIUM"}
    assert breakdown["Legitimacy Adjustment"] < 0


def test_flipkart_subdomain_return_path_aligns_with_header_from():
    content = (
        "From: Flipkart <noreply@flipkart.com>\n"
        "Return-Path: <bounce@sctrans.rmt.flipkart.com>\n"
        "Authentication-Results: mx; spf=pass smtp.mailfrom=sctrans.rmt.flipkart.com; "
        "dkim=pass header.d=flipkart.com; dmarc=pass header.from=flipkart.com\n\n"
        "Your order update is ready."
    )
    findings, score = analyze_headers(content)

    assert score == 0
    assert any("SPF Authentication Passed" in finding for finding in findings)
    assert any("Return-Path aligned" in finding for finding in findings)
    assert not any("mismatch" in finding.lower() for finding in findings)
