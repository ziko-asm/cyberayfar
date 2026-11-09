"""
OWASP TOP 10 (2021) XƏRİTƏSİ
============================
Hər tapıntı kodunu OWASP Top 10 kateqoriyasına bağlayır — compliance
hesabatı və peşəkar görünüş üçün.
"""

XERITE = {
    # A01 — Broken Access Control
    "idor": "A01", "open_redirect": "A01", "host_header": "A01",
    # A02 — Cryptographic Failures
    "tls_kohne": "A02", "tls_self": "A02", "tls_sertifikat": "A02",
    "mixed_content": "A02", "cookie_zeif": "A02", "hsts_yox": "A02",
    "sirr_sizma": "A02",
    # A03 — Injection
    "xss_url": "A03", "xss_forma": "A03", "stored_xss": "A03", "sqli_url": "A03",
    "sqli_forma": "A03", "sqli_blind": "A03", "sqli_bool": "A03", "ssti": "A03",
    "crlf": "A03", "nosql_bool": "A03", "nosql_error": "A03", "cmd_injection": "A03",
    "rce_oob": "A03", "lfi": "A03",
    # A05 — Security Misconfiguration
    "csp_yox": "A05", "xcto_yox": "A05", "refpol_yox": "A05",
    "permpol_yox": "A05", "server_versiya": "A05", "cors_acar": "A05",
    "cors_reflect": "A05", "tehlukeli_metod": "A05", "graphql_introspection": "A05",
    "hessas_fayl": "A05", "robots": "A05", "gizli_yol": "A05",
    "clickjacking": "A05", "xxe": "A05", "xxe_oob": "A05", "csrf_yox": "A05",
    "subdomainler": "A05",
    # A06 — Vulnerable and Outdated Components
    "kohne_js": "A06",
    # A07 — Identification and Authentication Failures
    "spf_yox": "A07", "spf_zeif": "A07", "dmarc_yox": "A07",
    "dmarc_passiv": "A07", "dkim_yox": "A07",
    # A10 — SSRF
    "ssrf": "A10", "ssrf_oob": "A10",
    # məlumat (xəritəsiz)
    "platforma": None, "waf_askarlandi": None,
}

ADLAR = {
    "A01": {"az": "Broken Access Control", "en": "Broken Access Control", "ru": "Broken Access Control"},
    "A02": {"az": "Cryptographic Failures", "en": "Cryptographic Failures", "ru": "Cryptographic Failures"},
    "A03": {"az": "Injection", "en": "Injection", "ru": "Injection"},
    "A05": {"az": "Security Misconfiguration", "en": "Security Misconfiguration", "ru": "Security Misconfiguration"},
    "A06": {"az": "Vulnerable & Outdated Components", "en": "Vulnerable & Outdated Components", "ru": "Vulnerable & Outdated Components"},
    "A07": {"az": "Auth Failures", "en": "Identification & Auth Failures", "ru": "Identification & Auth Failures"},
    "A10": {"az": "SSRF", "en": "Server-Side Request Forgery", "ru": "SSRF"},
}


def kateqoriya(kod):
    return XERITE.get(kod)


def icmal(tapintilar):
    """Təsir olunan OWASP kateqoriyaları {A0x: say} (yalnız zəif tapıntılar)."""
    say = {}
    for t in tapintilar:
        if t.get("ciddilik") == "info":
            continue
        a = XERITE.get(t.get("kod"))
        if a:
            say[a] = say.get(a, 0) + 1
    return say
