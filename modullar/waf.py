"""
MODUL: WAF AŞKARLAMA
====================
Saytın qarşısında Web Application Firewall (WAF) varmı? Bu, saytın
XEYRİNƏDİR (əlavə müdafiə), amma skanerin dəqiqliyinə təsir edə bilər,
ona görə məlumat kimi qeyd edirik.
Zərərsiz: bir "şübhəli" sorğu göndərib WAF imzalarına baxır.
"""

from core import http_client

# İmza: (WAF adı, başlıq açarı/ad, dəyər-naxışı)
BASLIQ_IMZALARI = [
    ("Cloudflare", "server", "cloudflare"),
    ("Cloudflare", "cf-ray", ""),
    ("Sucuri", "x-sucuri-id", ""),
    ("Akamai", "x-akamai-transformed", ""),
    ("Imperva/Incapsula", "x-iinfo", ""),
    ("AWS WAF", "x-amzn-waf-action", ""),
    ("F5 BIG-IP", "x-waf-event-info", ""),
    ("Fastly", "x-served-by", "fastly"),
    ("Vercel", "x-vercel-id", ""),
]
# Şübhəli yük (XSS+SQLi) — WAF-ı "oyatmaq" üçün (zərərsiz test input-u)
SUBHELI = "?cyb=<script>alert(1)</script>' OR '1'='1"


def yoxla(bas_url, hesabat, timeout=8):
    # Həm normal, həm şübhəli sorğu başlıqlarını yığ
    tapilan = set()
    for u in (bas_url, bas_url.rstrip("/") + "/" + SUBHELI):
        cavab = http_client.al(u, timeout=timeout)
        if not cavab:
            continue
        basliqlar = {k.lower(): (v or "").lower() for k, v in cavab.headers.items()}
        for ad, acar, naxis in BASLIQ_IMZALARI:
            if acar in basliqlar and (not naxis or naxis in basliqlar[acar]):
                tapilan.add(ad)
    if tapilan:
        hesabat.elave_et("info", "waf_askarlandi", bas_url, ad=", ".join(sorted(tapilan)))
