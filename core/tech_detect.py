"""
TEXNOLOGİYA AŞKARLAMA (Fingerprinting)
======================================
Mərhələ 2: saytın server/framework/CMS-ini tapır. Bu, həm hesabatda
göstərilir, həm də gələcəkdə "ağıllı yoxlama" üçün istifadə oluna bilər
(məs: WordPress görsə -> WordPress zəifliklərini yoxla).
"""

import re
from core import http_client

# İmza qaydaları: (ad, harada, regex)
IMZALAR = [
    ("WordPress", "html", r"wp-content|wp-includes"),
    ("Joomla", "html", r"/media/jui/|Joomla"),
    ("Drupal", "html", r"Drupal.settings|/sites/default/"),
    ("React", "html", r"__REACT|data-reactroot|react(?:\.min)?\.js"),
    ("Vue.js", "html", r"vue(?:\.min)?\.js|data-v-"),
    ("Angular", "html", r"ng-version|angular(?:\.min)?\.js"),
    ("Next.js", "html", r"/_next/|__NEXT_DATA__"),
    ("Laravel", "cookie", r"laravel_session|XSRF-TOKEN"),
    ("Django", "cookie", r"csrftoken|sessionid"),
    ("Express", "header_x-powered-by", r"Express"),
    ("PHP", "header_x-powered-by", r"PHP"),
    ("ASP.NET", "header_x-powered-by", r"ASP\.NET"),
    ("Nginx", "header_server", r"nginx"),
    ("Apache", "header_server", r"Apache"),
    ("Cloudflare", "header_server", r"cloudflare"),
    ("Vercel", "header_server", r"Vercel"),
    ("jQuery", "html", r"jquery(?:[-.]\d|\.min)?\.js"),
    ("Bootstrap", "html", r"bootstrap(?:\.min)?\.(?:css|js)"),
]


def askarla(bas_url, timeout=8):
    cavab = http_client.al(bas_url, timeout=timeout)
    if not cavab:
        return {"server": "?", "texnologiyalar": []}

    html = cavab.text or ""
    basliqlar = {k.lower(): v for k, v in cavab.headers.items()}
    cookieler = "; ".join(f"{c.name}" for c in cavab.cookies)
    tapilan = []

    for ad, harada, naxis in IMZALAR:
        hedef = ""
        if harada == "html":
            hedef = html
        elif harada == "cookie":
            hedef = cookieler
        elif harada.startswith("header_"):
            hedef = basliqlar.get(harada[7:], "")
        if hedef and re.search(naxis, hedef, re.IGNORECASE):
            if ad not in tapilan:
                tapilan.append(ad)

    return {
        "server": basliqlar.get("server", "?"),
        "powered_by": basliqlar.get("x-powered-by", ""),
        "texnologiyalar": tapilan,
    }
