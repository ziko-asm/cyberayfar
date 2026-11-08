"""
MODUL: TƏHLÜKƏSİZLİK BAŞLIQLARI + COOKIE
========================================
Passiv (yalnız oxuyur). Vacib müdafiə başlıqları var-yoxdur yoxlayır.
"""

from core import http_client

BASLIQLAR = [
    ("content-security-policy", "yuksek", "csp_yox"),
    ("strict-transport-security", "orta", "hsts_yox"),
    ("x-content-type-options", "asagi", "xcto_yox"),
    ("referrer-policy", "asagi", "refpol_yox"),
    ("permissions-policy", "asagi", "permpol_yox"),
]


def yoxla(bas_url, hesabat, timeout=8):
    cavab = http_client.al(bas_url, timeout=timeout)
    if not cavab:
        return
    mövcud = {k.lower() for k in cavab.headers}

    for ad, ciddilik, kod in BASLIQLAR:
        if ad not in mövcud:
            hesabat.elave_et(ciddilik, kod, bas_url, basliq=ad)

    # Server versiya sızması
    server = cavab.headers.get("Server", "")
    if any(c.isdigit() for c in server):
        hesabat.elave_et("asagi", "server_versiya", bas_url, server=server)

    # Cookie bayraqları
    for c in cavab.cookies:
        problemler = []
        if not c.secure:
            problemler.append("Secure")
        if not c.has_nonstandard_attr("HttpOnly") and "httponly" not in str(c._rest).lower():
            problemler.append("HttpOnly")
        if problemler:
            hesabat.elave_et("orta", "cookie_zeif", bas_url,
                             cookie=c.name, bayraqlar=", ".join(problemler))
