"""
MODUL: OPEN REDIRECT
====================
Saytın ?url=, ?next=, ?redirect= kimi parametrləri yoxlamadan
başqa sayta yönləndirməsi = fişinq üçün təhlükəlidir.

Zərərsiz: parametrə xarici ünvan qoyub, saytın ora yönləndirib-
yönləndirmədiyinə baxır (redirect izləmədən).
"""

from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client

ƏLAMƏTLƏR = ("url", "next", "redirect", "return", "returnurl", "goto",
             "dest", "destination", "continue", "r", "u")
TEST_HEDEF = "https://cyberayfar-redirect-test.example/"


def yoxla(parametrli_url, hesabat, timeout=8):
    for url in parametrli_url:
        parcalar = urlparse(url)
        parametrler = parse_qs(parcalar.query)
        # Bütün parametrləri sına: təsdiq (Location bizim sentinel-ə yönəlir)
        # qəti olduğu üçün qeyri-standart adlarda da yalançı müsbət yoxdur.
        # Ad-uyğunları əvvəl sına (sürət).
        for param in sorted(parametrler, key=lambda p: p.lower() not in ƏLAMƏTLƏR):
            yeni = {k: v[0] for k, v in parametrler.items()}
            yeni[param] = TEST_HEDEF
            test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
            cavab = http_client.al(test_url, timeout=timeout, redirect=False)
            if not cavab:
                continue
            yer = cavab.headers.get("Location", "")
            if yer.startswith(TEST_HEDEF) or "cyberayfar-redirect-test" in yer:
                hesabat.elave_et("orta", "open_redirect", test_url, param=param)
                break
