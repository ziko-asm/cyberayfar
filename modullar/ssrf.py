"""
MODUL: SSRF (Server-Side Request Forgery)
=========================================
Server istifadəçinin verdiyi URL-ə sorğu göndərirsə, hücumçu onu
daxili sistemlərə (məs: bulud metadata serveri) yönəldə bilər.

Zərərsiz + DƏQİQ: yalnız URL-ə bənzər parametrlərə daxili metadata
ünvanı qoyur və cavabda AÇIQ metadata imzası görünərsə işarələyir
(yalançı müsbəti minimuma salır).
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client

ƏLAMƏTLƏR = ("url", "uri", "link", "target", "dest", "redirect", "fetch",
             "image", "img", "load", "proxy", "callback", "webhook", "feed",
             "host", "domain", "site", "page", "path", "file", "data")

# Bulud metadata ünvanları (daxili)
PAYLOADLAR = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:22/",
]
# Cavabda bunlar görünərsə = metadata əldə olunub (əsl SSRF)
IMZA = re.compile(r"ami-id|instance-id|iam/|computeMetadata|security-credentials|SSH-2\.0", re.IGNORECASE)


def yoxla(parametrli_url, hesabat, timeout=8):
    for url in parametrli_url:
        parcalar = urlparse(url)
        parametrler = parse_qs(parcalar.query)
        for param in parametrler:
            if param.lower() not in ƏLAMƏTLƏR:
                continue
            for p in PAYLOADLAR:
                yeni = {k: v[0] for k, v in parametrler.items()}
                yeni[param] = p
                test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
                cavab = http_client.al(test_url, timeout=timeout + 3)
                if cavab and IMZA.search(cavab.text or ""):
                    hesabat.elave_et("kritik", "ssrf", test_url, param=param)
                    return
