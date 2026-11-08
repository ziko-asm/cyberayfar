"""
MODUL: ƏKS OLUNAN XSS (Reflected) — doğrulama ilə
=================================================
Canary (nişan) + HTML təhlükəli simvolları göndərir. Təmizlənmədən
qayıdarsa = XSS. Mərhələ 2: tapılanı 2-ci canary ilə TƏSDİQLƏYİR
(yalançı müsbəti azaldır).
"""

import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client

TEHLUKELI = "<>\"'"


def _canary():
    n = secrets.token_hex(4)
    return f"xss{n}<>\"'", n


def _reflekte(metn, token):
    if f"xss{token}" not in metn:
        return False
    sonra = metn.split(f"xss{token}")[-1][:6]
    return any(s in sonra for s in TEHLUKELI)


def _tesdiqle_get(test_url_sablonu, param, parametrler, parcalar):
    """İkinci canary ilə təkrar yoxla."""
    canary, token = _canary()
    yeni = {k: v[0] for k, v in parametrler.items()}
    yeni[param] = canary
    url = urlunparse(parcalar._replace(query=urlencode(yeni)))
    cavab = http_client.al(url)
    return cavab and _reflekte(cavab.text, token)


def _get_yoxla(url, hesabat, timeout):
    parcalar = urlparse(url)
    parametrler = parse_qs(parcalar.query)
    for param in parametrler:
        canary, token = _canary()
        yeni = {k: v[0] for k, v in parametrler.items()}
        yeni[param] = canary
        test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
        cavab = http_client.al(test_url, timeout=timeout)
        if cavab and _reflekte(cavab.text, token):
            # DOĞRULAMA: ikinci dəfə təsdiqlə
            if _tesdiqle_get(test_url, param, parametrler, parcalar):
                hesabat.elave_et("yuksek", "xss_url", test_url, param=param)


def _forma_yoxla(form, hesabat, timeout):
    canary, token = _canary()
    data = {inp["ad"]: canary for inp in form["inputlar"]}
    if not data:
        return
    metod = form["metod"]
    kw = {"data": data} if metod == "post" else {"params": data}
    cavab = http_client.al(form["hereket"], metod=metod.upper(), timeout=timeout, **kw)
    if cavab and _reflekte(cavab.text, token):
        # Doğrulama
        c2, t2 = _canary()
        d2 = {inp["ad"]: c2 for inp in form["inputlar"]}
        kw2 = {"data": d2} if metod == "post" else {"params": d2}
        cavab2 = http_client.al(form["hereket"], metod=metod.upper(), timeout=timeout, **kw2)
        if cavab2 and _reflekte(cavab2.text, t2):
            hesabat.elave_et("yuksek", "xss_forma", form["hereket"],
                             menbe=form["menbe_sehife"])


def yoxla(parametrli_url, formalar, hesabat, timeout=8):
    for url in parametrli_url:
        _get_yoxla(url, hesabat, timeout)
    for form in formalar:
        _forma_yoxla(form, hesabat, timeout)
