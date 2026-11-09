"""
MODUL: ƏKS OLUNAN XSS (Reflected) — KONTEKST-BİLƏN + doğrulama
=============================================================
Burp kimi işləyir:
  1) Unikal nişan + təhlükəli simvolları (< > " ') göndərir.
  2) Cavabda nişanın HANSI kontekstdə düşdüyünü təyin edir:
     HTML gövdə / atribut(") / atribut(') / teq-daxili / JavaScript.
  3) HƏR kontekst üçün yalnız O kontekstdə işləyən simvolların
     təmizlənmədiyini yoxlayır -> real istismar olunan XSS tapır,
     yalançı müsbəti azaldır.
  4) Tapılanı 2-ci nişanla TƏSDİQLƏYİR və işləyən payload-u göstərir.
Zərərsizdir — alert işlətmir, yalnız filtrasiyanı yoxlayır.
"""

import re
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client

SPECIAL = "<>\"'"


def _marker():
    return "zx" + secrets.token_hex(3)          # alnum -> filtrdən keçir


def _probe(marker):
    # iki nişan arasına təhlükəli simvolları qoyuruq (hansı sağ qalır?)
    return f"{marker}{SPECIAL}{marker}"


def _analiz(text, marker):
    """(sağ-qalan simvollar, kontekst) qaytarır; nişan yoxdursa (set(), None)."""
    if not text or marker not in text:
        return set(), None
    survivors = set()
    m = re.search(re.escape(marker) + r"(.*?)" + re.escape(marker), text, re.S)
    if m:
        seg = m.group(1)
        for c in SPECIAL:
            if c in seg:
                survivors.add(c)
    i = text.find(marker)
    low = text.lower()
    acik = low.rfind("<script", 0, i)
    bagli = low.rfind("</script", 0, i)
    if acik > bagli:
        kontekst = "JavaScript"
    else:
        lt = text.rfind("<", 0, i)
        gt = text.rfind(">", 0, i)
        if lt > gt:                              # teq daxilindəyik
            seg2 = text[lt:i]
            if seg2.count('"') % 2 == 1:
                kontekst = 'atribut(")'
            elif seg2.count("'") % 2 == 1:
                kontekst = "atribut(')"
            else:
                kontekst = "teq"
        else:
            kontekst = "HTML"
    return survivors, kontekst


def _qerar(survivors, kontekst):
    """(ciddilik, işləyən_payload) və ya (None, None)."""
    lt = "<" in survivors
    gt = ">" in survivors
    dq = '"' in survivors
    sq = "'" in survivors
    if kontekst == "JavaScript":
        if lt and gt:
            return "yuksek", "</script><svg onload=alert(1)>"
        if dq:
            return "yuksek", '";alert(1)//'
        if sq:
            return "yuksek", "';alert(1)//"
        return None, None
    if kontekst == 'atribut(")':
        if dq:
            return "yuksek", '"><svg onload=alert(1)>'
        return None, None
    if kontekst == "atribut(')":
        if sq:
            return "yuksek", "'><svg onload=alert(1)>"
        return None, None
    # HTML gövdə və ya tırnaqsız teq
    if lt and gt:
        return "yuksek", "<svg onload=alert(1)>"
    if kontekst == "teq" and (dq or sq):
        return "orta", "x autofocus onfocus=alert(1)"
    return None, None


def _get_yoxla(url, hesabat, timeout):
    parcalar = urlparse(url)
    parametrler = parse_qs(parcalar.query)
    for param in parametrler:
        marker = _marker()
        yeni = {k: v[0] for k, v in parametrler.items()}
        yeni[param] = _probe(marker)
        test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
        cavab = http_client.al(test_url, timeout=timeout)
        if not cavab:
            continue
        survivors, kontekst = _analiz(cavab.text, marker)
        if not kontekst:
            continue
        ciddilik, payload = _qerar(survivors, kontekst)
        if not ciddilik:
            continue
        # TƏSDİQ: ikinci nişanla eyni nəticə
        m2 = _marker()
        yeni[param] = _probe(m2)
        url2 = urlunparse(parcalar._replace(query=urlencode(yeni)))
        c2 = http_client.al(url2, timeout=timeout)
        s2, k2 = _analiz(c2.text if c2 else "", m2)
        cd2, _ = _qerar(s2, k2)
        if cd2:
            hesabat.elave_et(ciddilik, "xss_url", test_url,
                             param=param, kontekst=kontekst, payload=payload)


def _forma_yoxla(form, hesabat, timeout):
    if not form["inputlar"]:
        return
    metod = form["metod"]
    marker = _marker()
    data = {inp["ad"]: _probe(marker) for inp in form["inputlar"]}
    kw = {"data": data} if metod == "post" else {"params": data}
    cavab = http_client.al(form["hereket"], metod=metod.upper(), timeout=timeout, **kw)
    if not cavab:
        return
    survivors, kontekst = _analiz(cavab.text, marker)
    if not kontekst:
        return
    ciddilik, payload = _qerar(survivors, kontekst)
    if not ciddilik:
        return
    m2 = _marker()
    d2 = {inp["ad"]: _probe(m2) for inp in form["inputlar"]}
    kw2 = {"data": d2} if metod == "post" else {"params": d2}
    c2 = http_client.al(form["hereket"], metod=metod.upper(), timeout=timeout, **kw2)
    s2, k2 = _analiz(c2.text if c2 else "", m2)
    cd2, _ = _qerar(s2, k2)
    if cd2:
        hesabat.elave_et(ciddilik, "xss_forma", form["hereket"],
                         menbe=form["menbe_sehife"], kontekst=kontekst, payload=payload)


def yoxla(parametrli_url, formalar, hesabat, timeout=8):
    for url in parametrli_url:
        _get_yoxla(url, hesabat, timeout)
    for form in formalar:
        _forma_yoxla(form, hesabat, timeout)
