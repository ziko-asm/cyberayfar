"""
MODUL: SSTI — Server-Side Template Injection
============================================
Şablon mühərrikinə (Jinja2, Twig, Freemarker, ERB, Razor, Smarty...)
düşən input RCE-yə qədər gedə bilər. Necə tapırıq (zərərsiz):
  1) Təsadüfi iki ədəd seçirik (məs. 947 və 983), payload göndəririk:
     {{947*983}}, ${947*983}, #{947*983}, <%= 947*983 %> ...
  2) Cavabda HESABLANMIŞ nəticə (930701) görünür, amma payload-un ÖZÜ
     (947*983) görünmürsə -> şablon inputu icra etdi = SSTI.
  3) İkinci təsadüfi ədəd cütü ilə TƏSDİQLƏNİR (yalançı müsbət olmasın).
Zərərli kod işlətmir — yalnız riyazi ifadənin hesablanıb-hesablanmadığını
yoxlayır.
"""

import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client


def _cut():
    a = 900 + secrets.randbelow(99)
    b = 900 + secrets.randbelow(99)
    return a, b, a * b


def _payloadlar(a, b):
    # mühərrik -> payload sətri
    return {
        "Jinja2/Twig": "{{%d*%d}}" % (a, b),
        "Freemarker/EL": "${%d*%d}" % (a, b),
        "Ruby/JSF": "#{%d*%d}" % (a, b),
        "ERB": "<%%= %d*%d %%>" % (a, b),
        "Razor": "@(%d*%d)" % (a, b),
        "Smarty/Mako": "{%d*%d}" % (a, b),
        "Velocity": "#set($x=%d*%d)$x" % (a, b),
    }


def _test_dey(gonder, kontrol_metn):
    """gonder(payload)->metn. SSTI tapılarsa (muherrik, payload) qaytarır."""
    a, b, netice = _cut()
    hedef = str(netice)
    # nəticə ədədi normal səhifədə onsuz da varsa, bu cütü işlətmə
    if hedef in (kontrol_metn or ""):
        a, b, netice = _cut()
        hedef = str(netice)
        if hedef in (kontrol_metn or ""):
            return None, None
    for muherrik, payload in _payloadlar(a, b).items():
        metn = gonder(payload)
        if metn is None:
            continue
        # hesablanmış nəticə var, amma payload sətri (xam) yoxdursa -> icra olundu
        if hedef in metn and payload not in metn:
            # TƏSDİQ: ayrı ədəd cütü ilə təkrarla
            a2, b2, net2 = _cut()
            p2 = _payloadlar(a2, b2)[muherrik]
            m2 = gonder(p2)
            if m2 is not None and str(net2) in m2 and p2 not in m2:
                return muherrik, payload
    return None, None


def _get_yoxla(url, hesabat, timeout):
    parcalar = urlparse(url)
    parametrler = parse_qs(parcalar.query)
    kontrol = http_client.al(url, timeout=timeout)
    kontrol_metn = kontrol.text if kontrol else ""
    for param in parametrler:
        def _gonder(payload):
            yeni = {k: v[0] for k, v in parametrler.items()}
            yeni[param] = payload
            u = urlunparse(parcalar._replace(query=urlencode(yeni)))
            c = http_client.al(u, timeout=timeout)
            return c.text if c else None
        muherrik, payload = _test_dey(_gonder, kontrol_metn)
        if muherrik:
            hesabat.elave_et("kritik", "ssti", url, param=param,
                             muherrik=muherrik, payload=payload)


def _forma_yoxla(form, hesabat, timeout):
    if not form["inputlar"]:
        return
    metod = form["metod"]
    kontrol = http_client.al(form["hereket"], metod=metod.upper(), timeout=timeout,
                             **({"data": {i["ad"]: "test" for i in form["inputlar"]}}
                                if metod == "post"
                                else {"params": {i["ad"]: "test" for i in form["inputlar"]}}))
    kontrol_metn = kontrol.text if kontrol else ""

    def _gonder(payload):
        data = {inp["ad"]: payload for inp in form["inputlar"]}
        kw = {"data": data} if metod == "post" else {"params": data}
        c = http_client.al(form["hereket"], metod=metod.upper(), timeout=timeout, **kw)
        return c.text if c else None
    muherrik, payload = _test_dey(_gonder, kontrol_metn)
    if muherrik:
        hesabat.elave_et("kritik", "ssti", form["hereket"],
                         menbe=form["menbe_sehife"], muherrik=muherrik, payload=payload)


def yoxla(parametrli_url, formalar, hesabat, timeout=8):
    for url in parametrli_url:
        _get_yoxla(url, hesabat, timeout)
    for form in formalar:
        _forma_yoxla(form, hesabat, timeout)
