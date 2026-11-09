"""
MODUL: CRLF Injection / HTTP Response Splitting
===============================================
İstifadəçi inputu cavab BAŞLIĞINA (header) təmizlənmədən düşərsə,
hücumçu \r\n (CRLF) ilə yeni başlıq və ya bütöv cavab yarada bilər:
  - saxta Set-Cookie (sessiya təyini),
  - cache poisoning,
  - başlıq vasitəsilə XSS.

NECƏ (zərərsiz):
  param dəyərinə `\r\nX-Cyb-<token>: 1` əlavə edirik və cavab
  BAŞLIQLARINDA həmin unikal başlıq görünürsə -> CRLF injection.
  Redirect-i izləmirik (redirect=False) ki, yeridilən başlığı görək.
  2-ci token ilə TƏSDİQLƏNİR.
"""

import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client


def _basliqda_var(cavab, basliq):
    if not cavab:
        return False
    hb = basliq.lower()
    for k in cavab.headers.keys():
        if k.lower() == hb:
            return True
    return False


def _sinaq(parcalar, parametrler, param, timeout):
    token = secrets.token_hex(4)
    basliq = "X-Cyb-" + token
    yeni = {k: v[0] for k, v in parametrler.items()}
    yeni[param] = yeni[param] + "\r\n" + basliq + ": 1"
    url = urlunparse(parcalar._replace(query=urlencode(yeni)))
    cavab = http_client.al(url, timeout=timeout, redirect=False)
    return _basliqda_var(cavab, basliq), url


def _get_yoxla(url, hesabat, timeout):
    parcalar = urlparse(url)
    parametrler = parse_qs(parcalar.query)
    for param in parametrler:
        tapildi, test_url = _sinaq(parcalar, parametrler, param, timeout)
        if not tapildi:
            continue
        # TƏSDİQ: ikinci unikal başlıqla
        tapildi2, _ = _sinaq(parcalar, parametrler, param, timeout)
        if tapildi2:
            hesabat.elave_et("yuksek", "crlf", test_url, param=param)


def yoxla(parametrli_url, hesabat, timeout=8):
    for url in parametrli_url:
        _get_yoxla(url, hesabat, timeout)
