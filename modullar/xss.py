"""
MODUL: ƏKS OLUNAN XSS (Reflected XSS) DETEKTORU
===============================================
XSS = saytın istifadəçi inputunu təmizləmədən səhifəyə qaytarması.
Bu zaman hücumçu zərərli JavaScript yeridə bilər.

NECƏ AŞKARLAYIRIQ (zərərsiz üsul):
  1. Hər input/parametrə unikal "canary" (nişan) göndəririk, məs: zXy123
     ətrafında HTML üçün təhlükəli simvollarla: <>"'
  2. Əgər bu simvollar cavabda OLDUĞU KİMİ (təmizlənmədən) görünürsə,
     deməli sayt XSS-ə açıqdır.
  Biz real zərərli skript İŞLƏTMİRİK — yalnız simvolların filtrlənib-
  filtrlənmədiyini yoxlayırıq. Bu, standart və təhlükəsiz metoddur.
"""

import secrets
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Canary: cavabda tapması asan, təsadüfi nişan
def _canary():
    n = secrets.token_hex(4)
    # HTML-də təhlükəli simvollar — filtrlənməlidirlər
    return f"xss{n}<>\"'", n


def _reflektə_olunur(cavab_metni, nishan, token):
    """Təhlükəli simvollar təmizlənmədən qayıdıbsa True."""
    tehlukeli = f"<>\"'"
    # Nişanla birlikdə təhlükəli simvollar varsa = filtrlənməyib
    return (f"xss{token}" in cavab_metni and
            any(s in cavab_metni.split(f"xss{token}")[-1][:6] for s in tehlukeli))


def _get_parametrleri_yoxla(url, hesabat, sessiya, timeout):
    parcalar = urlparse(url)
    parametrler = parse_qs(parcalar.query)
    if not parametrler:
        return
    for param in parametrler:
        canary, token = _canary()
        yeni = {k: v[0] for k, v in parametrler.items()}
        yeni[param] = canary
        test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
        try:
            cavab = sessiya.get(test_url, timeout=timeout)
        except requests.RequestException:
            continue
        if _reflektə_olunur(cavab.text, canary, token):
            hesabat.elave_et("yuksek", "xss_url", test_url, param=param)


def _formalari_yoxla(formalar, hesabat, sessiya, timeout):
    for form in formalar:
        canary, token = _canary()
        data = {inp["ad"]: canary for inp in form["inputlar"]}
        if not data:
            continue
        try:
            if form["metod"] == "post":
                cavab = sessiya.post(form["hereket"], data=data, timeout=timeout)
            else:
                cavab = sessiya.get(form["hereket"], params=data, timeout=timeout)
        except requests.RequestException:
            continue
        if _reflektə_olunur(cavab.text, canary, token):
            hesabat.elave_et("yuksek", "xss_forma", form["hereket"],
                             menbe=form["menbe_sehife"])


def yoxla(parametrli_url, formalar, hesabat, timeout=10):
    sessiya = requests.Session()
    sessiya.headers.update({"User-Agent": "SaytYoxla-Skaner/1.0"})
    for url in parametrli_url:
        _get_parametrleri_yoxla(url, hesabat, sessiya, timeout)
    _formalari_yoxla(formalar, hesabat, sessiya, timeout)
