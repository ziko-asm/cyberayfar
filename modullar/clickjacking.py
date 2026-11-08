"""
MODUL: CLICKJACKING (dərin)
===========================
Sayt iframe-ə salına bilirsə, hücumçu onu gizli pəncərədə göstərib
istifadəçini aldadıcı klikə yönəldə bilər (clickjacking).
Qoruma İKİ üsulla olur: X-Frame-Options VƏ YA CSP frame-ancestors.
Yalnız HƏR İKİSİ yoxdursa zəiflik var (dəqiq, yalançı müsbət az).
"""

from core import http_client


def yoxla(bas_url, hesabat, timeout=8):
    cavab = http_client.al(bas_url, timeout=timeout)
    if not cavab:
        return
    basliqlar = {k.lower(): v for k, v in cavab.headers.items()}
    xfo = basliqlar.get("x-frame-options", "")
    csp = basliqlar.get("content-security-policy", "")
    if not xfo and "frame-ancestors" not in csp.lower():
        hesabat.elave_et("orta", "clickjacking", bas_url)
