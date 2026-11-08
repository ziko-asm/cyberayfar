"""
MODUL: IDOR (Insecure Direct Object Reference) — BƏRK yoxlama
============================================================
OWASP #1 (Broken Access Control). '/profil?id=5' -> 'id=6' dəyişib
BAŞQASININ məlumatını görmək.

GÜCLÜ MƏNTİQ (yalançı müsbəti azaldır):
  1) Orijinal id-nin cavabını götür (öz obyektin).
  2) "Mövcud olmayan" id (çox böyük) -> saytın "tapılmadı" bazası.
  3) Qonşu id-ləri (±1, ±2, +3) sına. Əgər cavab:
       - 200, boş deyil, login/xəta səhifəsi deyil
       - "tapılmadı" bazasından FƏRQLİ (yəni real obyekt açılıb)
       - orijinalla oxşar struktur AMMA fərqli məzmun (başqa obyekt)
     -> IDOR! (başqasının məlumatı açıldı)
  http_client sessiya cookie-si ilə işləyir -> authenticated skanla birləşir.
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client

ID_ADLAR = ("id", "uid", "user", "userid", "user_id", "account", "acc", "pid",
            "oid", "docid", "doc", "order", "orderid", "order_id", "invoice",
            "cid", "ref", "record", "item", "profile", "member", "customer",
            "file", "fid", "no", "num")
# Şəxsi/həssas adlar -> daha yüksək ciddilik
PRIVAT = ("user", "userid", "user_id", "account", "acc", "order", "orderid",
          "order_id", "invoice", "profile", "member", "customer", "doc", "file")

LOGIN_XETA = re.compile(
    r"type=[\"']password|sign ?in|log ?in|giriş|войти|unauthorized|forbidden|"
    r"access denied|not found|does not exist|404|403|401|error", re.IGNORECASE)


def _url_ile(parcalar, params, param, deyer):
    yeni = {k: v[0] for k, v in params.items()}
    yeni[param] = str(deyer)
    return urlunparse(parcalar._replace(query=urlencode(yeni)))


def _getir(url):
    r = http_client.al(url, timeout=10)
    if not r:
        return None
    return (r.status_code, len(r.content or b""), r.text or "")


def _oxsar(a, b):
    if a == 0 or b == 0:
        return a == b
    return 0.5 <= a / b <= 2.0


def yoxla(parametrli_url, hesabat, auth_edildi=False):
    gorulmus = set()
    for url in parametrli_url:
        parcalar = urlparse(url)
        params = parse_qs(parcalar.query)
        for p in params:
            deyer = params[p][0]
            if not deyer.isdigit():
                continue
            n = int(deyer)
            if n <= 0 or n > 10**9:
                continue
            adbenzer = p.lower() in ID_ADLAR

            orig = _getir(url)
            if not orig or orig[0] != 200 or orig[1] < 80:
                continue
            inv = _getir(_url_ile(parcalar, params, p, n + 987654))
            inv_uz = inv[1] if inv else -1

            for delta in (1, -1, 2, -2, 3):
                m = n + delta
                if m <= 0 or m == n:
                    continue
                turl = _url_ile(parcalar, params, p, m)
                r = _getir(turl)
                if not r or r[0] != 200 or r[1] < 80:
                    continue
                st, uz, metn = r
                if LOGIN_XETA.search(metn[:3000]):
                    continue
                # "tapılmadı" bazası ilə eyni ölçü -> real obyekt deyil
                if inv_uz > 0 and abs(uz - inv_uz) <= max(40, inv_uz * 0.05):
                    continue
                # orijinalla oxşar struktur, fərqli məzmun -> BAŞQA obyekt açıldı
                if _oxsar(uz, orig[1]) and metn[:2500] != orig[2][:2500]:
                    if p in gorulmus:
                        break
                    gorulmus.add(p)
                    if auth_edildi:
                        c = "kritik" if (adbenzer and p.lower() in PRIVAT) else "yuksek"
                    else:
                        c = "yuksek" if (adbenzer and p.lower() in PRIVAT) else "orta"
                    hesabat.elave_et(c, "idor", turl, param=p, id1=str(n), id2=str(m))
                    break
