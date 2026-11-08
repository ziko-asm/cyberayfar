"""
MODUL: TƏHLÜKƏLİ HTTP METODLARI
===============================
Serverin PUT/DELETE/TRACE kimi təhlükəli metodlara icazə verməsi
risklidir (fayl yükləmə/silmə, XST). OPTIONS sorğusu ilə yoxlayır.
Zərərsiz: yalnız icazəli metodları soruşur.
"""

from core import http_client

TEHLUKELI = ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT")


def yoxla(bas_url, hesabat, timeout=8):
    cavab = http_client.al(bas_url, metod="OPTIONS", timeout=timeout)
    if not cavab:
        return
    allow = (cavab.headers.get("Allow", "") + "," +
             cavab.headers.get("Access-Control-Allow-Methods", "")).upper()
    tapilan = [m for m in TEHLUKELI if m in allow]
    if tapilan:
        hesabat.elave_et("orta", "tehlukeli_metod", bas_url,
                         metodlar=", ".join(tapilan))
