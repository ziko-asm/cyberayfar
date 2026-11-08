"""
MODUL: HOST HEADER INJECTION
============================
Server "Host" başlığını yoxlamadan istifadə edirsə (məs: parol-sıfırlama
linkində), hücumçu saxta domen yeridib istifadəçini aldada bilər.

Zərərsiz: saxta Host başlığı ilə sorğu göndərir, cavabda (və ya
yönləndirmədə) həmin saxta domenin əks olunub-olunmadığına baxır.
"""

from core import http_client

SAXTA = "cyberayfar-evil-host.example"


def yoxla(bas_url, hesabat, timeout=8):
    cavab = http_client.al(bas_url, timeout=timeout, redirect=False,
                           headers={"Host": SAXTA,
                                    "X-Forwarded-Host": SAXTA})
    if not cavab:
        return
    yer = cavab.headers.get("Location", "")
    # Yönləndirmədə və ya cavab gövdəsində saxta host əks olunubsa = zəiflik
    if SAXTA in yer:
        hesabat.elave_et("orta", "host_header", bas_url)
    elif SAXTA in (cavab.text or "")[:20000]:
        hesabat.elave_et("asagi", "host_header", bas_url)
