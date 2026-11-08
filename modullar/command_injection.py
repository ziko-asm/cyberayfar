"""
MODUL: COMMAND INJECTION (vaxt-əsaslı)
======================================
Saytın inputu birbaşa OS əmrinə qoşması = hücumçu serverdə əmr işlədə bilər.

NECƏ (zərərsiz, vaxt-əsaslı): inputa "gözlə" əmri (sleep) qoyuruq.
Əgər cavab məhz o qədər gec gəlirsə, deməli əmr işləyir = zəiflik var.
Heç nə silmir/pozmur — yalnız serverə "bir az gözlə" deyir.
"""

import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client

GOZLEME = 5   # saniyə
PAYLOADLAR = [f";sleep {GOZLEME}", f"| sleep {GOZLEME}",
              f"& sleep {GOZLEME}", f"`sleep {GOZLEME}`",
              f"$(sleep {GOZLEME})"]


def _test_et(url, param, parcalar, parametrler, hesabat, timeout):
    # Baza vaxtını ölç
    t0 = time.time()
    http_client.al(url, timeout=timeout)
    baza = time.time() - t0

    for p in PAYLOADLAR:
        yeni = {k: v[0] for k, v in parametrler.items()}
        yeni[param] = yeni[param] + p
        test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
        t0 = time.time()
        http_client.al(test_url, timeout=GOZLEME + timeout + 4)
        kecen = time.time() - t0
        # Cavab baza + gözləmə qədər gecikdisə = əmr işlədi
        if kecen >= GOZLEME + max(baza, 0) - 1.5:
            hesabat.elave_et("kritik", "cmd_injection", test_url, param=param)
            return True
    return False


def yoxla(parametrli_url, hesabat, timeout=8):
    for url in parametrli_url:
        parcalar = urlparse(url)
        parametrler = parse_qs(parcalar.query)
        for param in parametrler:
            if _test_et(url, param, parcalar, parametrler, hesabat, timeout):
                break
