"""
MODUL: GİZLİ YOLLAR / ADMIN PANELLƏRİ
=====================================
Ümumi həssas yolları yoxlayır (admin, phpmyadmin, swagger...).

YALANÇI MÜSBƏT QORUMASI (vacib!):
  • Əvvəlcə 2 TƏSADÜFİ yolun cavabını "baseline" kimi götürür.
  • Baseline 200-dirsə -> sayt hər yola 200 verir (SPA catch-all) -> ATLA.
  • Baseline 401/403/429-dursa -> sayt hər şeyi bloklayır (rate-limit/WAF)
    -> ATLA (bunlar əsl zəiflik deyil).
  • Yalnız baseline-dan FƏRQLİ, 200 qaytaran və məzmunu fərqli yolları
    "real açıq yol" kimi göstərir. 403/401 ARTIQ işarələnmir (etibarsız).
"""

import secrets
from core import http_client

YOLLAR = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "dashboard", "api", "api-docs", "swagger",
    "swagger-ui.html", "actuator", "actuator/health", "server-status",
    "manager/html", "console", "adminer.php", "config", "debug",
]


def yoxla(bas_url, hesabat, timeout=8):
    bas = bas_url.rstrip("/")
    # İki təsadüfi baseline (mövcud olmayan yollar)
    b1 = http_client.al(f"{bas}/{secrets.token_hex(10)}zz", timeout=timeout)
    b2 = http_client.al(f"{bas}/{secrets.token_hex(10)}qq", timeout=timeout)
    if b1 is None or b2 is None:
        return
    # Catch-all (hər yola 200) və ya sayt-geneli bloklama -> etibarsız, atla
    if 200 in (b1.status_code, b2.status_code):
        return
    if b1.status_code in (401, 403, 429) or b2.status_code in (401, 403, 429):
        return
    baza_uzunluq = len(b1.content or b"")

    url_map = {f"{bas}/{y}": y for y in YOLLAR}
    cavablar = http_client.paralel_al(list(url_map), timeout=timeout)
    for url, cavab in cavablar.items():
        if cavab is None:
            continue
        yol = url_map[url]
        uz = len(cavab.content or b"")
        # Yalnız 200 + baseline-dan ƏHƏMİYYƏTLİ dərəcədə fərqli məzmun = real yol
        if cavab.status_code == 200 and abs(uz - baza_uzunluq) > 64:
            hesabat.elave_et("orta", "gizli_yol", url, yol=yol, status="açıq")
