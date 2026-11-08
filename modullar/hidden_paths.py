"""
MODUL: GİZLİ YOLLAR / ADMIN PANELLƏRİ
=====================================
Ümumi həssas yolları yoxlayır (admin, phpmyadmin, swagger...).
SPA saytlarda "hər yol 200 qaytarır" problemini həll etmək üçün
əvvəlcə təsadüfi yol yoxlanılır (catch-all aşkarlama) — yalançı
müsbətin qarşısını alır.
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
    # Catch-all yoxlaması: təsadüfi yol 200 qaytarırsa, sayt hər şeyə 200 verir
    random_yol = f"{bas}/{secrets.token_hex(8)}-yoxdur"
    baza = http_client.al(random_yol, timeout=timeout)
    if baza is not None and baza.status_code == 200:
        return  # catch-all sayt -> etibarlı yoxlama mümkün deyil

    url_map = {f"{bas}/{y}": y for y in YOLLAR}
    cavablar = http_client.paralel_al(list(url_map), timeout=timeout)
    for url, cavab in cavablar.items():
        if cavab is None:
            continue
        yol = url_map[url]
        if cavab.status_code == 200 and len(cavab.content) > 0:
            hesabat.elave_et("orta", "gizli_yol", url, yol=yol, status="açıq")
        elif cavab.status_code in (401, 403):
            hesabat.elave_et("asagi", "gizli_yol", url, yol=yol, status="qorunur")
