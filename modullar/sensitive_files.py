"""
MODUL: HƏSSAS FAYL DETEKTORU
============================
Çox saytda təsadüfən açıq qalan həssas fayllar olur:
.git qovluğu (bütün mənbə kodu!), .env (parollar!), backup-lar və s.
Bu modul həmin faylların açıq olub-olmadığını yoxlayır.

Bu "hücumdur" amma ZƏRƏRSİZDİR: sadəcə faylın mövcudluğunu soruşur,
heç nə silmir/dəyişmir.
"""

import requests

# Yoxlanılacaq təhlükəli yollar və hər birinin ciddiliyi
HEDEF_FAYLLAR = [
    (".git/config", "kritik", "Bütün mənbə kodu oğurlana bilər"),
    (".env", "kritik", "Parollar, API açarları, DB məlumatı sızır"),
    (".env.local", "kritik", "Lokal mühit sirləri sızır"),
    ("config.php.bak", "yuksek", "Konfiqurasiya backup-ı açıqdır"),
    ("backup.zip", "yuksek", "Sayt backup-ı yüklənə bilər"),
    ("backup.sql", "kritik", "Verilənlər bazası dump-ı açıqdır"),
    (".DS_Store", "asagi", "Qovluq strukturu sızır (macOS)"),
    ("phpinfo.php", "orta", "Server konfiqurasiyası tam açılır"),
    (".svn/entries", "yuksek", "SVN mənbə kodu sızır"),
    ("wp-config.php.bak", "kritik", "WordPress DB parolu açıqdır"),
    ("robots.txt", "info", "Gizli yollar robots.txt-də görünə bilər"),
]


def yoxla(bas_url: str, hesabat, timeout=8):
    bas = bas_url.rstrip("/")
    for yol, ciddilik, risk in HEDEF_FAYLLAR:
        url = f"{bas}/{yol}"
        try:
            cavab = requests.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException:
            continue
        # 200 + boş olmayan cavab = fayl, çox güman, açıqdır
        if cavab.status_code == 200 and len(cavab.content) > 0:
            kod = "robots" if yol == "robots.txt" else "hessas_fayl"
            hesabat.elave_et(ciddilik, kod, url, yol=yol)
