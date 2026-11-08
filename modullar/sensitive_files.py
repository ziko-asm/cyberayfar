"""
MODUL: HƏSSAS FAYL DETEKTORU — paralel + genişləndirilmiş
=========================================================
Açıq qalan həssas faylları paralel yoxlayır (sürətli).
Zərərsiz: yalnız faylın mövcudluğunu soruşur.
"""

from urllib.parse import urlparse
from core import http_client

HEDEF_FAYLLAR = [
    (".git/config", "kritik"), (".git/HEAD", "kritik"),
    (".env", "kritik"), (".env.local", "kritik"), (".env.production", "kritik"),
    ("config.php.bak", "yuksek"), ("config.bak", "yuksek"),
    ("backup.zip", "yuksek"), ("backup.sql", "kritik"), ("dump.sql", "kritik"),
    ("db.sqlite", "kritik"), (".DS_Store", "asagi"),
    ("phpinfo.php", "orta"), ("info.php", "orta"),
    (".svn/entries", "yuksek"), (".htpasswd", "kritik"),
    ("wp-config.php.bak", "kritik"), ("web.config", "orta"),
    ("docker-compose.yml", "orta"), ("Dockerfile", "asagi"),
    ("package.json", "asagi"), ("composer.json", "asagi"),
    (".vscode/settings.json", "asagi"), ("id_rsa", "kritik"),
    ("robots.txt", "info"), (".well-known/security.txt", "info"),
]


def yoxla(bas_url, hesabat, timeout=8):
    bas = bas_url.rstrip("/")
    url_map = {f"{bas}/{yol}": (yol, ciddilik) for yol, ciddilik in HEDEF_FAYLLAR}
    cavablar = http_client.paralel_al(list(url_map), timeout=timeout)

    for url, cavab in cavablar.items():
        yol, ciddilik = url_map[url]
        if cavab is not None and cavab.status_code == 200 and len(cavab.content) > 0:
            kod = "robots" if yol == "robots.txt" else "hessas_fayl"
            hesabat.elave_et(ciddilik, kod, url, yol=yol)
