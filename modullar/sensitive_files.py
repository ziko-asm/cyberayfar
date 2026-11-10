"""
MODUL: HƏSSAS FAYL DETEKTORU — paralel + yalançı-müsbət qoruması
================================================================
Açıq qalan həssas faylları paralel yoxlayır (sürətli).
Zərərsiz: yalnız faylın mövcudluğunu soruşur.

YALANÇI MÜSBƏT QORUMASI (vacib!):
  SPA hostinqləri (React/Vue) HƏR yola 200 + eyni index.html qaytarır.
  Yalnız status koduna baxsaq, olmayan `.env`, `id_rsa` kimi faylları
  "kritik açıq" kimi göstərərik. Ona görə:
    1) Mövcud olmayan təsadüfi yolun cavabı "baza" kimi götürülür;
       bazaya bənzəyən cavab = fayl yoxdur.
    2) Hər fayl üçün MƏZMUN imzası yoxlanılır (məs. `.git/config`-də
       `[core]`, `.env`-də `AÇAR=dəyər`). HTML səhifəsi fayl sayılmır.
"""

import re
import secrets
from core import http_client

# (yol, ciddilik, məzmun imzası — None isə yalnız "HTML deyil" şərti)
HEDEF_FAYLLAR = [
    (".git/config", "kritik", r"\[(core|remote|branch)"),
    (".git/HEAD", "kritik", r"^(ref: refs/|[0-9a-f]{40})"),
    (".env", "kritik", r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*="),
    (".env.local", "kritik", r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*="),
    (".env.production", "kritik", r"(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*="),
    ("config.php.bak", "yuksek", r"<\?php|\$[A-Za-z_]+\s*="),
    ("config.bak", "yuksek", None),
    ("backup.zip", "yuksek", r"^PK\x03\x04"),
    ("backup.sql", "kritik", r"(?i)CREATE TABLE|INSERT INTO|-- .*dump"),
    ("dump.sql", "kritik", r"(?i)CREATE TABLE|INSERT INTO|-- .*dump"),
    ("db.sqlite", "kritik", r"^SQLite format 3"),
    (".DS_Store", "asagi", r"Bud1"),
    ("phpinfo.php", "orta", r"(?i)phpinfo\(\)|PHP Version"),
    ("info.php", "orta", r"(?i)phpinfo\(\)|PHP Version"),
    (".svn/entries", "yuksek", r"^\d+\s|svn"),
    (".htpasswd", "kritik", r"(?m)^[^:\s<]+:[^\s<]+$"),
    ("wp-config.php.bak", "kritik", r"DB_PASSWORD|<\?php"),
    ("web.config", "orta", r"(?i)<configuration"),
    ("docker-compose.yml", "orta", r"(?m)^\s*(services|version)\s*:"),
    ("Dockerfile", "asagi", r"(?m)^\s*FROM\s+\S+"),
    ("package.json", "asagi", r'"(name|dependencies|scripts)"\s*:'),
    ("composer.json", "asagi", r'"(name|require)"\s*:'),
    (".vscode/settings.json", "asagi", r"^\s*\{"),
    ("id_rsa", "kritik", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ("robots.txt", "info", r"(?i)user-agent\s*:"),
    (".well-known/security.txt", "info", r"(?i)contact\s*:"),
]

_HTML = re.compile(r"^\s*(<!doctype html|<html|<head|<body)", re.IGNORECASE)


def _metn(cavab):
    try:
        return (cavab.content or b"")[:4000].decode("latin-1")
    except Exception:
        return ""


def _real_fayldir(cavab, imza, baza):
    """Cavab həqiqətən həmin fayldırmı? (status + baza + məzmun imzası)"""
    if cavab is None or cavab.status_code != 200 or not cavab.content:
        return False
    metn = _metn(cavab)
    # Catch-all: mövcud olmayan yolla eyni cavab -> fayl yoxdur
    if baza is not None and baza.status_code == 200 and \
            abs(len(cavab.content) - len(baza.content or b"")) <= 32:
        return False
    if _HTML.match(metn) and "text/html" in cavab.headers.get("Content-Type", "").lower():
        # HTML səhifəsi yalnız imzası açıq-aşkar uyğun gələndə fayl sayılır (phpinfo)
        return bool(imza and "(?i)phpinfo" in imza and re.search(imza, metn))
    if imza is None:
        return True
    return bool(re.search(imza, metn))


def yoxla(bas_url, hesabat, timeout=8):
    bas = bas_url.rstrip("/")
    baza = http_client.al(f"{bas}/{secrets.token_hex(8)}.txt", timeout=timeout)
    url_map = {f"{bas}/{yol}": (yol, ciddilik, imza)
               for yol, ciddilik, imza in HEDEF_FAYLLAR}
    cavablar = http_client.paralel_al(list(url_map), timeout=timeout)

    for url, cavab in cavablar.items():
        yol, ciddilik, imza = url_map[url]
        if _real_fayldir(cavab, imza, baza):
            kod = "robots" if yol == "robots.txt" else "hessas_fayl"
            hesabat.elave_et(ciddilik, kod, url, yol=yol)
