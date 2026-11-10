"""
MODUL: MƏLUMAT SIZMASI (passiv)
===============================
Gəzilən səhifələrin məzmununu OXUYUR (heç bir test yükü göndərmir) və
iki geniş yayılmış konfiqurasiya səhvini axtarır:

  1) Açıq qovluq siyahısı ("Index of /...") — serverdəki faylların adı,
     ölçüsü və tarixi hər kəsə görünür.
  2) Debug rejimi / stack trace — xəta səhifəsində daxili fayl yolları,
     kod sətirləri və kitabxana versiyaları görünür.

Yalançı müsbət qoruması: imza HTML teqləri çıxarılmış MƏTNDƏ deyil,
strukturda axtarılır (başlıq + siyahı / iz + fayl yolu birlikdə).
"""

import re
from core import http_client

MAKS_SEHIFE = 40

_QOVLUQ = re.compile(
    r"<title>\s*Index of /[^<]*</title>|<h1>\s*Index of /[^<]*</h1>|"
    r"<title>\s*Directory listing for /[^<]*</title>", re.IGNORECASE)
_QOVLUQ_LINK = re.compile(r'<a href="\.\./?">', re.IGNORECASE)

# (ad, imza) — hər biri iz + fayl yolu/sətir nömrəsi tələb edir
_DEBUG = [
    ("Python", re.compile(r"Traceback \(most recent call last\):\s+File &quot;|"
                          r"Traceback \(most recent call last\):\s+File \"")),
    ("PHP", re.compile(r"<b>(Fatal error|Warning|Parse error)</b>:.{0,300} on line <b>\d+</b>", re.S)),
    ("Java", re.compile(r"(Exception|Error)[^\n<]{0,200}\s+at [\w.$]+\([\w$]+\.java:\d+\)")),
    (".NET", re.compile(r"Server Error in '.{0,80}' Application|\[\w+Exception: .{0,200}\]\s+\w[\w.]+\(")),
    ("Node.js", re.compile(r"\bat [\w.<>$ ]+ \((?:/|[A-Z]:\\)[^\s)]+\.js:\d+:\d+\)")),
    ("Django", re.compile(r"You're seeing this error because you have <code>DEBUG = True</code>")),
    ("Laravel", re.compile(r"Whoops, looks like something went wrong|Illuminate\\[\w\\]+Exception")),
]


def yoxla(sehifeler, hesabat, timeout=8):
    qovluq_tapildi = set()
    debug_tapildi = set()
    for url in list(dict.fromkeys(sehifeler or []))[:MAKS_SEHIFE]:
        cavab = http_client.al(url, timeout=timeout)
        if cavab is None or "html" not in cavab.headers.get("Content-Type", "").lower():
            continue
        metn = (cavab.text or "")[:200000]

        if url not in qovluq_tapildi and _QOVLUQ.search(metn) and _QOVLUQ_LINK.search(metn):
            qovluq_tapildi.add(url)
            hesabat.elave_et("orta", "qovluq_siyahisi", url)

        for ad, imza in _DEBUG:
            if ad not in debug_tapildi and imza.search(metn):
                debug_tapildi.add(ad)
                hesabat.elave_et("orta", "debug_sizma", url, texnologiya=ad)
