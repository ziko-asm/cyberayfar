"""
MODUL: KÖHNƏ JS KİTABXANALARI
=============================
Səhifədəki JavaScript kitabxanalarının versiyasını tapır və məlum
təhlükəli (CVE-li) versiyaları işarələyir.

Zərərsiz: yalnız HTML-dəki <script src> ünvanlarını oxuyur.
"""

import re
from core import http_client

# (kitabxana, regex[versiya tutur], təhlükəsiz_min_versiya, qeyd)
QAYDALAR = [
    ("jQuery", r"jquery[-.]?(\d+\.\d+\.\d+)", (3, 5, 0),
     "Köhnə jQuery-də XSS (CVE-2020-11022/23)"),
    ("Bootstrap", r"bootstrap[-.]?(\d+\.\d+\.\d+)", (4, 3, 1),
     "Köhnə Bootstrap-da XSS zəiflikləri"),
    ("AngularJS", r"angular[-.]?(\d+\.\d+\.\d+)", (1, 8, 0),
     "AngularJS 1.x artıq dəstəklənmir (təhlükəsizlik yeniləməsi yoxdur)"),
    ("Lodash", r"lodash[-.]?(\d+\.\d+\.\d+)", (4, 17, 21),
     "Köhnə Lodash-da prototype pollution (CVE-2019-10744)"),
    ("Moment.js", r"moment[-.]?(\d+\.\d+\.\d+)", (2, 29, 4),
     "Köhnə Moment.js-də ReDoS/path traversal"),
]


def _versiya_kohnedir(tapilan, minimum):
    try:
        t = tuple(int(x) for x in tapilan.split("."))
        return t < minimum
    except ValueError:
        return False


def yoxla(bas_url, hesabat, timeout=8):
    cavab = http_client.al(bas_url, timeout=timeout)
    if not cavab:
        return
    html = cavab.text or ""
    for ad, naxis, minimum, qeyd in QAYDALAR:
        m = re.search(naxis, html, re.IGNORECASE)
        if m and _versiya_kohnedir(m.group(1), minimum):
            hesabat.elave_et("orta", "kohne_js", bas_url,
                             kitabxana=ad, versiya=m.group(1),
                             min=".".join(map(str, minimum)), qeyd=qeyd)
