"""
MODUL: MIXED CONTENT
====================
HTTPS səhifənin HTTP (şifrəsiz) resurslar yükləməsi = təhlükəsizliyi
pozur, brauzer xəbərdarlıq verir. Zərərsiz: yalnız HTML-i oxuyur.
"""

import re
from core import http_client

NAXIS = re.compile(r'(?:src|href)\s*=\s*["\'](http://[^"\']+)["\']', re.IGNORECASE)


def yoxla(bas_url, hesabat, timeout=8):
    if not bas_url.startswith("https://"):
        return
    cavab = http_client.al(bas_url, timeout=timeout)
    if not cavab:
        return
    tapilan = set(NAXIS.findall(cavab.text or ""))
    # xmlns/schema kimi real-resurs olmayanları çıxar
    tapilan = {u for u in tapilan if "w3.org" not in u and "schema" not in u}
    if tapilan:
        hesabat.elave_et("orta", "mixed_content", bas_url, say=len(tapilan))
