"""
MODUL: SUBDOMAIN ENUMERATION (hücum səthi)
==========================================
Domenin ümumi subdomenlərini tapır (api, admin, dev, staging...).
Hər aşkar subdomen hücum üçün əlavə qapıdır. Yalnız DNS oxuyur (zərərsiz).
Yalnız xüsusi (apex) domenlərdə işləyir — platforma subdomenlərində yox.
"""

import dns.resolver
from concurrent.futures import ThreadPoolExecutor

PREFIKSLER = ("www", "api", "admin", "dev", "staging", "test", "mail",
              "blog", "shop", "app", "portal", "vpn", "cpanel", "webmail",
              "m", "mobile", "dashboard", "beta", "demo", "git", "ftp",
              "ns1", "smtp", "secure", "old")


def _var(ad):
    try:
        dns.resolver.resolve(ad, "A")
        return ad
    except Exception:
        return None


def yoxla(domen, hesabat):
    domen = domen.split(":")[0]
    adlar = [f"{p}.{domen}" for p in PREFIKSLER]
    tapilan = []
    with ThreadPoolExecutor(max_workers=10) as ex:
        for netice in ex.map(_var, adlar):
            if netice:
                tapilan.append(netice)
    if tapilan:
        hesabat.elave_et("info", "subdomainler", domen,
                         say=len(tapilan), siyahi=", ".join(tapilan[:14]))
