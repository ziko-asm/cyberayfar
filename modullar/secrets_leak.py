"""
MODUL: SİRR / API-AÇAR SIZMASI
==============================
Saytın HTML və JS fayllarında təsadüfən açıq qalmış sirləri tapır:
AWS açarları, Stripe/Google/GitHub tokenləri, private key-lər və s.
Bu, ən təhlükəli sızmalardandır. Zərərsiz: yalnız faylları oxuyur.
"""

import re
from urllib.parse import urljoin, urlparse
from core import http_client

# (ad, regex, ciddilik) — aşağı yalançı-müsbətli, məşhur formatlar
NAXISLAR = [
    ("Private Key", r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "kritik"),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}", "kritik"),
    ("Stripe Secret Key", r"sk_live_[0-9a-zA-Z]{24,}", "kritik"),
    ("GitHub Token", r"gh[pousr]_[0-9A-Za-z]{36}", "kritik"),
    ("Slack Token", r"xox[baprs]-[0-9A-Za-z-]{10,48}", "kritik"),
    ("SendGrid API Key", r"SG\.[\w\-]{22}\.[\w\-]{43}", "kritik"),
    ("Mailgun Key", r"key-[0-9a-f]{32}", "kritik"),
    ("Google API Key", r"AIza[0-9A-Za-z_\-]{35}", "orta"),
    ("Twilio SID", r"AC[0-9a-fA-F]{32}", "asagi"),
    ("Stripe Publishable Key", r"pk_live_[0-9a-zA-Z]{24,}", "asagi"),
]
DERLENMIS = [(ad, re.compile(nx), c) for ad, nx, c in NAXISLAR]


def _tap(metn, yer, hesabat, gorulmus):
    for ad, nx, ciddilik in DERLENMIS:
        if nx.search(metn or ""):
            acar = (ad, yer)
            if acar not in gorulmus:
                gorulmus.add(acar)
                hesabat.elave_et(ciddilik, "sirr_sizma", yer, tip=ad)


def yoxla(bas_url, hesabat, timeout=8):
    gorulmus = set()
    cavab = http_client.al(bas_url, timeout=timeout)
    if not cavab:
        return
    html = cavab.text or ""
    _tap(html, bas_url, hesabat, gorulmus)

    # JS fayllarını topla (maks 15) və skan et
    js_adresler = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)
    tam = []
    for s in js_adresler[:15]:
        tam.append(urljoin(bas_url, s))
    cavablar = http_client.paralel_al(tam, timeout=timeout)
    for url, c in cavablar.items():
        if c is not None and c.status_code == 200:
            _tap(c.text, url, hesabat, gorulmus)
