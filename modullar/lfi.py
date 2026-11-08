"""
MODUL: LFI (Local File Inclusion) / Path Traversal
==================================================
Saytın ?file=, ?page= kimi parametrlərlə server fayllarını oxumağa
icazə verməsi = hücumçu /etc/passwd kimi həssas faylları oxuya bilər.

Zərərsiz: parametrə "../../../../etc/passwd" qoyub, cavabda Linux
parol faylının imzasını (root:x:) axtarır. Heç nə dəyişmir.
"""

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client

ƏLAMƏTLƏR = ("file", "page", "path", "doc", "document", "folder",
             "include", "inc", "template", "view", "load")
PAYLOADLAR = [
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
]
# Linux parol faylının imzası + Windows
IMZA = re.compile(r"root:.*:0:0:|\[fonts\]|\[extensions\]", re.IGNORECASE)


def yoxla(parametrli_url, hesabat, timeout=8):
    for url in parametrli_url:
        parcalar = urlparse(url)
        parametrler = parse_qs(parcalar.query)
        for param in parametrler:
            if param.lower() not in ƏLAMƏTLƏR:
                continue
            for p in PAYLOADLAR:
                yeni = {k: v[0] for k, v in parametrler.items()}
                yeni[param] = p
                test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
                cavab = http_client.al(test_url, timeout=timeout)
                if cavab and IMZA.search(cavab.text or ""):
                    hesabat.elave_et("kritik", "lfi", test_url, param=param)
                    break
            else:
                continue
            break
