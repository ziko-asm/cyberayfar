"""
MODUL: CORS SƏHV-KONFİQURASİYASI
================================
Saytın Access-Control-Allow-Origin başlığını yoxlayır. Əgər sayt
İSTƏNİLƏN mənbəyə (origin) icazə verirsə + credentials açıqdırsa,
hücumçu istifadəçi məlumatını oğurlaya bilər.

Zərərsiz: sadəcə saxta "Origin" başlığı ilə sorğu göndərib cavaba baxır.
"""

from core import http_client

TEST_ORIGIN = "https://cyberayfar-evil-test.example"


def yoxla(bas_url, hesabat, timeout=8):
    cavab = http_client.al(bas_url, timeout=timeout,
                           headers={"Origin": TEST_ORIGIN})
    if not cavab:
        return
    acao = cavab.headers.get("Access-Control-Allow-Origin", "")
    acac = cavab.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*" and acac == "true":
        hesabat.elave_et("yuksek", "cors_acar", bas_url)
    elif acao == TEST_ORIGIN:
        # Saytın bizim saxta origin-i əks etdirməsi = təhlükəli
        ciddilik = "yuksek" if acac == "true" else "orta"
        hesabat.elave_et(ciddilik, "cors_reflect", bas_url)
