"""
MODUL: STORED (Persistent) XSS
==============================
Ən təhlükəli XSS: input saytda SAXLANILIR və sonra başqa səhifədə
(məs: şərh, profil, mesaj) bütün ziyarətçilərə göstərilir.

NECƏ (zərərsiz):
  1) Hər formaya unikal nişan + HTML təhlükəli simvollar göndərir (saxlanılsın).
  2) Bütün səhifələri yenidən çəkir; nişan HƏR HANSI səhifədə təmizlənmədən
     görünərsə -> Stored XSS (başqa səhifədə qalıb).
Real zərərli skript işlətmir — yalnız simvolların filtrlənib-filtrlənmədiyini
yoxlayır.
"""

import secrets
from core import http_client


def yoxla(formalar, sehifeler, hesabat, timeout=8):
    if not formalar:
        return
    nisan_map = {}   # token -> menbe_sehife
    for form in formalar:
        if not form["inputlar"]:
            continue
        token = "cystd" + secrets.token_hex(4)
        canary = f'{token}<x>"'
        data = {inp["ad"]: canary for inp in form["inputlar"]}
        metod = form["metod"]
        kw = {"data": data} if metod == "post" else {"params": data}
        http_client.al(form["hereket"], metod=metod.upper(), timeout=timeout, **kw)
        nisan_map[token] = form["menbe_sehife"]

    if not nisan_map:
        return

    # Bütün səhifələri + forma mənbələrini yenidən çək, nişanı axtar
    yoxlanacaq = set(sehifeler or []) | {f["menbe_sehife"] for f in formalar} \
        | {f["hereket"] for f in formalar}
    tapildi = set()
    for url in yoxlanacaq:
        cavab = http_client.al(url, timeout=timeout)
        if not cavab:
            continue
        metn = cavab.text or ""
        for token, menbe in nisan_map.items():
            if token in tapildi:
                continue
            # nişan + təmizlənməmiş <x> -> saxlanılıb və escape olunmayıb
            if f"{token}<x>" in metn:
                tapildi.add(token)
                hesabat.elave_et("kritik", "stored_xss", url, menbe=menbe)
