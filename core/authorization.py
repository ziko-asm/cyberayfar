"""
İCAZƏ QAPISI (Authorization Gate)
=================================
Bu modul məhsulun ən vacib hissəsidir. Qanuni skanerləri qanunsuz
"hücum silahlarından" ayıran məhz budur: skan yalnız SAHİBLİYİ
TƏSDİQLƏNMİŞ domenlərdə işləyir.

İki təsdiq üsulu:
  1) FAYL üsulu: hədəf saytın kökündə xüsusi token faylı olmalıdır
     -> https://site.com/.well-known/skaner-verify.txt  (içində token)
  2) DNS üsulu: domenin TXT qeydində token olmalıdır
     -> "skaner-verify=<token>"

Müştəri bu tokeni yerləşdirə bilirsə, deməli saytın sahibidir.
Bu, sənin SaytYoxla saytındakı "sahib təsdiqindən sonra" məntiqidir.
"""

import hashlib
import requests
import dns.resolver


class IcazeXetasi(Exception):
    """Sahiblik təsdiqlənmədikdə atılan xəta."""
    pass


def token_yarat(domen: str, gizli_acar: str) -> str:
    """
    Hər domen üçün unikal, təxmin edilə bilməyən token yaradır.
    gizli_acar yalnız səndə (serverində) saxlanılır -> müştəri
    tokeni özü uydura bilməz.
    """
    xam = f"{domen.lower()}:{gizli_acar}".encode()
    return "skaner-" + hashlib.sha256(xam).hexdigest()[:32]


def fayl_ile_yoxla(domen: str, gozlenilen_token: str, timeout=10) -> bool:
    """Üsul 1: /.well-known/skaner-verify.txt faylını yoxlayır."""
    for sxem in ("https", "http"):
        url = f"{sxem}://{domen}/.well-known/skaner-verify.txt"
        try:
            cavab = requests.get(url, timeout=timeout)
            if cavab.status_code == 200 and gozlenilen_token in cavab.text:
                return True
        except requests.RequestException:
            continue
    return False


def dns_ile_yoxla(domen: str, gozlenilen_token: str) -> bool:
    """Üsul 2: domenin TXT qeydlərində tokeni axtarır."""
    try:
        cavablar = dns.resolver.resolve(domen, "TXT")
        for qeyd in cavablar:
            if gozlenilen_token in qeyd.to_text():
                return True
    except Exception:
        return False
    return False


def icazeni_tesdiqle(domen: str, gizli_acar: str, test_rejimi=False,
                     allowlist=()) -> str:
    """
    Əsas giriş nöqtəsi. Sahiblik təsdiqlənməsə IcazeXetasi atır və
    skan ƏSLA başlamır.

    test_rejimi=True: yalnız ÖZ saytlarını sınamaq üçün (lokal geliştirmə).
    allowlist: operatorun öz domenləri — bunlar təsdiq tələb etmir (canlı demo).
    Real müştəri domenləri fayl/DNS token ilə təsdiqlənməlidir.
    """
    domen = domen.replace("https://", "").replace("http://", "").strip("/")
    token = token_yarat(domen, gizli_acar)

    if test_rejimi:
        print(f"  [TEST REJİMİ] İcazə yoxlaması atlandı: {domen}")
        return token

    # Operatorun öz domenləri (allowlist) — təsdiq lazım deyil
    if domen in allowlist:
        return token

    if fayl_ile_yoxla(domen, token):
        print(f"  [✓] Sahiblik FAYL ilə təsdiqləndi: {domen}")
        return token
    if dns_ile_yoxla(domen, token):
        print(f"  [✓] Sahiblik DNS ilə təsdiqləndi: {domen}")
        return token

    raise IcazeXetasi(
        f"\n  [✗] '{domen}' üçün sahiblik TƏSDİQLƏNMƏDİ — skan dayandırıldı.\n"
        f"  Skan etmək üçün müştəri bunlardan birini etməlidir:\n"
        f"    • Fayl: https://{domen}/.well-known/skaner-verify.txt\n"
        f"      içinə yaz: {token}\n"
        f"    • Və ya DNS TXT qeydi: skaner-verify={token}\n"
    )
