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

import re
import socket
import hashlib
import ipaddress
import requests
import dns.resolver


class IcazeXetasi(Exception):
    """Skan başlamazdan əvvəl atılan xəta.

    kod:  "sahiblik"  — sahiblik təsdiqlənmədi (domen + token doludur)
          "etibarsiz" — ünvan yanlışdır və ya daxili/qorunan ünvandır
          "tapilmadi" — domen DNS-də tapılmadı
    Mətn (str) CLI üçündür; veb interfeys `kod`-a görə öz dilində göstərir.
    """

    def __init__(self, mesaj, kod="sahiblik", domen="", token=""):
        super().__init__(mesaj)
        self.kod = kod
        self.domen = domen
        self.token = token


_HOST_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
_QADAGAN_SONLUQ = (".localhost", ".local", ".internal", ".lan", ".home", ".corp")


def hedefi_yoxla(domen: str) -> None:
    """Sahiblik sorğusundan ƏVVƏL ünvanı yoxlayır (SSRF qoruması).

    Yalnız açıq internetdəki adi domen adlarına icazə verir: IP ünvanı,
    localhost, daxili şəbəkə adları və daxili IP-yə açılan domenlər rədd
    edilir — skaner serverin öz daxili şəbəkəsinə sorğu göndərməsin.
    """
    host, _, port = domen.partition(":")
    host = host.strip().lower().rstrip(".")
    if port and not (port.isdigit() and 0 < int(port) < 65536):
        raise IcazeXetasi(f"Yanlış ünvan: {domen}", kod="etibarsiz", domen=domen)
    if not _HOST_RE.match(host) or host.endswith(_QADAGAN_SONLUQ):
        raise IcazeXetasi(f"Yanlış və ya daxili ünvan: {domen}",
                          kod="etibarsiz", domen=domen)
    try:
        unvanlar = {i[4][0] for i in socket.getaddrinfo(host, None)}
    except (socket.gaierror, UnicodeError):
        raise IcazeXetasi(f"Domen tapılmadı: {domen}", kod="tapilmadi", domen=domen)
    for u in unvanlar:
        ip = ipaddress.ip_address(u.split("%")[0])
        if not ip.is_global:
            raise IcazeXetasi(f"Daxili ünvana skan qadağandır: {domen}",
                              kod="etibarsiz", domen=domen)


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

    # Kənar sorğudan əvvəl: yalnız açıq internetdəki adi domenlər
    hedefi_yoxla(domen)

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
        f"    • Və ya DNS TXT qeydi: skaner-verify={token}\n",
        kod="sahiblik", domen=domen, token=token,
    )
