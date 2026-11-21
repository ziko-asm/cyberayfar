"""
HTTP CLIENT — paylaşılan sessiya + paralel sorğular + rate limit
================================================================
Mərhələ 3 (sürət): ThreadPool ilə onlarla sorğunu eyni anda göndərir,
amma semafor ilə "nəzakətli" qalır (saytı yükləmir).
"""

import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse

import requests
from urllib3.util import connection as _u3_connection
from urllib3.util.retry import Retry

ISTIFADECI_AGENT = "CyberAyfar-Scanner/2.0 (+authorized-security-test)"

# Böyük connection pool -> paralel sorğular üçün.
# Retry: hədəf server xəta/5xx-dən sonra bağlantını bağlayanda (çox olur,
# xüsusən SQL xətası -> 500), köhnəlmiş pooled bağlantını atıb YENİSİ ilə
# təkrar cəhd edir. Bu olmadan skaner məhz zəiflik göstərən cavabı (500)
# "cavab yoxdur" kimi itirirdi -> error-based aşkarlama pozulurdu.
_retry = Retry(total=3, connect=3, read=2, redirect=0, other=2,
               backoff_factor=0.3, raise_on_status=False,
               allowed_methods=None)   # bütün metodlar üçün (GET/POST/...)
_sessiya = requests.Session()
_sessiya.headers.update({"User-Agent": ISTIFADECI_AGENT})
_adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20,
                                         max_retries=_retry)
_sessiya.mount("http://", _adapter)
_sessiya.mount("https://", _adapter)

# Nəzakət: eyni anda maksimum sorğu sayı
PARALEL = 8
_semafor = threading.Semaphore(PARALEL)


# ---------------------------------------------------------------- SKAN SƏRHƏDİ
# Skaner hücum yüklərini YALNIZ sahibliyi təsdiqlənmiş hosta göndərməlidir.
# Əvvəllər redirect-lər avtomatik izlənirdi: təsdiqlənmiş pis.com bütün
# sorğuları qurban.az-a (və ya 169.254.169.254 kimi daxili ünvana) yönləndirə
# bilərdi və XSS/SQLi yükləri icazəsiz sayta gedərdi. İndi:
#   1) redirect-lər əl ilə izlənir, yalnız aktiv skanın hostuna (və www- variantına);
#   2) hər TCP bağlantısı açılmadan əvvəl IP yoxlanır və həmin IP-yə qoşulur
#      (DNS rebinding: təsdiqdən sonra domen daxili IP-yə dəyişə bilməz).
MAKS_YONLENDIRME = 10
_sərhəd_kilid = threading.Lock()
_aktiv_hostlar = {}          # host -> neçə aktiv skan
_daxiliye_icaze = False      # yalnız lokal test rejimi (lab 127.0.0.1-də işləyir)


class HedefXaricindedir(Exception):
    """Sorğu təsdiqlənmiş hostdan və ya açıq internetdən kənara çıxmaq istədi.
    OSError DEYİL: urllib3 onu tutub təkrar cəhd etməsin, dərhal dayansın."""


def _host_variantlari(host):
    host = (host or "").lower().rstrip(".")
    esas = host[4:] if host.startswith("www.") else host
    return {esas, "www." + esas}


def hedef_qur(host, daxiliye_icaze=False):
    """Skan başlayanda: bu hosta (və www-variantına) sorğu icazəlidir."""
    global _daxiliye_icaze
    ad = (urlparse("//" + host).hostname or "").lower()
    with _sərhəd_kilid:
        _aktiv_hostlar[ad] = _aktiv_hostlar.get(ad, 0) + 1
        _daxiliye_icaze = bool(daxiliye_icaze)


def hedef_sil(host):
    """Skan bitəndə hostu siyahıdan çıxarır."""
    global _daxiliye_icaze
    ad = (urlparse("//" + host).hostname or "").lower()
    with _sərhəd_kilid:
        say = _aktiv_hostlar.get(ad, 0) - 1
        if say > 0:
            _aktiv_hostlar[ad] = say
        else:
            _aktiv_hostlar.pop(ad, None)
        if not _aktiv_hostlar:
            _daxiliye_icaze = False


def host_icazelidir(url):
    """URL-in hostu aktiv skanlardan birinə aiddirmi? Heç bir skan aktiv deyilsə
    (məs. modul ayrıca test olunur) host məhdudiyyəti yoxdur — IP yoxlaması isə qalır."""
    ad = (urlparse(url).hostname or "").lower().rstrip(".")
    with _sərhəd_kilid:
        if not _aktiv_hostlar:
            return True
        return any(ad in _host_variantlari(h) for h in _aktiv_hostlar)


def ip_icazelidir(ip):
    if _daxiliye_icaze:
        return True
    unvan = ipaddress.ip_address(ip.split("%")[0])
    return unvan.is_global and not unvan.is_multicast


_asil_baglanti = _u3_connection.create_connection


def _yoxlanmis_baglanti(address, *args, **kwargs):
    """urllib3-ün hər TCP bağlantısı buradan keçir: adı bir dəfə həll edir,
    bütün ünvanlar açıq internetdədirsə, həmin IP-yə qoşulur."""
    host, port = address[0], address[1]
    if _daxiliye_icaze:
        return _asil_baglanti(address, *args, **kwargs)
    infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    ipler = [i[4][0] for i in infos]
    if not ipler or not all(ip_icazelidir(ip) for ip in ipler):
        raise HedefXaricindedir(f"Daxili ünvana qoşulma qadağandır: {host}")
    return _asil_baglanti((ipler[0], port), *args, **kwargs)


_u3_connection.create_connection = _yoxlanmis_baglanti


def cookie_qur(kukiler):
    """Headless login-dən gələn sessiya cookie-lərini paylaşılan sessiyaya qoyur
    ki, bütün modullar (requests) də GİRİŞ ETMİŞ vəziyyətdə işləsin."""
    for c in kukiler or []:
        try:
            _sessiya.cookies.set(c.get("name"), c.get("value"),
                                 domain=(c.get("domain") or "").lstrip("."),
                                 path=c.get("path", "/"))
        except Exception:
            pass


def cookie_sil():
    """Skan bitəndə giriş cookie-lərini sil — növbəti skana (başqa
    istifadəçiyə) keçməsin."""
    _sessiya.cookies.clear()


class Cavab:
    """requests.Response üçün nazik örtük.

    KRİTİK SƏBƏB: requests.Response.__bool__ -> response.ok, yəni 4xx/5xx
    cavab `if cavab:` yoxlamasında YALAN sayılır. Bu, error-based aşkarlamanı
    (SQLi/LFI və s. çox vaxt 500/404 ilə cavab verir) tamamilə pozurdu:
    modullar `if cavab and ...` yazır və 500 cavabı səssizcə atılırdı.
    Bu örtük cavab MÖVCUDDURSA həmişə doğrudur; bütün atributlar ötürülür.
    """
    __slots__ = ("_r",)

    def __init__(self, r):
        self._r = r

    def __getattr__(self, ad):
        return getattr(self._r, ad)

    def __bool__(self):
        return True

    def __repr__(self):
        return f"<Cavab {self._r.status_code} {self._r.url}>"


def _sorgu(metod, url, timeout, redirect, kw):
    """Redirect-ləri əl ilə izləyir: hər addımda hostu yoxlayır. Növbəti addım
    sərhəddən kənardırsa, izləmir və redirect cavabının özünü qaytarır."""
    if not host_icazelidir(url):
        raise HedefXaricindedir(f"Təsdiqlənməmiş host: {url}")
    tarixce = []
    while True:
        r = _sessiya.request(metod, url, timeout=timeout, allow_redirects=False, **kw)
        if not redirect or not r.is_redirect or len(tarixce) >= MAKS_YONLENDIRME:
            break
        novbeti = urljoin(r.url, r.headers.get("location", ""))
        if urlparse(novbeti).scheme not in ("http", "https") or not host_icazelidir(novbeti):
            break
        tarixce.append(r)
        if r.status_code in (301, 302, 303) and metod.upper() != "HEAD":
            metod = "GET"
            for acar in ("data", "json", "files"):
                kw.pop(acar, None)
        url = novbeti
    r.history = tarixce
    return r


def al(url, metod="GET", timeout=8, **kw):
    """Tək sorğu (rate-limit ilə). Cavab varsa Cavab örtüyü, yoxdursa None.
    Qeyd: 4xx/5xx də MÖVCUD cavabdır (atılmır) — error-based aşkarlama üçün.
    Sorğu yalnız aktiv skanın hostuna və açıq internet IP-lərinə gedir."""
    redirect = kw.pop("redirect", True)
    with _semafor:
        for cehd in (1, 2):
            try:
                return Cavab(_sorgu(metod, url, timeout, redirect, dict(kw)))
            except HedefXaricindedir:
                return None
            except requests.RequestException:
                # Köhnəlmiş keep-alive bağlantısı 1-ci cəhdi poza bilər;
                # 2-ci cəhd yeni bağlantı alır.
                if cehd == 2:
                    return None
    return None


def paralel_al(url_siyahi, timeout=8):
    """Çox URL-i paralel çək. {url: cavab} qaytarır (xəta -> None)."""
    netice = {}
    with ThreadPoolExecutor(max_workers=PARALEL) as ex:
        gelecek = {ex.submit(al, u, timeout=timeout): u for u in url_siyahi}
        for g in gelecek:
            netice[gelecek[g]] = g.result()
    return netice


def modullari_paralel_islet(ishler):
    """
    Modulları paralel işlət. `ishler` = [(funksiya, (arqumentlər...)), ...]
    Hər modul öz işini görür, hesabata yazır (append thread-safe-dir).
    """
    with ThreadPoolExecutor(max_workers=12) as ex:
        gelecek = [ex.submit(f, *args) for f, args in ishler]
        for g in gelecek:
            try:
                g.result()
            except Exception:
                pass   # bir modulun xətası bütün skanı dayandırmasın
