"""
HTTP CLIENT — paylaşılan sessiya + paralel sorğular + rate limit
================================================================
Mərhələ 3 (sürət): ThreadPool ilə onlarla sorğunu eyni anda göndərir,
amma semafor ilə "nəzakətli" qalır (saytı yükləmir).
"""

import time
import threading
import requests
from concurrent.futures import ThreadPoolExecutor
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


def al(url, metod="GET", timeout=8, **kw):
    """Tək sorğu (rate-limit ilə). Cavab varsa Cavab örtüyü, yoxdursa None.
    Qeyd: 4xx/5xx də MÖVCUD cavabdır (atılmır) — error-based aşkarlama üçün."""
    redirect = kw.pop("redirect", True)
    with _semafor:
        for cehd in (1, 2):
            try:
                r = _sessiya.request(metod, url, timeout=timeout,
                                     allow_redirects=redirect, **kw)
                return Cavab(r)
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
