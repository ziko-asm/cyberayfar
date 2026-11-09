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

ISTIFADECI_AGENT = "CyberAyfar-Scanner/2.0 (+authorized-security-test)"

# Böyük connection pool -> paralel sorğular üçün
_sessiya = requests.Session()
_sessiya.headers.update({"User-Agent": ISTIFADECI_AGENT})
_adapter = requests.adapters.HTTPAdapter(pool_connections=20, pool_maxsize=20)
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


def al(url, metod="GET", timeout=8, **kw):
    """Tək sorğu (rate-limit ilə). Bağlantı sıfırlanarsa 1 dəfə təkrar
    cəhd edir (500/reset cavablarını itirməmək üçün). Yenə alınmasa None."""
    redirect = kw.pop("redirect", True)
    with _semafor:
        for cehd in (1, 2):
            try:
                return _sessiya.request(metod, url, timeout=timeout,
                                        allow_redirects=redirect, **kw)
            except requests.RequestException:
                # 1-ci cəhd sınıq keep-alive bağlantıya düşə bilər; urllib3 onu
                # atır, 2-ci cəhd yeni bağlantı alır (sessiyanı bağlamırıq —
                # paralel thread-ləri pozmasın).
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
