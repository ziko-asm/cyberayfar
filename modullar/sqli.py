"""
MODUL: SQL INJECTION — error-based + time-based (blind)
=======================================================
1) Error-based: ' göndərib SQL xəta mesajı axtarır.
2) Time-based (blind): xəta görünməsə belə, "gözlə" payload-u ilə
   cavab gecikməsini ölçür (kor zəiflikləri tapır).
Hər ikisi zərərsizdir — data çıxarmır, heç nə silmir.
"""

import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client

SQL_XETA = re.compile(
    r"SQL syntax.*MySQL|Warning.*mysqli?|MySQLSyntaxErrorException|"
    r"valid MySQL result|PostgreSQL.*ERROR|pg_query\(\)|ORA-\d{5}|"
    r"Oracle error|Microsoft SQL Server|ODBC SQL Server Driver|"
    r"SQLite/JDBCDriver|sqlite3.OperationalError|Unclosed quotation mark|"
    r"quoted string not properly terminated", re.IGNORECASE)

ERROR_PAYLOAD = ["'", '"', "')", "' --", "`"]
GOZLEME = 5
TIME_PAYLOAD = [f"' AND SLEEP({GOZLEME})-- -", f"'; WAITFOR DELAY '0:0:{GOZLEME}'-- -",
                f"' OR SLEEP({GOZLEME})-- -"]


def _xeta_var(metn):
    return bool(SQL_XETA.search(metn or ""))


def _get_yoxla(url, hesabat, timeout):
    parcalar = urlparse(url)
    parametrler = parse_qs(parcalar.query)
    for param in parametrler:
        tapildi = False
        # 1) Error-based
        for p in ERROR_PAYLOAD:
            yeni = {k: v[0] for k, v in parametrler.items()}
            yeni[param] = yeni[param] + p
            test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
            cavab = http_client.al(test_url, timeout=timeout)
            if cavab and _xeta_var(cavab.text):
                hesabat.elave_et("kritik", "sqli_url", test_url, param=param)
                tapildi = True
                break
        if tapildi:
            continue
        # 2) Time-based (blind) — baza vaxtını ölç
        t0 = time.time(); http_client.al(url, timeout=timeout)
        baza = time.time() - t0
        for p in TIME_PAYLOAD:
            yeni = {k: v[0] for k, v in parametrler.items()}
            yeni[param] = yeni[param] + p
            test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
            t0 = time.time()
            http_client.al(test_url, timeout=GOZLEME + timeout + 4)
            if time.time() - t0 >= GOZLEME + max(baza, 0) - 1.5:
                hesabat.elave_et("kritik", "sqli_blind", test_url, param=param)
                break


def _forma_yoxla(form, hesabat, timeout):
    metod = form["metod"]
    for p in ERROR_PAYLOAD:
        data = {inp["ad"]: f"test{p}" for inp in form["inputlar"]}
        if not data:
            return
        kw = {"data": data} if metod == "post" else {"params": data}
        cavab = http_client.al(form["hereket"], metod=metod.upper(), timeout=timeout, **kw)
        if cavab and _xeta_var(cavab.text):
            hesabat.elave_et("kritik", "sqli_forma", form["hereket"],
                             menbe=form["menbe_sehife"])
            return


def yoxla(parametrli_url, formalar, hesabat, timeout=8):
    for url in parametrli_url:
        _get_yoxla(url, hesabat, timeout)
    for form in formalar:
        _forma_yoxla(form, hesabat, timeout)
