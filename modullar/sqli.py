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
    r"valid MySQL result|check the manual that corresponds to your MySQL|"
    r"PostgreSQL.*ERROR|pg_query\(\)|pg_exec\(\)|PSQLException|"
    r"ORA-\d{5}|Oracle error|Oracle.*Driver|quoted string not properly terminated|"
    r"Microsoft SQL Server|ODBC SQL Server Driver|SQLServer JDBC Driver|"
    r"System\.Data\.SqlClient\.SqlException|Unclosed quotation mark|"
    r"SQLite/JDBCDriver|sqlite3?.OperationalError|SQLITE_ERROR|"
    r"SQLSTATE\[|DB2 SQL error|CLI Driver.*DB2|Sybase message|"
    r"JDBC Driver|SQL error.*POS\d|you have an error in your sql syntax",
    re.IGNORECASE)

ERROR_PAYLOAD = ["'", '"', "')", "' --", "`", "''", "\")", "' OR '1'='1' -- ", "1'1"]
GOZLEME = 5
TIME_PAYLOAD = [f"' AND SLEEP({GOZLEME})-- -", f"'; WAITFOR DELAY '0:0:{GOZLEME}'-- -",
                f"' OR SLEEP({GOZLEME})-- -"]


def _xeta_var(metn):
    return bool(SQL_XETA.search(metn or ""))


def _vaxt(url, timeout):
    t0 = time.time()
    http_client.al(url, timeout=timeout)
    return time.time() - t0


def _get_yoxla(url, hesabat, timeout):
    parcalar = urlparse(url)
    parametrler = parse_qs(parcalar.query)

    # YALANÇI MÜSBƏT QORUMASI: normal səhifə onsuz da SQL xətası göstərirsə,
    # bu modul etibarsızdır (sayt həmişə o mətni göstərir) -> atla.
    normal = http_client.al(url, timeout=timeout)
    if normal and _xeta_var(normal.text):
        return

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
        # 2) Time-based (blind) — davamlı baza + TƏSDİQ
        baza = max(_vaxt(url, timeout), _vaxt(url, timeout))
        astana = baza + GOZLEME * 0.8
        for p in TIME_PAYLOAD:
            yeni = {k: v[0] for k, v in parametrler.items()}
            yeni[param] = yeni[param] + p
            test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
            if _vaxt(test_url, GOZLEME + timeout + 4) < astana:
                continue
            # İkinci dəfə də gecikməlidir (bir anlıq sıçrayış deyil)
            if _vaxt(test_url, GOZLEME + timeout + 4) >= astana:
                hesabat.elave_et("kritik", "sqli_blind", test_url, param=param)
                break


def _forma_yoxla(form, hesabat, timeout):
    metod = form["metod"]
    if not form["inputlar"]:
        return
    kw_normal = {"data": {i["ad"]: "test123" for i in form["inputlar"]}} if metod == "post" \
        else {"params": {i["ad"]: "test123" for i in form["inputlar"]}}
    # Yalançı müsbət qoruması: normal göndəriş onsuz da xəta göstərirsə -> atla
    normal = http_client.al(form["hereket"], metod=metod.upper(), timeout=timeout, **kw_normal)
    if normal and _xeta_var(normal.text):
        return
    for p in ERROR_PAYLOAD:
        data = {inp["ad"]: f"test{p}" for inp in form["inputlar"]}
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
