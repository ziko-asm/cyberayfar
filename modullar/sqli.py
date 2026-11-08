"""
MODUL: SQL INJECTION (Error-based) DETEKTORU
============================================
SQL injection = saytın istifadəçi inputunu birbaşa SQL sorğusuna
qoşması. Hücumçu verilənlər bazasını oxuya/poza bilər.

NECƏ AŞKARLAYIRIQ (zərərsiz üsul):
  1. İnputa tək dırnaq (') kimi "sorğunu pozan" simvol göndəririk.
  2. Əgər cavabda SQL XƏTA MESAJI görünürsə (məs: "SQL syntax",
     "mysql_fetch", "ORA-01756"), deməli input birbaşa SQL-ə düşür
     = sayt SQLi-yə açıqdır.

Biz DATA ÇIXARMIRIQ, heç nə SİLMİRİK (DROP/DELETE yoxdur). Yalnız
xəta mesajının görünüb-görünmədiyini yoxlayırıq. Bu "error-based
detection" standart və təhlükəsiz metoddur.
"""

import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Müxtəlif verilənlər bazalarının xəta imzaları
SQL_XETA_IMZALARI = [
    r"SQL syntax.*MySQL", r"Warning.*mysqli?", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"PostgreSQL.*ERROR", r"pg_query\(\)",
    r"ORA-\d{5}", r"Oracle error", r"Microsoft SQL Server",
    r"ODBC SQL Server Driver", r"SQLite/JDBCDriver", r"sqlite3.OperationalError",
    r"Unclosed quotation mark", r"quoted string not properly terminated",
]
IMZA_REGEX = re.compile("|".join(SQL_XETA_IMZALARI), re.IGNORECASE)

# Sorğunu pozmaq üçün zərərsiz test inputları
TEST_INPUTLARI = ["'", '"', "')", "' --", "`"]


def _xeta_var(metn):
    return bool(IMZA_REGEX.search(metn))


def _get_parametrleri_yoxla(url, hesabat, sessiya, timeout):
    parcalar = urlparse(url)
    parametrler = parse_qs(parcalar.query)
    if not parametrler:
        return
    for param in parametrler:
        for test in TEST_INPUTLARI:
            yeni = {k: v[0] for k, v in parametrler.items()}
            yeni[param] = yeni[param] + test
            test_url = urlunparse(parcalar._replace(query=urlencode(yeni)))
            try:
                cavab = sessiya.get(test_url, timeout=timeout)
            except requests.RequestException:
                continue
            if _xeta_var(cavab.text):
                hesabat.elave_et("kritik", "sqli_url", test_url, param=param)
                return  # bu parametr üçün tapdıq, davam etmə


def _formalari_yoxla(formalar, hesabat, sessiya, timeout):
    for form in formalar:
        for test in TEST_INPUTLARI:
            data = {inp["ad"]: f"test{test}" for inp in form["inputlar"]}
            if not data:
                break
            try:
                if form["metod"] == "post":
                    cavab = sessiya.post(form["hereket"], data=data, timeout=timeout)
                else:
                    cavab = sessiya.get(form["hereket"], params=data, timeout=timeout)
            except requests.RequestException:
                continue
            if _xeta_var(cavab.text):
                hesabat.elave_et("kritik", "sqli_forma", form["hereket"],
                                 menbe=form["menbe_sehife"])
                break


def yoxla(parametrli_url, formalar, hesabat, timeout=10):
    sessiya = requests.Session()
    sessiya.headers.update({"User-Agent": "SaytYoxla-Skaner/1.0"})
    for url in parametrli_url:
        _get_parametrleri_yoxla(url, hesabat, sessiya, timeout)
    _formalari_yoxla(formalar, hesabat, sessiya, timeout)
