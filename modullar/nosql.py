"""
MODUL: NoSQL Injection (MongoDB və s.)
======================================
Müasir saytlar SQL əvəzinə NoSQL (MongoDB) işlədir. İki yol:

1) Operator injection (boolean): `user=admin` əvəzinə `user[$ne]=xxx`
   göndərilir. Server operatoru şərh edirsə, "bərabər deyil" bütün
   nəticələri qaytarır -> auth bypass / data sızması. Zərərsiz aşkarlanır:
   $ne/$gt/$regex nəticəsini "uyğun gəlməyən" dəyərlə müqayisə edirik.

2) Error-based: `'` / `{` / `"` göndərib Mongo/JS xəta imzası axtarırıq.

Hər tapıntı 2+ operator və ya təkrar ilə TƏSDİQLƏNİR (yalançı müsbət az).
"""

import re
import secrets
import difflib
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core import http_client

NOSQL_XETA = re.compile(
    r"MongoError|MongoServerError|MongoParseError|MongoNetworkError|"
    r"BSONError|BSONTypeError|CastError|E11000|MongooseError|"
    r"failed to parse|couldn'?t parse|\$where|\$regex|"
    r"SyntaxError: Unexpected|unexpected token|"
    r"com\.mongodb|pymongo|MongoDB",
    re.IGNORECASE)

ERROR_PAYLOAD = ["'", '"', "`", "'\"", "{", "'||'1'=='1", "\\", "';return true;//"]
OPERATORLAR = (("$ne", None), ("$gt", ""), ("$regex", ".*"))


def _ratio(a, b):
    return difflib.SequenceMatcher(None, a or "", b or "").quick_ratio()


def _fetch(parcalar, params, timeout):
    u = urlunparse(parcalar._replace(query=urlencode(params)))
    c = http_client.al(u, timeout=timeout)
    return (c.text if c else None), u


def _error_yoxla(parcalar, parametrler, param, timeout):
    others = {k: v[0] for k, v in parametrler.items()}
    # normal cavab onsuz da xəta göstərirsə -> etibarsız
    normal, _ = _fetch(parcalar, others, timeout)
    if normal and NOSQL_XETA.search(normal):
        return None
    for p in ERROR_PAYLOAD:
        t, u = _fetch(parcalar, {**others, param: others[param] + p}, timeout)
        if t and NOSQL_XETA.search(t):
            return u
    return None


def _bool_yoxla(parcalar, parametrler, param, timeout):
    others = {k: v[0] for k, v in parametrler.items()}
    orig = others[param]
    rand = secrets.token_hex(3)
    wrong = orig + rand

    base, _ = _fetch(parcalar, {**others, param: orig}, timeout)
    wr, _ = _fetch(parcalar, {**others, param: wrong}, timeout)
    if base is None or wr is None:
        return None
    # parametr cavaba təsir etmirsə (base≈wrong) -> fərq tapa bilmərik
    if _ratio(base, wr) > 0.95:
        return None

    uygunlar = 0
    son_url = None
    for op, sabit in OPERATORLAR:
        deger = wrong if sabit is None else sabit
        p = dict(others)
        del p[param]
        p["%s[%s]" % (param, op)] = deger
        ne, u = _fetch(parcalar, p, timeout)
        if ne is None:
            continue
        # operator şərh olunubsa: nəticə "uyğunsuz" səhifədən fərqli,
        # "nəticə var" bazasına daha yaxın olmalıdır
        if _ratio(ne, wr) < 0.9 and (_ratio(ne, base) - _ratio(ne, wr)) > 0.1:
            uygunlar += 1
            son_url = u
    # ən azı 2 operator eyni davranışı göstərməlidir (yalançı müsbət qoruması)
    return son_url if uygunlar >= 2 else None


def _get_yoxla(url, hesabat, timeout):
    parcalar = urlparse(url)
    parametrler = parse_qs(parcalar.query)
    for param in parametrler:
        # 1) Boolean operator injection (daha ciddi -> auth bypass)
        u = _bool_yoxla(parcalar, parametrler, param, timeout)
        if u:
            hesabat.elave_et("kritik", "nosql_bool", u, param=param)
            continue
        # 2) Error-based
        u2 = _error_yoxla(parcalar, parametrler, param, timeout)
        if u2:
            hesabat.elave_et("yuksek", "nosql_error", u2, param=param)


def yoxla(parametrli_url, hesabat, timeout=8):
    for url in parametrli_url:
        _get_yoxla(url, hesabat, timeout)
