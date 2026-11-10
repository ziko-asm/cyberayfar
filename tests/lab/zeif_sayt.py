"""
LABORATORİYA: BİLƏRƏKDƏN ZƏİF SAYT (yalnız lokal test üçün!)
============================================================
Skanerin DƏQİQLİYİNİ ölçmək üçün. Hər zəifliyin iki nüsxəsi var:
  /v/...  — ZƏİF     (skaner TAPMALIDIR)
  /s/...  — TƏHLÜKƏSİZ (skaner TAPMAMALIDIR — yalançı müsbət ölçüsü)

TƏHLÜKƏSİZLİK: təhlükəli əməliyyatlar (əmr icrası, fayl oxuma, xarici
sorğu, şablon icrası) REAL DEYİL — davranışı TƏQLİD olunur. Yəni bu
tətbiq zəif kimi CAVAB verir, amma maşında heç nə icra etmir/oxumur.
Yeganə real zəiflik yaddaşdakı (in-memory) SQLite bazasına SQL injection-dur.
Yalnız 127.0.0.1-də işlədin. İnternetə ÇIXARMAYIN.

`GERCEK` siyahısı — "həqiqət cədvəli": benchmark bunu skan nəticəsi ilə tutuşdurur.
"""

import os
import re
import html
import time
import sqlite3
import tempfile
import threading
import posixpath
from urllib.parse import urlparse

from flask import Flask, request, Response, redirect, jsonify

# ---------------------------------------------------------------- həqiqət
# (ad, yer-alt-sətri, qəbul olunan tapıntı kodları)
GERCEK = [
    ("XSS — HTML gövdə",              "/v/axtar",           {"xss_url"}),
    ("XSS — atribut",                 "/v/profil",          {"xss_url"}),
    ("XSS — JavaScript sətri",        "/v/js",              {"xss_url"}),
    ("XSS — GET forması",             "/v/forma-axtar",     {"xss_forma", "xss_url"}),
    ("Stored XSS — şərhlər",          "/v/serh",            {"stored_xss"}),
    ("SQLi — xəta əsaslı (URL)",      "/v/mehsul",          {"sqli_url"}),
    ("SQLi — boolean, ədədi",         "/v/xeber",           {"sqli_bool", "sqli_url", "sqli_blind"}),
    ("SQLi — boolean, sətir",         "/v/istifadeci",      {"sqli_bool", "sqli_url", "sqli_blind"}),
    ("SQLi — vaxt əsaslı",            "/v/hesabat",         {"sqli_blind"}),
    ("SQLi — forma, xəta əsaslı",     "/v/giris",           {"sqli_forma"}),
    ("SQLi — forma, kor (boolean)",   "/v/kor-giris",       {"sqli_forma", "sqli_bool", "sqli_blind"}),
    ("Open redirect — ?url=",         "/v/get",             {"open_redirect"}),
    ("Open redirect — qeyri-adi ad",  "/v/kecid",           {"open_redirect"}),
    ("LFI — ?file=",                  "/v/oxu",             {"lfi"}),
    ("LFI — qeyri-adi ad",            "/v/sened",           {"lfi"}),
    ("Command injection",             "/v/ping",            {"cmd_injection"}),
    ("SSTI",                          "/v/salam",           {"ssti"}),
    ("CRLF injection",                "/v/dil",             {"crlf"}),
    ("NoSQL injection",               "/v/api/istifadeci",  {"nosql_bool", "nosql_error"}),
    ("IDOR",                          "/v/sifaris",         {"idor"}),
    ("SSRF",                          "/v/yukle",           {"ssrf"}),
    ("XXE",                           "/xml",               {"xxe"}),
    ("CSRF — tokensiz POST forma",    "/v/serh",            {"csrf_yox"}),
    ("Qovluq siyahısı açıqdır",       "/v/fayllar",         {"qovluq_siyahisi"}),
    ("Debug / stack trace sızması",   "/v/xeta",            {"debug_sizma"}),
    ("Həssas fayl — .env",            "/.env",              {"hessas_fayl"}),
    ("Həssas fayl — .git/config",     "/.git/config",       {"hessas_fayl"}),
    ("Həssas fayl — backup.sql",      "/backup.sql",        {"hessas_fayl"}),
    ("Gizli yol — /admin",            "/admin",             {"gizli_yol"}),
    ("Sirr sızması — AWS açarı",      "app.js",             {"sirr_sizma"}),
    ("Köhnə jQuery",                  "",                   {"kohne_js"}),
    ("CSP yoxdur",                    "",                   {"csp_yox"}),
    ("X-Content-Type-Options yoxdur", "",                   {"xcto_yox"}),
    ("Cookie bayraqları zəifdir",     "",                   {"cookie_zeif"}),
    ("Server versiya sızması",        "",                   {"server_versiya"}),
    ("CORS — origin əks olunur",      "",                   {"cors_reflect", "cors_acar"}),
    ("Clickjacking",                  "",                   {"clickjacking"}),
    ("Təhlükəli HTTP metodları",      "",                   {"tehlukeli_metod"}),
    ("Host header injection",         "",                   {"host_header"}),
    ("GraphQL introspection",         "/graphql",           {"graphql_introspection"}),
]
# Bu yolda HƏR tapıntı yalançı müsbətdir (csrf_yox istisna: /s/ formaları tokenlidir)
TEHLUKESIZ_PREFIKS = "/s/"

# ---------------------------------------------------------------- baza
# Müvəqqəti FAYL-DB + WAL: skaner onlarla paralel sorğu göndərir; fayl-DB
# WAL rejimində paralel oxunuşları dəstəkləyir, in-memory shared-cache isə
# "database is locked" verirdi. Hər sorğu öz bağlantısını açır — bir sorğudakı
# SQL xətası (injection testi) digərlərini pozmur.
_DB_YOL = os.path.join(tempfile.mkdtemp(prefix="cyblab_"), "lab.db")
_db = sqlite3.connect(_DB_YOL, check_same_thread=False)
_db.execute("PRAGMA journal_mode=WAL")
_db_kilid = threading.Lock()
_db.executescript("""
CREATE TABLE mehsul(id INTEGER PRIMARY KEY, ad TEXT, qiymet REAL, tesvir TEXT);
CREATE TABLE xeber(id INTEGER PRIMARY KEY, baslik TEXT, metn TEXT);
CREATE TABLE istifadeci(id INTEGER PRIMARY KEY, ad TEXT, parol TEXT, bio TEXT);
""")
_UZUN = ("Bu mətn səhifənin əsas məzmununu təşkil edir və kifayət qədər uzundur ki, "
         "tapılan və tapılmayan nəticələr arasında aydın fərq olsun. ")
for i, (ad, q) in enumerate([("Klaviatura", 45.0), ("Siçan", 19.9), ("Monitor", 320.0),
                             ("Qulaqlıq", 59.5)], 1):
    _db.execute("INSERT INTO mehsul VALUES(?,?,?,?)", (i, ad, q, f"{ad}: " + _UZUN * 4))
for i, b in enumerate(["Yeni versiya çıxdı", "Texniki fasilə", "Endirim həftəsi"], 1):
    _db.execute("INSERT INTO xeber VALUES(?,?,?)", (i, b, f"{b}. " + _UZUN * 5))
for i, (ad, p) in enumerate([("ali", "ali123"), ("leyla", "gizli!"), ("admin", "Adm1n#2024"),
                             ("murad", "qwerty"), ("nigar", "n1gar")], 1):
    _db.execute("INSERT INTO istifadeci VALUES(?,?,?,?)",
                (i, ad, p, f"{ad} haqqında: " + _UZUN * 3))
_db.commit()


def _sorgu(sql, params=()):
    # Hər çağırış üçün ayrıca bağlantı (xəta digərlərinə keçməsin)
    conn = sqlite3.connect(_DB_YOL, timeout=5)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


_SIFARISLER = {
    1000 + i: {"musteri": m, "unvan": u, "mebleg": 40 + i * 13.5, "kart": f"**** **** **** {4100 + i * 7}"}
    for i, (m, u) in enumerate([("Əli Məmmədov", "Bakı, Nizami küç. 12"),
                                ("Leyla Həsənova", "Gəncə, Atatürk pr. 45"),
                                ("Murad Əliyev", "Sumqayıt, 9-cu mkr. 3"),
                                ("Nigar Quliyeva", "Şəki, M.F.Axundov 8"),
                                ("Rəşad Babayev", "Lənkəran, Sahil küç. 21"),
                                ("Aynur Kərimova", "Mingəçevir, Heydər Əliyev pr. 6")])
}
_SERHLER_V, _SERHLER_S = [], []
_SENEDLER = {"haqqinda.txt": "Şirkət haqqında: 2015-ci ildə yaradılıb. " + _UZUN,
             "qaydalar.txt": "İstifadə qaydaları: hörmətli olun. " + _UZUN}
_PASSWD = ("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
           "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n")

app = Flask(__name__, static_folder=None)
e = html.escape


# ---------------------------------------------------------------- şablon
def sehife(baslik, govde, status=200):
    # Real saytlardakı kimi: naviqasiyada "Giriş" linki var
    h = f"""<!doctype html><html lang="az"><head><meta charset="utf-8"><title>{e(baslik)} — LabMağaza</title>
<link rel="canonical" href="http://{request.host}{request.path}">
<script src="/static/js/jquery-1.8.3.min.js"></script><script src="/static/js/app.js"></script></head>
<body><header><nav><a href="/">Ana səhifə</a> | <a href="/v/giris">Giriş</a> | <a href="/s/haqqinda">Haqqımızda</a></nav></header>
<main><h1>{e(baslik)}</h1>
{govde}
</main><footer><p>© LabMağaza — yalnız test üçün. Əlaqə: info@lab.example</p></footer></body></html>"""
    return Response(h, status=status, mimetype="text/html")


LINKLER = [
    ("/v/axtar?q=telefon", "Axtarış"), ("/v/profil?ad=ali", "Profil"), ("/v/js?ad=ali", "Salamlama"),
    ("/v/forma-axtar", "Axtarış forması"), ("/v/serh", "Şərhlər"),
    ("/v/mehsul?id=1", "Məhsul"), ("/v/xeber?id=1", "Xəbər"), ("/v/istifadeci?ad=ali", "İstifadəçi"),
    ("/v/hesabat?ay=1", "Aylıq hesabat"), ("/v/giris", "Giriş"), ("/v/kor-giris", "Tərəfdaş girişi"),
    ("/v/get?url=/s/haqqinda", "Keçid"), ("/v/kecid?hedef=/s/haqqinda", "Tərəfdaş keçidi"),
    ("/v/oxu?file=haqqinda.txt", "Sənəd oxu"), ("/v/sened?ad=qaydalar.txt", "Qaydalar"),
    ("/v/ping?host=127.0.0.1", "Şəbəkə testi"), ("/v/salam?ad=dunya", "Salam"),
    ("/v/dil?lang=az", "Dil"), ("/v/api/istifadeci?username=ali", "API"),
    ("/v/sifaris?id=1002", "Sifarişim"), ("/v/yukle?url=http://lab.example/sekil.png", "Şəkil yüklə"),
    ("/v/fayllar/", "Fayllar"), ("/v/xeta?n=0", "Kalkulyator"),
    # ---- təhlükəsiz əkizlər
    ("/s/axtar?q=telefon", "T: Axtarış"), ("/s/profil?ad=ali", "T: Profil"), ("/s/js?ad=ali", "T: Salamlama"),
    ("/s/forma-axtar", "T: Axtarış forması"), ("/s/serh", "T: Şərhlər"),
    ("/s/mehsul?id=1", "T: Məhsul"), ("/s/xeber?id=1", "T: Xəbər"), ("/s/istifadeci?ad=ali", "T: İstifadəçi"),
    ("/s/giris", "T: Giriş"), ("/s/get?url=/s/haqqinda", "T: Keçid"),
    ("/s/oxu?file=haqqinda.txt", "T: Sənəd"), ("/s/ping?host=127.0.0.1", "T: Şəbəkə"),
    ("/s/salam?ad=dunya", "T: Salam"), ("/s/dil?lang=az", "T: Dil"),
    ("/s/api/istifadeci?username=ali", "T: API"), ("/s/sifaris?id=1002", "T: Sifariş"),
    ("/s/yukle?url=http://lab.example/sekil.png", "T: Şəkil"), ("/s/sql-derslik?movzu=1", "T: SQL dərsliyi"),
    ("/s/tesadufi?x=1", "T: Təsadüfi"), ("/s/xeta?n=5", "T: Kalkulyator"), ("/s/haqqinda", "Haqqımızda"),
]


@app.after_request
def _ana_basliqlar(cavab):
    cavab.headers["Server"] = "Apache/2.4.49 (Unix) PHP/7.4.3"
    return cavab


@app.route("/", methods=["GET", "OPTIONS"])
def ana():
    if request.method == "OPTIONS":
        return Response("", headers={"Allow": "GET, POST, PUT, DELETE, OPTIONS"})
    ul = "".join(f'<li><a href="{e(u)}">{e(t)}</a></li>' for u, t in LINKLER)
    host = request.headers.get("X-Forwarded-Host") or request.host
    r = sehife("LabMağaza", f'<p>Xoş gəldiniz! Paylaş: <a href="http://{host}/">http://{host}/</a></p><ul>{ul}</ul>')
    r.headers["Set-Cookie"] = "sessiya=5f2a9c1e7b; Path=/"
    origin = request.headers.get("Origin")
    if origin:
        r.headers["Access-Control-Allow-Origin"] = origin
        r.headers["Access-Control-Allow-Credentials"] = "true"
    return r


@app.route("/static/js/jquery-1.8.3.min.js")
def jq():
    return Response("/*! jQuery v1.8.3 */", mimetype="application/javascript")


@app.route("/static/js/app.js")
def appjs():
    # AWS-in sənədlərdəki NÜMUNƏ açarı (real deyil)
    return Response('const cfg={region:"eu-west-1",accessKeyId:"AKIAIOSFODNN7EXAMPLE"};',
                    mimetype="application/javascript")


# ---------------------------------------------------------------- XSS
@app.route("/v/axtar")
def v_axtar():
    q = request.args.get("q", "")
    return sehife("Axtarış", f"<p>Axtarılan: <b>{q}</b></p><p>Nəticə tapılmadı.</p>")


@app.route("/s/axtar")
def s_axtar():
    q = request.args.get("q", "")
    return sehife("Axtarış", f"<p>Axtarılan: <b>{e(q)}</b></p><p>Nəticə tapılmadı.</p>")


@app.route("/v/profil")
def v_profil():
    ad = request.args.get("ad", "").replace("<", "&lt;").replace(">", "&gt;")   # yalnız < > təmizlənir
    return sehife("Profil", f'<form><input type="text" name="ad" value="{ad}"><button>Saxla</button></form>')


@app.route("/s/profil")
def s_profil():
    return sehife("Profil", f'<form><input type="text" name="ad" value="{e(request.args.get("ad", ""))}">'
                            f'<button>Saxla</button></form>')


@app.route("/v/js")
def v_js():
    ad = request.args.get("ad", "").replace("<", "").replace(">", "")           # dırnaq qalır
    return sehife("Salamlama", f'<p id="s"></p><script>var ad = "{ad}"; document.getElementById("s").textContent = "Salam, " + ad;</script>')


@app.route("/s/js")
def s_js():
    import json
    ad = json.dumps(request.args.get("ad", "")).replace("<", "\\u003c").replace(">", "\\u003e")
    return sehife("Salamlama", f'<p id="s"></p><script>var ad = {ad}; document.getElementById("s").textContent = "Salam, " + ad;</script>')


@app.route("/v/forma-axtar")
def v_forma_axtar():
    s = request.args.get("soz")
    netice = f"<p>“{s}” üçün nəticə yoxdur.</p>" if s is not None else ""
    return sehife("Axtarış forması", f'<form method="get" action="/v/forma-axtar"><input name="soz"><button>Axtar</button></form>{netice}')


@app.route("/s/forma-axtar")
def s_forma_axtar():
    s = request.args.get("soz")
    netice = f"<p>“{e(s)}” üçün nəticə yoxdur.</p>" if s is not None else ""
    return sehife("Axtarış forması", f'<form method="get" action="/s/forma-axtar"><input name="soz"><button>Axtar</button></form>{netice}')


def _serh_sehife(siyahi, yol, tehlukesiz):
    if request.method == "POST":
        siyahi.append((request.form.get("ad", "")[:200], request.form.get("metn", "")[:500]))
        del siyahi[:-40]
    f = (lambda x: e(x)) if tehlukesiz else (lambda x: x)
    token = '<input type="hidden" name="csrf_token" value="b7e1c0ffee">' if tehlukesiz else ""
    lst = "".join(f"<li><b>{f(a)}</b>: {f(m)}</li>" for a, m in siyahi)
    return sehife("Şərhlər", f'<form method="post" action="{yol}">{token}<input name="ad" placeholder="Ad">'
                             f'<textarea name="metn"></textarea><button>Göndər</button></form><ul>{lst}</ul>')


@app.route("/v/serh", methods=["GET", "POST"])
def v_serh():
    return _serh_sehife(_SERHLER_V, "/v/serh", False)


@app.route("/s/serh", methods=["GET", "POST"])
def s_serh():
    return _serh_sehife(_SERHLER_S, "/s/serh", True)


# ---------------------------------------------------------------- SQLi
@app.route("/v/mehsul")
def v_mehsul():
    i = request.args.get("id", "")
    try:
        r = _sorgu(f"SELECT ad, qiymet, tesvir FROM mehsul WHERE id={i}")
    except Exception as x:   # xəta istifadəçiyə göstərilir
        return sehife("Xəta", f"<pre>sqlite3.OperationalError: {e(str(x))}</pre>", 500)
    if not r:
        return sehife("Məhsul", "<p>Məhsul tapılmadı.</p>", 404)
    return sehife(r[0][0], f"<p>Qiymət: {r[0][1]} AZN</p><p>{e(r[0][2])}</p>")


@app.route("/s/mehsul")
def s_mehsul():
    r = _sorgu("SELECT ad, qiymet, tesvir FROM mehsul WHERE id=?", (request.args.get("id", ""),))
    if not r:
        return sehife("Məhsul", "<p>Məhsul tapılmadı.</p>", 404)
    return sehife(r[0][0], f"<p>Qiymət: {r[0][1]} AZN</p><p>{e(r[0][2])}</p>")


@app.route("/v/xeber")
def v_xeber():
    try:
        r = _sorgu(f"SELECT baslik, metn FROM xeber WHERE id={request.args.get('id', '')}")
    except Exception:
        r = []               # xəta gizlədilir -> yalnız "kor" üsulla tapılır
    if not r:
        return sehife("Xəbər", "<p>Xəbər tapılmadı.</p>")
    return sehife(r[0][0], f"<article>{e(r[0][1])}</article>")


@app.route("/s/xeber")
def s_xeber():
    i = request.args.get("id", "")
    r = _sorgu("SELECT baslik, metn FROM xeber WHERE id=?", (i,))
    if not r:
        return sehife("Xəbər", f"<p>“{e(i)}” nömrəli xəbər tapılmadı.</p>")
    return sehife(r[0][0], f"<article>{e(r[0][1])}</article>")


@app.route("/v/istifadeci")
def v_istifadeci():
    try:
        r = _sorgu(f"SELECT ad, bio FROM istifadeci WHERE ad='{request.args.get('ad', '')}'")
    except Exception:
        r = []
    if not r:
        return sehife("İstifadəçi", "<p>Belə istifadəçi yoxdur.</p>")
    return sehife(r[0][0], f"<p>{e(r[0][1])}</p>")


@app.route("/s/istifadeci")
def s_istifadeci():
    r = _sorgu("SELECT ad, bio FROM istifadeci WHERE ad=?", (request.args.get("ad", ""),))
    if not r:
        return sehife("İstifadəçi", "<p>Belə istifadəçi yoxdur.</p>")
    return sehife(r[0][0], f"<p>{e(r[0][1])}</p>")


_YUXU = re.compile(r"(?:SLEEP|PG_SLEEP)\s*\(\s*(\d+)\s*\)|WAITFOR\s+DELAY\s+'0:0:(\d+)'", re.I)


@app.route("/v/hesabat")
def v_hesabat():
    # TƏQLİD: nəticə görünmür; yalnız DB-nin "yatması" (vaxt) zəifliyi göstərir
    m = _YUXU.search(request.args.get("ay", ""))
    if m:
        time.sleep(min(int(m.group(1) or m.group(2)), 6))
    return sehife("Aylıq hesabat", "<p>Hesabat hazırlanır və e-poçtunuza göndəriləcək.</p>")


def _giris_forma(yol, token=""):
    return (f'<form method="post" action="{yol}">{token}<input name="ad" placeholder="İstifadəçi">'
            f'<input name="parol" type="password" placeholder="Parol"><button>Daxil ol</button></form>')


@app.route("/v/giris", methods=["GET", "POST"])
def v_giris():
    if request.method == "GET":
        return sehife("Giriş", _giris_forma("/v/giris"))
    a, p = request.form.get("ad", ""), request.form.get("parol", "")
    try:
        r = _sorgu(f"SELECT ad FROM istifadeci WHERE ad='{a}' AND parol='{p}'")
    except Exception as x:
        return sehife("Xəta", f"<pre>sqlite3.OperationalError: {e(str(x))}</pre>", 500)
    return sehife("Giriş", (f"<p>Xoş gəldin, {e(r[0][0])}!</p><p>{_UZUN * 3}</p>" if r
                            else "<p>İstifadəçi adı və ya parol yanlışdır.</p>") + _giris_forma("/v/giris"))


@app.route("/v/kor-giris", methods=["GET", "POST"])
def v_kor_giris():
    if request.method == "GET":
        return sehife("Tərəfdaş girişi", _giris_forma("/v/kor-giris"))
    a, p = request.form.get("ad", ""), request.form.get("parol", "")
    try:
        r = _sorgu(f"SELECT ad FROM istifadeci WHERE ad='{a}' AND parol='{p}'")
    except Exception:
        r = []               # xəta gizlədilir
    return sehife("Tərəfdaş girişi", (f"<p>Xoş gəldin, {e(r[0][0])}!</p><p>{_UZUN * 3}</p>" if r
                                      else "<p>İstifadəçi adı və ya parol yanlışdır.</p>") + _giris_forma("/v/kor-giris"))


@app.route("/s/giris", methods=["GET", "POST"])
def s_giris():
    tok = '<input type="hidden" name="csrf_token" value="b7e1c0ffee">'
    if request.method == "GET":
        return sehife("Giriş", _giris_forma("/s/giris", tok))
    r = _sorgu("SELECT ad FROM istifadeci WHERE ad=? AND parol=?",
               (request.form.get("ad", ""), request.form.get("parol", "")))
    return sehife("Giriş", (f"<p>Xoş gəldin, {e(r[0][0])}!</p>" if r
                            else "<p>İstifadəçi adı və ya parol yanlışdır.</p>") + _giris_forma("/s/giris", tok))


# ---------------------------------------------------------------- redirect
@app.route("/v/get")
def v_get():
    return redirect(request.args.get("url", "/"))


@app.route("/v/kecid")
def v_kecid():
    return redirect(request.args.get("hedef", "/"))


@app.route("/s/get")
def s_get():
    u = request.args.get("url", "/")
    p = urlparse(u)
    if p.scheme or p.netloc or not u.startswith("/") or u.startswith("//"):
        u = "/"
    return redirect(u)


# ---------------------------------------------------------------- LFI (təqlid)
def _fayl_oxu(ad):
    yol = posixpath.normpath(posixpath.join("/var/www/sened", ad.replace("\\", "/").split("\x00")[0]))
    if yol == "/etc/passwd":
        return _PASSWD
    if yol.startswith("/var/www/sened/"):
        return _SENEDLER.get(yol.rsplit("/", 1)[1])
    return None


@app.route("/v/oxu")
def v_oxu():
    m = _fayl_oxu(request.args.get("file", ""))
    return sehife("Sənəd", f"<pre>{e(m)}</pre>" if m else "<p>Fayl tapılmadı.</p>")


@app.route("/v/sened")
def v_sened():
    m = _fayl_oxu(request.args.get("ad", ""))
    return sehife("Qaydalar", f"<pre>{e(m)}</pre>" if m else "<p>Fayl tapılmadı.</p>")


@app.route("/s/oxu")
def s_oxu():
    m = _SENEDLER.get(posixpath.basename(request.args.get("file", "").replace("\\", "/")))
    return sehife("Sənəd", f"<pre>{e(m)}</pre>" if m else "<p>Fayl tapılmadı.</p>")


# ---------------------------------------------------------------- cmd (təqlid)
def _qabiq_teqlid(setir):
    """Əmr İCRA ETMİR. Qabıq metasimvollarını ayırıb `sleep N` görsə yatır."""
    dirnaqsiz = re.sub(r"'[^']*'|\"[^\"]*\"", " ", setir)
    for hisse in re.split(r"[;|&\n`]|\$\(", dirnaqsiz)[1:]:
        m = re.match(r"\s*(?:sleep|timeout)\s+(\d+)", hisse) or re.match(r"\s*ping\s+-c\s+(\d+)", hisse)
        if m:
            time.sleep(min(int(m.group(1)), 6))
            return


@app.route("/v/ping")
def v_ping():
    host = request.args.get("host", "")
    _qabiq_teqlid("ping -c 1 " + host)
    return sehife("Şəbəkə testi", f"<pre>PING {e(host[:40])}: 1 paket göndərildi, 1 qəbul edildi</pre>")


@app.route("/s/ping")
def s_ping():
    host = request.args.get("host", "")
    if not re.fullmatch(r"[A-Za-z0-9.\-]{1,60}", host):
        return sehife("Şəbəkə testi", "<p>Yanlış ünvan.</p>", 400)
    return sehife("Şəbəkə testi", f"<pre>PING {e(host)}: 1 paket göndərildi, 1 qəbul edildi</pre>")


# ---------------------------------------------------------------- SSTI (təqlid)
@app.route("/v/salam")
def v_salam():
    ad = request.args.get("ad", "")
    icra = re.sub(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}", lambda m: str(int(m.group(1)) * int(m.group(2))), ad)
    return sehife("Salam", f"<p>Salam, {e(icra)}!</p>")


@app.route("/s/salam")
def s_salam():
    return sehife("Salam", f"<p>Salam, {e(request.args.get('ad', ''))}!</p>")


# ---------------------------------------------------------------- CRLF (təqlid)
@app.route("/v/dil")
def v_dil():
    r = sehife("Dil", "<p>Dil seçildi.</p>")
    setirler = request.args.get("lang", "az").split("\r\n")
    r.headers["X-Dil"] = setirler[0][:40]
    for s in setirler[1:]:                       # yeridilən başlıqlar
        if ":" in s:
            k, v = s.split(":", 1)
            if re.fullmatch(r"[A-Za-z0-9\-]{1,40}", k.strip()):
                r.headers[k.strip()] = v.strip()[:80]
    return r


@app.route("/s/dil")
def s_dil():
    r = sehife("Dil", "<p>Dil seçildi.</p>")
    lang = request.args.get("lang", "az")
    r.headers["X-Dil"] = lang if lang in ("az", "en", "ru") else "az"
    return r


# ---------------------------------------------------------------- NoSQL (təqlid)
def _mongo_tap(sorgu):
    adlar = [r[0] for r in _sorgu("SELECT ad FROM istifadeci")]
    if isinstance(sorgu, dict):
        if "$ne" in sorgu:
            return [a for a in adlar if a != sorgu["$ne"]]
        if "$gt" in sorgu:
            return [a for a in adlar if a > sorgu["$gt"]]
        if "$regex" in sorgu:
            try:
                return [a for a in adlar if re.search(sorgu["$regex"], a)]
            except re.error:
                return []
        return []
    return [a for a in adlar if a == sorgu]


def _api_cavab(adlar):
    return jsonify([{"username": a, "email": f"{a}@lab.example", "rol": "user", "aktiv": True} for a in adlar])


@app.route("/v/api/istifadeci")
def v_api():
    ops = {k[len("username["):-1]: v for k, v in request.args.items() if k.startswith("username[")}
    return _api_cavab(_mongo_tap(ops if ops else request.args.get("username", "")))


@app.route("/s/api/istifadeci")
def s_api():
    return _api_cavab(_mongo_tap(str(request.args.get("username", ""))))


# ---------------------------------------------------------------- IDOR
def _sifaris_sehife(s, i):
    return sehife(f"Sifariş #{i}", f"<table><tr><td>Müştəri</td><td>{e(s['musteri'])}</td></tr>"
                                   f"<tr><td>Ünvan</td><td>{e(s['unvan'])}</td></tr>"
                                   f"<tr><td>Məbləğ</td><td>{s['mebleg']} AZN</td></tr>"
                                   f"<tr><td>Kart</td><td>{s['kart']}</td></tr></table>")


@app.route("/v/sifaris")
def v_sifaris():
    i = request.args.get("id", "")
    s = _SIFARISLER.get(int(i)) if i.isdigit() else None
    return _sifaris_sehife(s, i) if s else sehife("Sifariş", "<p>Sifariş mövcud deyil.</p>", 404)


@app.route("/s/sifaris")
def s_sifaris():
    i = request.args.get("id", "")
    # yalnız "öz" sifarişi (1002) göstərilir; qalanları üçün icazə yoxdur
    if i == "1002":
        return _sifaris_sehife(_SIFARISLER[1002], i)
    return sehife("Sifariş", "<p>Bu sifarişə baxmaq icazəniz yoxdur.</p>", 403)


# ---------------------------------------------------------------- SSRF (təqlid)
@app.route("/v/yukle")
def v_yukle():
    host = (urlparse(request.args.get("url", "")).hostname or "").lower()
    if host == "169.254.169.254":                 # sorğu GÖNDƏRİLMİR — cavab təqlid olunur
        return Response("ami-id\nami-launch-index\nhostname\ninstance-id\niam/\nsecurity-credentials/\n",
                        mimetype="text/plain")
    if host == "metadata.google.internal":
        return Response("computeMetadata/v1/instance/\n", mimetype="text/plain")
    return sehife("Şəkil yüklə", "<p>Şəkil yükləndi və saxlanıldı.</p>")


@app.route("/s/yukle")
def s_yukle():
    host = (urlparse(request.args.get("url", "")).hostname or "").lower()
    if host != "lab.example":
        return sehife("Şəkil yüklə", "<p>Bu ünvana icazə yoxdur.</p>", 400)
    return sehife("Şəkil yüklə", "<p>Şəkil yükləndi və saxlanıldı.</p>")


# ---------------------------------------------------------------- XXE (təqlid)
@app.route("/xml", methods=["POST"])
def xml_api():
    govde = request.get_data(as_text=True)[:5000]
    varliqlar = dict(re.findall(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"', govde))
    m = re.search(r"<r>(.*?)</r>", govde, re.S)
    metn = m.group(1) if m else ""
    for ad, sistem in varliqlar.items():           # fayl OXUNMUR — təqlid
        metn = metn.replace(f"&{ad};", _PASSWD if sistem == "file:///etc/passwd" else "")
    return Response(f"<cavab><qebul>{e(metn)}</qebul></cavab>", mimetype="application/xml")


# ---------------------------------------------------------------- digər
@app.route("/v/fayllar/")
def v_fayllar():
    return Response('<html><head><title>Index of /v/fayllar</title></head><body><h1>Index of /v/fayllar</h1><hr><pre>'
                    '<a href="../">../</a>\n<a href="hesabat-2023.xlsx">hesabat-2023.xlsx</a>   12-Mar-2024 10:21   48K\n'
                    '<a href="musteriler.csv">musteriler.csv</a>   02-Feb-2024 09:03   1.2M\n</pre><hr></body></html>',
                    mimetype="text/html")


@app.route("/v/xeta")
def v_xeta():
    n = request.args.get("n", "")
    try:
        return sehife("Kalkulyator", f"<p>Nəticə: {100 / int(n)}</p>")
    except Exception as x:   # debug rejimi açıq qalıb: stack trace istifadəçiyə gedir
        iz = (f'Traceback (most recent call last):\n  File "/var/www/app/kalkulyator.py", line 42, in hesabla\n'
              f"    return 100 / int(n)\n{type(x).__name__}: {x}")
        return sehife("Daxili xəta", f"<pre>{e(iz)}</pre>", 500)


@app.route("/s/xeta")
def s_xeta():
    try:
        return sehife("Kalkulyator", f"<p>Nəticə: {100 / int(request.args.get('n', ''))}</p>")
    except Exception:
        return sehife("Kalkulyator", "<p>Düzgün ədəd daxil edin.</p>", 400)


@app.route("/s/sql-derslik")
def s_sql_derslik():
    # Mətnində SQL xəta nümunəsi olan ADİ səhifə (yalançı müsbət tələsi)
    return sehife("SQL dərsliyi", "<p>Tez-tez rast gəlinən xəta: <code>You have an error in your SQL syntax; "
                                  "check the manual that corresponds to your MySQL server version</code></p>" + f"<p>{_UZUN * 3}</p>")


@app.route("/s/tesadufi")
def s_tesadufi():
    import secrets
    # Hər sorğuda dəyişən məzmun (reklam/token) — boolean-test tələsi
    return sehife("Təsadüfi", "".join(f"<p>Təklif #{secrets.randbelow(10**6)}: {secrets.token_hex(24)}</p>" for _ in range(8)))


@app.route("/s/haqqinda")
def s_haqqinda():
    return sehife("Haqqımızda", f"<p>{_UZUN * 4}</p>")


@app.route("/.env")
def dotenv():
    return Response("APP_ENV=production\nDB_PASSWORD=S3cr3t-lab-only\nSECRET_KEY=lab-0123456789\n", mimetype="text/plain")


@app.route("/.git/config")
def gitconfig():
    return Response("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@lab.example:shop/app.git\n",
                    mimetype="text/plain")


@app.route("/backup.sql")
def backup():
    return Response("-- MySQL dump 10.13\nCREATE TABLE `users` (id INT);\nINSERT INTO `users` VALUES (1);\n",
                    mimetype="application/sql")


@app.route("/admin")
def admin():
    return sehife("Admin panel", f"<p>İdarəetmə paneli.</p><p>{_UZUN * 3}</p>")


@app.route("/graphql", methods=["POST"])
def graphql():
    if "__schema" in request.get_data(as_text=True):
        return jsonify({"data": {"__schema": {"queryType": {"name": "Query"},
                                              "types": [{"name": "Query"}, {"name": "User"}, {"name": "Order"}]}}})
    return jsonify({"errors": [{"message": "Sorğu dəstəklənmir"}]})


@app.errorhandler(404)
def yoxdur(_x):
    return sehife("Tapılmadı", "<p>Səhifə mövcud deyil.</p>", 404)


# ---------------------------------------------------------------- SPA (catch-all) tətbiqi
spa = Flask("spa_lab", static_folder=None)
_SPA_HTML = ('<!doctype html><html><head><meta charset="utf-8"><title>SPA</title></head><body><div id="root"></div>'
             '<script src="/assets/index-4f1a.js"></script></body></html>')


@spa.route("/", defaults={"yol": ""})
@spa.route("/<path:yol>")
def spa_hamisi(yol):
    """Hər yola 200 + eyni index.html (React/Vue hostinqlərində adi hal).
    Burada `.env`, `.git/config` və s. YOXDUR -> hər 'həssas fayl' tapıntısı yalançı müsbətdir."""
    if yol.startswith("assets/"):
        return Response("console.log('spa')", mimetype="application/javascript")
    r = Response(_SPA_HTML, mimetype="text/html")
    r.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Permissions-Policy"] = "camera=()"
    return r


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5099, threaded=True)
