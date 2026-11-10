"""Unit testlər: icazə qapısı, hesabat/CVSS, yalançı-müsbət qorumaları, veb API."""

import pytest

import app as veb
from core import authorization, reporter
from modullar import sensitive_files, xss


class SaxtaCavab:
    def __init__(self, govde, status=200, tip="text/plain"):
        self.content = govde.encode() if isinstance(govde, str) else govde
        self.text = self.content.decode("latin-1")
        self.status_code = status
        self.headers = {"Content-Type": tip}


# ------------------------------------------------------------ icazə qapısı
@pytest.mark.parametrize("unvan", ["asdf", "127.0.0.1", "localhost:22", "169.254.169.254",
                                   "[::1]", "", "foo.local", "a.b:99999", "<img src=x>"])
def test_daxili_ve_yanlis_unvan_redd_edilir(unvan):
    with pytest.raises(authorization.IcazeXetasi) as x:
        authorization.hedefi_yoxla(unvan)
    assert x.value.kod == "etibarsiz"


def test_token_domene_gore_sabit_ve_ferqlidir():
    a = authorization.token_yarat("Sayt.AZ", "acar")
    assert a == authorization.token_yarat("sayt.az", "acar")
    assert a != authorization.token_yarat("basqa.az", "acar")
    assert a != authorization.token_yarat("sayt.az", "basqa-acar")


def test_test_rejimi_ve_allowlist_sorgusuz_kecir():
    assert authorization.icazeni_tesdiqle("x.invalid", "k", test_rejimi=True)
    assert authorization.icazeni_tesdiqle("menim.az", "k", allowlist=("menim.az",))


# ------------------------------------------------------------ CVSS / bal
@pytest.mark.parametrize("vektor,bal", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", 4.3),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_cvss31_resmi_ballarla_uygundur(vektor, bal):
    assert reporter.cvss31(vektor) == bal


def test_ciddilik_cvss_balindan_gelir():
    h = reporter.Hesabat("https://x.az")
    h.elave_et("asagi", "sqli_url", "https://x.az/?id=1", param="id")   # modul nə desə də
    h.elave_et("kritik", "xss_url", "https://x.az/?q=1", param="q")
    assert [t["ciddilik"] for t in h.tapintilar] == ["kritik", "orta"]


def test_bal_ve_qiymet():
    assert reporter.xal_hesabla([]) == 100 and reporter.qiymet(100) == "A"
    assert reporter.xal_hesabla([{"ciddilik": "kritik"}]) <= 45
    assert reporter.xal_hesabla([{"ciddilik": "yuksek"}]) <= 78
    assert reporter.xal_hesabla([{"ciddilik": "info"}] * 9) == 100


# ------------------------------------------------------------ yalançı müsbət
def test_spa_catch_all_hessas_fayl_sayilmir():
    spa = SaxtaCavab("<!doctype html><html><body><div id=root></div></body></html>", tip="text/html")
    for yol, _c, imza in sensitive_files.HEDEF_FAYLLAR:
        assert not sensitive_files._real_fayldir(spa, imza, spa), yol


def test_real_fayl_taninir_html_ise_taninmir():
    baza = SaxtaCavab("yoxdur", status=404)
    imza = dict((y, i) for y, _c, i in sensitive_files.HEDEF_FAYLLAR)
    assert sensitive_files._real_fayldir(SaxtaCavab("DB_PASSWORD=abc\nAPP=1\n"), imza[".env"], baza)
    assert sensitive_files._real_fayldir(SaxtaCavab("[core]\n\tbare = false\n"), imza[".git/config"], baza)
    assert not sensitive_files._real_fayldir(
        SaxtaCavab("<html><body>Xoş gəldiniz</body></html>", tip="text/html"), imza[".env"], baza)
    assert not sensitive_files._real_fayldir(SaxtaCavab("x", status=403), imza[".env"], baza)


def test_js_setrinde_escape_olunmus_dirnaq_xss_deyil():
    m = "zxabc123"
    tehlukesiz = f'<script>var ad = "{m}\\u003c\\u003e\\"\'{m}";</script>'
    sag, kontekst = xss._analiz(tehlukesiz, m)
    assert kontekst.startswith("JavaScript") and '"' not in sag
    zeif = f'<script>var ad = "{m}"\'{m}";</script>'
    sag, _ = xss._analiz(zeif, m)
    assert '"' in sag


# ------------------------------------------------------------ veb API
@pytest.fixture
def c():
    veb._limit_vaxtlar.clear()
    return veb.app.test_client()


def test_tehlukesizlik_basliqlari(c):
    r = c.get("/")
    assert r.status_code == 200
    csp = r.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    for b in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy",
              "Permissions-Policy", "Strict-Transport-Security"):
        assert b in r.headers, b
    assert "onclick=" not in r.get_data(as_text=True)


def test_komekci_yollar(c):
    assert c.get("/favicon.ico").status_code == 200
    assert b"Sitemap:" in c.get("/robots.txt").data
    assert c.get("/sitemap.xml").status_code == 200
    assert c.get("/yoxdur").status_code == 404
    assert c.get("/api/yoxdur").is_json


@pytest.mark.parametrize("govde,status,kod", [
    ({}, 400, "bos"),
    ({"hedef": "127.0.0.1"}, 400, "etibarsiz"),
    ({"hedef": "file:///etc/passwd"}, 400, "etibarsiz"),
    ({"hedef": "http://a@127.0.0.1/"}, 400, "etibarsiz"),
])
def test_api_xetalari_duzgun_statusla(c, govde, status, kod):
    for yol in ("/api/skan", "/api/skan-stream"):
        r = c.post(yol, json=govde)
        assert r.status_code == status and r.get_json()["xeta_kod"] == kod


def test_yanlis_json_400(c):
    r = c.post("/api/skan", data="json deyil", content_type="application/json")
    assert r.status_code == 400 and r.get_json()["xeta_kod"] == "sorgu"


def test_suret_limiti(c):
    for _ in range(veb.LIMIT_SAY):
        assert c.post("/api/skan", json={"hedef": "127.0.0.1"}).status_code == 400
    r = c.post("/api/skan", json={"hedef": "127.0.0.1"})
    assert r.status_code == 429 and r.get_json()["xeta_kod"] == "limit"
    assert int(r.headers["Retry-After"]) >= 1
    # başqa IP təsirlənmir
    r2 = c.post("/api/skan", json={"hedef": "127.0.0.1"}, headers={"X-Forwarded-For": "203.0.113.9"})
    assert r2.status_code == 400


def test_tercumeler_tamdir():
    """Hər tapıntı kodunun 3 dildə mətni və hər kateqoriyanın UI adı olmalıdır."""
    import re
    import motor
    from core import diller, owasp
    for kod in set(motor.KATEQORIYA) | set(reporter.CVSS_VEKTOR):
        assert kod in diller.METINLER, kod
        assert set(diller.METINLER[kod]) >= {"az", "en", "ru"}, kod
        assert kod in owasp.XERITE, kod
    html = veb.app.test_client().get("/").get_data(as_text=True)
    for kat in motor.KATEQORIYALAR:
        assert len(re.findall(rf"\b{kat}:\"", html)) >= 3, kat
