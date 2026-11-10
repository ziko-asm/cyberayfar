"""
REPORTER (Hesabat)
==================
Tapıntıları KOD + dəyişənlər kimi saxlayır (mətn deyil!), ki sonra
3 dildə (AZ/EN/RU) göstərilə bilsin. Scoring və A-F qiymət burdadır.
"""

CIDDILIK = {"kritik": 4, "yuksek": 3, "orta": 2, "asagi": 1, "info": 0}

# Hər ciddilik üçün bal cəriməsi (scoring üçün)
CERIME = {"kritik": 35, "yuksek": 18, "orta": 8, "asagi": 3, "info": 0}


class Hesabat:
    def __init__(self, hedef: str):
        self.hedef = hedef
        self.tapintilar = []   # {ciddilik, kod, yer, deyishken}

    def elave_et(self, ciddilik, kod, yer, **deyishken):
        """Bir tapıntı qeydə alır. 'kod' tərcümə açarıdır (bax: diller.py).

        CVSS vektoru olan kodlarda ciddilik vektordan hesablanır ki, hesabatda
        "KRİTİK" nişanı ilə CVSS balı bir-birinə zidd olmasın."""
        vektor = CVSS_VEKTOR.get(kod)
        if vektor:
            ciddilik = cvss_ciddilik(cvss31(vektor))
        self.tapintilar.append({
            "ciddilik": ciddilik, "kod": kod, "yer": yer,
            "deyishken": deyishken,
        })

    def sirala(self):
        self.tapintilar.sort(
            key=lambda t: CIDDILIK.get(t["ciddilik"], 0), reverse=True)


def xal_hesabla(tapintilar) -> int:
    """
    Dürüst scoring:
      • Hər tapıntı ciddiliyinə görə bal azaldır
      • Əgər KRİTİK varsa -> bal 45-dən yuxarı ola bilməz (SQLi ilə "yaxşı" olmaz)
      • Əgər YÜKSEK varsa -> bal 78-dən yuxarı ola bilməz
      • info bala TƏSİR ETMİR (sadəcə məlumat)
    """
    cerime = sum(CERIME.get(t["ciddilik"], 0) for t in tapintilar)
    bal = max(0, 100 - cerime)

    ciddiliks = {t["ciddilik"] for t in tapintilar}
    if "kritik" in ciddiliks:
        bal = min(bal, 45)
    elif "yuksek" in ciddiliks:
        bal = min(bal, 78)
    return bal


def qiymet(bal: int) -> str:
    """0-100 balı A-F hərf qiymətinə çevirir (SaytYoxla kimi)."""
    if bal >= 90: return "A"
    if bal >= 75: return "B"
    if bal >= 60: return "C"
    if bal >= 40: return "D"
    return "F"


# ------------------------------------------------------------------ CVSS 3.1
# Vektoru olmayan (konfiqurasiya tipli) tapıntılar üçün təxmini bal
CVSS = {"kritik": 9.5, "yuksek": 7.5, "orta": 5.0, "asagi": 3.0, "info": 0.0}

_ASAS = "CVSS:3.1/AV:N/AC:L/"
# İstismar oluna bilən zəifliklər üçün standart CVSS 3.1 baza vektorları
CVSS_VEKTOR = {
    "sqli_url": _ASAS + "PR:N/UI:N/S:U/C:H/I:H/A:H",
    "sqli_forma": _ASAS + "PR:N/UI:N/S:U/C:H/I:H/A:H",
    "sqli_bool": _ASAS + "PR:N/UI:N/S:U/C:H/I:H/A:H",
    "sqli_blind": _ASAS + "PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cmd_injection": _ASAS + "PR:N/UI:N/S:U/C:H/I:H/A:H",
    "rce_oob": _ASAS + "PR:N/UI:N/S:U/C:H/I:H/A:H",
    "ssti": _ASAS + "PR:N/UI:N/S:U/C:H/I:H/A:H",
    "nosql_bool": _ASAS + "PR:N/UI:N/S:U/C:H/I:H/A:N",
    "nosql_error": _ASAS + "PR:N/UI:N/S:U/C:L/I:N/A:N",
    "lfi": _ASAS + "PR:N/UI:N/S:U/C:H/I:N/A:N",
    "xxe": _ASAS + "PR:N/UI:N/S:U/C:H/I:N/A:N",
    "xxe_oob": _ASAS + "PR:N/UI:N/S:U/C:H/I:N/A:N",
    "ssrf": _ASAS + "PR:N/UI:N/S:C/C:H/I:N/A:N",
    "ssrf_oob": _ASAS + "PR:N/UI:N/S:C/C:H/I:N/A:N",
    "stored_xss": _ASAS + "PR:N/UI:R/S:C/C:H/I:L/A:N",
    "xss_url": _ASAS + "PR:N/UI:R/S:C/C:L/I:L/A:N",
    "xss_forma": _ASAS + "PR:N/UI:R/S:C/C:L/I:L/A:N",
    "open_redirect": _ASAS + "PR:N/UI:R/S:C/C:L/I:L/A:N",
    "crlf": _ASAS + "PR:N/UI:R/S:C/C:L/I:L/A:N",
    "csrf_yox": _ASAS + "PR:N/UI:R/S:U/C:N/I:L/A:N",
    "clickjacking": _ASAS + "PR:N/UI:R/S:U/C:N/I:L/A:N",
    "qovluq_siyahisi": _ASAS + "PR:N/UI:N/S:U/C:L/I:N/A:N",
    "debug_sizma": _ASAS + "PR:N/UI:N/S:U/C:L/I:N/A:N",
}

_W = {"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
      "AC": {"L": 0.77, "H": 0.44},
      "UI": {"N": 0.85, "R": 0.62},
      "CIA": {"H": 0.56, "L": 0.22, "N": 0.0}}


def _yuxari_yuvarlaqla(x: float) -> float:
    """CVSS 3.1 spesifikasiyasındakı Roundup (1 onluq, yuxarı)."""
    i = round(x * 100000)
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss31(vektor: str) -> float:
    """CVSS 3.1 baza balını vektordan hesablayır (rəsmi düstur)."""
    m = dict(h.split(":") for h in vektor.split("/")[1:])
    deyisir = m["S"] == "C"
    pr = {"N": 0.85, "L": 0.68 if deyisir else 0.62, "H": 0.5 if deyisir else 0.27}[m["PR"]]
    iss = 1 - (1 - _W["CIA"][m["C"]]) * (1 - _W["CIA"][m["I"]]) * (1 - _W["CIA"][m["A"]])
    tesir = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if deyisir else 6.42 * iss
    if tesir <= 0:
        return 0.0
    istismar = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * pr * _W["UI"][m["UI"]]
    cem = 1.08 * (tesir + istismar) if deyisir else tesir + istismar
    return _yuxari_yuvarlaqla(min(cem, 10))


def cvss_ciddilik(bal: float) -> str:
    """CVSS balı -> ciddilik (rəsmi aralıqlar)."""
    if bal >= 9.0: return "kritik"
    if bal >= 7.0: return "yuksek"
    if bal >= 4.0: return "orta"
    if bal > 0: return "asagi"
    return "info"


def cvss(ciddilik: str, kod: str = None) -> float:
    """Tapıntının CVSS balı: vektor varsa hesablanmış, yoxdursa təxmini."""
    vektor = CVSS_VEKTOR.get(kod)
    return cvss31(vektor) if vektor else CVSS.get(ciddilik, 0.0)


def cvss_vektor(kod: str):
    return CVSS_VEKTOR.get(kod)


def icmal(tapintilar) -> dict:
    """Exec summary: hər ciddilikdən neçə ədəd (Mərhələ 4)."""
    say = {"kritik": 0, "yuksek": 0, "orta": 0, "asagi": 0, "info": 0}
    for t in tapintilar:
        say[t["ciddilik"]] = say.get(t["ciddilik"], 0) + 1
    return say
