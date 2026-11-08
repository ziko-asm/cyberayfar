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
        """Bir tapıntı qeydə alır. 'kod' tərcümə açarıdır (bax: diller.py)."""
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
