"""
MOTOR (Engine)
==============
Skanerin "beyni". Terminal və veb bunu çağırır.
- ilerleme(addim_kodu): canlı irəliləmə üçün ("icaze","crawl"...)
- nəticələr 3 dildə (AZ/EN/RU) qaytarılır
- yoxlanılan HƏR kateqoriya (XSS, SQLi...) status ilə göstərilir
"""

from urllib.parse import urlparse

from core import authorization, crawler as crawler_modulu, reporter, diller
from modullar import sensitive_files, email_spoof, xss, sqli

GIZLI_ACAR = "DEYISDIR-MENI-uzun-tesadufi-acar"

PLATFORMA_DOMENLERI = (".vercel.app", ".netlify.app", ".github.io",
                       ".pages.dev", ".herokuapp.com", ".web.app",
                       ".firebaseapp.com", ".onrender.com")

# Hər tapıntı kodunun hansı yoxlama kateqoriyasına aid olduğu
KATEQORIYA = {
    "hessas_fayl": "fayllar", "robots": "fayllar",
    "spf_yox": "email", "spf_zeif": "email", "dmarc_yox": "email",
    "dmarc_passiv": "email", "dkim_yox": "email", "platforma": "email",
    "xss_url": "xss", "xss_forma": "xss",
    "sqli_url": "sqli", "sqli_forma": "sqli",
}
KATEQORIYALAR = ("fayllar", "email", "xss", "sqli")


def skan_et(hedef: str, test_rejimi=True, maks_sehife=30, ilerleme=None,
            allowlist=()):
    def bildir(addim):
        if ilerleme:
            ilerleme(addim)

    hedef = hedef if "://" in hedef else "https://" + hedef
    domen = urlparse(hedef).netloc
    platforma = domen.endswith(PLATFORMA_DOMENLERI)
    hesabat = reporter.Hesabat(hedef)

    # 1) İcazə
    bildir("icaze")
    authorization.icazeni_tesdiqle(domen, GIZLI_ACAR, test_rejimi=test_rejimi,
                                   allowlist=allowlist)

    # 2) Crawl
    bildir("crawl")
    crawler = crawler_modulu.Crawler(hedef, maks_sehife=maks_sehife)
    netice = crawler.gez()

    # 3) Həssas fayllar
    bildir("hessas")
    sensitive_files.yoxla(hedef, hesabat)

    # 3b) Domain spoofing
    bildir("spoofing")
    if platforma:
        hesabat.elave_et("info", "platforma", domen, domen=domen)
    else:
        email_spoof.yoxla(domen, hesabat)

    # 4) XSS
    bildir("xss")
    xss.yoxla(netice["parametrli_url"], netice["formalar"], hesabat)

    # 5) SQLi
    bildir("sqli")
    sqli.yoxla(netice["parametrli_url"], netice["formalar"], hesabat)

    bildir("bitdi")
    hesabat.sirala()

    # Tapıntıları 3 dildə formatla
    tapintilar = []
    for t in hesabat.tapintilar:
        tapintilar.append({
            "ciddilik": t["ciddilik"],
            "kod": t["kod"],
            "yer": t["yer"],
            "metn": diller.render_hamisi(t["kod"], t["deyishken"]),
        })

    # Yoxlama kateqoriyalarının statusu (hamısı görünsün!)
    yoxlamalar = []
    for kat in KATEQORIYALAR:
        aid = [t for t in hesabat.tapintilar if KATEQORIYA.get(t["kod"]) == kat]
        zeif = [t for t in aid if t["ciddilik"] != "info"]
        yoxlamalar.append({
            "kat": kat,
            "status": "zeif" if zeif else "temiz",
            "say": len(zeif),
        })

    bal = reporter.xal_hesabla(hesabat.tapintilar)
    return {
        "hedef": hedef,
        "domen": domen,
        "bal": bal,
        "qiymet": reporter.qiymet(bal),
        "platforma_domeni": platforma,
        "statistika": {
            "sehifeler": netice["sehifeler"],
            "formalar": len(netice["formalar"]),
            "parametrli_url": len(netice["parametrli_url"]),
        },
        "yoxlamalar": yoxlamalar,
        "tapintilar": tapintilar,
    }
