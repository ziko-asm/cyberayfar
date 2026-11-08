"""
MOTOR (Engine) v3 — 15 kateqoriya, paralel
==========================================
"""

from urllib.parse import urlparse

from core import (authorization, crawler as crawler_modulu, reporter, diller,
                  tech_detect, http_client)
from modullar import (sensitive_files, email_spoof, xss, sqli, headers, cors,
                      open_redirect, js_libs, command_injection, lfi,
                      csrf, subdomain, http_methods, mixed_content, hidden_paths)

GIZLI_ACAR = "DEYISDIR-MENI-uzun-tesadufi-acar"

PLATFORMA_DOMENLERI = (".vercel.app", ".netlify.app", ".github.io",
                       ".pages.dev", ".herokuapp.com", ".web.app",
                       ".firebaseapp.com", ".onrender.com", ".streamlit.app")

KATEQORIYA = {
    "hessas_fayl": "fayllar", "robots": "fayllar",
    "spf_yox": "email", "spf_zeif": "email", "dmarc_yox": "email",
    "dmarc_passiv": "email", "dkim_yox": "email", "platforma": "email",
    "xss_url": "xss", "xss_forma": "xss",
    "sqli_url": "sqli", "sqli_forma": "sqli", "sqli_blind": "sqli",
    "csp_yox": "basliqlar", "hsts_yox": "basliqlar", "xfo_yox": "basliqlar",
    "xcto_yox": "basliqlar", "refpol_yox": "basliqlar", "permpol_yox": "basliqlar",
    "server_versiya": "basliqlar", "cookie_zeif": "basliqlar",
    "cors_acar": "cors", "cors_reflect": "cors",
    "open_redirect": "redirect", "kohne_js": "kohne_js",
    "cmd_injection": "cmd", "lfi": "lfi",
    "csrf_yox": "csrf", "gizli_yol": "yollar",
    "tehlukeli_metod": "metodlar", "mixed_content": "mixed",
    "subdomainler": "subdomain",
}
KATEQORIYALAR = ("fayllar", "basliqlar", "email", "xss", "sqli", "cmd", "lfi",
                 "redirect", "cors", "kohne_js", "csrf", "yollar", "metodlar",
                 "mixed", "subdomain")


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

    # 2) Crawl + texnologiya
    bildir("crawl")
    crawler = crawler_modulu.Crawler(hedef, maks_sehife=maks_sehife)
    netice = crawler.gez()
    purl, formalar = netice["parametrli_url"], netice["formalar"]

    bildir("texnologiya")
    tech = tech_detect.askarla(hedef)

    # 3) PASSİV modullar (paralel)
    bildir("fayllar"); bildir("basliqlar"); bildir("cors"); bildir("kohne_js")
    bildir("metodlar"); bildir("mixed"); bildir("yollar")
    passiv = [
        (sensitive_files.yoxla, (hedef, hesabat)),
        (headers.yoxla, (hedef, hesabat)),
        (cors.yoxla, (hedef, hesabat)),
        (js_libs.yoxla, (hedef, hesabat)),
        (http_methods.yoxla, (hedef, hesabat)),
        (mixed_content.yoxla, (hedef, hesabat)),
        (hidden_paths.yoxla, (hedef, hesabat)),
    ]
    bildir("spoofing")
    if platforma:
        hesabat.elave_et("info", "platforma", domen, domen=domen)
    else:
        passiv.append((email_spoof.yoxla, (domen, hesabat)))
        bildir("subdomain")
        passiv.append((subdomain.yoxla, (domen, hesabat)))
    http_client.modullari_paralel_islet(passiv)

    # 4) AKTİV modullar (paralel)
    bildir("xss"); bildir("sqli"); bildir("redirect")
    bildir("cmd"); bildir("lfi"); bildir("csrf")
    aktiv = [
        (xss.yoxla, (purl, formalar, hesabat)),
        (sqli.yoxla, (purl, formalar, hesabat)),
        (open_redirect.yoxla, (purl, hesabat)),
        (command_injection.yoxla, (purl, hesabat)),
        (lfi.yoxla, (purl, hesabat)),
        (csrf.yoxla, (formalar, hesabat)),
    ]
    http_client.modullari_paralel_islet(aktiv)

    bildir("bitdi")
    hesabat.sirala()

    tapintilar = [{
        "ciddilik": t["ciddilik"], "kod": t["kod"], "yer": t["yer"],
        "cvss": reporter.cvss(t["ciddilik"]),
        "metn": diller.render_hamisi(t["kod"], t["deyishken"]),
    } for t in hesabat.tapintilar]

    yoxlamalar = []
    for kat in KATEQORIYALAR:
        aid = [t for t in hesabat.tapintilar if KATEQORIYA.get(t["kod"]) == kat]
        zeif = [t for t in aid if t["ciddilik"] != "info"]
        yoxlamalar.append({"kat": kat,
                           "status": "zeif" if zeif else "temiz",
                           "say": len(zeif)})

    bal = reporter.xal_hesabla(hesabat.tapintilar)
    return {
        "hedef": hedef, "domen": domen,
        "bal": bal, "qiymet": reporter.qiymet(bal),
        "platforma_domeni": platforma, "texnologiya": tech,
        "icmal": reporter.icmal(hesabat.tapintilar),
        "statistika": {"sehifeler": netice["sehifeler"],
                       "formalar": len(formalar), "parametrli_url": len(purl)},
        "yoxlamalar": yoxlamalar, "tapintilar": tapintilar,
    }
