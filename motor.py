"""
MOTOR (Engine) v3 — 15 kateqoriya, paralel
==========================================
"""

import os
import sys
from urllib.parse import urlparse

from core import (authorization, crawler as crawler_modulu, reporter, diller,
                  tech_detect, http_client, owasp)
from modullar import (sensitive_files, email_spoof, xss, sqli, headers, cors,
                      open_redirect, js_libs, command_injection, lfi,
                      csrf, subdomain, http_methods, mixed_content, hidden_paths,
                      secrets_leak, tls_analiz, ssrf, xxe, graphql,
                      host_header, clickjacking, waf, idor, oob_checks, stored_xss,
                      ssti, crlf)

GIZLI_ACAR = "DEYISDIR-MENI-uzun-tesadufi-acar"

PLATFORMA_DOMENLERI = (".vercel.app", ".netlify.app", ".github.io",
                       ".pages.dev", ".herokuapp.com", ".web.app",
                       ".firebaseapp.com", ".onrender.com", ".streamlit.app")

KATEQORIYA = {
    "hessas_fayl": "fayllar", "robots": "fayllar",
    "spf_yox": "email", "spf_zeif": "email", "dmarc_yox": "email",
    "dmarc_passiv": "email", "dkim_yox": "email", "platforma": "email",
    "xss_url": "xss", "xss_forma": "xss", "stored_xss": "xss",
    "sqli_url": "sqli", "sqli_forma": "sqli", "sqli_blind": "sqli",
    "sqli_bool": "sqli", "ssti": "ssti", "crlf": "crlf",
    "csp_yox": "basliqlar", "hsts_yox": "basliqlar",
    "xcto_yox": "basliqlar", "refpol_yox": "basliqlar", "permpol_yox": "basliqlar",
    "server_versiya": "basliqlar", "cookie_zeif": "basliqlar",
    "cors_acar": "cors", "cors_reflect": "cors",
    "open_redirect": "redirect", "kohne_js": "kohne_js",
    "cmd_injection": "cmd", "lfi": "lfi",
    "csrf_yox": "csrf", "gizli_yol": "yollar",
    "tehlukeli_metod": "metodlar", "mixed_content": "mixed",
    "subdomainler": "subdomain",
    "sirr_sizma": "sirr",
    "tls_self": "tls", "tls_sertifikat": "tls", "tls_kohne": "tls",
    "ssrf": "ssrf", "xxe": "xxe",
    "graphql_introspection": "graphql", "host_header": "host",
    "clickjacking": "clickjacking", "waf_askarlandi": "waf",
    "idor": "idor",
    "ssrf_oob": "ssrf", "rce_oob": "cmd", "xxe_oob": "xxe",
}
KATEQORIYALAR = ("fayllar", "basliqlar", "email", "xss", "sqli", "cmd", "lfi",
                 "redirect", "cors", "kohne_js", "csrf", "yollar", "metodlar",
                 "mixed", "subdomain", "sirr", "tls", "clickjacking",
                 "graphql", "host", "ssrf", "xxe", "idor", "ssti", "crlf", "waf")


def skan_et(hedef: str, test_rejimi=True, maks_sehife=30, ilerleme=None,
            allowlist=(), auth=None, oob_base=None):
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
    # HEADLESS (əsl Chrome) ayrıca prosesdə — Playwright-in thread problemini
    # həll edir. Alınmasa köhnə (requests) crawler-ə avtomatik keçir.
    netice, headless, headless_xeta, auth_edildi = None, False, None, False
    try:
        import subprocess
        kok = os.path.dirname(os.path.abspath(__file__))
        skript = os.path.join(kok, "core", "crawler_js.py")
        env = dict(os.environ)
        if auth and auth.get("user") and auth.get("parol"):
            env["CYB_USER"] = str(auth["user"])
            env["CYB_PASS"] = str(auth["parol"])
            env["CYB_LOGIN_URL"] = str(auth.get("login_url") or hedef)
        cp = subprocess.run(
            [sys.executable, skript, hedef, str(min(maks_sehife, 15))],
            capture_output=True, text=True, timeout=140, env=env)
        if cp.returncode == 0 and cp.stdout.strip():
            import json as _json
            netice = _json.loads(cp.stdout)
            headless = True
            auth_edildi = bool(netice.get("auth_ok"))
            if netice.get("cookies"):   # giriş sessiyasını bütün modullara ver
                http_client.cookie_qur(netice["cookies"])
        else:
            headless_xeta = (cp.stderr or cp.stdout or f"rc={cp.returncode}").strip()[-400:]
    except Exception as e:
        headless_xeta = f"{type(e).__name__}: {e}"[-400:]
    if not netice:
        netice = crawler_modulu.Crawler(hedef, maks_sehife=maks_sehife).gez()
    purl, formalar = netice["parametrli_url"], netice["formalar"]
    sehifeler_list = netice.get("sehife_list", [])

    bildir("texnologiya")
    tech = tech_detect.askarla(hedef)

    # 3) PASSİV modullar (paralel)
    bildir("fayllar"); bildir("basliqlar"); bildir("cors"); bildir("kohne_js")
    bildir("metodlar"); bildir("mixed"); bildir("yollar"); bildir("sirr")
    bildir("tls"); bildir("clickjacking"); bildir("graphql"); bildir("host"); bildir("waf")
    passiv = [
        (sensitive_files.yoxla, (hedef, hesabat)),
        (headers.yoxla, (hedef, hesabat)),
        (cors.yoxla, (hedef, hesabat)),
        (js_libs.yoxla, (hedef, hesabat)),
        (http_methods.yoxla, (hedef, hesabat)),
        (mixed_content.yoxla, (hedef, hesabat)),
        (hidden_paths.yoxla, (hedef, hesabat)),
        (secrets_leak.yoxla, (hedef, hesabat)),
        (tls_analiz.yoxla, (hedef, hesabat)),
        (clickjacking.yoxla, (hedef, hesabat)),
        (graphql.yoxla, (hedef, hesabat)),
        (host_header.yoxla, (hedef, hesabat)),
        (waf.yoxla, (hedef, hesabat)),
        (xxe.yoxla, (hedef, hesabat)),
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
    bildir("cmd"); bildir("lfi"); bildir("csrf"); bildir("ssrf"); bildir("idor")
    bildir("oob"); bildir("stored"); bildir("ssti"); bildir("crlf")
    aktiv = [
        (xss.yoxla, (purl, formalar, hesabat)),
        (sqli.yoxla, (purl, formalar, hesabat)),
        (ssti.yoxla, (purl, formalar, hesabat)),
        (crlf.yoxla, (purl, hesabat)),
        (open_redirect.yoxla, (purl, hesabat)),
        (command_injection.yoxla, (purl, hesabat)),
        (lfi.yoxla, (purl, hesabat)),
        (csrf.yoxla, (formalar, hesabat)),
        (ssrf.yoxla, (purl, hesabat)),
        (idor.yoxla, (purl, hesabat, auth_edildi)),
        (oob_checks.yoxla, (purl, hedef, oob_base, hesabat)),
        (stored_xss.yoxla, (formalar, sehifeler_list, hesabat)),
    ]
    http_client.modullari_paralel_islet(aktiv)

    bildir("bitdi")
    hesabat.sirala()

    tapintilar = [{
        "ciddilik": t["ciddilik"], "kod": t["kod"], "yer": t["yer"],
        "cvss": reporter.cvss(t["ciddilik"]),
        "owasp": owasp.kateqoriya(t["kod"]),
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
        "headless": headless, "headless_xeta": headless_xeta,
        "auth_edildi": auth_edildi,
        "icmal": reporter.icmal(hesabat.tapintilar),
        "owasp_icmal": owasp.icmal(hesabat.tapintilar),
        "owasp_adlar": owasp.ADLAR,
        "statistika": {"sehifeler": netice["sehifeler"],
                       "formalar": len(formalar), "parametrli_url": len(purl)},
        "yoxlamalar": yoxlamalar, "tapintilar": tapintilar,
    }
