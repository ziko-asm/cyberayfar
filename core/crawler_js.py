"""
HEADLESS CRAWLER (JS-render)
============================
Əsl Chrome (Playwright) ilə səhifəni açır, JavaScript-i işlədir və
SONRADAN yüklənən səhifə/forma/input-ları da görür. Bu, müasir
React/Vue/Next saytlarında hücum səthini tapmağın yeganə yoludur.

Bonus: səhifənin etdiyi şəbəkə sorğularını (API/XHR) tutub parametrli
URL-ləri də toplayır.

Qeyd: Playwright + brauzer olmayan mühitdə (məs: Vercel) import alınmır
-> motor avtomatik köhnə (requests) crawler-ə keçir.
"""

import os
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright

# Bu mühitdə brauzer başqa yoldadır; Render/Docker-də Playwright özü tapır
EXEC = os.environ.get("PLAYWRIGHT_EXECUTABLE_PATH")


def _form_cixar(form, sehife_url):
    hereket = urljoin(sehife_url, form.get("action") or sehife_url)
    metod = (form.get("method") or "get").lower()
    inputlar = []
    for tag in form.find_all(["input", "textarea", "select"]):
        ad = tag.get("name")
        if ad:
            inputlar.append({"ad": ad, "tip": tag.get("type", "text")})
    return {"hereket": hereket, "metod": metod, "inputlar": inputlar,
            "menbe_sehife": sehife_url}


def gez(bas_url, maks_sehife=20, timeout=15000):
    bas_url = bas_url.rstrip("/")
    domen = urlparse(bas_url).netloc
    gorulmus, formalar, parametrli = set(), [], set()
    novbe = [bas_url]

    launch_kw = {"args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]}
    if EXEC:
        launch_kw["executable_path"] = EXEC

    with sync_playwright() as pw:
        browser = pw.chromium.launch(**launch_kw)
        ctx = browser.new_context(
            user_agent="CyberAyfar-Scanner/3.0 (+authorized-security-test)",
            ignore_https_errors=True)
        page = ctx.new_page()

        def on_request(req):
            u = req.url.split("#")[0]
            if urlparse(u).netloc == domen and parse_qs(urlparse(u).query):
                parametrli.add(u)
        page.on("request", on_request)

        while novbe and len(gorulmus) < maks_sehife:
            url = novbe.pop(0)
            if url in gorulmus:
                continue
            gorulmus.add(url)
            try:
                page.goto(url, wait_until="networkidle", timeout=timeout)
            except Exception:
                try:
                    page.goto(url, wait_until="domcontentloaded", timeout=timeout)
                except Exception:
                    continue
            try:
                page.wait_for_timeout(400)   # JS-in bitməsinə kiçik möhlət
                html = page.content()
            except Exception:
                continue

            corba = BeautifulSoup(html, "html.parser")
            for form in corba.find_all("form"):
                formalar.append(_form_cixar(form, url))
            for a in corba.find_all("a", href=True):
                tam = urljoin(url, a["href"]).split("#")[0]
                if urlparse(tam).netloc == domen and tam not in gorulmus:
                    novbe.append(tam)
                    if parse_qs(urlparse(tam).query):
                        parametrli.add(tam)
        browser.close()

    return {"sehifeler": len(gorulmus), "formalar": formalar,
            "parametrli_url": list(parametrli)}


# Ayrıca proses kimi işlədiləndə (motor subprocess ilə çağırır) —
# bu, Playwright-in web-server thread problemini həll edir.
if __name__ == "__main__":
    import sys
    import json as _json
    _url = sys.argv[1]
    _maks = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    netice = gez(_url, maks_sehife=_maks)
    sys.stdout.write(_json.dumps(netice))
