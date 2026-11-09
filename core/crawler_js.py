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


def _login(page, login_url, user, pw, timeout):
    """Headless login: forma tapır, doldurur, göndərir. True = forma tapıldı."""
    try:
        page.goto(login_url, wait_until="networkidle", timeout=timeout)
    except Exception:
        try:
            page.goto(login_url, wait_until="domcontentloaded", timeout=timeout)
        except Exception:
            return False
    page.wait_for_timeout(500)
    if page.locator('input[type="password"]').count() == 0:
        return False
    user_sel = None
    for sel in ('input[type="email"]', 'input[name*="user" i]',
                'input[name*="email" i]', 'input[name*="login" i]',
                'input[id*="user" i]', 'input[type="text"]'):
        if page.locator(sel).count() > 0:
            user_sel = sel
            break
    if not user_sel:
        return False
    try:
        page.fill(user_sel, user)
        page.fill('input[type="password"]', pw)
        btn = page.locator('button[type="submit"], input[type="submit"], '
                           'button:has-text("Login"), button:has-text("Sign in"), '
                           'button:has-text("Log in"), button:has-text("Giriş")')
        if btn.count() > 0:
            btn.first.click()
        else:
            page.locator('input[type="password"]').press("Enter")
        page.wait_for_load_state("networkidle", timeout=timeout)
        page.wait_for_timeout(800)
        return True
    except Exception:
        return False


def gez(bas_url, maks_sehife=20, timeout=15000):
    import os as _os
    bas_url = bas_url.rstrip("/")
    domen = urlparse(bas_url).netloc
    gorulmus, formalar, parametrli = set(), [], set()
    novbe = [bas_url]
    kukiler, auth_ok = [], False

    # Giriş məlumatı (motor env ilə ötürür)
    login_url = _os.environ.get("CYB_LOGIN_URL")
    user = _os.environ.get("CYB_USER")
    pw = _os.environ.get("CYB_PASS")

    launch_kw = {"args": ["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]}
    if EXEC:
        launch_kw["executable_path"] = EXEC

    with sync_playwright() as pw_api:
        browser = pw_api.chromium.launch(**launch_kw)
        ctx = browser.new_context(
            user_agent="CyberAyfar-Scanner/3.0 (+authorized-security-test)",
            ignore_https_errors=True)
        page = ctx.new_page()

        def on_request(req):
            u = req.url.split("#")[0]
            if urlparse(u).netloc == domen and parse_qs(urlparse(u).query):
                parametrli.add(u)
        page.on("request", on_request)

        # AUTENTİFİKASİYA (əgər məlumat verilibsə)
        if user and pw:
            auth_ok = _login(page, login_url or bas_url, user, pw, timeout)
            if auth_ok:
                try:
                    cur = page.url.split("#")[0]
                    if urlparse(cur).netloc == domen and cur not in novbe:
                        novbe.insert(0, cur)   # giriş sonrası səhifədən başla
                except Exception:
                    pass

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
        try:
            kukiler = [{"name": c["name"], "value": c["value"],
                        "domain": c.get("domain", ""), "path": c.get("path", "/")}
                       for c in ctx.cookies()]
        except Exception:
            kukiler = []
        browser.close()

    return {"sehifeler": len(gorulmus), "formalar": formalar,
            "parametrli_url": list(parametrli), "sehife_list": list(gorulmus),
            "cookies": kukiler, "auth_ok": auth_ok}


# Ayrıca proses kimi işlədiləndə (motor subprocess ilə çağırır) —
# bu, Playwright-in web-server thread problemini həll edir.
if __name__ == "__main__":
    import sys
    import json as _json
    _url = sys.argv[1]
    _maks = int(sys.argv[2]) if len(sys.argv) > 2 else 20
    netice = gez(_url, maks_sehife=_maks)
    sys.stdout.write(_json.dumps(netice))
