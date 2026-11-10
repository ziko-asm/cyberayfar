#!/usr/bin/env python3
"""
VEB SERVER (Flask) — lokal + Vercel
===================================
Lokal:  py app.py  -> http://127.0.0.1:5000  (test rejimi, rahat)
Vercel: avtomatik   -> icazə qapısı AÇIQ (yalnız öz domenlərin + təsdiqli müştərilər)

Mühit dəyişənləri (Vercel-də Settings -> Environment Variables):
  SAHIB_DOMENLER    = saytyoxla.vercel.app,saytyoxla.az   (öz domenlərin, vergüllə)
  SKANER_GIZLI_ACAR = uzun təsadüfi sətir (sahiblik tokenlərinin açarı)
"""

import os
import json
import queue
import secrets
import threading

from flask import Flask, request, jsonify, render_template, Response, g
import motor
from core import authorization

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE, "templates"))

# Vercel "VERCEL", Render "RENDER" dəyişənini avtomatik qoyur -> PROD rejimi
# (PROD-da təhlükəsizlik qapısı AKTİV: yalnız allowlist/təsdiqli domenlər)
PROD = bool(os.environ.get("VERCEL") or os.environ.get("RENDER")
            or os.environ.get("PROD"))
TEST_REJIMI = not PROD                       # lokalda rahat, canlıda təhlükəsiz
MAKS_SEHIFE = 15 if PROD else 30             # serverless timeout üçün az
# Operatorun öz domenləri (ayfar.dev-dəki layihələr) — həmişə icazəli.
# Bunlar koda yazılıb; Vercel-dəki SAHIB_DOMENLER env dəyişəni əlavə domen üçündür.
SAHIB_DEFOLT = (
    "ayfar.dev", "www.ayfar.dev",
    "saytyoxla.vercel.app",
    "provguard.vercel.app",
    "prompt-injection-detector-snowy.vercel.app",
    "graphguard-iot.vercel.app",
    "agent-audit-ten.vercel.app",
    "bathshop-az-selling-site.vercel.app",
    "mexaniki-emal.vercel.app",
    "ai-nids-robustness.streamlit.app",
    "mansia.az", "www.mansia.az",
)
_env_domenler = tuple(
    d.strip().lower()
    for d in os.environ.get("SAHIB_DOMENLER", "").split(",")
    if d.strip()
)
# Defolt + env (təkrarsız)
ALLOWLIST = tuple(dict.fromkeys(SAHIB_DEFOLT + _env_domenler))

FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48">'
    '<rect width="48" height="48" rx="10" fill="#03050a"/>'
    '<path d="M24 5L8 11v11c0 10 6.8 17.2 16 21 9.2-3.8 16-11 16-21V11L24 5z" '
    'stroke="#00ff9c" stroke-width="2.5" fill="rgba(0,255,156,.08)"/>'
    '<path d="M17 24l5 5 9-11" stroke="#00ff9c" stroke-width="3" fill="none" '
    'stroke-linecap="round" stroke-linejoin="round"/></svg>'
)


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


def _kok_url() -> str:
    return request.url_root.replace("http://", "https://", 1) if PROD \
        else request.url_root


# ---------------------------------------------------------------- başlıqlar
@app.before_request
def _nonce_yarat():
    g.nonce = secrets.token_urlsafe(16)


@app.after_request
def _tehlukesizlik_basliqlari(cavab):
    """Skanerin başqalarında yoxladığı başlıqları özü də göndərir."""
    csp = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{g.get('nonce', '')}'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data:; connect-src 'self'; "
        "object-src 'none'; base-uri 'self'; form-action 'self'; "
        "frame-ancestors 'none'"
    )
    h = cavab.headers
    h.setdefault("Content-Security-Policy", csp)
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    h.setdefault("Permissions-Policy",
                 "camera=(), microphone=(), geolocation=(), payment=()")
    h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    if PROD:
        h.setdefault("Strict-Transport-Security",
                     "max-age=63072000; includeSubDomains; preload")
    return cavab


# ---------------------------------------------------------------- səhifələr
@app.route("/")
def ana_sehife():
    return render_template("index.html", nonce=g.nonce, kok_url=_kok_url(),
                           yoxlama_sayi=len(motor.KATEQORIYALAR))


@app.route("/favicon.svg")
@app.route("/favicon.ico")
def favicon():
    return Response(FAVICON_SVG, mimetype="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=604800"})


@app.route("/robots.txt")
def robots():
    return Response(
        f"User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /oob/\n\n"
        f"Sitemap: {_kok_url()}sitemap.xml\n", mimetype="text/plain")


@app.route("/sitemap.xml")
def sitemap():
    return Response(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"  <url><loc>{_kok_url()}</loc></url>\n</urlset>\n",
        mimetype="application/xml")


@app.errorhandler(404)
def tapilmadi(_e):
    if request.path.startswith("/api/"):
        return jsonify({"xeta": "Tapılmadı", "xeta_kod": "tapilmadi_404"}), 404
    return render_template("404.html"), 404


@app.errorhandler(405)
def metod_yox(_e):
    if request.path.startswith("/api/"):
        return jsonify({"xeta": "Bu metod dəstəklənmir",
                        "xeta_kod": "metod"}), 405
    return render_template("404.html"), 405


@app.route("/health")
def health():
    """Keep-alive / monitorinq üçün ucuz endpoint (serveri oyaq saxlayır)."""
    return {"status": "ok", "headless": bool(os.environ.get("RENDER"))}, 200


@app.route("/oob/<token>", methods=["GET", "POST", "PUT", "HEAD", "OPTIONS"])
def oob_callback(token):
    """OOB collaborator: hədəf buraya sorğu edərsə, blind zəiflik təsdiqlənir."""
    from core import oob as oob_store
    oob_store.qeyd_et(token, {"ip": request.remote_addr,
                              "metod": request.method,
                              "ua": request.headers.get("User-Agent", "")})
    return "1", 200


def _oob_base():
    # Blind OOB davamlı serverdə (Render/lokal) işləyir; Vercel efemer -> söndür
    if os.environ.get("VERCEL"):
        return None
    try:
        return request.host_url.rstrip("/")
    except Exception:
        return None


# ---------------------------------------------------------------- API
def _icaze_xetasi(e: authorization.IcazeXetasi) -> dict:
    """İnterfeys `xeta_kod`-a görə öz dilində göstərir; `xeta` CLI mətni."""
    return {"xeta": str(e).strip(), "xeta_kod": e.kod,
            "domen": e.domen, "token": e.token}


def _sorgunu_oxu():
    """GET (?hedef=) və POST (JSON) sorğusundan (hedef, auth) çıxarır."""
    if request.method == "POST":
        data = request.get_json(force=True, silent=True)
        if not isinstance(data, dict):
            return None, None
    else:
        data = request.args
    hedef = str(data.get("hedef") or "").strip()
    auth = None
    user = str(data.get("istifadeci") or "").strip()
    parol = str(data.get("parol") or "")
    if request.method == "POST" and user and parol:
        auth = {"user": user, "parol": parol,
                "login_url": str(data.get("login_url") or "").strip() or None}
    return hedef, auth


def _on_yoxlama(hedef):
    """Skandan əvvəl: boş ünvan / icazə. Xəta varsa (cavab, status)."""
    if not hedef:
        return jsonify({"xeta": "Sayt ünvanı boşdur", "xeta_kod": "bos"}), 400
    try:
        motor.icaze_yoxla(hedef, test_rejimi=TEST_REJIMI, allowlist=ALLOWLIST)
    except authorization.IcazeXetasi as e:
        return jsonify(_icaze_xetasi(e)), (403 if e.kod == "sahiblik" else 400)
    return None


@app.route("/api/skan-stream", methods=["GET", "POST"])
def api_skan_stream():
    """Canlı irəliləmə (SSE). POST — girişli skan da REAL addımları görür
    və parol URL-də getmir. Boş ünvan / icazə xətası axından ƏVVƏL düzgün
    HTTP statusu (400/403) ilə qayıdır."""
    hedef, auth = _sorgunu_oxu()
    if hedef is None:
        return jsonify({"xeta": "Yanlış sorğu", "xeta_kod": "sorgu"}), 400
    xeta = _on_yoxlama(hedef)
    if xeta:
        return xeta
    ob = _oob_base()

    def generate():
        q = queue.Queue()
        qutu = {}

        def ilerleme(addim):
            q.put({"tip": "ilerleme", "addim": addim})

        def isle():
            try:
                qutu["data"] = motor.skan_et(
                    hedef, test_rejimi=TEST_REJIMI, maks_sehife=MAKS_SEHIFE,
                    ilerleme=ilerleme, allowlist=ALLOWLIST, auth=auth,
                    oob_base=ob, icaze_verilib=True)
            except authorization.IcazeXetasi as e:
                qutu["xeta"] = dict(_icaze_xetasi(e), tip="xeta")
            except Exception:
                app.logger.exception("Skan xətası")
                qutu["xeta"] = {"tip": "xeta", "xeta_kod": "skan",
                                "xeta": "Skan xətası"}
            finally:
                q.put({"tip": "_son"})

        threading.Thread(target=isle, daemon=True).start()
        while True:
            item = q.get()
            if item.get("tip") == "_son":
                break
            yield _sse(item)

        if "xeta" in qutu:
            yield _sse(qutu["xeta"])
        else:
            yield _sse({"tip": "netice", "data": qutu["data"]})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/skan", methods=["POST"])
def api_skan():
    """Sadə (axınsız) endpoint — bütün nəticə bir JSON cavabda."""
    hedef, auth = _sorgunu_oxu()
    if hedef is None:
        return jsonify({"xeta": "Yanlış sorğu", "xeta_kod": "sorgu"}), 400
    xeta = _on_yoxlama(hedef)
    if xeta:
        return xeta
    try:
        return jsonify(motor.skan_et(
            hedef, test_rejimi=TEST_REJIMI, maks_sehife=MAKS_SEHIFE,
            allowlist=ALLOWLIST, auth=auth, oob_base=_oob_base(),
            icaze_verilib=True))
    except authorization.IcazeXetasi as e:
        return jsonify(_icaze_xetasi(e)), (403 if e.kod == "sahiblik" else 400)
    except Exception:
        app.logger.exception("Skan xətası")
        return jsonify({"xeta": "Skan xətası", "xeta_kod": "skan"}), 500


if __name__ == "__main__":
    print("\n  CYBERAYFAR SCANNER işə düşdü!")
    print("  Brauzerdə aç:  http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
