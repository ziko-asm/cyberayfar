#!/usr/bin/env python3
"""
VEB SERVER (Flask) — lokal + Vercel
===================================
Lokal:  py app.py  -> http://127.0.0.1:5000  (test rejimi, rahat)
Vercel: avtomatik   -> icazə qapısı AÇIQ (yalnız öz domenlərin + təsdiqli müştərilər)

Mühit dəyişənləri (Vercel-də Settings -> Environment Variables):
  SAHIB_DOMENLER = saytyoxla.vercel.app,saytyoxla.az   (öz domenlərin, vergüllə)
"""

import os
import json
import queue
import threading

from flask import Flask, request, jsonify, render_template, Response
import motor
from core import authorization

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE, "templates"))

# Vercel-də "VERCEL" dəyişəni avtomatik var -> PROD rejimi
PROD = bool(os.environ.get("VERCEL"))
TEST_REJIMI = not PROD                       # lokalda rahat, canlıda təhlükəsiz
MAKS_SEHIFE = 15 if PROD else 30             # serverless timeout üçün az
ALLOWLIST = tuple(
    d.strip().lower()
    for d in os.environ.get("SAHIB_DOMENLER", "saytyoxla.vercel.app").split(",")
    if d.strip()
)


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data, ensure_ascii=False)}\n\n"


@app.route("/")
def ana_sehife():
    return render_template("index.html")


@app.route("/api/skan-stream")
def api_skan_stream():
    """Canlı irəliləmə (lokalda işləyir; Vercel-də frontend POST-a keçir)."""
    hedef = (request.args.get("hedef") or "").strip()

    def generate():
        if not hedef:
            yield _sse({"tip": "xeta", "mesaj": "Sayt ünvanı boşdur"})
            return
        q = queue.Queue()
        qutu = {}

        def ilerleme(addim):
            q.put({"tip": "ilerleme", "addim": addim})

        def isle():
            try:
                qutu["data"] = motor.skan_et(
                    hedef, test_rejimi=TEST_REJIMI, maks_sehife=MAKS_SEHIFE,
                    ilerleme=ilerleme, allowlist=ALLOWLIST)
            except authorization.IcazeXetasi as e:
                qutu["xeta"] = str(e)
            except Exception as e:
                qutu["xeta"] = f"Skan xətası: {e}"
            finally:
                q.put({"tip": "_son"})

        threading.Thread(target=isle, daemon=True).start()
        while True:
            item = q.get()
            if item.get("tip") == "_son":
                break
            yield _sse(item)

        if "xeta" in qutu:
            yield _sse({"tip": "xeta", "mesaj": qutu["xeta"]})
        else:
            yield _sse({"tip": "netice", "data": qutu["data"]})

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/skan", methods=["POST"])
def api_skan():
    """Sadə (axınsız) endpoint — Vercel üçün əsas, ehtiyat kimi."""
    data = request.get_json(force=True)
    hedef = (data.get("hedef") or "").strip()
    if not hedef:
        return jsonify({"xeta": "Sayt ünvanı boşdur"}), 400
    try:
        return jsonify(motor.skan_et(
            hedef, test_rejimi=TEST_REJIMI, maks_sehife=MAKS_SEHIFE,
            allowlist=ALLOWLIST))
    except authorization.IcazeXetasi as e:
        return jsonify({"xeta": str(e)}), 403
    except Exception as e:
        return jsonify({"xeta": f"Skan xətası: {e}"}), 500


if __name__ == "__main__":
    print("\n  CYBERAYFAR SCANER işə düşdü!")
    print("  Brauzerdə aç:  http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=True, threaded=True)
