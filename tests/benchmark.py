#!/usr/bin/env python3
"""
BENCHMARK — skanerin dəqiqliyini ölçür
======================================
Lokal "bilərəkdən zəif" laboratoriya saytını (tests/lab/zeif_sayt.py) işə
salır, skan edir və nəticəni həqiqət cədvəli (GERCEK) ilə tutuşdurur:

  • Aşkarlama (recall)  = tapılan real zəifliklər / bütün real zəifliklər
  • Yalançı müsbət      = təhlükəsiz (/s/...) səhifələrdəki tapıntılar
  • SPA testi           = hər yola 200 verən saytda "həssas fayl" uydurulmamalıdır

İşlətmə:
    python tests/benchmark.py            # cədvəl + BENCHMARK.md yeniləyir
    python tests/benchmark.py --json     # maşın üçün JSON

Qeyd: laboratoriya bu skanerlə birlikdə yazılıb, ona görə nəticə YUXARI
sərhəddir — real saytlarda aşkarlama bundan aşağı olacaq. Müstəqil ölçü üçün
OWASP Juice Shop / DVWA kimi kənar hədəflərdə də sınayın.
"""

import os
import sys
import json
import time
import threading

KOK = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, KOK)
sys.path.insert(0, os.path.join(KOK, "tests"))

from waitress.server import create_server   # noqa: E402

import motor                                # noqa: E402
from lab import zeif_sayt                   # noqa: E402


def _server_basla(tetbiq):
    # Waitress (əsl WSGI server): werkzeug dev-serveri 500-dən sonra bağlantını
    # düzgün bağlamır və skaner həmin cavabı itirir — real serverlər (nginx/
    # gunicorn/waitress) belə etmir, ona görə ölçü waitress-lə aparılır.
    srv = create_server(tetbiq, host="127.0.0.1", port=0, threads=24)
    threading.Thread(target=srv.run, daemon=True).start()

    class _Srv:
        def __init__(s, srv): s._srv = srv
        def shutdown(s): s._srv.close()
    return _Srv(srv), f"http://127.0.0.1:{srv.getsockname()[1]}"


def olc():
    """Hər iki laboratoriyanı skan edir -> nəticə lüğəti."""
    srv, url = _server_basla(zeif_sayt.app)
    spa_srv, spa_url = _server_basla(zeif_sayt.spa)
    try:
        t0 = time.time()
        netice = motor.skan_et(url, test_rejimi=True, maks_sehife=80)
        muddet = time.time() - t0
        spa_netice = motor.skan_et(spa_url, test_rejimi=True, maks_sehife=10)
    finally:
        srv.shutdown()
        spa_srv.shutdown()

    tap = netice["tapintilar"]
    setirler = []
    for ad, yer, kodlar in zeif_sayt.GERCEK:
        uygun = [t for t in tap if t["kod"] in kodlar and yer in t["yer"]
                 and zeif_sayt.TEHLUKESIZ_PREFIKS not in t["yer"]]
        setirler.append({"ad": ad, "yer": yer or "/", "tapildi": bool(uygun),
                         "kod": uygun[0]["kod"] if uygun else None})
    yalanci = [{"kod": t["kod"], "yer": t["yer"]} for t in tap
               if zeif_sayt.TEHLUKESIZ_PREFIKS in t["yer"]]
    spa_yalanci = [{"kod": t["kod"], "yer": t["yer"]} for t in spa_netice["tapintilar"]
                   if t["kod"] in ("hessas_fayl", "gizli_yol", "qovluq_siyahisi")]
    tapilan = sum(1 for s in setirler if s["tapildi"])
    return {
        "cemi": len(setirler), "tapilan": tapilan,
        "recall": round(tapilan / len(setirler), 3),
        "yalanci_musbet": yalanci, "spa_yalanci_musbet": spa_yalanci,
        "muddet_san": round(muddet, 1),
        "sehife": netice["statistika"]["sehifeler"], "forma": netice["statistika"]["formalar"],
        "setirler": setirler,
    }


def markdown(n):
    s = ["# Skaner benchmarkı", "",
         "Lokal laboratoriya saytına (`tests/lab/zeif_sayt.py`) qarşı ölçülüb: hər zəifliyin",
         "zəif (`/v/…`) və təhlükəsiz (`/s/…`) nüsxəsi var. `python tests/benchmark.py` ilə yenilənir.", "",
         "| Göstərici | Nəticə |", "|---|---|",
         f"| Aşkarlama (recall) | **{n['tapilan']} / {n['cemi']}** ({n['recall'] * 100:.0f}%) |",
         f"| Yalançı müsbət (təhlükəsiz səhifələr) | **{len(n['yalanci_musbet'])}** |",
         f"| Yalançı müsbət (SPA catch-all) | **{len(n['spa_yalanci_musbet'])}** |",
         f"| Gəzilən səhifə / forma | {n['sehife']} / {n['forma']} |",
         f"| Skan müddəti | {n['muddet_san']} san |", "",
         "> Laboratoriya bu skanerlə birlikdə yazılıb, ona görə bu rəqəm **yuxarı sərhəddir**.",
         "> Real saytlarda aşkarlama aşağı olacaq; skaner əl ilə pentesti əvəz etmir.", "",
         "**Məlum məhdudiyyət:** forma üzərindən *kor* (auth-bypass) SQL injection",
         "hələ aşkarlanmır — yalnız xəta-əsaslı forma SQLi tapılır. JS ilə render",
         "olunan (SPA) səhifələr yalnız serverdə Playwright olanda tam gəzilir.", "",
         "| Zəiflik | Yer | Tapıldı |", "|---|---|---|"]
    for r in n["setirler"]:
        s.append(f"| {r['ad']} | `{r['yer']}` | {'✅' if r['tapildi'] else '❌'} |")
    if n["yalanci_musbet"] or n["spa_yalanci_musbet"]:
        s += ["", "## Yalançı müsbətlər", ""]
        s += [f"- `{y['kod']}` — `{y['yer']}`" for y in n["yalanci_musbet"] + n["spa_yalanci_musbet"]]
    return "\n".join(s) + "\n"


if __name__ == "__main__":
    n = olc()
    if "--json" in sys.argv:
        print(json.dumps(n, ensure_ascii=False, indent=2))
    else:
        for r in n["setirler"]:
            print(("  OK   " if r["tapildi"] else "  MISS ") + f"{r['ad']:<34} {r['yer']}")
        print(f"\n  Aşkarlama: {n['tapilan']}/{n['cemi']} ({n['recall'] * 100:.0f}%)   müddət: {n['muddet_san']}s"
              f"   səhifə/forma: {n['sehife']}/{n['forma']}")
        for y in n["yalanci_musbet"]:
            print(f"  YALANÇI MÜSBƏT: {y['kod']}  {y['yer']}")
        for y in n["spa_yalanci_musbet"]:
            print(f"  YALANÇI MÜSBƏT (SPA): {y['kod']}  {y['yer']}")
        if "--yazma" not in sys.argv:
            with open(os.path.join(KOK, "BENCHMARK.md"), "w", encoding="utf-8", newline="\n") as f:
                f.write(markdown(n))
