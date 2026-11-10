"""Reqressiya: laboratoriya saytında aşkarlama düşməməli, yalançı müsbət çıxmamalıdır."""

import benchmark

# Bu hədd yalnız YUXARI qaldırılmalıdır (aşkarlama yaxşılaşdıqca).
# Cari: 98% (39/40). CI runnerlərində kiçik dəyişkənliyə yer saxlanılıb.
MIN_RECALL = 0.90


def test_benchmark_heddleri():
    n = benchmark.olc()
    tapilmayan = [s["ad"] for s in n["setirler"] if not s["tapildi"]]
    assert n["yalanci_musbet"] == [], n["yalanci_musbet"]
    assert n["spa_yalanci_musbet"] == [], n["spa_yalanci_musbet"]
    assert n["recall"] >= MIN_RECALL, f"recall={n['recall']} tapılmayan={tapilmayan}"
