#!/usr/bin/env python3
"""
=======================================================================
  SaytYoxla DAST Skaner — İcazəli Veb Zəiflik Skaneri
=======================================================================
İşlədilmə:
  python3 skan.py https://saytyoxla.vercel.app --oz-saytim

  --oz-saytim : TEST rejimi — yalnız ÖZ saytlarını sınamaq üçün icazə
                yoxlamasını atlayır. Real müştəridə bunu İŞLƏTMƏ.

Real məhsulda icazə qapısı (core/authorization) sahibliyi yoxlayır.
Qanun: yalnız sahibi olduğun və ya yazılı icazən olan saytları skan et.
=======================================================================
"""

import sys
import argparse
from urllib.parse import urlparse

from core import authorization, crawler as crawler_modulu, reporter
from modullar import sensitive_files, email_spoof, xss, sqli

# Serverində saxlanılan gizli açar (token yaratmaq üçün). Real məhsulda
# bu mühit dəyişənindən gəlməlidir, koda yazılmamalıdır.
GIZLI_ACAR = "DEYISDIR-MENI-uzun-tesadufi-acar"


def main():
    p = argparse.ArgumentParser(description="SaytYoxla DAST Skaner")
    p.add_argument("hedef", help="Skan ediləcək sayt, məs: https://site.com")
    p.add_argument("--oz-saytim", action="store_true",
                   help="TEST rejimi: icazə yoxlamasını atla (yalnız öz saytın)")
    p.add_argument("--maks-sehife", type=int, default=40,
                   help="Maksimum gəziləcək səhifə sayı")
    args = p.parse_args()

    hedef = args.hedef if "://" in args.hedef else "https://" + args.hedef
    domen = urlparse(hedef).netloc

    print("\n" + "=" * 64)
    print("  SaytYoxla DAST Skaner v1.0")
    print(f"  Hədəf: {hedef}")
    print("=" * 64)

    # 1) İCAZƏ QAPISI ----------------------------------------------------
    print("\n[1/5] İcazə yoxlanılır...")
    try:
        authorization.icazeni_tesdiqle(domen, GIZLI_ACAR,
                                       test_rejimi=args.oz_saytim)
    except authorization.IcazeXetasi as e:
        print(e)
        sys.exit(1)

    hesabat = reporter.Hesabat(hedef)

    # 2) CRAWL -----------------------------------------------------------
    print("\n[2/5] Sayt gəzilir (crawl)...")
    crawler = crawler_modulu.Crawler(hedef, maks_sehife=args.maks_sehife)
    netice = crawler.gez()
    print(f"  {netice['sehifeler']} səhifə, {len(netice['formalar'])} forma, "
          f"{len(netice['parametrli_url'])} parametrli URL tapıldı.")

    # 3) PASSİV YOXLAMALAR ----------------------------------------------
    print("\n[3/5] Həssas fayllar və domain spoofing yoxlanılır...")
    sensitive_files.yoxla(hedef, hesabat)
    email_spoof.yoxla(domen, hesabat)

    # 4) AKTİV YOXLAMALAR (XSS / SQLi) ----------------------------------
    print("\n[4/5] XSS yoxlanılır...")
    xss.yoxla(netice["parametrli_url"], netice["formalar"], hesabat)

    print("\n[5/5] SQL Injection yoxlanılır...")
    sqli.yoxla(netice["parametrli_url"], netice["formalar"], hesabat)

    # 5) HESABAT ---------------------------------------------------------
    hesabat.cap_et()
    print(f"  Təhlükəsizlik balı: {hesabat.xal_hesabla()}/100\n")


if __name__ == "__main__":
    main()
