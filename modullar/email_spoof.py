"""
MODUL: DOMAIN / EMAIL SPOOFING YOXLAMASI
========================================
"Domain spoofing" = kimsə SƏNİN domenindən saxta e-poçt göndərə bilirmi?
Bu, DNS qeydləri ilə qarşısı alınır:
  • SPF   -> kim sənin adından mail göndərə bilər
  • DMARC -> saxta mail-lə nə edilsin (rədd/karantin)
  • DKIM  -> mail-in imzalanması

Əgər bunlar yoxdursa/zəifdirsə, fişinq üçün domenin açıqdır.
Bu tam PASSİV yoxlamadır (yalnız DNS oxuyur).
"""

import dns.resolver


def _txt_qeydleri(domen):
    try:
        return [q.to_text().strip('"') for q in dns.resolver.resolve(domen, "TXT")]
    except Exception:
        return []


def yoxla(domen: str, hesabat):
    domen = domen.replace("https://", "").replace("http://", "").strip("/").split("/")[0]

    # --- SPF ---
    spf = [t for t in _txt_qeydleri(domen) if t.lower().startswith("v=spf1")]
    if not spf:
        hesabat.elave_et("yuksek", "spf_yox", domen, domen=domen)
    elif "+all" in spf[0]:
        hesabat.elave_et("kritik", "spf_zeif", domen, domen=domen)

    # --- DMARC ---
    dmarc = _txt_qeydleri(f"_dmarc.{domen}")
    dmarc = [t for t in dmarc if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        hesabat.elave_et("yuksek", "dmarc_yox", f"_dmarc.{domen}", domen=domen)
    elif "p=none" in dmarc[0].lower():
        hesabat.elave_et("orta", "dmarc_passiv", f"_dmarc.{domen}", domen=domen)

    # --- DKIM (ümumi selektorları yoxla) ---
    dkim_var = False
    for selektor in ("google", "default", "selector1", "k1", "dkim"):
        if _txt_qeydleri(f"{selektor}._domainkey.{domen}"):
            dkim_var = True
            break
    if not dkim_var:
        hesabat.elave_et("asagi", "dkim_yox", domen, domen=domen)
