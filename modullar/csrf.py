"""
MODUL: CSRF (tokensiz formalar)
===============================
POST formalarında CSRF token olmaması = hücumçu istifadəçi adından
saxta sorğu göndərə bilər. Şəbəkə sorğusu yoxdur — crawler-in tapdığı
forma məlumatından işləyir (sürətli).
"""

TOKEN_ACAR = ("csrf", "token", "_token", "authenticity", "nonce", "xsrf")


def yoxla(formalar, hesabat):
    for form in formalar:
        if form["metod"] != "post":
            continue
        adlar = " ".join(i["ad"].lower() for i in form["inputlar"])
        if not any(k in adlar for k in TOKEN_ACAR):
            hesabat.elave_et("orta", "csrf_yox", form["hereket"],
                             menbe=form["menbe_sehife"])
