"""
CRAWLER (Örümcək)
=================
Saytı gəzir, bütün daxili linkləri və FORMALARI toplayır.
XSS/SQLi modulları bu formalara və URL parametrlərinə "təhlükəsiz
test inputları" göndərəcək.

Vacib: yalnız eyni domen daxilində gəzir (başqa saytlara keçmir)
və səhifə sayını məhdudlaşdırır (sonsuz döngəyə düşməmək üçün).
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs


class Crawler:
    def __init__(self, bas_url: str, maks_sehife=40, timeout=10):
        self.bas_url = bas_url.rstrip("/")
        self.domen = urlparse(bas_url).netloc
        self.maks_sehife = maks_sehife
        self.timeout = timeout
        self.gorulmus = set()          # artıq gəzilmiş URL-lər
        self.formalar = []             # tapılan formalar
        self.parametrli_url = []       # ?id=5 kimi parametrli URL-lər
        self.sessiya = requests.Session()
        self.sessiya.headers.update({
            "User-Agent": "SaytYoxla-Skaner/1.0 (icazeli-tehlukesizlik-testi)"
        })

    def _eyni_domen(self, url: str) -> bool:
        return urlparse(url).netloc == self.domen

    def gez(self):
        """BFS ilə saytı gəzir."""
        novbe = [self.bas_url]
        while novbe and len(self.gorulmus) < self.maks_sehife:
            url = novbe.pop(0)
            if url in self.gorulmus:
                continue
            self.gorulmus.add(url)

            try:
                cavab = self.sessiya.get(url, timeout=self.timeout)
            except requests.RequestException:
                continue
            if "text/html" not in cavab.headers.get("Content-Type", ""):
                continue

            corba = BeautifulSoup(cavab.text, "html.parser")

            # Formaları topla
            for form in corba.find_all("form"):
                self.formalar.append(self._form_cixar(form, url))

            # Linkləri topla
            for a in corba.find_all("a", href=True):
                tam = urljoin(url, a["href"]).split("#")[0]
                if self._eyni_domen(tam) and tam not in self.gorulmus:
                    novbe.append(tam)
                    # Parametrli URL-ləri də ayrıca saxla (SQLi/XSS üçün)
                    if parse_qs(urlparse(tam).query):
                        self.parametrli_url.append(tam)

        return {
            "sehifeler": len(self.gorulmus),
            "formalar": self.formalar,
            "parametrli_url": self.parametrli_url,
        }

    def _form_cixar(self, form, sehife_url):
        """Bir formanı test üçün lazım olan məlumata çevirir."""
        hereket = urljoin(sehife_url, form.get("action") or sehife_url)
        metod = (form.get("method") or "get").lower()
        inputlar = []
        for tag in form.find_all(["input", "textarea", "select"]):
            ad = tag.get("name")
            if ad:
                inputlar.append({
                    "ad": ad,
                    "tip": tag.get("type", "text"),
                })
        return {"hereket": hereket, "metod": metod, "inputlar": inputlar,
                "menbe_sehife": sehife_url}
