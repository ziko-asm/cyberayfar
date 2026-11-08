"""
CRAWLER (Örümcək) — paralel + sitemap/robots
=============================================
Mərhələ 2: sitemap.xml və robots.txt oxuyur (ağıllı crawl).
Mərhələ 3: səhifələri paralel çəkir (sürətli).
"""

import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from core import http_client


class Crawler:
    def __init__(self, bas_url: str, maks_sehife=40, timeout=8):
        self.bas_url = bas_url.rstrip("/")
        self.domen = urlparse(bas_url).netloc
        self.maks_sehife = maks_sehife
        self.timeout = timeout
        self.gorulmus = set()
        self.formalar = []
        self.parametrli_url = []

    def _eyni_domen(self, url):
        return urlparse(url).netloc == self.domen

    def _sitemapdan_oxu(self):
        """sitemap.xml varsa, URL-ləri oradan götür (ağıllı)."""
        tapilan = []
        for yol in ("/sitemap.xml", "/sitemap_index.xml"):
            cavab = http_client.al(self.bas_url + yol, timeout=self.timeout)
            if cavab and cavab.status_code == 200:
                tapilan += re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", cavab.text)
        return [u for u in tapilan if self._eyni_domen(u)][:self.maks_sehife]

    def gez(self):
        novbe = [self.bas_url] + self._sitemapdan_oxu()

        while novbe and len(self.gorulmus) < self.maks_sehife:
            # Bu "dalğanı" paralel çək
            dalga = []
            while novbe and len(dalga) < http_client.PARALEL and \
                    len(self.gorulmus) + len(dalga) < self.maks_sehife:
                u = novbe.pop(0)
                if u not in self.gorulmus and u not in dalga:
                    dalga.append(u)
            if not dalga:
                break

            cavablar = http_client.paralel_al(dalga, timeout=self.timeout)
            for url, cavab in cavablar.items():
                self.gorulmus.add(url)
                if not cavab or "text/html" not in cavab.headers.get("Content-Type", ""):
                    continue
                corba = BeautifulSoup(cavab.text, "html.parser")

                for form in corba.find_all("form"):
                    self.formalar.append(self._form_cixar(form, url))

                for a in corba.find_all("a", href=True):
                    tam = urljoin(url, a["href"]).split("#")[0]
                    if self._eyni_domen(tam) and tam not in self.gorulmus:
                        novbe.append(tam)
                        if parse_qs(urlparse(tam).query) and tam not in self.parametrli_url:
                            self.parametrli_url.append(tam)

        return {
            "sehifeler": len(self.gorulmus),
            "formalar": self.formalar,
            "parametrli_url": self.parametrli_url,
        }

    def _form_cixar(self, form, sehife_url):
        hereket = urljoin(sehife_url, form.get("action") or sehife_url)
        metod = (form.get("method") or "get").lower()
        inputlar = []
        for tag in form.find_all(["input", "textarea", "select"]):
            ad = tag.get("name")
            if ad:
                inputlar.append({"ad": ad, "tip": tag.get("type", "text")})
        return {"hereket": hereket, "metod": metod, "inputlar": inputlar,
                "menbe_sehife": sehife_url}
