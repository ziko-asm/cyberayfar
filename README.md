# CYBERAYFAR SCANNER 🔐

İcazəli **Veb Zəiflik Skaneri** (DAST — Dynamic Application Security Testing).
Saytlara zərərsiz test sorğuları göndərib zəiflikləri tapır: XSS, SQL/NoSQL
injection, SSTI, LFI, SSRF, CRLF, IDOR, təhlükəsizlik başlıqları, TLS, həssas
fayllar, məlumat sızması və s. — OWASP Top 10 xəritəsi və CVSS 3.1 balı ilə.

🌐 Canlı: https://cyberayfar.vercel.app · Dillər: AZ / EN / RU

> ⚖️ **Qanuni istifadə:** Yalnız SAHİBİ olduğun və ya yazılı icazən olan
> saytları skan et. Məhsulun içindəki "icazə qapısı" məhz bunu təmin edir.
> Skaner əl ilə pentesti ƏVƏZ ETMİR — ilkin/avtomatik yoxlama vasitəsidir.

---

## 🚀 İşlətmə

### Veb (tövsiyə)
```bash
py app.py        # http://127.0.0.1:5000  (lokalda test rejimi)
```

### CLI
```bash
# Öz saytında (test rejimi — icazə yoxlaması atlanır):
python skan.py https://saytyoxla.vercel.app --oz-saytim

# Real müştəridə (sahiblik təsdiqi tələb olunur):
python skan.py https://musteri-sayti.com
```

Canlı (PROD) rejimdə skan yalnız sahibliyi təsdiqlənmiş domenlərdə işləyir:
hədəfin kökünə `/.well-known/skaner-verify.txt` faylı və ya `skaner-verify=...`
DNS TXT qeydi qoyulmalıdır.

---

## 🔑 Mühit dəyişənləri (Vercel/Render)

| Dəyişən | Təyinat |
|---------|---------|
| `SAHIB_DOMENLER` | Təsdiq tələb etməyən öz domenlərin (vergüllə) |
| `SKANER_GIZLI_ACAR` | Sahiblik tokenlərinin açarı (uzun təsadüfi sətir) |
| `SKAN_LIMIT` | Bir IP üçün dəqiqədə maksimum skan (defolt 6) |

---

## 📂 Quruluş

| Fayl | Vəzifəsi |
|------|----------|
| `app.py` | Flask veb server (CSP və digər təhlükəsizlik başlıqları, sürət limiti, SSE) |
| `motor.py` | Mühərrik — crawl + bütün modulları paralel işlədir |
| `core/authorization.py` | 🔐 İcazə qapısı + SSRF qoruması (daxili/IP ünvanları rədd) |
| `core/crawler.py` | 🕷️ Saytı gəzir (sitemap/robots), səhifə/forma/parametr tapır |
| `core/http_client.py` | 🌐 Paralel HTTP + retry (4xx/5xx cavabları itirmir) |
| `core/reporter.py` | 📊 CVSS 3.1 vektorları + 0–100 bal |
| `core/owasp.py` | 🗺️ OWASP Top 10 (2021) xəritəsi |
| `core/diller.py` | 🌍 AZ/EN/RU tərcümələr |
| `modullar/*.py` | 🧩 27 yoxlama modulu (injection, başlıqlar, TLS, IDOR, sızma…) |
| `tests/` | ✅ Unit testlər + zəif-sayt benchmarkı |

---

## 📊 Dəqiqlik (benchmark)

`tests/lab/zeif_sayt.py` — bilərəkdən zəif lokal sayt (hər zəifliyin zəif
`/v/…` və təhlükəsiz `/s/…` nüsxəsi). `tests/benchmark.py` skan nəticəsini
həqiqət cədvəli ilə tutuşdurur. Cari nəticə: **aşkarlama 39/40 (98%),
yalançı müsbət 0**. Detallar: [`BENCHMARK.md`](BENCHMARK.md).

```bash
python tests/benchmark.py      # cədvəl + BENCHMARK.md
pytest -q                      # unit testlər + benchmark həddi
```

> Laboratoriya bu skanerlə yazıldığı üçün 98% **yuxarı sərhəddir**; real
> saytlarda aşkarlama daha aşağı olar. Müstəqil ölçü üçün DVWA / OWASP Juice
> Shop kimi kənar hədəflərdə də sınayın.
> **Məlum məhdudiyyət:** forma üzərindən *kor* (auth-bypass) SQLi hələ
> aşkarlanmır; JS-render (SPA) səhifələr yalnız Playwright olan mühitdə
> (Render/Docker) tam gəzilir, Vercel-də statik crawl işləyir.

---

## 🧠 Necə işləyir (addım-addım)

1. **İcazə** — hədəfin sahibi olduğun təsdiqlənir (yoxsa dayanır); daxili/IP ünvanlar rədd edilir
2. **Crawl** — səhifə, forma və parametrlər toplanır
3. **Passiv yoxlama** — başlıqlar, həssas fayllar, TLS, sızma, DNS/spoofing…
4. **Aktiv yoxlama** — XSS/SQLi/NoSQL/SSTI/LFI/SSRF/CRLF/IDOR üçün zərərsiz, təsdiqlənmiş testlər
5. **Hesabat** — tapıntılar CVSS/OWASP ilə, ciddiliyə görə sıralanır; sayt cavab vermirsə "natamam" deyilir (yalan "100/A" yox)
