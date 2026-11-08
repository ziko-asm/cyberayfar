# SaytYoxla DAST Skaner 🔐

İcazəli **Veb Zəiflik Skaneri** (DAST — Dynamic Application Security Testing).
Saytlara zərərsiz test sorğuları göndərib zəiflikləri tapır.

> ⚖️ **Qanuni istifadə:** Yalnız SAHİBİ olduğun və ya yazılı icazən olan
> saytları skan et. Məhsulun içindəki "icazə qapısı" məhz bunu təmin edir.

---

## 🚀 İşlətmə

```bash
cd /home/user/kiber-lab/skaner

# Öz saytında (test rejimi — icazə yoxlaması atlanır):
python3 skan.py https://saytyoxla.vercel.app --oz-saytim

# Real müştəridə (sahiblik təsdiqi tələb olunur):
python3 skan.py https://musteri-sayti.com
```

---

## 📂 Fayllar və nə edirlər

| Fayl | Vəzifəsi |
|------|----------|
| `skan.py` | Əsas fayl — hər şeyi birləşdirir, CLI |
| `core/authorization.py` | 🔐 İcazə qapısı (sahiblik təsdiqi: fayl və ya DNS) |
| `core/crawler.py` | 🕷️ Saytı gəzir, səhifə/forma/parametr tapır |
| `core/reporter.py` | 📊 Hesabat + 0–100 bal |
| `modullar/sensitive_files.py` | 📂 Açıq həssas fayllar (.git, .env, backup) |
| `modullar/email_spoof.py` | 📧 Domain spoofing (SPF/DMARC/DKIM) |
| `modullar/xss.py` | 🎯 Əks olunan XSS |
| `modullar/sqli.py` | 💉 SQL Injection (xəta-əsaslı) |

---

## 🧠 Necə işləyir (addım-addım)

1. **İcazə** — hədəfin sahibi olduğun təsdiqlənir (yoxsa dayanır)
2. **Crawl** — saytdakı bütün səhifə, forma və parametrlər toplanır
3. **Passiv yoxlama** — həssas fayllar + DNS (spoofing)
4. **Aktiv yoxlama** — XSS və SQLi üçün zərərsiz test inputları
5. **Hesabat** — tapılanlar ciddiliyə görə sıralanır, bal verilir

---

## 🛠️ Növbəti addımlar (satılabilən məhsula doğru)

- [ ] Async ilə sürəti 10x artır
- [ ] Yeni modullar: CORS, open redirect, təhlükəsizlik başlıqları, köhnə JS (CVE)
- [ ] JSON/PDF hesabat
- [ ] SaytYoxla-ya "Dərin Skan" kimi birləşdir
- [ ] Abunə / sahiblik təsdiqi sistemi
