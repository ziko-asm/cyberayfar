# Skaner benchmarkı

Lokal laboratoriya saytına (`tests/lab/zeif_sayt.py`) qarşı ölçülüb: hər zəifliyin
zəif (`/v/…`) və təhlükəsiz (`/s/…`) nüsxəsi var. `python tests/benchmark.py` ilə yenilənir.

| Göstərici | Nəticə |
|---|---|
| Aşkarlama (recall) | **39 / 40** (98%) |
| Yalançı müsbət (təhlükəsiz səhifələr) | **0** |
| Yalançı müsbət (SPA catch-all) | **0** |
| Gəzilən səhifə / forma | 43 / 9 |
| Skan müddəti | 121.3 san |

> Laboratoriya bu skanerlə birlikdə yazılıb, ona görə bu rəqəm **yuxarı sərhəddir**.
> Real saytlarda aşkarlama aşağı olacaq; skaner əl ilə pentesti əvəz etmir.

**Məlum məhdudiyyət:** forma üzərindən *kor* (auth-bypass) SQL injection
hələ aşkarlanmır — yalnız xəta-əsaslı forma SQLi tapılır. JS ilə render
olunan (SPA) səhifələr yalnız serverdə Playwright olanda tam gəzilir.

| Zəiflik | Yer | Tapıldı |
|---|---|---|
| XSS — HTML gövdə | `/v/axtar` | ✅ |
| XSS — atribut | `/v/profil` | ✅ |
| XSS — JavaScript sətri | `/v/js` | ✅ |
| XSS — GET forması | `/v/forma-axtar` | ✅ |
| Stored XSS — şərhlər | `/v/serh` | ✅ |
| SQLi — xəta əsaslı (URL) | `/v/mehsul` | ✅ |
| SQLi — boolean, ədədi | `/v/xeber` | ✅ |
| SQLi — boolean, sətir | `/v/istifadeci` | ✅ |
| SQLi — vaxt əsaslı | `/v/hesabat` | ✅ |
| SQLi — forma, xəta əsaslı | `/v/giris` | ✅ |
| SQLi — forma, kor (boolean) | `/v/kor-giris` | ❌ |
| Open redirect — ?url= | `/v/get` | ✅ |
| Open redirect — qeyri-adi ad | `/v/kecid` | ✅ |
| LFI — ?file= | `/v/oxu` | ✅ |
| LFI — qeyri-adi ad | `/v/sened` | ✅ |
| Command injection | `/v/ping` | ✅ |
| SSTI | `/v/salam` | ✅ |
| CRLF injection | `/v/dil` | ✅ |
| NoSQL injection | `/v/api/istifadeci` | ✅ |
| IDOR | `/v/sifaris` | ✅ |
| SSRF | `/v/yukle` | ✅ |
| XXE | `/xml` | ✅ |
| CSRF — tokensiz POST forma | `/v/serh` | ✅ |
| Qovluq siyahısı açıqdır | `/v/fayllar` | ✅ |
| Debug / stack trace sızması | `/v/xeta` | ✅ |
| Həssas fayl — .env | `/.env` | ✅ |
| Həssas fayl — .git/config | `/.git/config` | ✅ |
| Həssas fayl — backup.sql | `/backup.sql` | ✅ |
| Gizli yol — /admin | `/admin` | ✅ |
| Sirr sızması — AWS açarı | `app.js` | ✅ |
| Köhnə jQuery | `/` | ✅ |
| CSP yoxdur | `/` | ✅ |
| X-Content-Type-Options yoxdur | `/` | ✅ |
| Cookie bayraqları zəifdir | `/` | ✅ |
| Server versiya sızması | `/` | ✅ |
| CORS — origin əks olunur | `/` | ✅ |
| Clickjacking | `/` | ✅ |
| Təhlükəli HTTP metodları | `/` | ✅ |
| Host header injection | `/` | ✅ |
| GraphQL introspection | `/graphql` | ✅ |
