"""
DİLLƏR (i18n)
=============
Hər tapıntı 'kod' ilə saxlanılır; burada o kodun AZ/EN/RU mətni var.
{deyishken}-lər (yol, param, domen...) formatla doldurulur.
"""

METINLER = {
    # ---------- Həssas fayllar ----------
    "hessas_fayl": {
        "az": {"ad": "Açıq həssas fayl: /{yol}",
               "izah": "Bu fayl/qovluq kənardan əlçatandır və həssas məlumat (mənbə kodu, parollar, backup) sıza bilər.",
               "hell": "Faylı web root-dan çıxar və ya server qaydası (nginx/.htaccess) ilə kənar girişi blokla."},
        "en": {"ad": "Exposed sensitive file: /{yol}",
               "izah": "This file/folder is publicly reachable and may leak sensitive data (source code, passwords, backups).",
               "hell": "Remove it from the web root or block external access via a server rule (nginx/.htaccess)."},
        "ru": {"ad": "Открытый чувствительный файл: /{yol}",
               "izah": "Файл/папка доступны извне и могут раскрыть данные (исходный код, пароли, бэкапы).",
               "hell": "Удалите из web root или заблокируйте доступ правилом сервера (nginx/.htaccess)."},
    },
    "robots": {
        "az": {"ad": "robots.txt mövcuddur", "izah": "Normaldır, amma gizli yollar burda görünə bilər.",
               "hell": "robots.txt-də admin/gizli yolları açıq yazma."},
        "en": {"ad": "robots.txt present", "izah": "Normal, but hidden paths may be revealed here.",
               "hell": "Do not list admin/secret paths in robots.txt."},
        "ru": {"ad": "robots.txt присутствует", "izah": "Это нормально, но скрытые пути могут быть видны.",
               "hell": "Не указывайте админ/секретные пути в robots.txt."},
    },
    # ---------- Email / Domain Spoofing ----------
    "spf_yox": {
        "az": {"ad": "SPF qeydi yoxdur", "izah": "Domenindən kimsə saxta e-poçt (spoofing) göndərə bilər.",
               "hell": 'DNS-ə TXT qeydi əlavə et: "v=spf1 include:_spf.google.com ~all"'},
        "en": {"ad": "No SPF record", "izah": "Anyone could send spoofed e-mail from your domain.",
               "hell": 'Add a DNS TXT record: "v=spf1 include:_spf.google.com ~all"'},
        "ru": {"ad": "Нет записи SPF", "izah": "Кто угодно может отправлять поддельные письма от вашего домена.",
               "hell": 'Добавьте TXT-запись: "v=spf1 include:_spf.google.com ~all"'},
    },
    "spf_zeif": {
        "az": {"ad": "SPF çox zəifdir (+all)", "izah": "+all hər kəsə sənin adından mail göndərməyə icazə verir.",
               "hell": "+all -> ~all və ya -all ilə əvəz et."},
        "en": {"ad": "SPF too weak (+all)", "izah": "+all lets anyone send mail as you.",
               "hell": "Replace +all with ~all or -all."},
        "ru": {"ad": "SPF слишком слабый (+all)", "izah": "+all разрешает всем отправлять почту от вашего имени.",
               "hell": "Замените +all на ~all или -all."},
    },
    "dmarc_yox": {
        "az": {"ad": "DMARC qeydi yoxdur", "izah": "Saxta mail-lər bloklanmır; fişinq riski yüksəkdir.",
               "hell": 'TXT qeydi əlavə et: "v=DMARC1; p=reject; rua=mailto:sən@domen"'},
        "en": {"ad": "No DMARC record", "izah": "Spoofed mail is not blocked; high phishing risk.",
               "hell": 'Add a TXT record: "v=DMARC1; p=reject; rua=mailto:you@domain"'},
        "ru": {"ad": "Нет записи DMARC", "izah": "Поддельные письма не блокируются; высокий риск фишинга.",
               "hell": 'Добавьте TXT-запись: "v=DMARC1; p=reject; rua=mailto:you@domain"'},
    },
    "dmarc_passiv": {
        "az": {"ad": "DMARC passivdir (p=none)", "izah": "p=none yalnız izləyir, saxta mail-i bloklamır.",
               "hell": "p=none -> p=quarantine və ya p=reject et."},
        "en": {"ad": "DMARC is passive (p=none)", "izah": "p=none only monitors, does not block spoofed mail.",
               "hell": "Change p=none to p=quarantine or p=reject."},
        "ru": {"ad": "DMARC пассивен (p=none)", "izah": "p=none только наблюдает, не блокирует подделки.",
               "hell": "Измените p=none на p=quarantine или p=reject."},
    },
    "dkim_yox": {
        "az": {"ad": "DKIM imzası tapılmadı", "izah": "DKIM e-poçtların həqiqiliyini təsdiqləyir; tapılmadı.",
               "hell": "E-poçt provayderində (Google/Microsoft) DKIM-i aktiv et."},
        "en": {"ad": "No DKIM signature", "izah": "DKIM verifies e-mail authenticity; none found.",
               "hell": "Enable DKIM in your e-mail provider (Google/Microsoft)."},
        "ru": {"ad": "Подпись DKIM не найдена", "izah": "DKIM подтверждает подлинность писем; не найдена.",
               "hell": "Включите DKIM у вашего почтового провайдера (Google/Microsoft)."},
    },
    # ---------- XSS ----------
    "xss_url": {
        "az": {"ad": "Əks olunan XSS (URL parametri)", "izah": "'{param}' parametri inputu təmizləmədən səhifəyə qaytarır — zərərli JavaScript yeridilə bilər.",
               "hell": "Çıxışda escape et (htmlspecialchars), CSP başlığı əlavə et."},
        "en": {"ad": "Reflected XSS (URL parameter)", "izah": "The '{param}' parameter reflects input without sanitizing — malicious JavaScript can be injected.",
               "hell": "Escape output (htmlspecialchars), add a CSP header."},
        "ru": {"ad": "Отражённый XSS (параметр URL)", "izah": "Параметр '{param}' возвращает ввод без очистки — можно внедрить вредоносный JavaScript.",
               "hell": "Экранируйте вывод (htmlspecialchars), добавьте заголовок CSP."},
    },
    "xss_forma": {
        "az": {"ad": "Əks olunan XSS (forma)", "izah": "Forma inputu təmizlənmədən qaytarılır (mənbə: {menbe}).",
               "hell": "İnputu escape et, çıxışı kodla, CSP tətbiq et."},
        "en": {"ad": "Reflected XSS (form)", "izah": "Form input is reflected without sanitizing (source: {menbe}).",
               "hell": "Escape input, encode output, apply CSP."},
        "ru": {"ad": "Отражённый XSS (форма)", "izah": "Ввод формы возвращается без очистки (источник: {menbe}).",
               "hell": "Экранируйте ввод, кодируйте вывод, примените CSP."},
    },
    # ---------- SQL Injection ----------
    "sqli_url": {
        "az": {"ad": "SQL Injection (URL parametri)", "izah": "'{param}' parametri birbaşa SQL sorğusuna düşür — verilənlər bazası oğurlana/poza bilər.",
               "hell": "Prepared statements (parametrli sorğular) istifadə et, inputu heç vaxt birbaşa SQL-ə qoşma."},
        "en": {"ad": "SQL Injection (URL parameter)", "izah": "The '{param}' parameter goes directly into the SQL query — the database can be stolen/damaged.",
               "hell": "Use prepared statements; never concatenate input into SQL."},
        "ru": {"ad": "SQL-инъекция (параметр URL)", "izah": "Параметр '{param}' попадает прямо в SQL-запрос — базу могут украсть/повредить.",
               "hell": "Используйте подготовленные запросы; не вставляйте ввод в SQL напрямую."},
    },
    "sqli_forma": {
        "az": {"ad": "SQL Injection (forma)", "izah": "Forma inputu SQL sorğusuna düşür (mənbə: {menbe}).",
               "hell": "Prepared statements / ORM istifadə et, inputu validasiya et."},
        "en": {"ad": "SQL Injection (form)", "izah": "Form input reaches the SQL query (source: {menbe}).",
               "hell": "Use prepared statements / ORM, validate input."},
        "ru": {"ad": "SQL-инъекция (форма)", "izah": "Ввод формы попадает в SQL-запрос (источник: {menbe}).",
               "hell": "Используйте подготовленные запросы / ORM, валидируйте ввод."},
    },
    # ---------- Platforma ----------
    "platforma": {
        "az": {"ad": "Platforma domeni", "izah": "Bu platforma subdomenidir ({domen}). SPF/DMARC/DKIM-ə Vercel/Netlify nəzarət edir — sən dəyişə bilməzsən. Email yoxlaması yalnız öz xüsusi domenində vacibdir.",
               "hell": "Öz domenin (məs: saytyoxla.az) varsa, email yoxlamasını orada et."},
        "en": {"ad": "Platform domain", "izah": "This is a platform subdomain ({domen}). SPF/DMARC/DKIM are controlled by Vercel/Netlify — you can't change them. E-mail checks matter only on your own custom domain.",
               "hell": "If you have your own domain (e.g. saytyoxla.az), run e-mail checks there."},
        "ru": {"ad": "Домен платформы", "izah": "Это субдомен платформы ({domen}). SPF/DMARC/DKIM контролирует Vercel/Netlify — вы не можете их изменить. Проверки почты важны только на собственном домене.",
               "hell": "Если у вас есть свой домен (напр. saytyoxla.az), проверяйте почту там."},
    },
}

DILLER = ("az", "en", "ru")


def render_hamisi(kod, deyishken):
    """Bir tapıntını 3 dildə formatlanmış mətnə çevirir."""
    netice = {}
    sablon = METINLER.get(kod)
    for dil in DILLER:
        if not sablon:
            netice[dil] = {"ad": kod, "izah": "", "hell": ""}
            continue
        d = sablon[dil]
        try:
            netice[dil] = {
                "ad": d["ad"].format(**deyishken),
                "izah": d["izah"].format(**deyishken),
                "hell": d["hell"].format(**deyishken),
            }
        except (KeyError, IndexError):
            netice[dil] = dict(d)
    return netice
