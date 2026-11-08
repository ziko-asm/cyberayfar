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

METINLER.update({
    # ---------- Təhlükəsizlik başlıqları ----------
    "csp_yox": {
        "az": {"ad": "CSP başlığı yoxdur", "izah": "Content-Security-Policy yoxdur — XSS hücumlarının qarşısını alan əsas müdafiə işləmir.",
               "hell": "Content-Security-Policy başlığı əlavə et."},
        "en": {"ad": "Missing CSP header", "izah": "No Content-Security-Policy — a key defense against XSS is absent.",
               "hell": "Add a Content-Security-Policy header."},
        "ru": {"ad": "Нет заголовка CSP", "izah": "Нет Content-Security-Policy — ключевая защита от XSS отсутствует.",
               "hell": "Добавьте заголовок Content-Security-Policy."}},
    "hsts_yox": {
        "az": {"ad": "HSTS başlığı yoxdur", "izah": "Strict-Transport-Security yoxdur — istifadəçi HTTPS yerinə HTTP-yə düşə bilər.",
               "hell": "Strict-Transport-Security: max-age=31536000 əlavə et."},
        "en": {"ad": "Missing HSTS header", "izah": "No Strict-Transport-Security — users can be downgraded to HTTP.",
               "hell": "Add Strict-Transport-Security: max-age=31536000."},
        "ru": {"ad": "Нет заголовка HSTS", "izah": "Нет Strict-Transport-Security — возможен откат на HTTP.",
               "hell": "Добавьте Strict-Transport-Security: max-age=31536000."}},
    "xfo_yox": {
        "az": {"ad": "X-Frame-Options yoxdur", "izah": "Clickjacking mümkündür — saytın iframe-ə salına bilər.",
               "hell": "X-Frame-Options: DENY (və ya CSP frame-ancestors) əlavə et."},
        "en": {"ad": "Missing X-Frame-Options", "izah": "Clickjacking is possible — the site can be framed.",
               "hell": "Add X-Frame-Options: DENY (or CSP frame-ancestors)."},
        "ru": {"ad": "Нет X-Frame-Options", "izah": "Возможен clickjacking — сайт можно встроить в iframe.",
               "hell": "Добавьте X-Frame-Options: DENY (или CSP frame-ancestors)."}},
    "xcto_yox": {
        "az": {"ad": "X-Content-Type-Options yoxdur", "izah": "Brauzer MIME növünü təxmin edə bilər (MIME-sniffing).",
               "hell": "X-Content-Type-Options: nosniff əlavə et."},
        "en": {"ad": "Missing X-Content-Type-Options", "izah": "Browser may MIME-sniff content types.",
               "hell": "Add X-Content-Type-Options: nosniff."},
        "ru": {"ad": "Нет X-Content-Type-Options", "izah": "Браузер может угадывать MIME-тип (sniffing).",
               "hell": "Добавьте X-Content-Type-Options: nosniff."}},
    "refpol_yox": {
        "az": {"ad": "Referrer-Policy yoxdur", "izah": "Referrer məlumatı kənar saytlara sıza bilər.",
               "hell": "Referrer-Policy: no-referrer-when-downgrade əlavə et."},
        "en": {"ad": "Missing Referrer-Policy", "izah": "Referrer info may leak to external sites.",
               "hell": "Add Referrer-Policy: no-referrer-when-downgrade."},
        "ru": {"ad": "Нет Referrer-Policy", "izah": "Данные Referrer могут утекать на внешние сайты.",
               "hell": "Добавьте Referrer-Policy: no-referrer-when-downgrade."}},
    "permpol_yox": {
        "az": {"ad": "Permissions-Policy yoxdur", "izah": "Kamera/mikrofon/geolokasiya icazələri məhdudlaşdırılmayıb.",
               "hell": "Permissions-Policy başlığı ilə icazələri məhdudlaşdır."},
        "en": {"ad": "Missing Permissions-Policy", "izah": "Camera/mic/geolocation permissions are not restricted.",
               "hell": "Restrict features with a Permissions-Policy header."},
        "ru": {"ad": "Нет Permissions-Policy", "izah": "Разрешения камеры/микрофона/геолокации не ограничены.",
               "hell": "Ограничьте функции заголовком Permissions-Policy."}},
    "server_versiya": {
        "az": {"ad": "Server versiyası açıqdır", "izah": "Server başlığı versiyanı göstərir ({server}) — hücumçu məlum zəiflikləri axtara bilər.",
               "hell": "Server başlığından versiyanı gizlət."},
        "en": {"ad": "Server version exposed", "izah": "The Server header reveals a version ({server}) — attackers can look up known exploits.",
               "hell": "Hide the version from the Server header."},
        "ru": {"ad": "Раскрыта версия сервера", "izah": "Заголовок Server показывает версию ({server}) — помогает искать эксплойты.",
               "hell": "Скройте версию из заголовка Server."}},
    "cookie_zeif": {
        "az": {"ad": "Cookie təhlükəsiz deyil: {cookie}", "izah": "'{cookie}' cookie-sində çatmayan bayraqlar: {bayraqlar}.",
               "hell": "Cookie-yə Secure və HttpOnly bayraqlarını əlavə et."},
        "en": {"ad": "Insecure cookie: {cookie}", "izah": "Cookie '{cookie}' is missing flags: {bayraqlar}.",
               "hell": "Add Secure and HttpOnly flags to the cookie."},
        "ru": {"ad": "Небезопасная cookie: {cookie}", "izah": "У cookie '{cookie}' нет флагов: {bayraqlar}.",
               "hell": "Добавьте флаги Secure и HttpOnly."}},
    # ---------- CORS ----------
    "cors_acar": {
        "az": {"ad": "CORS tam açıqdır (* + credentials)", "izah": "Sayt istənilən mənbəyə credentials ilə icazə verir — istifadəçi məlumatı oğurlana bilər.",
               "hell": "Access-Control-Allow-Origin: * ilə credentials-i birlikdə işlətmə; icazəli domenləri açıq-aşkar yaz."},
        "en": {"ad": "CORS fully open (* + credentials)", "izah": "Any origin is allowed with credentials — user data can be stolen.",
               "hell": "Never combine ACAO: * with credentials; whitelist specific origins."},
        "ru": {"ad": "CORS полностью открыт (* + credentials)", "izah": "Любой источник с credentials — данные пользователя могут украсть.",
               "hell": "Не сочетайте ACAO: * с credentials; укажите конкретные источники."}},
    "cors_reflect": {
        "az": {"ad": "CORS mənbəni əks etdirir", "izah": "Sayt istənilən 'Origin'-i təsdiqləyir — hücumçu domeni etibarlı sayılır.",
               "hell": "Origin-i yoxla, yalnız icazəli domenlərə izin ver."},
        "en": {"ad": "CORS reflects origin", "izah": "The site reflects any Origin — an attacker's domain is trusted.",
               "hell": "Validate Origin; allow only whitelisted domains."},
        "ru": {"ad": "CORS отражает Origin", "izah": "Сайт доверяет любому Origin — домен атакующего считается доверенным.",
               "hell": "Проверяйте Origin; разрешайте только доверенные домены."}},
    # ---------- Open redirect ----------
    "open_redirect": {
        "az": {"ad": "Open Redirect", "izah": "'{param}' parametri xarici saytlara yönləndirir — fişinq üçün istifadə edilə bilər.",
               "hell": "Yalnız daxili (nisbi) yollara yönləndir; xarici URL-ləri rədd et."},
        "en": {"ad": "Open Redirect", "izah": "The '{param}' parameter redirects to external sites — usable for phishing.",
               "hell": "Only redirect to internal (relative) paths; reject external URLs."},
        "ru": {"ad": "Open Redirect", "izah": "Параметр '{param}' перенаправляет на внешние сайты — годится для фишинга.",
               "hell": "Разрешайте только внутренние (относительные) пути."}},
    # ---------- Köhnə JS ----------
    "kohne_js": {
        "az": {"ad": "Köhnə JS: {kitabxana} {versiya}", "izah": "{qeyd}. Tapılan: {versiya}, təhlükəsiz min: {min}.",
               "hell": "{kitabxana} kitabxanasını {min} və ya daha yeni versiyaya yenilə."},
        "en": {"ad": "Outdated JS: {kitabxana} {versiya}", "izah": "{qeyd}. Found: {versiya}, safe min: {min}.",
               "hell": "Update {kitabxana} to {min} or newer."},
        "ru": {"ad": "Устаревший JS: {kitabxana} {versiya}", "izah": "{qeyd}. Найдено: {versiya}, безопасный мин.: {min}.",
               "hell": "Обновите {kitabxana} до {min} или новее."}},
    # ---------- Command Injection ----------
    "cmd_injection": {
        "az": {"ad": "Command Injection", "izah": "'{param}' parametri serverdə OS əmri işlədə bilir — tam sistem ələ keçirilə bilər.",
               "hell": "İnputu heç vaxt shell-ə ötürmə; təhlükəsiz API-lərdən istifadə et, inputu validasiya et."},
        "en": {"ad": "Command Injection", "izah": "The '{param}' parameter can run OS commands on the server — full takeover is possible.",
               "hell": "Never pass input to a shell; use safe APIs and validate input."},
        "ru": {"ad": "Command Injection", "izah": "Параметр '{param}' выполняет команды ОС на сервере — возможен полный захват.",
               "hell": "Не передавайте ввод в shell; используйте безопасные API и валидацию."}},
    # ---------- LFI ----------
    "lfi": {
        "az": {"ad": "Local File Inclusion (LFI)", "izah": "'{param}' parametri server fayllarını (məs: /etc/passwd) oxuya bilir.",
               "hell": "Fayl yollarını whitelist ilə yoxla; istifadəçi inputunu fayl adında işlətmə."},
        "en": {"ad": "Local File Inclusion (LFI)", "izah": "The '{param}' parameter can read server files (e.g. /etc/passwd).",
               "hell": "Whitelist file paths; never use user input in file names."},
        "ru": {"ad": "Local File Inclusion (LFI)", "izah": "Параметр '{param}' может читать файлы сервера (напр. /etc/passwd).",
               "hell": "Используйте whitelist путей; не подставляйте ввод в имена файлов."}},
    # ---------- Blind SQLi ----------
    "sqli_blind": {
        "az": {"ad": "SQL Injection (kor / time-based)", "izah": "'{param}' parametri xəta göstərmədən SQL sorğusuna təsir edir (cavab gecikməsi ilə təsdiqləndi).",
               "hell": "Prepared statements istifadə et, inputu birbaşa SQL-ə qoşma."},
        "en": {"ad": "SQL Injection (blind / time-based)", "izah": "The '{param}' parameter affects the SQL query without errors (confirmed by response delay).",
               "hell": "Use prepared statements; never concatenate input into SQL."},
        "ru": {"ad": "SQL-инъекция (слепая / time-based)", "izah": "Параметр '{param}' влияет на SQL без ошибок (подтверждено задержкой ответа).",
               "hell": "Используйте подготовленные запросы; не вставляйте ввод в SQL."}},
})

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


# ---- Mərhələ 1 davamı: əlavə yoxlamalar ----
METINLER.update({
    "csrf_yox": {
        "az": {"ad": "CSRF qoruması yoxdur", "izah": "POST forması (mənbə: {menbe}) CSRF token olmadan göndərilir — hücumçu istifadəçi adından saxta sorğu edə bilər.",
               "hell": "Hər forma üçün CSRF token əlavə et və serverdə yoxla."},
        "en": {"ad": "Missing CSRF protection", "izah": "A POST form (source: {menbe}) has no CSRF token — an attacker can forge requests as the user.",
               "hell": "Add a CSRF token to each form and validate it server-side."},
        "ru": {"ad": "Нет защиты CSRF", "izah": "POST-форма (источник: {menbe}) без CSRF-токена — атакующий может подделать запрос от имени пользователя.",
               "hell": "Добавьте CSRF-токен в каждую форму и проверяйте на сервере."}},
    "subdomainler": {
        "az": {"ad": "{say} subdomen aşkarlandı", "izah": "Hücum səthi: {siyahi}. Hər subdomen ayrıca yoxlanılmalıdır.",
               "hell": "İstifadə olunmayan subdomenləri bağla; hər birini ayrıca qoru."},
        "en": {"ad": "{say} subdomains discovered", "izah": "Attack surface: {siyahi}. Each subdomain should be checked separately.",
               "hell": "Disable unused subdomains; secure each one individually."},
        "ru": {"ad": "Обнаружено {say} поддоменов", "izah": "Поверхность атаки: {siyahi}. Каждый поддомен нужно проверять отдельно.",
               "hell": "Отключите неиспользуемые поддомены; защитите каждый."}},
    "tehlukeli_metod": {
        "az": {"ad": "Təhlükəli HTTP metodları", "izah": "Server bu metodlara icazə verir: {metodlar}. Bu, fayl dəyişmə/silmə riski yaradır.",
               "hell": "İstifadə olunmayan metodları (PUT/DELETE/TRACE) serverdə bağla."},
        "en": {"ad": "Dangerous HTTP methods", "izah": "The server allows: {metodlar}. This risks file modification/deletion.",
               "hell": "Disable unused methods (PUT/DELETE/TRACE) on the server."},
        "ru": {"ad": "Опасные HTTP-методы", "izah": "Сервер разрешает: {metodlar}. Это риск изменения/удаления файлов.",
               "hell": "Отключите неиспользуемые методы (PUT/DELETE/TRACE)."}},
    "mixed_content": {
        "az": {"ad": "Mixed Content ({say} resurs)", "izah": "HTTPS səhifə {say} şifrəsiz (HTTP) resurs yükləyir — bu, təhlükəsizliyi pozur.",
               "hell": "Bütün resursları HTTPS-ə keçir (// və ya https://)."},
        "en": {"ad": "Mixed Content ({say} resources)", "izah": "The HTTPS page loads {say} insecure (HTTP) resources — this breaks security.",
               "hell": "Switch all resources to HTTPS (// or https://)."},
        "ru": {"ad": "Mixed Content ({say} ресурсов)", "izah": "HTTPS-страница загружает {say} незащищённых (HTTP) ресурсов.",
               "hell": "Переведите все ресурсы на HTTPS (// или https://)."}},
    "gizli_yol": {
        "az": {"ad": "Gizli yol: /{yol} ({status})", "izah": "'{yol}' yolu tapıldı ({status}) — admin panel/həssas bölmə ola bilər.",
               "hell": "Bu yolu kənar girişdən qoru və ya gizlət."},
        "en": {"ad": "Hidden path: /{yol} ({status})", "izah": "The path '{yol}' was found ({status}) — may be an admin panel/sensitive area.",
               "hell": "Protect or hide this path from public access."},
        "ru": {"ad": "Скрытый путь: /{yol} ({status})", "izah": "Найден путь '{yol}' ({status}) — возможно админ-панель/важный раздел.",
               "hell": "Защитите или скройте этот путь от публичного доступа."}},
})


# ---- A paketi: 8 yeni yoxlama ----
METINLER.update({
    "sirr_sizma": {
        "az": {"ad": "Sirr sızması: {tip}", "izah": "Saytın kodunda açıq qalıb: {tip}. Hücumçu bunu oğurlayıb sistemlərinə girə bilər.",
               "hell": "Açarı DƏRHAL ləğv et (rotate), koddan çıxar, mühit dəyişəni/server tərəfdə saxla."},
        "en": {"ad": "Secret leak: {tip}", "izah": "Exposed in the site code: {tip}. An attacker can steal it and access your systems.",
               "hell": "Revoke (rotate) the key NOW, remove it from code, store server-side/in env vars."},
        "ru": {"ad": "Утечка секрета: {tip}", "izah": "В коде сайта открыто: {tip}. Атакующий может украсть его и получить доступ.",
               "hell": "Немедленно отзовите (ротация) ключ, уберите из кода, храните на сервере/в env."}},
    "tls_self": {
        "az": {"ad": "Sertifikat doğrulanmadı / self-signed", "izah": "TLS sertifikatı etibarlı deyil — istifadəçi brauzeri xəbərdarlıq verir, MITM riski var.",
               "hell": "Etibarlı sertifikat ver (məs: Let's Encrypt, pulsuz)."},
        "en": {"ad": "Certificate not trusted / self-signed", "izah": "The TLS certificate is invalid — browsers warn users, MITM risk exists.",
               "hell": "Install a trusted certificate (e.g. Let's Encrypt, free)."},
        "ru": {"ad": "Сертификат не доверенный / self-signed", "izah": "TLS-сертификат недействителен — браузеры предупреждают, риск MITM.",
               "hell": "Установите доверенный сертификат (напр. Let's Encrypt, бесплатно)."}},
    "tls_sertifikat": {
        "az": {"ad": "TLS sertifikatı bitir ({gun} gün)", "izah": "Sertifikatın müddəti bitmək üzrədir ({gun} gün). Bitsə, sayt açılmayacaq.",
               "hell": "Sertifikatı yenilə (avtomatik yeniləmə qur — Let's Encrypt)."},
        "en": {"ad": "TLS certificate expiring ({gun} days)", "izah": "The certificate expires soon ({gun} days). When it does, the site breaks.",
               "hell": "Renew the certificate (set up auto-renewal — Let's Encrypt)."},
        "ru": {"ad": "Сертификат TLS истекает ({gun} дн.)", "izah": "Срок сертификата скоро истекает ({gun} дн.). После — сайт не откроется.",
               "hell": "Обновите сертификат (настройте авто-обновление — Let's Encrypt)."}},
    "tls_kohne": {
        "az": {"ad": "Köhnə TLS protokolu ({versiyalar})", "izah": "Zəif/köhnə protokol dəstəklənir: {versiyalar}. Bunlar sındırıla bilər.",
               "hell": "Serverdə TLS 1.0/1.1-i söndür, yalnız TLS 1.2+ saxla."},
        "en": {"ad": "Outdated TLS protocol ({versiyalar})", "izah": "Weak/old protocols supported: {versiyalar}. These are breakable.",
               "hell": "Disable TLS 1.0/1.1 on the server; keep only TLS 1.2+."},
        "ru": {"ad": "Устаревший TLS ({versiyalar})", "izah": "Поддерживаются слабые протоколы: {versiyalar}. Их можно взломать.",
               "hell": "Отключите TLS 1.0/1.1 на сервере; оставьте только TLS 1.2+."}},
    "ssrf": {
        "az": {"ad": "SSRF (Server-Side Request Forgery)", "izah": "'{param}' parametri serveri daxili sistemlərə sorğu göndərməyə məcbur edir — bulud metadata/sirrləri oğurlana bilər.",
               "hell": "İstifadəçi URL-lərini whitelist ilə yoxla, daxili IP-lərə girişi blokla."},
        "en": {"ad": "SSRF (Server-Side Request Forgery)", "izah": "The '{param}' parameter makes the server request internal systems — cloud metadata/secrets can be stolen.",
               "hell": "Whitelist user URLs; block access to internal IPs."},
        "ru": {"ad": "SSRF (Server-Side Request Forgery)", "izah": "Параметр '{param}' заставляет сервер обращаться к внутренним системам — можно украсть metadata/секреты.",
               "hell": "Проверяйте URL по whitelist; блокируйте доступ к внутренним IP."}},
    "xxe": {
        "az": {"ad": "XXE (XML External Entity)", "izah": "Server XML-i təhlükəli emal edir — hücumçu server fayllarını (/etc/passwd) oxuya bilər.",
               "hell": "XML parserdə xarici entity-ləri (DTD) söndür."},
        "en": {"ad": "XXE (XML External Entity)", "izah": "The server parses XML unsafely — an attacker can read server files (/etc/passwd).",
               "hell": "Disable external entities (DTD) in the XML parser."},
        "ru": {"ad": "XXE (XML External Entity)", "izah": "Сервер небезопасно обрабатывает XML — можно читать файлы сервера (/etc/passwd).",
               "hell": "Отключите внешние сущности (DTD) в XML-парсере."}},
    "graphql_introspection": {
        "az": {"ad": "GraphQL introspection açıqdır", "izah": "Bütün API sxemi (sorğular, mutasiyalar, tiplər) kənara görünür — hücum səthini açır.",
               "hell": "Produksiyada GraphQL introspection-u söndür."},
        "en": {"ad": "GraphQL introspection enabled", "izah": "The full API schema (queries, mutations, types) is exposed — widens the attack surface.",
               "hell": "Disable GraphQL introspection in production."},
        "ru": {"ad": "GraphQL introspection включён", "izah": "Вся схема API (запросы, мутации, типы) доступна — расширяет поверхность атаки.",
               "hell": "Отключите introspection GraphQL в продакшене."}},
    "host_header": {
        "az": {"ad": "Host Header Injection", "izah": "Server 'Host' başlığını yoxlamadan əks etdirir — parol-sıfırlama linkləri saxtalaşdırıla, keş zəhərlənə bilər.",
               "hell": "Host başlığını whitelist ilə yoxla, mütləq (absolute) URL-lər üçün sabit domen işlət."},
        "en": {"ad": "Host Header Injection", "izah": "The server reflects the 'Host' header unchecked — password-reset links can be forged, cache poisoned.",
               "hell": "Validate Host against a whitelist; use a fixed domain for absolute URLs."},
        "ru": {"ad": "Host Header Injection", "izah": "Сервер отражает заголовок 'Host' без проверки — можно подделать ссылки сброса пароля, отравить кэш.",
               "hell": "Проверяйте Host по whitelist; используйте фиксированный домен для абсолютных URL."}},
    "clickjacking": {
        "az": {"ad": "Clickjacking mümkündür", "izah": "Sayt iframe-ə salına bilər (nə X-Frame-Options, nə də CSP frame-ancestors var) — istifadəçi aldadıla bilər.",
               "hell": "X-Frame-Options: DENY və ya CSP frame-ancestors 'none' əlavə et."},
        "en": {"ad": "Clickjacking possible", "izah": "The site can be framed (no X-Frame-Options nor CSP frame-ancestors) — users can be tricked.",
               "hell": "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."},
        "ru": {"ad": "Возможен clickjacking", "izah": "Сайт можно встроить в iframe (нет ни X-Frame-Options, ни CSP frame-ancestors) — пользователя можно обмануть.",
               "hell": "Добавьте X-Frame-Options: DENY или CSP frame-ancestors 'none'."}},
    "waf_askarlandi": {
        "az": {"ad": "WAF aşkarlandı: {ad}", "izah": "Saytın qarşısında firewall var ({ad}) — bu müsbətdir. Qeyd: WAF bəzi skan nəticələrini gizlədə bilər.",
               "hell": "Əlavə tədbir lazım deyil — bu, müdafiə əlamətidir."},
        "en": {"ad": "WAF detected: {ad}", "izah": "A firewall protects the site ({ad}) — this is good. Note: a WAF may mask some scan results.",
               "hell": "No action needed — this is a sign of protection."},
        "ru": {"ad": "Обнаружен WAF: {ad}", "izah": "Сайт защищён фаерволом ({ad}) — это хорошо. Примечание: WAF может скрывать часть результатов.",
               "hell": "Действий не требуется — это признак защиты."}},
})


# ---- IDOR ----
METINLER.update({
    "idor": {
        "az": {"ad": "IDOR (icazə pozuntusu)", "izah": "'{param}' parametrini {id1} -> {id2} dəyişəndə BAŞQA obyektin məlumatı açıldı — hücumçu başqa istifadəçilərin məlumatına baxa/dəyişə bilər.",
               "hell": "Hər sorğuda obyektin SAHİBİNİ yoxla (server tərəfdə icazə nəzarəti). Təsadüfi UUID işlət, ardıcıl id yox."},
        "en": {"ad": "IDOR (Broken Access Control)", "izah": "Changing '{param}' from {id1} to {id2} exposed ANOTHER object's data — an attacker can read/modify other users' data.",
               "hell": "Check object OWNERSHIP on every request (server-side authorization). Use random UUIDs, not sequential ids."},
        "ru": {"ad": "IDOR (нарушение контроля доступа)", "izah": "Изменение '{param}' с {id1} на {id2} открыло данные ДРУГОГО объекта — атакующий может читать/изменять данные других.",
               "hell": "Проверяйте владельца объекта на каждом запросе (серверная авторизация). Используйте случайные UUID."},
    },
})


# ---- OOB (callback-təsdiqli blind zəifliklər) ----
METINLER.update({
    "ssrf_oob": {
        "az": {"ad": "Blind SSRF (OOB təsdiqli)", "izah": "'{param}' parametri serveri bizim collaborator-a sorğu etməyə məcbur etdi — SSRF 100% təsdiqləndi. Hücumçu daxili sistemlərə/bulud metadata-ya çata bilər.",
               "hell": "İstifadəçi URL-lərini whitelist ilə yoxla, daxili IP/metadata ünvanlarını blokla."},
        "en": {"ad": "Blind SSRF (OOB-confirmed)", "izah": "The '{param}' parameter made the server call our collaborator — SSRF 100% confirmed. An attacker can reach internal systems/cloud metadata.",
               "hell": "Whitelist user URLs; block internal IP/metadata addresses."},
        "ru": {"ad": "Слепой SSRF (OOB-подтверждён)", "izah": "Параметр '{param}' заставил сервер обратиться к нашему коллаборатору — SSRF подтверждён на 100%. Доступ к внутренним системам/metadata.",
               "hell": "Проверяйте URL по whitelist; блокируйте внутренние IP/metadata."},
    },
    "rce_oob": {
        "az": {"ad": "Blind RCE (OOB təsdiqli)", "izah": "'{param}' parametri serverdə OS əmri (curl) işlətdi — kor RCE 100% təsdiqləndi. Tam sistem ələ keçirilə bilər.",
               "hell": "İnputu heç vaxt shell-ə ötürmə; təhlükəsiz API-lər, ciddi validasiya."},
        "en": {"ad": "Blind RCE (OOB-confirmed)", "izah": "The '{param}' parameter ran an OS command (curl) on the server — blind RCE 100% confirmed. Full system takeover is possible.",
               "hell": "Never pass input to a shell; use safe APIs and strict validation."},
        "ru": {"ad": "Слепой RCE (OOB-подтверждён)", "izah": "Параметр '{param}' выполнил команду ОС (curl) на сервере — слепой RCE подтверждён на 100%. Возможен полный захват.",
               "hell": "Не передавайте ввод в shell; безопасные API и строгая валидация."},
    },
    "xxe_oob": {
        "az": {"ad": "Blind XXE (OOB təsdiqli)", "izah": "Server XML xarici entity vasitəsilə collaborator-a sorğu etdi — kor XXE 100% təsdiqləndi. Server faylları oxuna/SSRF edilə bilər.",
               "hell": "XML parserdə xarici entity-ləri (DTD) tam söndür."},
        "en": {"ad": "Blind XXE (OOB-confirmed)", "izah": "The server fetched our collaborator via an XML external entity — blind XXE 100% confirmed. Server files can be read / SSRF performed.",
               "hell": "Fully disable external entities (DTD) in the XML parser."},
        "ru": {"ad": "Слепой XXE (OOB-подтверждён)", "izah": "Сервер обратился к коллаборатору через внешнюю XML-сущность — слепой XXE подтверждён на 100%. Чтение файлов / SSRF.",
               "hell": "Полностью отключите внешние сущности (DTD) в XML-парсере."},
    },
})
