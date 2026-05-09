# Advanced Endpoint Scanner

Advanced Endpoint Scanner adalah tools untuk mapping, scanning, dan klasifikasi endpoint web secara otomatis. Tools ini membantu pentester dan bug hunter untuk mengidentifikasi endpoint mana yang perlu dipentest, mendeteksi redirect ke login, dashboard, blank screen, API endpoint, dan memberikan rekomendasi prioritas berdasarkan potensi kerentanan.

Cocok untuk post-exploitation mapping setelah mendapatkan endpoint dari Burp Suite, crawling, atau JS extraction.

---

Fitur Unggulan:

- Multi-Auth Support: Bearer Token, Basic Auth, Cookie, Custom Header
- Multiple HTTP Methods: GET, POST, PUT, DELETE, OPTIONS
- Smart Classification: Deteksi 15+ jenis endpoint (login, dashboard, API, upload, dll)
- Prioritas Pentest: Rekomendasi endpoint mana yang paling penting di-test (skor 0-100)
- Multi-Threading: Scanning cepat dengan konfigurasi thread
- Laporan Ekspor: Output ke CSV, JSON, atau HTML report
- Resume Scan: Lanjutkan scan yang terhenti
- Proxy Support: Integrasi dengan Burp Suite
- Tech Stack Detection: Deteksi framework/CMS dari response

---

Instalasi

Di Kali Linux / Linux Distro:

1. Clone repository:
   git clone https://github.com/NARATHAMA/endpoint_scanner.git
   cd endpoint_scanner

2. Install dependencies:
   pip3 install -r requirements.txt

3. Beri permission execute:
   chmod +x endpoint_scanner.py

4. Test running:
   python3 endpoint_scanner.py --help

---

Cara Penggunaan

Basic Usage:

- Scan dari file endpoints.txt:
  python3 endpoint_scanner.py --file endpoints.txt --base https://target.com

- Scan single endpoint:
  python3 endpoint_scanner.py --single /api/users --base https://target.com

- Output ke HTML report:
  python3 endpoint_scanner.py --file endpoints.txt --base https://target.com --format html

Dengan Authentication:

- Bearer Token (API testing):
  python3 endpoint_scanner.py --file endpoints.txt --base https://api.target.com --auth-type bearer --token "your_jwt_token_here"

- Basic Auth:
  python3 endpoint_scanner.py --file endpoints.txt --base https://target.com --auth-type basic --username admin --password secret123

- Cookie Auth:
  python3 endpoint_scanner.py --file endpoints.txt --base https://target.com --auth-type cookie --cookie "sessionid=abc123; token=xyz789"

Advanced Usage:

- Multiple HTTP methods:
  python3 endpoint_scanner.py --single /api/users --methods GET,POST,PUT,DELETE --base https://target.com

- Via Burp Suite proxy:
  python3 endpoint_scanner.py --file endpoints.txt --base https://target.com --proxy http://127.0.0.1:8080

- Filter hasil dengan priority minimal 70:
  python3 endpoint_scanner.py --file endpoints.txt --base https://target.com --min-priority 70 --output high_priority

- Resume scan yang terhenti:
  python3 endpoint_scanner.py --file endpoints.txt --base https://target.com --resume scan_results.json

---

Format File Endpoints

Buat file endpoints.txt dengan isi satu endpoint per baris:

# Ini komentar (abaikan)
/api/users
/api/users/1
/login
/dashboard
/admin
/api/v1/profile
/search?q=test
/file/upload

---

Prioritas Skor

Skor 80-100 (High): Langsung test - Potensi kritis. Contoh: login form, file upload, admin panel.

Skor 50-79 (Medium): Test setelah high - Potensi medium. Contoh: dashboard, search, profile.

Skor 0-49 (Low): Test jika ada waktu - Low impact. Contoh: static files, 404, redirect.

---

Cara Mendapatkan Endpoints

Tools ini tidak otomatis mencari endpoint. Anda perlu menyediakan file endpoints.txt. Berikut cara mendapatkannya:

1. Dari Burp Suite:
   Target > Site map > Copy > URLs

2. Dari crawling dengan gospider/katana:
   gospider -s https://target.com -o crawl_output.txt
   cat crawl_output.txt | grep -oP '\/[a-zA-Z0-9\/_-]+' | sort -u > endpoints.txt

3. Dari JavaScript files:
   cat script.js | grep -oE '["'"'"']\/[a-zA-Z0-9\/_-]+["'"'"']' | sort -u > endpoints.txt

4. Dari Swagger/OpenAPI:
   curl https://target.com/swagger.json | jq '.paths | keys[]' > endpoints.txt

---

Daftar Klasifikasi Endpoint

LOGIN_FORM: Halaman login dengan form (High)
API_ENDPOINT: REST API / GraphQL (High)
FILE_UPLOAD: Endpoint upload file (High)
ADMIN_PANEL: Panel admin (High)
DASHBOARD_LANDING: Dashboard/user panel (Medium)
SEARCH_FUNCTION: Fitur pencarian (Medium)
JSON_RESPONSE: API JSON response (Medium)
REDIRECT_TO_LOGIN: Redirect ke login (Low)
BLANK_SCREEN: Halaman kosong (Low)
NOT_FOUND: 404 - tidak ditemukan (Low)
STATIC_FILE: CSS/JS/images (Low)

---

Struktur Project

endpoint_scanner/
├── endpoint_scanner.py    # Main script
├── README.md              # Dokumentasi
├── requirements.txt       # Dependencies
├── examples/
│   └── endpoints.txt      # Contoh file endpoints
└── .gitignore             # Abaikan hasil scan

---

Lisensi

MIT License - Bebas digunakan, dimodifikasi, dan didistribusikan.

---

Author

Narathama Firmansyah Putra
GitHub: https://github.com/NARATHAMA
Instagram: https://instagram.com/narathamaputra
Medium: https://medium.com/@naratama671
