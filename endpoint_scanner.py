#!/usr/bin/env python3
"""
Advanced Endpoint Scanner - Universal web endpoint mapper untuk pentesting
Mendeteksi, mengklasifikasi, dan merekomendasikan endpoint untuk pengujian lebih lanjut

Github: https://github.com/username/endpoint-scanner
Usage: python endpoint_scanner_advanced.py --file endpoints.txt --output report.html
"""

import requests
import argparse
import csv
import json
import sys
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Tuple, Optional
import warnings
warnings.filterwarnings('ignore')

# ============== KONFIGURASI DEFAULT ==============
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/json,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive"
}

# ============== DETEKSI TEKNOLOGI ==============
TECH_SIGNATURES = {
    'PHP': ['X-Powered-By: PHP', '.php', 'PHPSESSID'],
    'ASP.NET': ['X-AspNet-Version', 'X-AspNetMvc-Version', 'ASP.NET', '.aspx'],
    'Node.js': ['X-Powered-By: Express', 'Node.js', 'connect.sid'],
    'Java/JSP': ['JSESSIONID', '.jsp', 'X-Powered-By: JSP', 'Java'],
    'Ruby/Rails': ['X-Powered-By: Phusion', 'rack.session', '.rb'],
    'WordPress': ['wp-content', 'wp-includes', 'wp-json', 'wordpress'],
    'Laravel': ['laravel_session', 'X-Powered-By: Laravel'],
    'Django': ['csrftoken', 'sessionid', 'django'],
    'Flask': ['flask-session', 'X-Powered-By: Flask'],
    'React': ['_next/static', 'react', 'webpack'],
    'Angular': ['ng-version', 'angular'],
    'Vue.js': ['vue.js', 'vue.min', 'data-v-'],
}

# ============== SKOR PRIORITAS (Semakin tinggi, semakin penting untuk di-test) ==============
PRIORITY_SCORES = {
    # HIGH PRIORITY (80-100) - Langsung test
    'LOGIN_FORM': 95,           # Form login - target utama
    'API_ENDPOINT': 90,         # API endpoint - sering vulnerable
    'FILE_UPLOAD': 100,         # Upload file - kritis
    'ADMIN_PANEL': 98,          # Admin panel - holy grail
    'PARAMETERIZED': 85,        # Endpoint dengan parameter - SQLi/XSS
    'GRAPHQL': 90,              # GraphQL - sering over-fetching
    
    # MEDIUM PRIORITY (50-79) - Test setelah high
    'DASHBOARD_LANDING': 75,    # Dashboard - sensitive data
    'USER_INPUT': 70,           # Menerima input user
    'JSON_RESPONSE': 65,        # API JSON - injection
    'SEARCH_FUNCTION': 80,      # Search - XSS/SQLi
    'PROFILE_PAGE': 60,         # Profile - IDOR
    
    # LOW PRIORITY (0-49) - Test if time permits
    'STATIC_FILE': 10,          # CSS/JS/images
    'REDIRECT_TO_LOGIN': 20,    # Protected, tapi low impact
    'NOT_FOUND': 5,             # 404 - low value
    'BLANK_SCREEN': 15,         # Possibly broken
    'INFO_DISCLOSURE': 40,      # Info leak - useful for recon
}

class EndpointScanner:
    def __init__(self, base_url: str, headers: dict = None, auth: dict = None, 
                 proxy: dict = None, timeout: int = 10, verify_ssl: bool = False):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Setup headers
        self.session.headers.update(DEFAULT_HEADERS)
        if headers:
            self.session.headers.update(headers)
        
        # Setup auth
        self.auth_config = auth or {}
        self._setup_auth()
        
        # Setup proxy
        if proxy:
            self.session.proxies.update(proxy)
        
        # Storage
        self.results = []
        self.start_time = None
        self.end_time = None
        
    def _setup_auth(self):
        """Setup authentication berdasarkan konfigurasi"""
        auth_type = self.auth_config.get('type', 'none')
        
        if auth_type == 'bearer':
            token = self.auth_config.get('token', '')
            self.session.headers.update({'Authorization': f'Bearer {token}'})
        elif auth_type == 'basic':
            username = self.auth_config.get('username', '')
            password = self.auth_config.get('password', '')
            self.session.auth = (username, password)
        elif auth_type == 'cookie':
            cookie_str = self.auth_config.get('cookie', '')
            self.session.headers.update({'Cookie': cookie_str})
        elif auth_type == 'header':
            custom_headers = self.auth_config.get('headers', {})
            self.session.headers.update(custom_headers)
    
    def _detect_tech_stack(self, response) -> List[str]:
        """Deteksi teknologi yang digunakan berdasarkan response"""
        detected = []
        headers_str = str(response.headers).lower()
        content_str = response.text[:5000].lower()
        
        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in headers_str or sig.lower() in content_str:
                    detected.append(tech)
                    break
        
        return list(set(detected))  # Remove duplicates
    
    def _extract_parameters(self, url: str) -> List[str]:
        """Ekstrak parameter dari URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())
    
    def _detect_input_forms(self, html: str) -> List[Dict]:
        """Deteksi form input dalam HTML"""
        forms = []
        # Simple regex untuk detect form dan input
        form_matches = re.findall(r'<form[^>]*action=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        input_matches = re.findall(r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>', html, re.IGNORECASE)
        
        if form_matches:
            forms.append({'action_urls': form_matches})
        if input_matches:
            forms.append({'input_fields': input_matches})
        
        return forms
    
    def classify_response_advanced(self, response, endpoint: str, response_time: float) -> Dict:
        """
        Klasifikasi endpoint secara detail
        Returns: dict dengan classification, priority_score, reason, metadata
        """
        result = {
            'classification': 'UNKNOWN',
            'priority_score': 0,
            'reason': '',
            'metadata': {}
        }
        
        url_lower = endpoint.lower()
        content_type = response.headers.get('Content-Type', '').lower()
        content_length = len(response.text)
        html_preview = response.text[:5000].lower()
        
        # === DETEKSI BERDASARKAN URL PATTERN ===
        if any(pattern in url_lower for pattern in ['/admin', '/administrator', '/manager', '/cpanel', '/wp-admin']):
            result['classification'] = 'ADMIN_PANEL'
            result['priority_score'] = PRIORITY_SCORES['ADMIN_PANEL']
            result['reason'] = 'Admin panel detected in URL'
        
        elif any(pattern in url_lower for pattern in ['/api', '/v1/', '/v2/', '/graphql', '/rest']):
            result['classification'] = 'API_ENDPOINT'
            result['priority_score'] = PRIORITY_SCORES['API_ENDPOINT']
            result['reason'] = 'API endpoint pattern detected'
        
        elif any(pattern in url_lower for pattern in ['/upload', '/file', '/image', '/media']):
            result['classification'] = 'FILE_UPLOAD'
            result['priority_score'] = PRIORITY_SCORES['FILE_UPLOAD']
            result['reason'] = 'File upload endpoint'
        
        elif any(pattern in url_lower for pattern in ['/search', '/find', '/lookup']):
            result['classification'] = 'SEARCH_FUNCTION'
            result['priority_score'] = PRIORITY_SCORES['SEARCH_FUNCTION']
            result['reason'] = 'Search functionality'
        
        # === DETEKSI BERDASARKAN RESPONSE ===
        elif response.status_code >= 500:
            result['classification'] = 'SERVER_ERROR'
            result['priority_score'] = 30
            result['reason'] = f'HTTP {response.status_code} - Server error (potentially exploitable)'
        
        elif response.status_code == 404:
            result['classification'] = 'NOT_FOUND'
            result['priority_score'] = PRIORITY_SCORES['NOT_FOUND']
            result['reason'] = 'HTTP 404 - Endpoint not found'
        
        elif response.status_code == 403:
            result['classification'] = 'FORBIDDEN'
            result['priority_score'] = 35
            result['reason'] = 'HTTP 403 - Access forbidden (check for bypass)'
        
        elif response.status_code == 401:
            result['classification'] = 'UNAUTHORIZED'
            result['priority_score'] = 40
            result['reason'] = 'HTTP 401 - Authentication required'
        
        elif response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get('Location', '')
            if '/login' in location:
                result['classification'] = 'REDIRECT_TO_LOGIN'
                result['priority_score'] = PRIORITY_SCORES['REDIRECT_TO_LOGIN']
                result['reason'] = f'Redirect to login page: {location}'
            elif '/dashboard' in location or '/home' in location:
                result['classification'] = 'REDIRECT_TO_DASHBOARD'
                result['priority_score'] = PRIORITY_SCORES['DASHBOARD_LANDING']
                result['reason'] = f'Redirect to dashboard: {location}'
            else:
                result['classification'] = 'REDIRECT_OTHER'
                result['priority_score'] = 15
                result['reason'] = f'Redirect to: {location}'
        
        elif response.status_code == 200:
            # === DETEKSI BEDASARKAN CONTENT ===
            
            # Login form detection
            if '<form' in html_preview and any(x in html_preview for x in ['password', 'login', 'signin']):
                result['classification'] = 'LOGIN_FORM'
                result['priority_score'] = PRIORITY_SCORES['LOGIN_FORM']
                result['reason'] = 'Login form detected'
                result['metadata']['forms'] = self._detect_input_forms(response.text)
            
            # Dashboard detection
            elif any(keyword in html_preview for keyword in ['dashboard', 'statistic', 'chart', 'welcome', 'panel', 'analytics']):
                result['classification'] = 'DASHBOARD_LANDING'
                result['priority_score'] = PRIORITY_SCORES['DASHBOARD_LANDING']
                result['reason'] = 'Dashboard/panel page detected'
            
            # GraphQL detection
            elif '/graphql' in url_lower or '"query"' in html_preview or 'GraphQL' in response.headers.get('X-Powered-By', ''):
                result['classification'] = 'GRAPHQL'
                result['priority_score'] = PRIORITY_SCORES['GRAPHQL']
                result['reason'] = 'GraphQL endpoint detected'
            
            # JSON API
            elif 'application/json' in content_type or response.text.strip().startswith(('{', '[')):
                result['classification'] = 'JSON_RESPONSE'
                result['priority_score'] = PRIORITY_SCORES['JSON_RESPONSE']
                result['reason'] = 'API endpoint with JSON response'
            
            # Blank/empty page
            elif content_length < 150:
                result['classification'] = 'BLANK_SCREEN'
                result['priority_score'] = PRIORITY_SCORES['BLANK_SCREEN']
                result['reason'] = f'Empty/blank page ({content_length} bytes)'
            
            # Static files
            elif any(ext in url_lower for ext in ['.css', '.js', '.jpg', '.png', '.gif', '.svg', '.ico']):
                result['classification'] = 'STATIC_FILE'
                result['priority_score'] = PRIORITY_SCORES['STATIC_FILE']
                result['reason'] = 'Static asset file'
            
            # HTML page biasa
            elif 'text/html' in content_type or '<html' in html_preview[:500]:
                result['classification'] = 'HTML_PAGE'
                result['priority_score'] = 25
                result['reason'] = f'Standard HTML page ({content_length} bytes)'
            
            else:
                result['classification'] = 'OTHER_200'
                result['priority_score'] = 20
                result['reason'] = f'Other 200 response (type: {content_type})'
        
        # Tambahan metadata
        result['metadata']['response_time'] = round(response_time, 3)
        result['metadata']['content_length'] = content_length
        result['metadata']['tech_stack'] = self._detect_tech_stack(response)
        result['metadata']['parameters'] = self._extract_parameters(endpoint)
        
        return result
    
    def test_endpoint(self, endpoint: str, method: str = 'GET', data: dict = None) -> Dict:
        """Test single endpoint dengan multiple method support"""
        url = urljoin(self.base_url, endpoint)
        
        result = {
            'endpoint': endpoint,
            'url': url,
            'method': method,
            'timestamp': datetime.now().isoformat(),
        }
        
        try:
            start_req = time.time()
            
            if method == 'GET':
                response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=False)
            elif method == 'POST':
                response = self.session.post(url, data=data, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=False)
            elif method == 'PUT':
                response = self.session.put(url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=False)
            elif method == 'DELETE':
                response = self.session.delete(url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=False)
            else:
                response = self.session.options(url, timeout=self.timeout, verify=self.verify_ssl, allow_redirects=False)
            
            response_time = time.time() - start_req
            
            classification_result = self.classify_response_advanced(response, endpoint, response_time)
            
            result.update({
                'status_code': response.status_code,
                'response_time': response_time,
                'content_length': len(response.text),
                **classification_result
            })
            
            # Tambahan info penting
            result['final_url'] = response.url
            result['headers'] = dict(response.headers)
            
        except requests.exceptions.Timeout:
            result.update({
                'status_code': 'TIMEOUT',
                'classification': 'TIMEOUT',
                'priority_score': 10,
                'reason': 'Request timeout - server slow or unresponsive',
                'response_time': self.timeout
            })
        except requests.exceptions.ConnectionError:
            result.update({
                'status_code': 'CONN_ERR',
                'classification': 'CONNECTION_ERROR',
                'priority_score': 5,
                'reason': 'Connection failed - host unreachable'
            })
        except Exception as e:
            result.update({
                'status_code': 'ERROR',
                'classification': 'EXCEPTION',
                'priority_score': 0,
                'reason': str(e)[:100]
            })
        
        return result
    
    def scan(self, endpoints: List[str], methods: List[str] = ['GET'], 
             threads: int = 10, resume_file: str = None) -> List[Dict]:
        """Scan multiple endpoints with concurrency"""
        
        # Resume support
        scanned_endpoints = set()
        if resume_file:
            try:
                with open(resume_file, 'r') as f:
                    existing = json.load(f)
                    scanned_endpoints = {r['endpoint'] for r in existing}
                    self.results = existing
                    print(f"[+] Resuming from {resume_file} - {len(scanned_endpoints)} already scanned")
            except FileNotFoundError:
                pass
        
        endpoints_to_scan = [ep for ep in endpoints if ep not in scanned_endpoints]
        
        if not endpoints_to_scan:
            print("[+] All endpoints already scanned!")
            return self.results
        
        print(f"[+] Scanning {len(endpoints_to_scan)} endpoints with {threads} threads...")
        self.start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {}
            for endpoint in endpoints_to_scan:
                for method in methods:
                    future = executor.submit(self.test_endpoint, endpoint, method)
                    futures[future] = (endpoint, method)
            
            for i, future in enumerate(as_completed(futures), 1):
                result = future.result()
                self.results.append(result)
                
                # Print progress
                priority_indicator = '⭐' * min(3, int(result.get('priority_score', 0) / 35))
                print(f"[{i}/{len(endpoints_to_scan)}] {priority_indicator} {result['classification']}: {result['endpoint']} ({result.get('response_time', 0)}s)")
        
        self.end_time = time.time()
        return self.results
    
    def get_priority_recommendations(self, top_n: int = 20) -> List[Dict]:
        """Rekomendasi endpoint prioritas untuk di-pentest"""
        sorted_results = sorted(self.results, key=lambda x: x.get('priority_score', 0), reverse=True)
        return sorted_results[:top_n]
    
    def generate_html_report(self, output_file: str = 'report.html'):
        """Generate HTML report yang bagus"""
        priority_endpoints = self.get_priority_recommendations(20)
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Endpoint Scanner Report - {self.base_url}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0c10; color: #e0e0e0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        .header {{ background: linear-gradient(135deg, #ff6b35, #ff4757); padding: 30px; border-radius: 20px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2rem; margin-bottom: 10px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #1a1d27; border-radius: 15px; padding: 20px; text-align: center; border: 1px solid #282d3a; }}
        .stat-card h3 {{ font-size: 2rem; color: #ff6b35; }}
        .section {{ background: #0f1117; border-radius: 15px; padding: 20px; margin-bottom: 30px; border: 1px solid #282d3a; }}
        .section h2 {{ color: #ff6b35; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }}
        .priority-table, .results-table {{ width: 100%; border-collapse: collapse; }}
        .priority-table th, .results-table th {{ text-align: left; padding: 12px; background: #1a1d27; color: #ff6b35; }}
        .priority-table td, .results-table td {{ padding: 10px 12px; border-bottom: 1px solid #282d3a; }}
        .badge {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; }}
        .badge-high {{ background: #ff4757; color: white; }}
        .badge-medium {{ background: #ffa502; color: #000; }}
        .badge-low {{ background: #2ed573; color: #000; }}
        .endpoint-link {{ color: #ff6b35; text-decoration: none; }}
        .endpoint-link:hover {{ text-decoration: underline; }}
        @media (max-width: 768px) {{ .stats-grid {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Endpoint Scanner Report</h1>
            <p>Target: <strong>{self.base_url}</strong> | Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card"><h3>{len(self.results)}</h3><p>Total Endpoints</p></div>
            <div class="stat-card"><h3>{self.end_time and round(self.end_time - self.start_time, 2) or 'N/A'}</h3><p>Scan Time (seconds)</p></div>
            <div class="stat-card"><h3>{len([r for r in self.results if r.get('priority_score', 0) >= 80])}</h3><p>High Priority</p></div>
            <div class="stat-card"><h3>{self.results[0].get('response_time', 'N/A') if self.results else 'N/A'}</h3><p>Avg Response Time</p></div>
        </div>
        
        <div class="section">
            <h2>⭐ Top 20 Prioritas untuk Dipentest</h2>
            <table class="priority-table">
                <thead><tr><th>Priority</th><th>Classification</th><th>Endpoint</th><th>Reason</th><th>Response Time</th></tr></thead>
                <tbody>
                    {''.join(f'''
                    <tr>
                        <td><span class="badge badge-{'high' if r['priority_score'] >= 80 else 'medium' if r['priority_score'] >= 50 else 'low'}">{r['priority_score']}</span></td>
                        <td>{r['classification']}</td>
                        <td><a href="{r['url']}" target="_blank" class="endpoint-link">{r['endpoint'][:60]}</a></td>
                        <td>{r.get('reason', '-')[:80]}</td>
                        <td>{r.get('response_time', 0)}s</td>
                    </tr>
                    ''' for r in priority_endpoints)}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>📊 Hasil Lengkap Berdasarkan Klasifikasi</h2>
            <table class="results-table">
                <thead><tr><th>Classification</th><th>Status</th><th>Endpoint</th><th>Score</th><th>Time</th></tr></thead>
                <tbody>
                    {''.join(f'''
                    <tr>
                        <td>{r['classification']}</td>
                        <td>{r['status_code']}</td>
                        <td><a href="{r['url']}" target="_blank" class="endpoint-link">{r['endpoint'][:50]}</a></td>
                        <td>{r.get('priority_score', 0)}</td>
                        <td>{r.get('response_time', 0)}s</td>
                    </tr>
                    ''' for r in self.results[:100])}
                </tbody>
            </table>
            {f'<p style="margin-top: 10px; color: #8e97a6;">... and {len(self.results) - 100} more results</p>' if len(self.results) > 100 else ''}
        </div>
    </div>
</body>
</html>
        """
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
        print(f"[+] HTML report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Endpoint Scanner - Universal web endpoint mapper untuk pentesting',
        epilog='''
Examples:
  python endpoint_scanner_advanced.py --file endpoints.txt
  python endpoint_scanner_advanced.py --file urls.txt --auth-type bearer --token TOKEN123
  python endpoint_scanner_advanced.py --file urls.txt --methods GET,POST --output report.html
  python endpoint_scanner_advanced.py --single /api/users --methods GET,POST,PUT
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Input
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', '-f', help='File containing endpoints (one per line)')
    input_group.add_argument('--single', '-s', help='Single endpoint to test')
    
    # Target
    parser.add_argument('--base', '-b', default='https://example.com', help='Base URL (default: https://example.com)')
    
    # Authentication
    parser.add_argument('--auth-type', choices=['bearer', 'basic', 'cookie', 'header', 'none'], default='none', help='Authentication type')
    parser.add_argument('--token', help='Bearer token (for bearer auth)')
    parser.add_argument('--username', help='Username (for basic auth)')
    parser.add_argument('--password', help='Password (for basic auth)')
    parser.add_argument('--cookie', help='Cookie string (for cookie auth)')
    parser.add_argument('--auth-header', help='Custom auth header (format: "Header: value")')
    
    # HTTP Methods
    parser.add_argument('--methods', '-m', default='GET', help='HTTP methods to test, comma-separated (default: GET)')
    
    # Performance
    parser.add_argument('--threads', '-t', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    # Output
    parser.add_argument('--output', '-o', default='scan_results', help='Output file (without extension, supports .csv, .json, .html)')
    parser.add_argument('--format', choices=['csv', 'json', 'html', 'all'], default='html', help='Output format (default: html)')
    
    # Filtering
    parser.add_argument('--min-priority', type=int, default=0, help='Minimum priority score to include (0-100)')
    parser.add_argument('--classification', help='Filter by classification (e.g., API_ENDPOINT,LOGIN_FORM)')
    
    # Other
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080 for Burp)')
    parser.add_argument('--resume', help='Resume from previous JSON results file')
    parser.add_argument('--verify-ssl', action='store_true', help='Verify SSL certificates (default: false)')
    parser.add_argument('--save-config', help='Save configuration to file for reuse')
    
    args = parser.parse_args()
    
    # Load endpoints
    endpoints = []
    if args.file:
        with open(args.file, 'r') as f:
            endpoints = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    elif args.single:
        endpoints = [args.single]
    
    if not endpoints:
        print("[!] No endpoints to scan")
        sys.exit(1)
    
    # Setup authentication
    auth_config = {'type': args.auth_type}
    if args.auth_type == 'bearer' and args.token:
        auth_config['token'] = args.token
    elif args.auth_type == 'basic':
        auth_config['username'] = args.username or ''
        auth_config['password'] = args.password or ''
    elif args.auth_type == 'cookie' and args.cookie:
        auth_config['cookie'] = args.cookie
    elif args.auth_type == 'header' and args.auth_header:
        if ':' in args.auth_header:
            key, val = args.auth_header.split(':', 1)
            auth_config['headers'] = {key.strip(): val.strip()}
    
    # Setup proxy
    proxy_config = {'http': args.proxy, 'https': args.proxy} if args.proxy else None
    
    # Parse methods
    methods = [m.strip().upper() for m in args.methods.split(',')]
    
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║     🚀 Advanced Endpoint Scanner - Web Pentesting Tool      ║
╚══════════════════════════════════════════════════════════════╝

[+] Target: {args.base}
[+] Endpoints: {len(endpoints)}
[+] Methods: {', '.join(methods)}
[+] Threads: {args.threads}
[+] Auth Type: {args.auth_type}
[+] Proxy: {args.proxy or 'None'}
[+] Output: {args.output}.{args.format if args.format != 'all' else '{csv,json,html}'}
""")
    
    # Initialize scanner
    scanner = EndpointScanner(
        base_url=args.base,
        auth=auth_config,
        proxy=proxy_config,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl
    )
    
    # Run scan
    results = scanner.scan(endpoints, methods=methods, threads=args.threads, resume_file=args.resume)
    
    # Filter berdasarkan priority
    if args.min_priority > 0:
        results = [r for r in results if r.get('priority_score', 0) >= args.min_priority]
    
    if args.classification:
        allowed_class = [c.strip() for c in args.classification.split(',')]
        results = [r for r in results if r.get('classification') in allowed_class]
    
    # Print priorities
    print("\n" + "="*80)
    print("🎯 TOP 10 PRIORITAS UNTUK DIPENTEST")
    print("="*80)
    priorities = scanner.get_priority_recommendations(10)
    for i, p in enumerate(priorities, 1):
        stars = '⭐' * min(3, int(p.get('priority_score', 0) // 35))
        print(f"{i:2}. {stars} [{p['priority_score']:3d}] {p['classification']:20} - {p['endpoint'][:60]}")
    
    # Export results
    base_output = args.output
    if args.format in ['csv', 'all']:
        csv_file = f"{base_output}.csv"
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].keys())
                writer.writeheader()
                writer.writerows(results)
        print(f"\n[+] CSV saved: {csv_file}")
    
    if args.format in ['json', 'all']:
        json_file = f"{base_output}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump({
                'target': args.base,
                'scan_time': datetime.now().isoformat(),
                'total_endpoints': len(results),
                'results': results
            }, f, indent=2)
        print(f"[+] JSON saved: {json_file}")
    
    if args.format in ['html', 'all']:
        html_file = f"{base_output}.html"
        scanner.generate_html_report(html_file)
    
    # Save config if requested
    if args.save_config:
        config = {
            'base_url': args.base,
            'auth_type': args.auth_type,
            'methods': args.methods,
            'threads': args.threads,
            'timeout': args.timeout
        }
        with open(args.save_config, 'w') as f:
            json.dump(config, f, indent=2)
        print(f"[+] Config saved: {args.save_config}")

if __name__ == '__main__':
    main()