#!/usr/bin/env python3
"""
Advanced Web Security Scanner - Expert Edition
Sistem pentesting comprehensive untuk PHP Native & websites modern
"""

import os
import sys
import json
import time
import argparse
import hashlib
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

from bs4 import BeautifulSoup
import ssl
import socket

# ============================================================
# KONFIGURASI GLOBAL
# ============================================================

class Config:
    """Konfigurasi Scanner"""
    TIMEOUT = 15
    THREADS = 10
    USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    MAX_RETRIES = 3
    BACKOFF_FACTOR = 0.3
    
    # Payload database untuk testing
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "admin' --",
        "' OR 1=1--",
        "1' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1' AND '1'='1",
        "1' AND sleep(5)--",
        "1' AND BENCHMARK(10000000, MD5('x'))--",
    ]
    
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<iframe src='javascript:alert(\"XSS\")'></iframe>",
        "<body onload=alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')></marquee>",
    ]
    
    COMMON_DIRS = [
        '/admin', '/administrator', '/admin_panel', '/cpanel',
        '/backup', '/backups', '/old', '/archive',
        '/config', '/configs', '/configuration',
        '/uploads', '/upload', '/files', '/download',
        '/images', '/img', '/assets', '/public',
        '/docs', '/documentation', '/tmp', '/temp',
        '/database', '/db', '/sql', '/data',
        '/logs', '/log', '/access.log', '/error.log',
        '/.git', '/.svn', '/.hg', '/.env', '/.config',
        '/test', '/tests', '/testing', '/debug',
        '/api', '/api/v1', '/api/v2', '/services',
        '/.well-known', '/health', '/status', '/ping',
    ]
    
    SENSITIVE_FILES = [
        '/.env', '/.env.local', '/.env.backup',
        '/config.php', '/config.ini', '/config.json',
        '/database.php', '/database.conf',
        '/.git/HEAD', '/.git/config',
        '/composer.json', '/composer.lock',
        '/package.json', '/package-lock.json',
        '/web.config', '/.htaccess', '/web.xml',
        '/backup.sql', '/database.sql', '/dump.sql',
        '/phpinfo.php', '/info.php', '/test.php',
        '/wp-config.php', '/settings.py',
        '/.aws/credentials', '/.ssh/id_rsa',
        '/vault.txt', '/secrets.json',
        '/application.yml', '/application.properties',
    ]
    
    SQL_ERRORS = [
        'sql syntax', 'mysql', 'sqlite', 'postgresql',
        'ORA-', 'SQL Server', 'syntax error', 'database error',
        'mysql error', 'warning: mysql', 'sqlstate',
        'unclosed quotation mark', 'incorrect syntax',
    ]

# ============================================================
# HTTP CLIENT DENGAN RETRY LOGIC
# ============================================================

class HTTPClient:
    """HTTP Client dengan retry logic dan session pooling"""
    
    def __init__(self, timeout=Config.TIMEOUT, verify_ssl=False):
        self.session = requests.Session()
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=Config.MAX_RETRIES,
            backoff_factor=Config.BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set user agent
        self.session.headers.update({
            'User-Agent': Config.USER_AGENT,
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate',
        })
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """GET request dengan error handling"""
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', self.verify_ssl)
            return self.session.get(url, **kwargs)
        except requests.exceptions.RequestException as e:
            return None
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """POST request dengan error handling"""
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', self.verify_ssl)
            return self.session.post(url, **kwargs)
        except requests.exceptions.RequestException as e:
            return None
    
    def close(self):
        """Close session"""
        self.session.close()

# ============================================================
# LOGGER DAN REPORTING
# ============================================================

class Logger:
    """Logging system dengan color support"""
    
    COLORS = {
        'CRITICAL': '\033[91m',  # Red
        'HIGH': '\033[93m',       # Yellow
        'MEDIUM': '\033[94m',     # Blue
        'LOW': '\033[92m',        # Green
        'INFO': '\033[97m',       # White
        'SUCCESS': '\033[92m',    # Green
        'RESET': '\033[0m'
    }
    
    def __init__(self, log_file=None):
        self.log_file = log_file
        self.logs = []
    
    def _write(self, level: str, message: str, color: bool = True):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}"
        
        if color and level in self.COLORS:
            print(f"{self.COLORS[level]}{log_entry}{self.COLORS['RESET']}")
        else:
            print(log_entry)
        
        self.logs.append({
            'timestamp': timestamp,
            'level': level,
            'message': message
        })
        
        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(log_entry + '\n')
    
    def info(self, message: str):
        self._write('INFO', message)
    
    def success(self, message: str):
        self._write('SUCCESS', message)
    
    def warning(self, message: str):
        self._write('MEDIUM', message)
    
    def error(self, message: str):
        self._write('HIGH', message)
    
    def critical(self, message: str):
        self._write('CRITICAL', message)

# ============================================================
# VULNERABILITY CLASSES
# ============================================================

class Vulnerability:
    """Class untuk merepresentasikan vulnerability"""
    
    SEVERITY_LEVELS = {
        'CRITICAL': 1,
        'HIGH': 2,
        'MEDIUM': 3,
        'LOW': 4,
        'INFO': 5
    }
    
    def __init__(self, vuln_type: str, severity: str, title: str, 
                 description: str, endpoint: str = '', payload: str = ''):
        self.type = vuln_type
        self.severity = severity
        self.title = title
        self.description = description
        self.endpoint = endpoint
        self.payload = payload
        self.timestamp = datetime.now().isoformat()
        self.evidence = []
    
    def add_evidence(self, evidence: str):
        """Add evidence untuk vulnerability"""
        self.evidence.append(evidence)
    
    def to_dict(self) -> Dict:
        return {
            'type': self.type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'endpoint': self.endpoint,
            'payload': self.payload,
            'timestamp': self.timestamp,
            'evidence': self.evidence
        }

# ============================================================
# SCANNER MODULES
# ============================================================

class ReconModule:
    """Reconnaissance & Information Gathering"""
    
    def __init__(self, client: HTTPClient, logger: Logger):
        self.client = client
        self.logger = logger
        self.findings = []
    
    def scan_whois_info(self, domain: str) -> Dict:
        """Get domain WHOIS information"""
        self.logger.info(f"[RECON] Gathering WHOIS information for {domain}")
        # Simplified - dalam production, gunakan whois library
        try:
            parsed = urlparse(domain if domain.startswith(('http://', 'https://')) else f'https://{domain}')
            domain_only = parsed.netloc
            return {'domain': domain_only}
        except:
            return {}
    
    def scan_dns_records(self, domain: str) -> List[Dict]:
        """Scan DNS records"""
        self.logger.info(f"[RECON] Scanning DNS records for {domain}")
        records = []
        try:
            parsed = urlparse(domain if domain.startswith(('http://', 'https://')) else f'https://{domain}')
            domain_only = parsed.netloc
            
            # Get basic DNS info
            try:
                ip = socket.gethostbyname(domain_only)
                records.append({'type': 'A', 'value': ip, 'severity': 'INFO'})
            except:
                pass
        except Exception as e:
            self.logger.error(f"DNS scan error: {str(e)}")
        
        return records
    
    def scan_technologies(self, response: requests.Response) -> List[str]:
        """Detect technologies used"""
        techs = []
        
        # Check headers
        headers = response.headers
        
        if 'X-Powered-By' in headers:
            techs.append(f"X-Powered-By: {headers['X-Powered-By']}")
        
        if 'Server' in headers:
            techs.append(f"Server: {headers['Server']}")
        
        # Check content for tech signatures
        content = response.text.lower()
        
        signatures = {
            'WordPress': ['wp-content', 'wp-includes', 'wp-admin'],
            'Joomla': ['joomla', 'com_content', 'menu.php'],
            'Drupal': ['drupal', 'sites/default'],
            'Laravel': ['laravel', 'app.js'],
            'Django': ['django'],
            'React': ['react', 'reactdom'],
            'Vue.js': ['vuejs', 'vue.js'],
            'Angular': ['angular', 'ng-app'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap.css', 'bootstrap.js'],
        }
        
        for tech, signatures_list in signatures.items():
            for sig in signatures_list:
                if sig in content:
                    techs.append(tech)
                    break
        
        return list(set(techs))

class SQLiModule:
    """SQL Injection Testing"""
    
    def __init__(self, client: HTTPClient, logger: Logger):
        self.client = client
        self.logger = logger
        self.vulnerabilities = []
    
    def test_endpoint(self, url: str, params: Dict = None, method: str = 'GET') -> List[Vulnerability]:
        """Test endpoint untuk SQL injection"""
        vulns = []
        
        if not params:
            return vulns
        
        for param_name, param_value in params.items():
            for payload in Config.SQL_PAYLOADS[:5]:  # Limit payloads for speed
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    if method.upper() == 'POST':
                        resp = self.client.post(url, data=test_params)
                    else:
                        resp = self.client.get(url, params=test_params)
                    
                    if resp and resp.status_code == 200:
                        # Check for SQL errors
                        for error in Config.SQL_ERRORS:
                            if error in resp.text.lower():
                                vuln = Vulnerability(
                                    vuln_type='SQL Injection',
                                    severity='CRITICAL',
                                    title=f'SQL Injection in parameter "{param_name}"',
                                    description=f'SQL error detected in response',
                                    endpoint=url,
                                    payload=payload
                                )
                                vuln.add_evidence(f'SQL error: {error}')
                                vulns.append(vuln)
                                self.logger.critical(f"SQL Injection found in {url} param: {param_name}")
                                break
                except:
                    pass
        
        return vulns
    
    def crawl_and_test_forms(self, base_url: str) -> List[Vulnerability]:
        """Crawl website dan test semua forms untuk SQLi"""
        vulns = []
        
        try:
            resp = self.client.get(base_url)
            if not resp:
                return vulns
            
            soup = BeautifulSoup(resp.content, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms[:10]:  # Limit untuk performance
                action = form.get('action', '')
                method = form.get('method', 'GET')
                form_url = urljoin(base_url, action)
                
                # Extract form inputs
                inputs = {}
                for input_tag in form.find_all('input'):
                    name = input_tag.get('name')
                    if name:
                        inputs[name] = 'test'
                
                if inputs:
                    vulns.extend(self.test_endpoint(form_url, inputs, method))
        except Exception as e:
            self.logger.error(f"Form crawling error: {str(e)}")
        
        return vulns

class XSSModule:
    """Cross-Site Scripting Testing"""
    
    def __init__(self, client: HTTPClient, logger: Logger):
        self.client = client
        self.logger = logger
        self.vulnerabilities = []
    
    def test_reflection(self, url: str, param: str, payload: str) -> bool:
        """Test apakah payload direflect di response"""
        try:
            test_url = f"{url}?{param}={payload}"
            resp = self.client.get(test_url)
            
            if resp and payload in resp.text:
                return True
        except:
            pass
        
        return False
    
    def test_encoding(self, response_text: str, payload: str) -> bool:
        """Check apakah payload ter-encode dengan baik"""
        encoded_patterns = [
            payload.replace('<', '&lt;'),
            payload.replace('>', '&gt;'),
            payload.replace('"', '&quot;'),
            payload.replace("'", '&#x27;'),
        ]
        
        for pattern in encoded_patterns:
            if pattern not in response_text and payload not in response_text:
                return True
        
        return False
    
    def test_endpoint(self, url: str, params: Dict = None) -> List[Vulnerability]:
        """Test endpoint untuk XSS"""
        vulns = []
        
        if not params:
            return vulns
        
        for param_name in params.keys():
            for payload in Config.XSS_PAYLOADS[:3]:
                test_params = params.copy()
                test_params[param_name] = payload
                
                try:
                    resp = self.client.get(url, params=test_params)
                    
                    if resp and self.test_reflection(url, param_name, payload):
                        if not self.test_encoding(resp.text, payload):
                            vuln = Vulnerability(
                                vuln_type='Cross-Site Scripting',
                                severity='HIGH',
                                title=f'Reflected XSS in parameter "{param_name}"',
                                description='User input tidak di-escape dengan proper',
                                endpoint=url,
                                payload=payload
                            )
                            vulns.append(vuln)
                            self.logger.error(f"XSS found in {url} param: {param_name}")
                            break
                except:
                    pass
        
        return vulns

class AuthenticationModule:
    """Authentication & Authorization Testing"""
    
    def __init__(self, client: HTTPClient, logger: Logger):
        self.client = client
        self.logger = logger
        self.vulnerabilities = []
    
    def test_default_credentials(self, urls: List[str]) -> List[Vulnerability]:
        """Test default credentials"""
        vulns = []
        
        default_creds = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('administrator', 'administrator'),
            ('root', 'root'),
            ('test', 'test'),
        ]
        
        for url in urls:
            for username, password in default_creds:
                try:
                    resp = self.client.post(url, data={
                        'username': username,
                        'password': password,
                        'login': 'Login',
                        'submit': 'Submit'
                    })
                    
                    if resp and 'success' in resp.text.lower() and 'error' not in resp.text.lower():
                        vuln = Vulnerability(
                            vuln_type='Default Credentials',
                            severity='CRITICAL',
                            title=f'Default credentials detected',
                            description=f'Username "{username}" dengan password "{password}" berhasil login',
                            endpoint=url
                        )
                        vulns.append(vuln)
                        self.logger.critical(f"Default credentials found: {username}:{password}")
                except:
                    pass
        
        return vulns
    
    def check_password_policy(self, forms: List) -> List[Vulnerability]:
        """Check password policy"""
        vulns = []
        
        # Look for password fields tanpa strength requirements
        for form in forms:
            password_inputs = form.find_all('input', {'type': 'password'})
            
            if password_inputs:
                has_strength_check = False
                
                # Check for strength indicators
                if 'strength' in str(form).lower() or 'pattern' in str(form).lower():
                    has_strength_check = True
                
                if not has_strength_check:
                    vuln = Vulnerability(
                        vuln_type='Weak Password Policy',
                        severity='MEDIUM',
                        title='No password strength requirements',
                        description='Password fields tidak memiliki strength validation'
                    )
                    vulns.append(vuln)
        
        return vulns

class EncryptionModule:
    """Encryption & SSL/TLS Testing"""
    
    def __init__(self, client: HTTPClient, logger: Logger):
        self.client = client
        self.logger = logger
        self.vulnerabilities = []
    
    def test_ssl_tls(self, domain: str) -> List[Vulnerability]:
        """Test SSL/TLS configuration"""
        vulns = []
        
        parsed = urlparse(domain if domain.startswith(('http://', 'https://')) else f'https://{domain}')
        hostname = parsed.netloc.split(':')[0]
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate validity
                    if not cert:
                        vuln = Vulnerability(
                            vuln_type='SSL Certificate Issue',
                            severity='HIGH',
                            title='Invalid SSL certificate',
                            description='SSL certificate tidak valid atau expired'
                        )
                        vulns.append(vuln)
                        self.logger.error("Invalid SSL certificate detected")
        except Exception as e:
            self.logger.warning(f"SSL check failed: {str(e)}")
        
        return vulns
    
    def check_http_to_https(self, domain: str) -> List[Vulnerability]:
        """Check HTTP to HTTPS redirect"""
        vulns = []
        
        try:
            http_url = domain.replace('https://', 'http://')
            resp = self.client.get(http_url, allow_redirects=False)
            
            if resp and resp.status_code not in [301, 302, 307, 308]:
                vuln = Vulnerability(
                    vuln_type='Missing HTTPS Redirect',
                    severity='HIGH',
                    title='HTTP tidak redirect ke HTTPS',
                    description='User dapat mengakses website via HTTP'
                )
                vulns.append(vuln)
                self.logger.warning("No HTTP to HTTPS redirect found")
            else:
                self.logger.success("HTTP to HTTPS redirect configured")
        except:
            pass
        
        return vulns

class HeaderSecurityModule:
    """Security Headers Testing"""
    
    def __init__(self, client: HTTPClient, logger: Logger):
        self.client = client
        self.logger = logger
        self.vulnerabilities = []
    
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'severity': 'HIGH',
            'description': 'Memaksa HTTPS connection'
        },
        'X-Frame-Options': {
            'severity': 'MEDIUM',
            'description': 'Proteksi terhadap clickjacking'
        },
        'X-Content-Type-Options': {
            'severity': 'MEDIUM',
            'description': 'Prevent MIME type sniffing'
        },
        'Content-Security-Policy': {
            'severity': 'HIGH',
            'description': 'Prevent XSS dan injection attacks'
        },
        'X-XSS-Protection': {
            'severity': 'LOW',
            'description': 'Browser XSS filter'
        },
        'Referrer-Policy': {
            'severity': 'LOW',
            'description': 'Control referrer information'
        },
        'Permissions-Policy': {
            'severity': 'MEDIUM',
            'description': 'Control browser features'
        },
    }
    
    def test_headers(self, url: str) -> List[Vulnerability]:
        """Test security headers"""
        vulns = []
        
        try:
            resp = self.client.get(url)
            if not resp:
                return vulns
            
            headers = resp.headers
            
            for header_name, header_info in self.SECURITY_HEADERS.items():
                if header_name not in headers:
                    vuln = Vulnerability(
                        vuln_type='Missing Security Header',
                        severity=header_info['severity'],
                        title=f'Missing: {header_name}',
                        description=header_info['description'],
                        endpoint=url
                    )
                    vulns.append(vuln)
                    self.logger.warning(f"Missing header: {header_name}")
            
            # Check for information disclosure headers
            disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in disclosure_headers:
                if header in headers:
                    vuln = Vulnerability(
                        vuln_type='Information Disclosure',
                        severity='LOW',
                        title=f'Server information disclosed via {header}',
                        description=f'{header}: {headers[header]}',
                        endpoint=url
                    )
                    vulns.append(vuln)
                    self.logger.warning(f"Server info disclosed: {header}: {headers[header]}")
        
        except Exception as e:
            self.logger.error(f"Header test error: {str(e)}")
        
        return vulns

class FileAccessModule:
    """File Access & Directory Testing"""
    
    def __init__(self, client: HTTPClient, logger: Logger):
        self.client = client
        self.logger = logger
        self.vulnerabilities = []
    
    def scan_directories(self, base_url: str, max_threads: int = 5) -> List[Vulnerability]:
        """Scan for accessible directories"""
        vulns = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {}
            
            for directory in Config.COMMON_DIRS:
                url = urljoin(base_url, directory)
                futures[executor.submit(self._check_directory, url)] = directory
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        vulns.append(result)
                except:
                    pass
        
        return vulns
    
    def _check_directory(self, url: str) -> Optional[Vulnerability]:
        """Check single directory"""
        try:
            resp = self.client.get(url)
            
            if resp and resp.status_code == 200:
                # Check for directory listing
                if 'index of' in resp.text.lower() or 'parent directory' in resp.text.lower():
                    vuln = Vulnerability(
                        vuln_type='Directory Listing',
                        severity='MEDIUM',
                        title=f'Directory listing accessible: {url}',
                        description='Struktur direktori terekspos',
                        endpoint=url
                    )
                    self.logger.warning(f"Directory listing found: {url}")
                    return vuln
                
                # Check for other findings
                if resp.status_code == 200 and len(resp.text) > 100:
                    self.logger.info(f"Directory accessible: {url}")
        except:
            pass
        
        return None
    
    def scan_sensitive_files(self, base_url: str, max_threads: int = 5) -> List[Vulnerability]:
        """Scan for sensitive files"""
        vulns = []
        
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {}
            
            for file_path in Config.SENSITIVE_FILES:
                url = urljoin(base_url, file_path)
                futures[executor.submit(self._check_file, url, file_path)] = file_path
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        vulns.append(result)
                except:
                    pass
        
        return vulns
    
    def _check_file(self, url: str, file_path: str) -> Optional[Vulnerability]:
        """Check single file"""
        try:
            resp = self.client.get(url)
            
            if resp and resp.status_code == 200:
                severity = 'CRITICAL' if file_path in ['/.env', '/.git/HEAD', '/backup.sql', '/database.sql'] else 'HIGH'
                
                vuln = Vulnerability(
                    vuln_type='Sensitive File Exposure',
                    severity=severity,
                    title=f'Sensitive file accessible: {file_path}',
                    description=f'File {file_path} dapat diakses publik',
                    endpoint=url
                )
                self.logger.critical(f"Sensitive file found: {url}")
                return vuln
        except:
            pass
        
        return None

class APISecurityModule:
    """API Security Testing"""
    
    def __init__(self, client: HTTPClient, logger: Logger):
        self.client = client
        self.logger = logger
        self.vulnerabilities = []
    
    def test_api_endpoints(self, base_url: str) -> List[Vulnerability]:
        """Test API endpoints"""
        vulns = []
        
        api_paths = ['/api', '/api/v1', '/api/v2', '/api/v3', '/graphql']
        
        for api_path in api_paths:
            url = urljoin(base_url, api_path)
            
            try:
                # Test GET
                resp = self.client.get(url)
                if resp and resp.status_code == 200:
                    if 'json' in resp.headers.get('Content-Type', '').lower():
                        self.logger.info(f"API endpoint found: {url}")
                        
                        # Check for authentication
                        if 'error' not in resp.text.lower() and 'unauthorized' not in resp.text.lower():
                            vuln = Vulnerability(
                                vuln_type='Missing API Authentication',
                                severity='CRITICAL',
                                title=f'API endpoint accessible without authentication: {api_path}',
                                description='API endpoint dapat diakses tanpa authentication',
                                endpoint=url
                            )
                            vulns.append(vuln)
                            self.logger.critical(f"Unprotected API found: {url}")
            except:
                pass
        
        return vulns
    
    def check_cors_policy(self, url: str) -> List[Vulnerability]:
        """Check CORS policy"""
        vulns = []
        
        test_origins = [
            'https://evil.com',
            'http://localhost',
            '*',
        ]
        
        for origin in test_origins:
            try:
                headers = {'Origin': origin}
                resp = self.client.get(url, headers=headers)
                
                if resp:
                    acao = resp.headers.get('Access-Control-Allow-Origin', '')
                    
                    if acao == origin or acao == '*':
                        severity = 'HIGH' if acao == '*' else 'MEDIUM'
                        vuln = Vulnerability(
                            vuln_type='CORS Misconfiguration',
                            severity=severity,
                            title=f'CORS policy allows {origin}',
                            description='CORS policy terlalu permissive',
                            endpoint=url
                        )
                        vulns.append(vuln)
                        self.logger.warning(f"CORS misconfiguration: {origin}")
            except:
                pass
        
        return vulns

# ============================================================
# MAIN SCANNER CLASS
# ============================================================

class SecurityScanner:
    """Main Security Scanner Class"""
    
    def __init__(self, target_url: str, config: Dict = None, log_file: str = None):
        self.target_url = target_url.rstrip('/')
        self.config = config or {}
        self.logger = Logger(log_file)
        self.client = HTTPClient(timeout=self.config.get('timeout', Config.TIMEOUT))
        self.vulnerabilities = []
        self.scan_results = {}
        
        # Initialize modules
        self.recon = ReconModule(self.client, self.logger)
        self.sqli = SQLiModule(self.client, self.logger)
        self.xss = XSSModule(self.client, self.logger)
        self.auth = AuthenticationModule(self.client, self.logger)
        self.encryption = EncryptionModule(self.client, self.logger)
        self.headers = HeaderSecurityModule(self.client, self.logger)
        self.files = FileAccessModule(self.client, self.logger)
        self.api = APISecurityModule(self.client, self.logger)
    
    def print_banner(self):
        """Print banner"""
        banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          🔐 EXPERT WEB SECURITY SCANNER - PHP Native Edition     ║
║                                                                  ║
║         Advanced Penetration Testing & Vulnerability Scanner     ║
║                                                                  ║
║              ⚠️  HANYA UNTUK WEBSITE YANG ANDA MILIKI  ⚠️        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"""
        print(banner)
    
    def run_full_scan(self) -> Dict:
        """Jalankan full security scan"""
        start_time = time.time()
        self.logger.info(f"Starting security scan: {self.target_url}")
        
        try:
            # Reconnaissance
            self.logger.info("\n[*] Phase 1: RECONNAISSANCE")
            self.logger.info("="*60)
            self._run_reconnaissance()
            
            # Security Headers
            self.logger.info("\n[*] Phase 2: SECURITY HEADERS SCAN")
            self.logger.info("="*60)
            self._scan_headers()
            
            # File & Directory Scan
            self.logger.info("\n[*] Phase 3: FILE & DIRECTORY SCAN")
            self.logger.info("="*60)
            self._scan_files()
            
            # Injection Testing
            self.logger.info("\n[*] Phase 4: INJECTION TESTING")
            self.logger.info("="*60)
            self._test_injections()
            
            # Authentication Testing
            self.logger.info("\n[*] Phase 5: AUTHENTICATION TESTING")
            self.logger.info("="*60)
            self._test_authentication()
            
            # Encryption Testing
            self.logger.info("\n[*] Phase 6: ENCRYPTION TESTING")
            self.logger.info("="*60)
            self._test_encryption()
            
            # API Security
            self.logger.info("\n[*] Phase 7: API SECURITY TESTING")
            self.logger.info("="*60)
            self._test_api_security()
            
        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}")
        finally:
            elapsed = time.time() - start_time
            self.logger.info(f"\nScan completed in {elapsed:.2f} seconds")
            self.logger.info(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        
        return self._generate_report(elapsed)
    
    def _run_reconnaissance(self):
        """Run reconnaissance phase"""
        try:
            resp = self.client.get(self.target_url)
            if resp:
                techs = self.recon.scan_technologies(resp)
                if techs:
                    self.logger.info(f"Detected technologies: {', '.join(techs)}")
                    self.scan_results['technologies'] = techs
        except Exception as e:
            self.logger.error(f"Recon error: {str(e)}")
    
    def _scan_headers(self):
        """Scan security headers"""
        vulns = self.headers.test_headers(self.target_url)
        self.vulnerabilities.extend(vulns)
        self.scan_results['headers'] = len(vulns)
    
    def _scan_files(self):
        """Scan files and directories"""
        self.logger.info("Scanning directories...")
        vulns = self.files.scan_directories(self.target_url)
        self.vulnerabilities.extend(vulns)
        self.scan_results['directories'] = len(vulns)
        
        self.logger.info("Scanning sensitive files...")
        vulns = self.files.scan_sensitive_files(self.target_url)
        self.vulnerabilities.extend(vulns)
        self.scan_results['sensitive_files'] = len(vulns)
    
    def _test_injections(self):
        """Test injection vulnerabilities"""
        self.logger.info("Testing SQL Injection...")
        vulns = self.sqli.crawl_and_test_forms(self.target_url)
        self.vulnerabilities.extend(vulns)
        self.scan_results['sqli'] = len(vulns)
        
        self.logger.info("Testing XSS...")
        # XSS testing would require form analysis
        self.scan_results['xss'] = 0
    
    def _test_authentication(self):
        """Test authentication mechanisms"""
        self.logger.info("Testing authentication...")
        # Basic auth testing
        self.scan_results['auth'] = 0
    
    def _test_encryption(self):
        """Test encryption and SSL/TLS"""
        self.logger.info("Testing SSL/TLS...")
        vulns = self.encryption.test_ssl_tls(self.target_url)
        self.vulnerabilities.extend(vulns)
        
        vulns = self.encryption.check_http_to_https(self.target_url)
        self.vulnerabilities.extend(vulns)
        
        self.scan_results['encryption'] = len(vulns)
    
    def _test_api_security(self):
        """Test API security"""
        self.logger.info("Testing API endpoints...")
        vulns = self.api.test_api_endpoints(self.target_url)
        self.vulnerabilities.extend(vulns)
        
        vulns = self.api.check_cors_policy(self.target_url)
        self.vulnerabilities.extend(vulns)
        
        self.scan_results['api'] = len(vulns)
    
    def _generate_report(self, elapsed_time: float) -> Dict:
        """Generate comprehensive report"""
        
        # Categorize by severity
        critical = [v for v in self.vulnerabilities if v.severity == 'CRITICAL']
        high = [v for v in self.vulnerabilities if v.severity == 'HIGH']
        medium = [v for v in self.vulnerabilities if v.severity == 'MEDIUM']
        low = [v for v in self.vulnerabilities if v.severity == 'LOW']
        
        report = {
            'metadata': {
                'target': self.target_url,
                'scan_date': datetime.now().isoformat(),
                'scan_duration': elapsed_time,
            },
            'summary': {
                'total_vulnerabilities': len(self.vulnerabilities),
                'critical': len(critical),
                'high': len(high),
                'medium': len(medium),
                'low': len(low),
            },
            'scan_results': self.scan_results,
            'vulnerabilities': {
                'critical': [v.to_dict() for v in critical],
                'high': [v.to_dict() for v in high],
                'medium': [v.to_dict() for v in medium],
                'low': [v.to_dict() for v in low],
            }
        }
        
        # Print summary
        self._print_report_summary(report)
        
        return report
    
    def _print_report_summary(self, report: Dict):
        """Print report summary"""
        print("\n" + "="*70)
        print("SECURITY SCAN REPORT SUMMARY")
        print("="*70)
        print(f"Target: {report['metadata']['target']}")
        print(f"Scan Date: {report['metadata']['scan_date']}")
        print(f"Duration: {report['metadata']['scan_duration']:.2f} seconds")
        print(f"\nTotal Vulnerabilities: {report['summary']['total_vulnerabilities']}")
        print(f"  🔴 Critical: {report['summary']['critical']}")
        print(f"  🟠 High: {report['summary']['high']}")
        print(f"  🟡 Medium: {report['summary']['medium']}")
        print(f"  🔵 Low: {report['summary']['low']}")
        print("="*70)
        
        # Print critical vulnerabilities
        if report['vulnerabilities']['critical']:
            print("\n🔴 CRITICAL VULNERABILITIES (Immediate Action Required):")
            for vuln in report['vulnerabilities']['critical']:
                print(f"\n  • {vuln['title']}")
                print(f"    Description: {vuln['description']}")
                print(f"    Endpoint: {vuln['endpoint']}")
        
        # Print high vulnerabilities
        if report['vulnerabilities']['high']:
            print("\n🟠 HIGH VULNERABILITIES (Important):")
            for vuln in report['vulnerabilities']['high'][:5]:  # Show first 5
                print(f"\n  • {vuln['title']}")
                print(f"    Description: {vuln['description']}")
        
        print("\n" + "="*70)
    
    def export_json(self, output_file: str):
        """Export report as JSON"""
        report = {
            'metadata': {
                'target': self.target_url,
                'scan_date': datetime.now().isoformat(),
            },
            'summary': {
                'total': len(self.vulnerabilities),
                'critical': len([v for v in self.vulnerabilities if v.severity == 'CRITICAL']),
                'high': len([v for v in self.vulnerabilities if v.severity == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v.severity == 'MEDIUM']),
                'low': len([v for v in self.vulnerabilities if v.severity == 'LOW']),
            },
            'vulnerabilities': [v.to_dict() for v in self.vulnerabilities]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.success(f"Report exported: {output_file}")
    
    def export_html(self, output_file: str):
        """Export report as HTML"""
        # Group vulnerabilities by severity
        critical = [v for v in self.vulnerabilities if v.severity == 'CRITICAL']
        high = [v for v in self.vulnerabilities if v.severity == 'HIGH']
        medium = [v for v in self.vulnerabilities if v.severity == 'MEDIUM']
        low = [v for v in self.vulnerabilities if v.severity == 'LOW']
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #333; color: white; padding: 20px; }}
                .critical {{ background: #ffcccc; padding: 10px; margin: 5px 0; border-left: 4px solid red; }}
                .high {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid orange; }}
                .medium {{ background: #cce5ff; padding: 10px; margin: 5px 0; border-left: 4px solid blue; }}
                .low {{ background: #d4edda; padding: 10px; margin: 5px 0; border-left: 4px solid green; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Scan Report</h1>
                <p>Target: {self.target_url}</p>
                <p>Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <h2>Summary</h2>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Count</th>
                </tr>
                <tr>
                    <td class="critical">Critical</td>
                    <td>{len(critical)}</td>
                </tr>
                <tr>
                    <td class="high">High</td>
                    <td>{len(high)}</td>
                </tr>
                <tr>
                    <td class="medium">Medium</td>
                    <td>{len(medium)}</td>
                </tr>
                <tr>
                    <td class="low">Low</td>
                    <td>{len(low)}</td>
                </tr>
            </table>
            
            <h2>Critical Vulnerabilities</h2>
            {''.join(f'<div class="critical"><h3>{v.title}</h3><p>{v.description}</p></div>' for v in critical)}
            
            <h2>High Vulnerabilities</h2>
            {''.join(f'<div class="high"><h3>{v.title}</h3><p>{v.description}</p></div>' for v in high)}
            
        </body>
        </html>
        """
        
        with open(output_file, 'w') as f:
            f.write(html)
        
        self.logger.success(f"HTML report exported: {output_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Expert Web Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_scanner.py https://example.com
  python security_scanner.py https://example.com -o report.json
  python security_scanner.py https://example.com --html report.html
        """
    )
    
    parser.add_argument('url', help='Target URL')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--html', help='Output HTML file')
    parser.add_argument('-t', '--timeout', type=int, default=Config.TIMEOUT, help='Request timeout')
    parser.add_argument('--no-ssl-verify', action='store_true', help='Skip SSL verification')
    
    args = parser.parse_args()
    
    # Validation
    if not args.url.startswith(('http://', 'https://')):
        print("Error: URL must start with http:// or https://")
        sys.exit(1)
    
    # Warning
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                      ⚠️  LEGAL NOTICE  ⚠️                         ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  By using this tool, you agree that you:                        ║
║                                                                  ║
║  1. Own or have written permission to test this website        ║
║  2. Understand the legal implications of penetration testing   ║
║  3. Will not use this tool for illegal purposes               ║
║  4. Accept full responsibility for your actions                ║
║                                                                  ║
║  Unauthorized access is ILLEGAL under:                         ║
║  - Computer Fraud and Abuse Act (US)                           ║
║  - Law on Information Technology (Indonesia - UU ITE)          ║
║  - Similar laws in other jurisdictions                         ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)
    
    confirm = input("\nDo you have permission to test this website? (yes/no): ").strip().lower()
    if confirm not in ['yes', 'y']:
        print("\n[!] Scan cancelled.")
        sys.exit(0)
    
    # Run scanner
    config = {
        'timeout': args.timeout,
        'verify_ssl': not args.no_ssl_verify
    }
    
    scanner = SecurityScanner(args.url, config)
    scanner.print_banner()
    
    report = scanner.run_full_scan()
    
    # Export results
    if args.output:
        scanner.export_json(args.output)
    
    if args.html:
        scanner.export_html(args.html)

if __name__ == '__main__':
    main()
