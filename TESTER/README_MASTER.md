# 🔐 EXPERT WEB SECURITY SCANNER - Complete Documentation

**Advanced Penetration Testing System untuk PHP Native & Modern Web Applications**

---

## 📑 Quick Navigation

### 🚀 Getting Started (5 minutes)
- [Installation Cepat](#quick-install)
- [First Scan](#first-scan)

### 📖 Documentation
- [Detailed Installation](#detailed-installation) - VPS/Linux setup
- [PHP Native Testing Guide](#php-native-testing) - Khusus untuk PHP murni
- [Usage Examples](#usage-examples)
- [Automated Scanning](#automated-scanning)

### 📚 Reference
- [Command Reference](#command-reference)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)

---

## Quick Install

```bash
# 1. Clone/Download ke VPS
ssh root@your-vps
cd /opt
git clone https://github.com/your-repo/security-scanner.git
cd security-scanner

# 2. Install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Run first scan
python3 security_scanner.py https://your-website.com

# Done! ✓
```

---

## First Scan

### Minimal Command
```bash
python3 security_scanner.py https://your-website.com
```

### With Report Export
```bash
python3 security_scanner.py https://your-website.com \
    -o report.json \
    --html report.html
```

### Result
- Console output dengan temuan real-time
- `report.json` - Structured report untuk processing
- `report.html` - Beautified report untuk stakeholders

---

## Detailed Installation

### Prasyarat
```bash
# Check requirements
uname -a              # Linux OS
python3 --version    # Python 3.7+
pip3 --version       # pip3
df -h /              # 500MB free space
```

### Step-by-Step Installation

#### 1. System Update & Dependencies
```bash
# Ubuntu/Debian
sudo apt update && apt upgrade -y
sudo apt install -y python3 python3-pip python3-venv build-essential \
                     libssl-dev libffi-dev git curl

# CentOS/RHEL
sudo yum update -y
sudo yum install -y python3 python3-pip gcc openssl-devel libffi-devel git curl
```

#### 2. Setup Directory
```bash
sudo mkdir -p /opt/security-scanner
sudo chown $USER:$USER /opt/security-scanner
cd /opt/security-scanner
```

#### 3. Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip setuptools wheel
```

#### 4. Install Scanner
```bash
# Copy files atau clone dari repo
wget https://your-server.com/security_scanner.py
wget https://your-server.com/requirements.txt

# Install Python packages
pip install -r requirements.txt

# Verify
python3 -c "import requests; print('✓ Ready!')"
```

#### 5. Create Config
```bash
mkdir -p config logs reports
cp config_targets_example.txt config/targets.txt
chmod +x automated_scanner.sh
```

#### 6. Test
```bash
python3 security_scanner.py https://httpbin.org --timeout 5
```

**Done!** ✅ Scanner siap digunakan.

### Full Installation Guide
👉 **[Lihat INSTALL_VPS_LINUX.md](INSTALL_VPS_LINUX.md)** untuk:
- Instalasi di berbagai distro Linux
- Setup systemd service
- Cron job configuration
- Email notifications
- Advanced configurations

---

## PHP Native Testing

### Mengapa Penting?

PHP Native websites adalah **most vulnerable** karena:
- Tidak ada built-in security framework
- Developers harus implement semua security manually
- Common mistakes lebih sering terjadi

### Vulnerabilities yang Sering Ditemukan

| Vulnerability | Risk | Contoh |
|---|---|---|
| SQL Injection | 🔴 CRITICAL | `SELECT * FROM users WHERE id=$_GET['id']` |
| Stored XSS | 🟠 HIGH | Echo user input tanpa sanitization |
| IDOR | 🟠 HIGH | `GET /profile.php?id=2` access other users |
| Broken Auth | 🟠 HIGH | No password hashing, default credentials |
| File Upload | 🟠 HIGH | Upload PHP files as images |
| Sensitive Data | 🟠 HIGH | .env, config.php publicly accessible |

### Testing Workflow

```
Phase 1: Recon (20 min)
├─ Detect technologies
├─ Scan directories
└─ Find sensitive files

Phase 2: Injections (30 min)
├─ SQL Injection testing
├─ XSS testing
└─ Command Injection testing

Phase 3: Authentication (20 min)
├─ Default credentials
├─ Session analysis
└─ Password reset flaws

Phase 4: Authorization (15 min)
├─ IDOR testing
├─ Privilege escalation
└─ CSRF testing

Phase 5: Data (15 min)
├─ Sensitive files
├─ File uploads
└─ API testing

Total: ~100 minutes untuk comprehensive test
```

### Quick PHP Vulnerability Checklist

```bash
# 1. SQL Injection
curl 'https://target.com/product.php?id=1' OR '1'='1'

# 2. XSS
curl 'https://target.com/search.php?q=<script>alert(1)</script>'

# 3. File Exposure
curl https://target.com/.env
curl https://target.com/config.php
curl https://target.com/backup.sql

# 4. Default Credentials
# Login: admin:admin, admin:password, root:root

# 5. IDOR
curl https://target.com/user_profile.php?id=1
curl https://target.com/user_profile.php?id=2  # Can access others?

# 6. CSRF
curl -X POST https://target.com/delete_user.php -d "id=1"  # No token required?

# 7. Authentication Bypass
curl 'https://target.com/login.php?user=admin&pass=anything'  # Bypass?
```

### Full PHP Native Testing Guide
👉 **[Lihat PHP_NATIVE_TESTING.md](PHP_NATIVE_TESTING.md)** untuk:
- Detailed vulnerability explanations
- Exploitation techniques
- Remediation code examples
- Testing checklists

---

## Usage Examples

### Single Target Scanning
```bash
# Basic scan
python3 security_scanner.py https://example.com

# With custom timeout (untuk slow servers)
python3 security_scanner.py https://slow.example.com --timeout 30

# Skip SSL verification (testing environments only!)
python3 security_scanner.py https://self-signed.example.com --no-ssl-verify

# Export reports
python3 security_scanner.py https://example.com \
    -o report.json \
    --html report.html
```

### Batch Scanning
```bash
# Setup targets
cat > targets.txt << EOF
https://website1.com
https://website2.com
https://api.website.com
EOF

# Scan all targets
./automated_scanner.sh batch targets.txt

# Results di: reports/batch_YYYYMMDD_HHMMSS/
```

### Scheduled Daily Scans
```bash
# Setup config
mkdir -p config
cat > config/targets.txt << EOF
https://production.example.com
https://api.example.com
EOF

# Run daily scan
./automated_scanner.sh daily

# Or schedule dengan cron (see Automated Scanning)
```

### Analysis & Reporting
```bash
# Generate summary report
./automated_scanner.sh report

# View specific report
cat reports/report.json | python3 -m json.tool

# Extract critical vulnerabilities only
python3 << 'EOF'
import json
with open('report.json') as f:
    data = json.load(f)
    critical = data['vulnerabilities']['critical']
    for v in critical:
        print(f"[CRITICAL] {v['title']}")
        print(f"  {v['description']}\n")
EOF
```

---

## Automated Scanning

### Daily Automated Scans

#### Option 1: Using Cron

```bash
# Edit crontab
crontab -e

# Add job - Run setiap hari pukul 2:00 AM
0 2 * * * /opt/security-scanner/automated_scanner.sh daily

# Run setiap minggu (Minggu, 3:00 AM)
0 3 * * 0 /opt/security-scanner/automated_scanner.sh daily && /opt/security-scanner/automated_scanner.sh report
```

#### Option 2: Using Systemd Timer

```bash
# Copy service files ke /etc/systemd/system/

# Check status
sudo systemctl status security-scanner.timer

# Start timer
sudo systemctl start security-scanner.timer

# View logs
sudo journalctl -u security-scanner.timer -f
```

### Email Notifications

```bash
# Setup mail service
sudo apt install -y ssmtp

# Configure ssmtp.conf
sudo nano /etc/ssmtp/ssmtp.conf

# Send report via email
./automated_scanner.sh email admin@example.com reports/report.json
```

### Automated Maintenance

```bash
# Archive old reports (>30 days)
./automated_scanner.sh archive 30

# Clean logs (>60 days)
./automated_scanner.sh cleanup 60

# Full maintenance
./automated_scanner.sh maintenance
```

---

## Command Reference

### Scanner Commands

```bash
# Usage
python3 security_scanner.py <URL> [OPTIONS]

# Options
-o, --output FILE       Save JSON report
--html FILE             Save HTML report
-t, --timeout SECONDS   Request timeout (default: 15)
--no-ssl-verify         Skip SSL verification
-h, --help              Show help message

# Examples
python3 security_scanner.py https://example.com
python3 security_scanner.py https://example.com -o scan.json
python3 security_scanner.py https://example.com --html scan.html
python3 security_scanner.py https://example.com -o scan.json --html scan.html --timeout 30
```

### Automation Commands

```bash
# Usage
./automated_scanner.sh <COMMAND> [OPTIONS]

# Commands
single <URL>           Scan single target
batch <FILE>           Scan multiple targets
daily                  Run daily scans (from config)
maintenance            Run maintenance tasks
archive [DAYS]         Archive old reports
cleanup [DAYS]         Clean old logs
report [TYPE]          Generate report
email <EMAIL> <FILE>   Send report via email
help                   Show help

# Examples
./automated_scanner.sh single https://example.com
./automated_scanner.sh batch targets.txt
./automated_scanner.sh daily
./automated_scanner.sh report
./automated_scanner.sh email admin@example.com report.json
```

---

## Configuration

### Scanner Config

Edit `security_scanner.py` untuk customize:

```python
class Config:
    TIMEOUT = 15                # Request timeout
    THREADS = 10                # Parallel threads
    MAX_RETRIES = 3             # Retry attempts
    
    # Customize SQL payloads
    SQL_PAYLOADS = [...]
    
    # Customize XSS payloads
    XSS_PAYLOADS = [...]
    
    # Customize directories to scan
    COMMON_DIRS = [...]
```

### Targets Configuration

Edit `config/targets.txt`:

```
# One URL per line
https://production.example.com
https://api.example.com
https://staging.example.com

# Comments start with #
```

### Email Configuration

Edit `/etc/ssmtp/ssmtp.conf`:

```ini
root=your-email@example.com
mailhub=smtp.gmail.com:587
AuthUser=your-email@gmail.com
AuthPass=your-app-password
UseSTARTTLS=YES
```

---

## Report Interpretation

### Report Structure

```json
{
  "metadata": {
    "target": "https://example.com",
    "scan_date": "2024-02-04T14:30:15",
    "scan_duration": 120.45
  },
  "summary": {
    "total_vulnerabilities": 12,
    "critical": 2,
    "high": 3,
    "medium": 5,
    "low": 2
  },
  "vulnerabilities": {
    "critical": [...],
    "high": [...],
    "medium": [...],
    "low": [...]
  }
}
```

### Severity Levels

| Level | Action | Timeframe |
|---|---|---|
| 🔴 CRITICAL | Immediate action | 24 hours |
| 🟠 HIGH | Urgent | 3 days |
| 🟡 MEDIUM | Important | 2 weeks |
| 🔵 LOW | Consider | When possible |

### Sample Report Output

```
Target: https://example.com
Scan Date: 2024-02-04 14:30:15
Duration: 120 seconds

SUMMARY:
========
Total: 12 vulnerabilities
🔴 Critical: 2 (SQL Injection, Sensitive File Exposure)
🟠 High: 3 (XSS, IDOR, Auth Bypass)
🟡 Medium: 5 (Missing Headers, Directory Listing)
🔵 Low: 2 (Information Disclosure)

CRITICAL ISSUES (IMMEDIATE ACTION):
==================================
1. SQL Injection in /product.php?id=1
2. .env file publicly accessible
```

---

## Troubleshooting

### "ModuleNotFoundError: No module named 'requests'"

```bash
# Solution
source venv/bin/activate
pip install requests beautifulsoup4 lxml
```

### "Connection refused" atau "Timeout"

```bash
# Check website accessibility
curl -I https://your-target.com

# Increase timeout
python3 security_scanner.py https://your-target.com --timeout 60

# Check firewall
sudo ufw status
```

### "SSL Certificate Error"

```bash
# Option 1: Skip verification (testing only)
python3 security_scanner.py https://your-target.com --no-ssl-verify

# Option 2: Fix certificates
sudo apt install -y ca-certificates
sudo update-ca-certificates
```

### "Permission Denied" on Scripts

```bash
chmod +x security_scanner.py
chmod +x automated_scanner.sh
```

### "Out of Disk Space"

```bash
# Check disk
df -h /

# Clean old reports
find reports/ -mtime +30 -delete

# Archive logs
gzip logs/*.log
```

### Full Troubleshooting Guide
👉 **[Lihat INSTALL_VPS_LINUX.md#troubleshooting](INSTALL_VPS_LINUX.md#troubleshooting)**

---

## FAQ

### Q: Apakah tool ini legal?
**A:** Ya, **jika digunakan untuk website yang Anda miliki atau dengan izin tertulis**. Penetration testing tanpa izin adalah ILLEGAL.

### Q: Berapa lama scanning?
**A:** Tergantung ukuran website:
- Small site (10 pages): ~5-10 menit
- Medium site (50 pages): ~20-30 menit
- Large site (500+ pages): ~60+ menit

### Q: Apakah scanner bisa merusak website?
**A:** Tidak. Scanner hanya melakukan READ operations. Tidak ada data yang ditulis/dihapus.

### Q: Bisakah dijalankan di Windows?
**A:** Tidak langsung. Gunakan:
- WSL (Windows Subsystem for Linux)
- Docker
- Virtual Machine Linux

### Q: Bagaimana dengan false positives?
**A:** Scanner melaporkan potential issues. Manual verification diperlukan untuk confirm.

### Q: Bisakah test database?
**A:** Tidak. Scanner test web interface saja. Database testing perlu tool khusus.

### Q: Bagaimana caranya update scanner?
```bash
cd /opt/security-scanner
git pull origin main
source venv/bin/activate
pip install -r requirements.txt --upgrade
```

### Q: Support untuk framework lain?
**A:** Yes! Scanner berfungsi untuk:
- PHP Native ✅
- Laravel ✅
- Symfony ✅
- Django ✅
- Node.js ✅
- ASP.NET ✅
- Etc.

---

## File Structure

```
/opt/security-scanner/
├── security_scanner.py          # Main scanner module
├── automated_scanner.sh          # Automation script
├── requirements.txt              # Python dependencies
├── config/
│   ├── targets.txt              # Target list for batch scanning
│   └── scanner_config.ini       # Scanner configuration
├── reports/                     # Generated reports
│   ├── report_20240204.json
│   └── report_20240204.html
├── logs/                        # Scanner logs
│   ├── scanner.log
│   └── audit.log
├── archive/                     # Archived reports
├── venv/                        # Virtual environment
└── docs/
    ├── INSTALL_VPS_LINUX.md
    ├── PHP_NATIVE_TESTING.md
    ├── README.md                # This file
    └── ...
```

---

## Performance Tips

### For Fast Scanning
```bash
# Reduce timeout
python3 security_scanner.py https://example.com --timeout 5

# Check source: fast.example.com vs slow.example.com
```

### For Large Websites
```bash
# Increase timeout & threads
python3 security_scanner.py https://large-site.com --timeout 30

# Scan in parallel dengan multiple processes
for url in $(cat targets.txt); do
    python3 security_scanner.py "$url" &
done
wait
```

### System Optimization
```bash
# Increase file descriptors
ulimit -n 10000

# Increase socket connections
sysctl -w net.core.somaxconn=65535
```

---

## Security Best Practices

### Protect Scanner
```bash
# Restrict access
chmod 700 /opt/security-scanner
chmod 600 config/targets.txt

# Use specific user
useradd -r scanner-user
chown -R scanner-user:scanner-user /opt/security-scanner
```

### Secure Credentials
```bash
# Never commit credentials
echo ".env" >> .gitignore

# Use environment variables
export SCANNER_API_KEY="your-key"
```

### Audit Logging
```bash
# Enable logging
tail -f logs/scanner.log

# Monitor access
sudo tail -f /var/log/auth.log | grep security_scanner
```

---

## Resources

### Official Documentation
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE Top 25: https://cwe.mitre.org/top25/

### PHP Security
- PHP Security Manual: https://www.php.net/manual/en/security.php
- OWASP PHP Security: https://owasp.org/www-project-cheat-sheets/

### Tools & Frameworks
- OWASP ZAP: https://www.zaproxy.org/
- Burp Suite: https://portswigger.net/burp
- SQLMap: http://sqlmap.org/

### Learning
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- HackTheBox: https://www.hackthebox.com/
- TryHackMe: https://tryhackme.com/

---

## Support & Contact

- **Issues**: Report bugs via GitHub Issues
- **Security**: security@your-domain.com
- **Documentation**: Check docs/ folder
- **Updates**: Star the repository for updates

---

## Changelog

### v1.0 (2024-02-04)
- ✅ Initial release
- ✅ 8 security modules
- ✅ JSON & HTML reporting
- ✅ Automated scheduling
- ✅ Batch scanning

### v1.1 (Upcoming)
- 🔲 Advanced SQLi detection
- 🔲 JavaScript rendering
- 🔲 Custom payload support
- 🔲 Web dashboard
- 🔲 API integration

---

## License & Legal

### Usage
This tool is provided "AS IS" for **authorized security testing only**.

### Disclaimer
Users are responsible for:
- Obtaining written permission before testing
- Complying with applicable laws
- Respecting privacy and security

### Liability
The authors are NOT liable for:
- Unauthorized use
- Damage caused by misuse
- Legal consequences

---

**Last Updated**: 2024-02-04
**Version**: 1.0
**Maintainer**: Your Security Team

---

## Quick Start Reminder

```bash
# 1. Install
source venv/bin/activate && pip install -r requirements.txt

# 2. Configure
nano config/targets.txt

# 3. Scan
python3 security_scanner.py https://your-website.com

# 4. Report
cat reports/report.json

# Done! 🎉
```

---

**Happy Secure Testing!** 🔐

Remember: **Security is not a destination, it's a journey. Keep scanning, keep learning, stay ethical!**
