# 🚀 INSTALASI EXPERT SECURITY SCANNER DI VPS/LINUX

## 📋 Daftar Isi
1. [Prasyarat](#prasyarat)
2. [Instalasi Cepat](#instalasi-cepat)
3. [Instalasi Detail Langkah per Langkah](#instalasi-detail)
4. [Konfigurasi Awal](#konfigurasi-awal)
5. [Menjalankan Scanner](#menjalankan-scanner)
6. [Setup Automated Scanning](#setup-automated-scanning)
7. [Troubleshooting](#troubleshooting)

---

## Prasyarat

### Sistem Requirements:
- **OS**: Linux (Ubuntu 20.04+, CentOS 7+, Debian 10+)
- **RAM**: Minimal 1GB (Recommended 2GB+)
- **Disk**: 500MB free space
- **Python**: 3.7 atau lebih tinggi
- **Network**: Koneksi internet untuk download packages

### Periksa Versi:
```bash
# Check OS
uname -a

# Check Python version
python3 --version

# Check pip
pip3 --version

# Check disk space
df -h /
```

---

## Instalasi Cepat

### 1. Login ke VPS sebagai Root atau dengan Sudo
```bash
ssh root@your-vps-ip
# atau
ssh user@your-vps-ip
sudo su -
```

### 2. Update System
```bash
apt update && apt upgrade -y
```

### 3. Install Dependencies
```bash
apt install -y python3 python3-pip python3-dev git curl wget
```

### 4. Download Scanner
```bash
# Create directory
mkdir -p /opt/security-scanner
cd /opt/security-scanner

# Download files (ganti dengan method sesuai)
# Option 1: Via Git
git clone https://github.com/yourrepo/security-scanner.git .

# Option 2: Via SCP dari lokal
# scp security_scanner.py requirements.txt root@your-vps:/opt/security-scanner/

# Option 3: Via curl/wget
wget https://yourserver.com/security_scanner.py
wget https://yourserver.com/requirements.txt
```

### 5. Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

### 6. Test Installation
```bash
python3 security_scanner.py https://example.com --timeout 5
```

---

## Instalasi Detail

### Step 1: Update System Repository

```bash
# Untuk Ubuntu/Debian
sudo apt update
sudo apt upgrade -y

# Untuk CentOS/RHEL
sudo yum update -y
sudo yum upgrade -y
```

### Step 2: Install Python & Essential Tools

```bash
# Ubuntu/Debian
sudo apt install -y \
  python3 \
  python3-pip \
  python3-dev \
  python3-venv \
  build-essential \
  libssl-dev \
  libffi-dev \
  git \
  curl \
  wget \
  netcat \
  dnsutils

# CentOS/RHEL
sudo yum install -y \
  python3 \
  python3-pip \
  python3-devel \
  gcc \
  openssl-devel \
  libffi-devel \
  git \
  curl \
  wget \
  ncat \
  bind-utils
```

### Step 3: Buat Directory Structure

```bash
# Create main directory
sudo mkdir -p /opt/security-scanner
sudo mkdir -p /opt/security-scanner/logs
sudo mkdir -p /opt/security-scanner/reports
sudo mkdir -p /opt/security-scanner/config

# Set permissions
sudo chown -R $(whoami):$(whoami) /opt/security-scanner
chmod -R 755 /opt/security-scanner
```

### Step 4: Buat Virtual Environment

```bash
cd /opt/security-scanner

# Create venv
python3 -m venv venv

# Activate venv
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

### Step 5: Install Dependencies

```bash
# Ensure you're in venv
source /opt/security-scanner/venv/bin/activate

# Create requirements.txt jika belum ada
cat > requirements.txt << 'EOF'
requests==2.31.0
beautifulsoup4==4.12.2
lxml==4.9.3
urllib3==2.0.7
certifi==2023.7.22
EOF

# Install
pip install -r requirements.txt

# Verify installation
pip list
```

### Step 6: Copy Scanner Files

```bash
# Method 1: Jika sudah ada file lokal
cd /opt/security-scanner
# Copy file security_scanner.py ke sini

# Method 2: Create dari scratch
cat > security_scanner.py << 'EOF'
# Paste isi file security_scanner.py di sini
EOF

# Set executable
chmod +x security_scanner.py
```

### Step 7: Verify Installation

```bash
# Activate venv
source /opt/security-scanner/venv/bin/activate

# Test basic command
python3 security_scanner.py --help

# Test dengan target
python3 security_scanner.py https://httpbin.org --timeout 5
```

---

## Konfigurasi Awal

### 1. Buat Konfigurasi File

```bash
cd /opt/security-scanner/config

# Create config file
cat > scanner_config.ini << 'EOF'
[scanner]
timeout = 15
threads = 10
max_retries = 3
verify_ssl = False

[logging]
log_level = INFO
log_file = ../logs/scanner.log

[output]
json_report = True
html_report = True
report_dir = ../reports/

[targets]
# Add your target URLs here
targets =
    https://your-website.com
    https://api.your-website.com
EOF

chmod 600 scanner_config.ini
```

### 2. Setup Logging Directory

```bash
# Create log rotation
cat > /etc/logrotate.d/security-scanner << 'EOF'
/opt/security-scanner/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF
```

### 3. Buat Wrapper Script

```bash
cat > /opt/security-scanner/scan.sh << 'EOF'
#!/bin/bash

# Security Scanner Wrapper
set -e

SCANNER_DIR="/opt/security-scanner"
VENV_PATH="$SCANNER_DIR/venv/bin/activate"
PYTHON_SCRIPT="$SCANNER_DIR/security_scanner.py"

# Source venv
source $VENV_PATH

# Log header
echo "[$(date)] Starting security scan..."

# Run scanner
python3 $PYTHON_SCRIPT "$@"

# Log completion
echo "[$(date)] Scan completed."
EOF

chmod +x /opt/security-scanner/scan.sh
```

---

## Menjalankan Scanner

### Basic Usage

```bash
# Activate virtual environment
source /opt/security-scanner/venv/bin/activate

# Run scanner
python3 security_scanner.py https://your-website.com

# Dengan custom timeout
python3 security_scanner.py https://your-website.com --timeout 30

# Export JSON report
python3 security_scanner.py https://your-website.com -o report.json

# Export HTML report
python3 security_scanner.py https://your-website.com --html report.html

# Export both
python3 security_scanner.py https://your-website.com -o report.json --html report.html
```

### Using Wrapper Script

```bash
# Simple run
/opt/security-scanner/scan.sh https://your-website.com

# With options
/opt/security-scanner/scan.sh https://your-website.com -o /tmp/report.json

# Run from anywhere
cd /tmp
/opt/security-scanner/scan.sh https://your-website.com
```

### Scanning Multiple Targets

```bash
#!/bin/bash
# Create file: multi_scan.sh

TARGETS=(
    "https://website1.com"
    "https://website2.com"
    "https://api.website.com"
)

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="/opt/security-scanner/reports/$TIMESTAMP"
mkdir -p $REPORT_DIR

source /opt/security-scanner/venv/bin/activate

for target in "${TARGETS[@]}"; do
    echo "Scanning: $target"
    python3 /opt/security-scanner/security_scanner.py \
        "$target" \
        -o "$REPORT_DIR/$(echo $target | sed 's/[^a-zA-Z0-9]/_/g').json" \
        --html "$REPORT_DIR/$(echo $target | sed 's/[^a-zA-Z0-9]/_/g').html"
    
    sleep 5  # Delay antara scans
done

echo "All scans completed. Reports in: $REPORT_DIR"
```

```bash
chmod +x multi_scan.sh
./multi_scan.sh
```

---

## Setup Automated Scanning

### 1. Setup Cron Job

```bash
# Edit crontab
crontab -e

# Add scan job (run setiap hari pukul 02:00 AM)
0 2 * * * source /opt/security-scanner/venv/bin/activate && python3 /opt/security-scanner/security_scanner.py https://your-website.com -o /opt/security-scanner/reports/daily_$(date +\%Y\%m\%d).json

# Run setiap minggu (Minggu pukul 03:00 AM)
0 3 * * 0 /opt/security-scanner/scan.sh https://your-website.com -o /opt/security-scanner/reports/weekly_$(date +\%Y\%m\%d).json --html /opt/security-scanner/reports/weekly_$(date +\%Y\%m\%d).html
```

### 2. Buat Systemd Service

```bash
sudo tee /etc/systemd/system/security-scanner.service << 'EOF'
[Unit]
Description=Web Security Scanner Service
After=network.target

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/security-scanner
ExecStart=/opt/security-scanner/venv/bin/python3 /opt/security-scanner/security_scanner.py https://your-website.com -o /opt/security-scanner/reports/scan_$(date +\%s).json
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable security-scanner.service
```

### 3. Buat Systemd Timer

```bash
sudo tee /etc/systemd/system/security-scanner.timer << 'EOF'
[Unit]
Description=Run Security Scanner Daily
Requires=security-scanner.service

[Timer]
# Run at 2:00 AM setiap hari
OnCalendar=daily
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
EOF

# Enable timer
sudo systemctl daemon-reload
sudo systemctl enable security-scanner.timer
sudo systemctl start security-scanner.timer

# Check status
sudo systemctl list-timers security-scanner.timer
```

### 4. Email Notification Setup

```bash
# Install mail utility
sudo apt install -y ssmtp

# Configure ssmtp
sudo nano /etc/ssmtp/ssmtp.conf
# Add:
# root=your-email@example.com
# mailhub=smtp.gmail.com:587
# AuthUser=your-email@gmail.com
# AuthPass=your-app-password
# UseSTARTTLS=YES

# Create notification script
cat > /opt/security-scanner/notify.sh << 'EOF'
#!/bin/bash

REPORT_FILE=$1
EMAIL_TO="admin@example.com"

if [ -f "$REPORT_FILE" ]; then
    echo "Security Scan Report attached" | \
    ssmtp -t << MAIL_END
To: $EMAIL_TO
From: scanner@example.com
Subject: Security Scan Report $(date +%Y-%m-%d)

Please see attached scan report.

Critical Issues: $(grep -c "CRITICAL" "$REPORT_FILE" || echo 0)
High Issues: $(grep -c "HIGH" "$REPORT_FILE" || echo 0)

MAIL_END
    
    echo "Email sent to $EMAIL_TO"
fi
EOF

chmod +x /opt/security-scanner/notify.sh
```

---

## Monitoring & Maintenance

### 1. Check Scan Logs

```bash
# View current logs
tail -f /opt/security-scanner/logs/scanner.log

# View by date
grep "2024-01-15" /opt/security-scanner/logs/scanner.log

# Count vulnerabilities
grep "CRITICAL\|HIGH\|MEDIUM" /opt/security-scanner/logs/scanner.log | wc -l
```

### 2. Analyze Reports

```bash
# List recent reports
ls -lh /opt/security-scanner/reports/ | tail -20

# View specific report
cat /opt/security-scanner/reports/report.json | python3 -m json.tool

# Extract critical vulnerabilities
python3 << 'EOF'
import json

with open('/opt/security-scanner/reports/report.json') as f:
    report = json.load(f)
    
critical = report.get('vulnerabilities', {}).get('critical', [])
print(f"Critical vulnerabilities: {len(critical)}")
for vuln in critical:
    print(f"  - {vuln['title']}")
EOF
```

### 3. Update Scanner

```bash
cd /opt/security-scanner

# Backup current version
cp security_scanner.py security_scanner.py.backup

# Pull updates
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt --upgrade

# Test
python3 security_scanner.py --help
```

### 4. Maintenance Tasks

```bash
# Clean old reports (lebih dari 30 hari)
find /opt/security-scanner/reports -type f -mtime +30 -delete

# Archive reports
tar -czf /opt/security-scanner/reports/archive_$(date +%Y%m%d).tar.gz \
    /opt/security-scanner/reports/*.json /opt/security-scanner/reports/*.html

# Compress logs
gzip /opt/security-scanner/logs/scanner.log
```

---

## Troubleshooting

### 1. "ModuleNotFoundError: No module named 'requests'"

```bash
# Solution: Ensure venv is activated
source /opt/security-scanner/venv/bin/activate

# Reinstall dependencies
pip install requests beautifulsoup4 lxml

# Verify
python3 -c "import requests; print(requests.__version__)"
```

### 2. "Permission denied" when executing

```bash
# Fix permissions
chmod +x /opt/security-scanner/security_scanner.py
chmod +x /opt/security-scanner/scan.sh

# Check ownership
ls -la /opt/security-scanner/

# Fix if needed
sudo chown -R $(whoami):$(whoami) /opt/security-scanner
```

### 3. Scanner hangs or times out

```bash
# Increase timeout
python3 security_scanner.py https://slow-website.com --timeout 60

# Reduce threads jika ada resource issue
# Edit security_scanner.py, set Config.THREADS = 2

# Monitor resources
watch -n 1 'ps aux | grep security_scanner'
```

### 4. "ConnectionError" atau "No internet"

```bash
# Test connectivity
curl -I https://google.com

# Check DNS
nslookup your-target.com

# Check firewall
sudo ufw status
sudo iptables -L

# Restart network
sudo systemctl restart networking
```

### 5. SSL Certificate Error

```bash
# Option 1: Skip SSL verification (untuk testing only)
python3 security_scanner.py https://your-site.com --no-ssl-verify

# Option 2: Update certificates
sudo apt install -y ca-certificates
sudo update-ca-certificates

# Option 3: Install specific cert
# wget https://your-site.com/cert.pem
# Add ke trusted certs
```

### 6. Out of Disk Space

```bash
# Check disk usage
du -sh /opt/security-scanner/

# Cleanup old reports
find /opt/security-scanner/reports -type f -mtime +7 -delete

# Archive logs
gzip /opt/security-scanner/logs/*.log

# Check disk
df -h
```

---

## Performance Tuning

### 1. Optimize untuk Website Besar

```bash
# Edit security_scanner.py atau config
Config.THREADS = 20  # Increase threads
Config.TIMEOUT = 30  # Increase timeout

# Split targets
# Scan different parts at different times
```

### 2. Monitor Resource Usage

```bash
# During scan
watch -n 1 'top -b -n 1 | head -20'

# Check memory
free -h

# Check CPU
nproc
```

### 3. Optimize Network

```bash
# Adjust system limits
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535

# Make permanent
echo "net.core.somaxconn=65535" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

## Security Best Practices

### 1. Protect Scanner Configuration

```bash
# Restrict permissions
chmod 700 /opt/security-scanner
chmod 600 /opt/security-scanner/config/*
chmod 600 /opt/security-scanner/logs/*

# Use specific user for scanning
sudo useradd -r -s /bin/false scanner-user
sudo chown -R scanner-user:scanner-user /opt/security-scanner
```

### 2. Secure API Keys & Credentials

```bash
# Never commit credentials
# Use environment variables
export SCANNER_APIKEY="your-api-key"
export SCANNER_DB_USER="db_user"

# Or use .env file (add to .gitignore)
cat > /opt/security-scanner/.env << 'EOF'
SCANNER_APIKEY=your-key
SCANNER_DB_USER=db_user
EOF

# Load in script
set -a
source /opt/security-scanner/.env
set +a
```

### 3. Audit Logging

```bash
# Enable detailed logging
echo "Scan started by $USER at $(date)" >> /opt/security-scanner/logs/audit.log

# Monitor log files
tail -f /opt/security-scanner/logs/audit.log

# Rotate logs
logrotate -f /etc/logrotate.d/security-scanner
```

---

## Quick Reference Commands

```bash
# Start scanning
source /opt/security-scanner/venv/bin/activate
python3 /opt/security-scanner/security_scanner.py https://target.com

# View reports
ls -la /opt/security-scanner/reports/

# View logs
tail -100f /opt/security-scanner/logs/scanner.log

# Check cron jobs
crontab -l

# Check systemd timer
sudo systemctl status security-scanner.timer

# Manual scan trigger
sudo systemctl start security-scanner.service

# Restart service
sudo systemctl restart security-scanner.service

# Check scanner updates
cd /opt/security-scanner && git status

# Backup reports
tar -czf reports_backup_$(date +%Y%m%d).tar.gz reports/
```

---

## Support & Additional Resources

- **Official Documentation**: https://your-docs-url
- **Issue Tracker**: https://github.com/yourrepo/issues
- **Security**: Report issues to security@your-domain.com
- **Community**: Discord/Slack channel

---

## Changelog & Updates

### Version 1.0
- Initial release
- Basic modules: Headers, Files, API, Encryption
- JSON & HTML reporting
- Automated scheduling support

### Future Updates
- Advanced SQL injection testing with time-based detection
- JavaScript-rendered content scanning
- Custom payload support
- Database integration for report history
- Web dashboard for monitoring

---

**Last Updated**: 2024-02-04
**Maintainer**: Your Team
