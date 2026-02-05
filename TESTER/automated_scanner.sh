#!/bin/bash

###############################################################################
#                   AUTOMATED SECURITY SCANNER SUITE                         #
#                  untuk VPS/Linux dengan Scheduling                         #
###############################################################################

set -e

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_PATH="${SCRIPT_DIR}/security_scanner.py"
VENV_PATH="${SCRIPT_DIR}/venv/bin/activate"
REPORTS_DIR="${SCRIPT_DIR}/reports"
LOGS_DIR="${SCRIPT_DIR}/logs"
ARCHIVE_DIR="${SCRIPT_DIR}/archive"
CONFIG_DIR="${SCRIPT_DIR}/config"

# Create directories if not exist
mkdir -p "$REPORTS_DIR" "$LOGS_DIR" "$ARCHIVE_DIR" "$CONFIG_DIR"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================================================
# FUNCTIONS
# ============================================================================

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO] $1" >> "$LOGS_DIR/scanner.log"
}

log_success() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [SUCCESS] $1" >> "$LOGS_DIR/scanner.log"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARNING] $1" >> "$LOGS_DIR/scanner.log"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $1" >> "$LOGS_DIR/scanner.log"
}

check_venv() {
    if [ ! -f "$VENV_PATH" ]; then
        log_error "Virtual environment not found at $VENV_PATH"
        exit 1
    fi
}

activate_venv() {
    source "$VENV_PATH"
    log_info "Virtual environment activated"
}

check_scanner() {
    if [ ! -f "$SCANNER_PATH" ]; then
        log_error "Scanner not found at $SCANNER_PATH"
        exit 1
    fi
}

# ============================================================================
# SCAN FUNCTIONS
# ============================================================================

scan_single_target() {
    local target=$1
    local timestamp=$(date +%s)
    local safe_target=$(echo "$target" | sed 's/[^a-zA-Z0-9]/_/g')
    
    log_info "Starting scan for: $target"
    
    local json_output="$REPORTS_DIR/${safe_target}_${timestamp}.json"
    local html_output="$REPORTS_DIR/${safe_target}_${timestamp}.html"
    
    if python3 "$SCANNER_PATH" "$target" \
        -o "$json_output" \
        --html "$html_output"; then
        
        log_success "Scan completed: $target"
        log_success "  JSON: $json_output"
        log_success "  HTML: $html_output"
        
        # Analyze results
        analyze_report "$json_output"
        
        return 0
    else
        log_error "Scan failed for: $target"
        return 1
    fi
}

scan_multiple_targets() {
    local targets_file=$1
    
    if [ ! -f "$targets_file" ]; then
        log_error "Targets file not found: $targets_file"
        return 1
    fi
    
    log_info "Scanning multiple targets from: $targets_file"
    
    local scan_dir="$REPORTS_DIR/batch_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$scan_dir"
    
    local success_count=0
    local fail_count=0
    
    while IFS= read -r target; do
        # Skip empty lines and comments
        [[ -z "$target" || "$target" =~ ^# ]] && continue
        
        local safe_target=$(echo "$target" | sed 's/[^a-zA-Z0-9]/_/g')
        local json_output="$scan_dir/${safe_target}.json"
        local html_output="$scan_dir/${safe_target}.html"
        
        log_info "Scanning: $target"
        
        if python3 "$SCANNER_PATH" "$target" \
            -o "$json_output" \
            --html "$html_output" 2>/dev/null; then
            
            ((success_count++))
            log_success "✓ $target"
            analyze_report "$json_output"
        else
            ((fail_count++))
            log_warning "✗ $target"
        fi
        
        # Delay between scans
        sleep 5
    done < "$targets_file"
    
    log_info "Batch scan completed: $success_count success, $fail_count failed"
    log_info "Reports directory: $scan_dir"
    
    return 0
}

# ============================================================================
# ANALYSIS FUNCTIONS
# ============================================================================

analyze_report() {
    local report_file=$1
    
    if [ ! -f "$report_file" ]; then
        return
    fi
    
    # Parse JSON and extract summary
    if command -v python3 &> /dev/null; then
        python3 << EOF
import json
import sys

try:
    with open('$report_file', 'r') as f:
        data = json.load(f)
        
    summary = data.get('summary', {})
    print(f"\nReport Analysis: $(basename $report_file)")
    print("=" * 60)
    print(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    print(f"  🔴 Critical: {summary.get('critical', 0)}")
    print(f"  🟠 High: {summary.get('high', 0)}")
    print(f"  🟡 Medium: {summary.get('medium', 0)}")
    print(f"  🔵 Low: {summary.get('low', 0)}")
    print("=" * 60)
    
    # Alert jika ada critical
    if summary.get('critical', 0) > 0:
        print(f"⚠️  WARNING: Found {summary['critical']} CRITICAL vulnerabilities!")
except Exception as e:
    print(f"Error analyzing report: {e}")
EOF
    fi
}

# ============================================================================
# CLEANUP & MAINTENANCE FUNCTIONS
# ============================================================================

archive_old_reports() {
    local days=${1:-30}
    
    log_info "Archiving reports older than $days days"
    
    # Find and archive
    find "$REPORTS_DIR" -maxdepth 1 -type f -mtime +$days | while read -r file; do
        if [ -f "$file" ]; then
            local basename=$(basename "$file")
            log_info "Archiving: $basename"
            gzip -c "$file" >> "$ARCHIVE_DIR/reports_$(date +%Y%m).tar.gz"
            rm "$file"
        fi
    done
    
    log_success "Archive completed"
}

cleanup_old_logs() {
    local days=${1:-60}
    
    log_info "Cleaning logs older than $days days"
    
    find "$LOGS_DIR" -type f -mtime +$days -delete
    
    # Rotate main log
    if [ -f "$LOGS_DIR/scanner.log" ] && [ $(stat -f%z "$LOGS_DIR/scanner.log" 2>/dev/null || stat -c%s "$LOGS_DIR/scanner.log") -gt $((10*1024*1024)) ]; then
        gzip "$LOGS_DIR/scanner.log"
        touch "$LOGS_DIR/scanner.log"
    fi
    
    log_success "Log cleanup completed"
}

# ============================================================================
# REPORTING FUNCTIONS
# ============================================================================

generate_summary_report() {
    local output_file=${1:-"$REPORTS_DIR/summary_$(date +%Y%m%d).txt"}
    
    log_info "Generating summary report: $output_file"
    
    cat > "$output_file" << EOF
================================================================================
                      SECURITY SCAN SUMMARY REPORT
                        Date: $(date)
================================================================================

REPORT STATISTICS:
==================

$(cat <<'PYTHON'
import json
import os
from pathlib import Path

reports_dir = "$REPORTS_DIR"
total_vulns = 0
total_critical = 0
total_high = 0

for report_file in Path(reports_dir).glob("*.json"):
    try:
        with open(report_file, 'r') as f:
            data = json.load(f)
        summary = data.get('summary', {})
        total_vulns += summary.get('total_vulnerabilities', 0)
        total_critical += summary.get('critical', 0)
        total_high += summary.get('high', 0)
    except:
        pass

print(f"Total Vulnerabilities: {total_vulns}")
print(f"Critical: {total_critical}")
print(f"High: {total_high}")
PYTHON
)

RECENT REPORTS:
===============
$(ls -lt "$REPORTS_DIR"/*.json 2>/dev/null | head -10 | awk '{print $NF, "("$6" "$7" "$8")"}')

LOG SUMMARY:
============
Total log size: $(du -sh "$LOGS_DIR" | cut -f1)
Critical errors: $(grep -c "ERROR" "$LOGS_DIR/scanner.log" 2>/dev/null || echo 0)

RECOMMENDATIONS:
================
1. Review all CRITICAL vulnerabilities immediately
2. Address HIGH severity issues within 3 days
3. Archive old reports to save disk space
4. Update scanner regularly
5. Implement automated fixes where possible

================================================================================
EOF
    
    log_success "Summary report generated: $output_file"
    cat "$output_file"
}

send_email_report() {
    local email=$1
    local report_file=$2
    
    if [ -z "$email" ] || [ -z "$report_file" ]; then
        log_error "Email or report file not specified"
        return 1
    fi
    
    if ! command -v mail &> /dev/null && ! command -v ssmtp &> /dev/null; then
        log_warning "Mail utility not installed"
        return 1
    fi
    
    log_info "Sending report to: $email"
    
    local subject="Security Scan Report - $(date +%Y-%m-%d)"
    
    python3 << EOF
import json
import subprocess

try:
    with open('$report_file', 'r') as f:
        data = json.load(f)
    
    summary = data.get('summary', {})
    
    body = f"""
Security Scan Report
Date: $(date)
Target: {data.get('metadata', {}).get('target', 'Unknown')}

Summary:
- Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}
- Critical: {summary.get('critical', 0)}
- High: {summary.get('high', 0)}
- Medium: {summary.get('medium', 0)}
- Low: {summary.get('low', 0)}

For full details, see attached report.
"""
    
    # Send via mail command
    import subprocess
    cmd = f'echo "{body}" | mail -s "$subject" $email'
    subprocess.run(cmd, shell=True)
    
    print("Email sent successfully")
except Exception as e:
    print(f"Error sending email: {e}")
EOF
}

# ============================================================================
# MAIN OPERATIONS
# ============================================================================

run_daily_scan() {
    log_info "========================================="
    log_info "Starting Daily Security Scan"
    log_info "========================================="
    
    check_venv
    activate_venv
    check_scanner
    
    local targets_file="$CONFIG_DIR/targets.txt"
    
    if [ -f "$targets_file" ]; then
        scan_multiple_targets "$targets_file"
    else
        log_warning "No targets file found at: $targets_file"
        log_info "Create $targets_file with one URL per line"
    fi
    
    log_info "Daily scan completed"
}

run_full_maintenance() {
    log_info "========================================="
    log_info "Starting Full System Maintenance"
    log_info "========================================="
    
    archive_old_reports 30
    cleanup_old_logs 60
    generate_summary_report
    
    log_info "Maintenance completed"
}

# ============================================================================
# HELP & USAGE
# ============================================================================

show_help() {
    cat << EOF
Security Scanner Automation Suite

Usage: ./automated_scanner.sh [COMMAND] [OPTIONS]

Commands:
    single <URL>              Scan single target
    batch <file>              Scan multiple targets from file
    daily                     Run daily scan (from config)
    maintenance               Run maintenance tasks
    archive [days]            Archive reports older than N days (default: 30)
    cleanup [days]            Clean logs older than N days (default: 60)
    report [type]             Generate report (summary, html, json)
    email <email> <report>    Send report via email
    help                      Show this help message

Examples:
    ./automated_scanner.sh single https://example.com
    ./automated_scanner.sh batch targets.txt
    ./automated_scanner.sh daily
    ./automated_scanner.sh maintenance
    ./automated_scanner.sh report summary
    ./automated_scanner.sh email admin@example.com reports/report.json

Configuration:
    - Edit config/targets.txt for daily scanning targets
    - Logs stored in: $LOGS_DIR
    - Reports stored in: $REPORTS_DIR
    - Archives stored in: $ARCHIVE_DIR

EOF
}

# ============================================================================
# MAIN SCRIPT
# ============================================================================

main() {
    local command=${1:-help}
    
    case "$command" in
        single)
            if [ -z "$2" ]; then
                log_error "Target URL required"
                exit 1
            fi
            check_venv
            activate_venv
            check_scanner
            scan_single_target "$2"
            ;;
        
        batch)
            if [ -z "$2" ]; then
                log_error "Targets file required"
                exit 1
            fi
            check_venv
            activate_venv
            check_scanner
            scan_multiple_targets "$2"
            ;;
        
        daily)
            run_daily_scan
            ;;
        
        maintenance)
            run_full_maintenance
            ;;
        
        archive)
            archive_old_reports "${2:-30}"
            ;;
        
        cleanup)
            cleanup_old_logs "${2:-60}"
            ;;
        
        report)
            generate_summary_report
            ;;
        
        email)
            if [ -z "$2" ] || [ -z "$3" ]; then
                log_error "Email and report file required"
                exit 1
            fi
            send_email_report "$2" "$3"
            ;;
        
        help)
            show_help
            ;;
        
        *)
            log_error "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
