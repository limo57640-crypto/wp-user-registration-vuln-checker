#!/bin/bash
# WordPress User Registration & Membership Plugin CVE-2026-1492 Checker
# https://github.com/limo57640-crypto/wp-user-registration-vuln-checker
# https://ping7.cc/cve/wordpress-1492
#
# Read-only checker for WordPress sites running the User Registration &
# Membership plugin and potentially affected by CVE-2026-1492 (CVSS 9.8,
# pre-auth admin takeover via authentication bypass + privilege escalation).
#
# Run from WordPress root (where wp-config.php lives):
#
#   curl -sSL https://raw.githubusercontent.com/limo57640-crypto/wp-user-registration-vuln-checker/main/check.sh | bash
#
# Or download and inspect first (recommended):
#
#   wget https://raw.githubusercontent.com/limo57640-crypto/wp-user-registration-vuln-checker/main/check.sh
#   less check.sh
#   bash check.sh
#
# Output: colored CLEAN / SUSPICIOUS / COMPROMISED summary
# Exit codes: 0=clean, 1=suspicious, 2=compromised, 3=error

set -u

VERSION="1.0.0"

# --------------------------------------------------------------------------- #
# Colors
# --------------------------------------------------------------------------- #
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    BOLD='\033[1m'
    DIM='\033[2m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' BOLD='' DIM='' NC=''
fi

# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
SUSPICIOUS_COUNT=0
COMPROMISED_COUNT=0
CHECKS_RUN=0

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
banner() {
    echo
    echo -e "${BOLD}${BLUE}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}${BLUE}║  WordPress User Registration CVE-2026-1492 Checker v${VERSION}            ║${NC}"
    echo -e "${BOLD}${BLUE}║  https://ping7.cc/cve/wordpress-1492                              ║${NC}"
    echo -e "${BOLD}${BLUE}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

step() {
    CHECKS_RUN=$((CHECKS_RUN + 1))
    printf "${BLUE}[%2d]${NC} %s ... " "$CHECKS_RUN" "$1"
}

ok() { echo -e "${GREEN}OK${NC}"; }

suspicious() {
    SUSPICIOUS_COUNT=$((SUSPICIOUS_COUNT + 1))
    echo -e "${YELLOW}SUSPICIOUS${NC}"
    [ -n "${1:-}" ] && echo -e "    ${YELLOW}↳ $1${NC}"
}

compromised() {
    COMPROMISED_COUNT=$((COMPROMISED_COUNT + 1))
    echo -e "${RED}${BOLD}COMPROMISED${NC}"
    [ -n "${1:-}" ] && echo -e "    ${RED}↳ $1${NC}"
}

skip() { echo -e "${DIM}skipped: ${1:-not applicable}${NC}"; }

# --------------------------------------------------------------------------- #
# Pre-flight
# --------------------------------------------------------------------------- #

WP_ROOT=""

find_wp_root() {
    # Try current dir first, then walk up
    local dir="$PWD"
    for _ in 1 2 3 4 5; do
        if [ -f "$dir/wp-config.php" ]; then
            WP_ROOT="$dir"
            return 0
        fi
        dir=$(dirname "$dir")
    done
    # Try common cPanel paths
    for candidate in /home/*/public_html /home/*/www /var/www/html /var/www; do
        if [ -f "$candidate/wp-config.php" ]; then
            WP_ROOT="$candidate"
            return 0
        fi
    done
    return 1
}

extract_db_credentials() {
    # Best-effort parse of wp-config.php for DB credentials
    DB_NAME=$(grep -oP "DB_NAME['\"]?\s*,\s*['\"]?\K[^'\"]+" "$WP_ROOT/wp-config.php" 2>/dev/null | head -1)
    DB_USER=$(grep -oP "DB_USER['\"]?\s*,\s*['\"]?\K[^'\"]+" "$WP_ROOT/wp-config.php" 2>/dev/null | head -1)
    DB_PASSWORD=$(grep -oP "DB_PASSWORD['\"]?\s*,\s*['\"]?\K[^'\"]+" "$WP_ROOT/wp-config.php" 2>/dev/null | head -1)
    DB_HOST=$(grep -oP "DB_HOST['\"]?\s*,\s*['\"]?\K[^'\"]+" "$WP_ROOT/wp-config.php" 2>/dev/null | head -1)
    TABLE_PREFIX=$(grep -oP "table_prefix\s*=\s*['\"]?\K[^'\"]+" "$WP_ROOT/wp-config.php" 2>/dev/null | head -1)
    DB_HOST=${DB_HOST:-localhost}
    TABLE_PREFIX=${TABLE_PREFIX:-wp_}
}

mysql_q() {
    # Run a SELECT query and return the result. Empty on error.
    if ! command -v mysql >/dev/null 2>&1; then
        return 1
    fi
    mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" \
        -N -B -e "$1" 2>/dev/null
}

# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

check_wp_version() {
    step "WordPress core version"
    if [ -f "$WP_ROOT/wp-includes/version.php" ]; then
        local version
        version=$(grep -oP "wp_version\s*=\s*['\"]?\K[^'\"]+" "$WP_ROOT/wp-includes/version.php" | head -1)
        if [ -n "$version" ]; then
            echo
            echo -e "    ${DIM}WordPress core: $version${NC}"
            ok
        else
            suspicious "Could not parse version"
        fi
    else
        suspicious "wp-includes/version.php not found"
    fi
}

check_user_registration_plugin() {
    step "User Registration & Membership plugin presence + version"
    local plugin_dir="$WP_ROOT/wp-content/plugins/user-registration"
    if [ ! -d "$plugin_dir" ]; then
        echo -e "${GREEN}NOT INSTALLED${NC}"
        echo -e "    ${DIM}CVE-2026-1492 does not directly apply.${NC}"
        return
    fi
    local version
    if [ -f "$plugin_dir/user-registration.php" ]; then
        version=$(grep -oP "Version:\s*\K[^\s]+" "$plugin_dir/user-registration.php" | head -1)
    fi
    echo
    echo -e "    ${DIM}Plugin version: ${version:-unknown}${NC}"
    if [ -z "$version" ]; then
        suspicious "Plugin installed but version could not be parsed"
        return
    fi
    # Heuristic: cross-reference NVD/Patchstack for the patched version.
    # Without an online check, just flag any version as needing manual verification.
    suspicious "Verify $version against the patched release at https://patchstack.com/database/vulnerability/user-registration/"
}

check_admin_users() {
    step "Administrator user list"
    extract_db_credentials
    if [ -z "${DB_NAME:-}" ] || [ -z "${DB_USER:-}" ]; then
        skip "Could not extract DB credentials from wp-config.php"
        return
    fi
    if ! command -v mysql >/dev/null 2>&1; then
        skip "mysql client not installed"
        return
    fi
    local result
    result=$(mysql_q "
        SELECT u.user_login, u.user_email, u.user_registered
        FROM ${TABLE_PREFIX}users u
        INNER JOIN ${TABLE_PREFIX}usermeta m ON u.ID = m.user_id
        WHERE m.meta_key = '${TABLE_PREFIX}capabilities'
          AND m.meta_value LIKE '%administrator%'
        ORDER BY u.user_registered DESC;
    ")
    if [ -z "$result" ]; then
        skip "Could not query DB (check credentials or permissions)"
        return
    fi
    local count
    count=$(echo "$result" | wc -l)
    echo
    echo -e "    ${DIM}Found $count administrator account(s):${NC}"
    echo "$result" | while IFS=$'\t' read -r login email registered; do
        echo -e "      ${DIM}- $login ($email) registered $registered${NC}"
    done
    if [ "$count" -gt 5 ]; then
        suspicious "$count admin accounts is unusually high — review the list above"
    else
        ok
    fi
}

check_recent_admin_creation() {
    step "Admin accounts created in CVE-2026-1492 exploit window"
    extract_db_credentials
    if [ -z "${DB_NAME:-}" ] || ! command -v mysql >/dev/null 2>&1; then
        skip "DB query unavailable"
        return
    fi
    # Look for admin accounts registered in the last 90 days
    local result
    result=$(mysql_q "
        SELECT u.user_login, u.user_email, u.user_registered
        FROM ${TABLE_PREFIX}users u
        INNER JOIN ${TABLE_PREFIX}usermeta m ON u.ID = m.user_id
        WHERE m.meta_key = '${TABLE_PREFIX}capabilities'
          AND m.meta_value LIKE '%administrator%'
          AND u.user_registered > DATE_SUB(NOW(), INTERVAL 90 DAY)
        ORDER BY u.user_registered DESC;
    ")
    if [ -z "$result" ]; then
        ok
        return
    fi
    local count
    count=$(echo "$result" | wc -l)
    suspicious "$count admin account(s) created in last 90 days — verify each one is legitimate:"
    echo "$result" | while IFS=$'\t' read -r login email registered; do
        echo -e "      ${YELLOW}- $login ($email) at $registered${NC}"
    done
}

check_hidden_admin_via_meta() {
    step "Hidden admin via direct usermeta override"
    extract_db_credentials
    if [ -z "${DB_NAME:-}" ] || ! command -v mysql >/dev/null 2>&1; then
        skip "DB query unavailable"
        return
    fi
    # Look for users where capabilities meta says admin but role mismatch
    local count
    count=$(mysql_q "
        SELECT COUNT(*)
        FROM ${TABLE_PREFIX}usermeta m
        WHERE m.meta_key = '${TABLE_PREFIX}capabilities'
          AND m.meta_value LIKE '%administrator%';
    ")
    local user_count
    user_count=$(mysql_q "
        SELECT COUNT(DISTINCT u.ID)
        FROM ${TABLE_PREFIX}users u
        INNER JOIN ${TABLE_PREFIX}usermeta m ON u.ID = m.user_id
        WHERE m.meta_key = '${TABLE_PREFIX}capabilities'
          AND m.meta_value LIKE '%administrator%';
    ")
    if [ "$count" != "$user_count" ]; then
        compromised "Mismatch: $count admin meta entries but $user_count users — possible orphan/hidden admin"
    else
        ok
    fi
}

check_php_in_uploads() {
    step "PHP files in wp-content/uploads/ (high-confidence webshell indicator)"
    local uploads="$WP_ROOT/wp-content/uploads"
    if [ ! -d "$uploads" ]; then
        skip "uploads directory not found"
        return
    fi
    local php_files
    php_files=$(find "$uploads" -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.php5" -o -name "*.phar" \) 2>/dev/null | head -10)
    if [ -n "$php_files" ]; then
        compromised "PHP files found in uploads dir (should never contain PHP):"
        echo "$php_files" | while read -r f; do
            echo -e "      ${RED}- $f${NC}"
        done
    else
        ok
    fi
}

check_wp_config_integrity() {
    step "wp-config.php for suspicious eval/base64/include patterns"
    if [ ! -f "$WP_ROOT/wp-config.php" ]; then
        skip "wp-config.php not found"
        return
    fi
    local content
    content=$(grep -E "eval\s*\(|base64_decode|gzinflate|str_rot13|preg_replace.*\\\\e|include.*\\\$_(GET|POST|REQUEST)" "$WP_ROOT/wp-config.php" 2>/dev/null)
    if [ -n "$content" ]; then
        compromised "wp-config.php contains obfuscation/eval patterns:"
        echo "$content" | head -5 | while read -r line; do
            echo -e "      ${RED}- $line${NC}"
        done
    else
        ok
    fi
}

check_theme_functions() {
    step "Active theme functions.php for suspicious patterns"
    extract_db_credentials
    local active_theme
    active_theme=$(mysql_q "SELECT option_value FROM ${TABLE_PREFIX}options WHERE option_name = 'stylesheet';" 2>/dev/null)
    if [ -z "$active_theme" ]; then
        skip "Could not determine active theme via DB"
        return
    fi
    local functions_php="$WP_ROOT/wp-content/themes/$active_theme/functions.php"
    if [ ! -f "$functions_php" ]; then
        skip "functions.php not found at $functions_php"
        return
    fi
    local content
    content=$(grep -E "eval\s*\(|base64_decode\s*\(|gzinflate|str_rot13|file_put_contents.*\\\$_(GET|POST)" "$functions_php" 2>/dev/null)
    if [ -n "$content" ]; then
        suspicious "Active theme functions.php has obfuscation patterns:"
        echo "$content" | head -3 | while read -r line; do
            echo -e "      ${YELLOW}- ${line:0:120}...${NC}"
        done
    else
        ok
    fi
}

check_suspicious_cron() {
    step "Suspicious wp_cron / wp_options cron entries"
    extract_db_credentials
    if [ -z "${DB_NAME:-}" ] || ! command -v mysql >/dev/null 2>&1; then
        skip "DB query unavailable"
        return
    fi
    local cron
    cron=$(mysql_q "SELECT option_value FROM ${TABLE_PREFIX}options WHERE option_name = 'cron';" 2>/dev/null)
    if [ -z "$cron" ]; then
        ok
        return
    fi
    # Look for known malicious cron hook names
    if echo "$cron" | grep -qE "wp_(version_check|update_)?fake|hidden_admin_create|backdoor|trojan|malware"; then
        compromised "Suspicious cron hook detected"
    else
        ok
    fi
}

check_unexpected_plugins() {
    step "Plugins folder for files matching common backdoor names"
    local plugins="$WP_ROOT/wp-content/plugins"
    if [ ! -d "$plugins" ]; then
        skip "plugins directory not found"
        return
    fi
    local backdoor_names=("wso.php" "c99.php" "r57.php" "alfa.php" "indoxploit.php"
                          "shell.php" "cmd.php" "backdoor.php" "wp-backdoor.php"
                          "wp-shell.php" "config.bak.php")
    local found=()
    for name in "${backdoor_names[@]}"; do
        local hits
        hits=$(find "$plugins" -name "$name" -type f 2>/dev/null)
        [ -n "$hits" ] && found+=("$hits")
    done
    if [ "${#found[@]}" -gt 0 ]; then
        compromised "Known backdoor file names found in plugins:"
        for f in "${found[@]}"; do
            echo -e "      ${RED}- $f${NC}"
        done
    else
        ok
    fi
}

check_wp_includes_tampering() {
    step "Unexpected files in wp-includes (core integrity)"
    local wpi="$WP_ROOT/wp-includes"
    if [ ! -d "$wpi" ]; then
        skip "wp-includes not found"
        return
    fi
    # Look for non-standard PHP files at top level of wp-includes
    local recent
    recent=$(find "$wpi" -maxdepth 1 -type f -name "*.php" -newer "$WP_ROOT/wp-load.php" 2>/dev/null | head -5)
    if [ -n "$recent" ]; then
        suspicious "Files in wp-includes/ newer than wp-load.php:"
        echo "$recent" | while read -r f; do
            echo -e "      ${YELLOW}- $f${NC}"
        done
    else
        ok
    fi
}

check_recent_user_registrations() {
    step "Recent user registration patterns (last 30 days)"
    extract_db_credentials
    if [ -z "${DB_NAME:-}" ] || ! command -v mysql >/dev/null 2>&1; then
        skip "DB query unavailable"
        return
    fi
    local count
    count=$(mysql_q "
        SELECT COUNT(*)
        FROM ${TABLE_PREFIX}users
        WHERE user_registered > DATE_SUB(NOW(), INTERVAL 30 DAY);
    ")
    if [ -z "$count" ] || [ "$count" -lt 1 ]; then
        ok
        return
    fi
    echo
    echo -e "    ${DIM}$count user(s) registered in last 30 days${NC}"
    if [ "$count" -gt 50 ]; then
        suspicious "Unusually high — review for spam or exploit-driven registrations"
    else
        ok
    fi
}

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #

print_summary() {
    echo
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}                            SUMMARY${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════════${NC}"
    echo
    printf "  Checks run:     %d\n" "$CHECKS_RUN"
    printf "  Suspicious:     %d\n" "$SUSPICIOUS_COUNT"
    printf "  Compromised:    %d\n" "$COMPROMISED_COUNT"
    echo

    if [ "$COMPROMISED_COUNT" -gt 0 ]; then
        echo -e "${RED}${BOLD}STATUS: COMPROMISED — IMMEDIATE ACTION REQUIRED${NC}"
        echo
        echo -e "  ${RED}Your site shows strong indicators of compromise.${NC}"
        echo -e "  ${RED}Do NOT delete files yet — preserve IOCs for forensics.${NC}"
        echo
        echo -e "  Next steps:"
        echo -e "    1. Take a backup if your host supports it"
        echo -e "    2. Read https://ping7.cc/cve/wordpress-1492"
        echo -e "    3. Need help? lo@ping7.cc or https://ping7.cc/services"
        exit 2
    elif [ "$SUSPICIOUS_COUNT" -gt 0 ]; then
        echo -e "${YELLOW}${BOLD}STATUS: SUSPICIOUS — INVESTIGATE FURTHER${NC}"
        echo
        echo -e "  Some checks need manual review."
        echo -e "  Read the full guide at:"
        echo -e "    ${BLUE}https://ping7.cc/cve/wordpress-1492${NC}"
        exit 1
    else
        echo -e "${GREEN}${BOLD}STATUS: CLEAN${NC}"
        echo
        echo -e "  All ${CHECKS_RUN} checks returned clean."
        echo
        echo -e "  Recommendations:"
        echo -e "    1. Keep User Registration plugin updated to the patched version"
        echo -e "    2. Subscribe to CVE alerts: https://ping7.cc/services"
        echo -e "    3. Re-run this scan monthly"
        exit 0
    fi
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

main() {
    banner

    if ! find_wp_root; then
        echo -e "${RED}ERROR: WordPress root not found.${NC}" >&2
        echo -e "Run from a directory containing wp-config.php, or pass it as argument:" >&2
        echo -e "  bash check.sh /path/to/wordpress" >&2
        exit 3
    fi

    echo -e "${BOLD}WordPress root: ${WP_ROOT}${NC}"
    echo -e "${DIM}This is a READ-ONLY scan. No files will be modified.${NC}"
    echo

    check_wp_version
    check_user_registration_plugin
    check_admin_users
    check_recent_admin_creation
    check_hidden_admin_via_meta
    check_php_in_uploads
    check_wp_config_integrity
    check_theme_functions
    check_suspicious_cron
    check_unexpected_plugins
    check_wp_includes_tampering
    check_recent_user_registrations

    print_summary
}

main "$@"
