# WordPress User Registration & Membership Plugin Vulnerability Checker

> Read-only checker for WordPress sites running the **User Registration & Membership** plugin and potentially affected by **CVE-2026-1492** (CVSS 9.8, pre-auth admin takeover).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CVE-2026-1492](https://img.shields.io/badge/CVE-2026--1492-red.svg)](https://nvd.nist.gov/vuln/detail/CVE-2026-1492)
[![CVSS 9.8](https://img.shields.io/badge/CVSS-9.8-critical.svg)](https://nvd.nist.gov/vuln/detail/CVE-2026-1492)

## Why this exists

**CVE-2026-1492** is a critical authentication bypass + privilege escalation vulnerability in the [User Registration & Membership](https://wordpress.org/plugins/user-registration/) plugin. Attackers can create hidden administrator accounts without any credentials. The plugin is installed on **60,000+ active sites**.

**Hidden admin accounts** are the worst part: attackers set the user role directly in the `wp_usermeta` table, bypassing the standard wp-admin Users page. You can be compromised and not see it through normal admin UI.

This tool checks 12 indicators including:
- Plugin version cross-reference
- Standard admin user list
- Recent admin creation in exploit window
- Hidden admin via DB meta override
- PHP files in uploads (webshell indicator)
- wp-config.php obfuscation patterns
- Theme functions.php tampering
- Malicious cron entries
- Known backdoor file names
- wp-includes tampering

## What it checks

| # | Check | Why it matters |
|---|-------|---------------|
| 1 | WordPress core version | Outdated core = wider attack surface |
| 2 | User Registration plugin presence + version | Direct CVE-2026-1492 applicability |
| 3 | Administrator user list | Baseline for comparing |
| 4 | Admin accounts created in last 90 days | Exploit window check |
| 5 | Hidden admin via `wp_usermeta` override | The actual CVE-2026-1492 attack signature |
| 6 | PHP files in `wp-content/uploads/` | Common webshell drop location |
| 7 | wp-config.php for `eval`/`base64_decode`/etc. | Obfuscated backdoor injection |
| 8 | Active theme `functions.php` for same patterns | Theme-based persistence |
| 9 | Suspicious entries in `wp_options.cron` | Scheduled malicious tasks |
| 10 | Plugins folder for known backdoor file names | Common script kit drops |
| 11 | wp-includes tampering | Core file modification |
| 12 | Recent user registration patterns | Spam / exploit-driven registrations |

## Quick start

**On the WordPress server (SSH):**

```bash
cd /path/to/wordpress    # where wp-config.php lives
curl -sSL https://raw.githubusercontent.com/limo57640-crypto/wp-user-registration-vuln-checker/main/check.sh | bash
```

**Or download first (recommended):**

```bash
wget https://raw.githubusercontent.com/limo57640-crypto/wp-user-registration-vuln-checker/main/check.sh
less check.sh    # read what it does
bash check.sh
```

**With explicit WordPress path:**

```bash
bash check.sh /home/yoursite/public_html
```

## Sample output (clean site)

```
╔═══════════════════════════════════════════════════════════════════╗
║  WordPress User Registration CVE-2026-1492 Checker v1.0.0         ║
║  https://ping7.cc/cve/wordpress-1492                              ║
╚═══════════════════════════════════════════════════════════════════╝

WordPress root: /home/example/public_html
This is a READ-ONLY scan. No files will be modified.

[ 1] WordPress core version ... 
    WordPress core: 6.5.3
    OK
[ 2] User Registration & Membership plugin presence + version ... NOT INSTALLED
    CVE-2026-1492 does not directly apply.
[ 3] Administrator user list ... 
    Found 2 administrator account(s):
      - admin (admin@example.com) registered 2024-01-15 12:30:00
      - editor (editor@example.com) registered 2024-03-20 09:15:00
    OK
[ 4] Admin accounts created in CVE-2026-1492 exploit window ... OK
[ 5] Hidden admin via direct usermeta override ... OK
[ 6] PHP files in wp-content/uploads/ ... OK
[ 7] wp-config.php for suspicious eval/base64/include patterns ... OK
[ 8] Active theme functions.php for suspicious patterns ... OK
[ 9] Suspicious wp_cron / wp_options cron entries ... OK
[10] Plugins folder for files matching common backdoor names ... OK
[11] Unexpected files in wp-includes (core integrity) ... OK
[12] Recent user registration patterns (last 30 days) ... OK

════════════════════════════════════════════════════════════════════
                            SUMMARY
════════════════════════════════════════════════════════════════════

  Checks run:     12
  Suspicious:     0
  Compromised:    0

STATUS: CLEAN
```

## Sample output (compromised site)

```
[ 5] Hidden admin via direct usermeta override ... COMPROMISED
    ↳ Mismatch: 7 admin meta entries but 5 users — possible orphan/hidden admin

[ 6] PHP files in wp-content/uploads/ ... COMPROMISED
    ↳ PHP files found in uploads dir (should never contain PHP):
      - /home/example/public_html/wp-content/uploads/2025/03/payload.php
      - /home/example/public_html/wp-content/uploads/2025/04/.htaccess.php

STATUS: COMPROMISED — IMMEDIATE ACTION REQUIRED
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no IOCs detected |
| `1` | Suspicious — manual review needed |
| `2` | Compromised — strong indicators, immediate action required |
| `3` | Error — could not run (no wp-config.php found, etc.) |

## Requirements

- Linux server hosting WordPress (SSH access required)
- Bash 4.0+
- `mysql` client (for DB checks; falls back to file-only checks if not available)
- Read access to:
  - `wp-config.php` (DB credentials)
  - `wp-content/`
  - `wp-includes/`

## What this is NOT

- ❌ Not a vulnerability scanner — checks for residue, not exploitability
- ❌ Not a cleanup tool — finds, doesn't remove
- ❌ Not WPScan / Wordfence equivalent — IOC-focused, not full plugin audit
- ❌ Not for shared hosting without SSH — see "Alternative for non-SSH" below

## Alternative for non-SSH (wp-admin only)

If you don't have SSH but have `/wp-admin` access, the equivalent checks done manually:

1. **Plugin version**: Plugins → Installed → look up "User Registration"
2. **Admin users**: Users → All Users → Role: Administrator
3. **Recent registrations**: Users → All Users → sort by Registration Date
4. **Hidden admin**: install [Health Check & Troubleshooting](https://wordpress.org/plugins/health-check/) plugin, run, look for role mismatch
5. **PHP in uploads**: install [Wordfence](https://wordpress.org/plugins/wordfence/) free, run "Scan"
6. **wp-config integrity**: download via FTP, search for `eval(` / `base64_decode(`

For a guided walkthrough, see https://ping7.cc/cve/wordpress-1492

## Background — what is CVE-2026-1492?

| Fact | Value |
|------|-------|
| **Vulnerability** | Authentication bypass + privilege escalation in User Registration & Membership plugin |
| **Impact** | Pre-auth attacker can create administrator accounts |
| **CVSS Score** | 9.8 (Critical) |
| **Plugin install base** | 60,000+ active sites |
| **Affected versions** | All releases prior to vendor's patched build (verify on Patchstack) |
| **Common attack pattern** | (1) Submit crafted registration → (2) Bypass role assignment → (3) Direct meta write to wp_usermeta with `administrator` capability |

### Authoritative sources

- **NVD**: https://nvd.nist.gov/vuln/detail/CVE-2026-1492
- **Patchstack**: https://patchstack.com/database/vulnerability/user-registration/
- **WPScan**: https://wpscan.com/plugin/user-registration
- **Plugin advisory**: https://wordpress.org/plugins/user-registration/#changelog

## I found something. What now?

If the scanner reports **SUSPICIOUS** or **COMPROMISED**:

1. **Do NOT delete files yet** — preserve IOCs
2. **Take a backup/snapshot** if your host supports it
3. Read the [self-check guide](https://ping7.cc/cve/wordpress-1492) for detailed remediation
4. Need help with cleanup or full incident response?
   - Email: lo@ping7.cc
   - Services: https://ping7.cc/services
   - Or open an issue here for community help

## Contributing

PRs welcome. Especially:

- Additional CVE checks for other WordPress plugins
- False-positive tuning
- Translations (Chinese, Spanish, French)

Open an issue first to discuss before large changes.

## License

MIT — see [LICENSE](LICENSE).

## Author

[Ping7 Security](https://ping7.cc) — public security toolkit and CVE triage.

If you maintain WordPress sites and want **proactive CVE alerts** for your installed plugins, see https://ping7.cc/services — $19/month for Telegram + email alerts tuned to your plugin stack.

---

**Disclaimer**: This is a community-maintained tool, not affiliated with WPEverest, WordPress, or Automattic. Run on sites you own or are authorized to audit.
