# WordPress User Registration CVE-2026-1492 Checker

Read-only checker for WordPress sites that may be affected by **CVE-2026-1492** in the **User Registration & Membership** plugin.

The goal is simple: confirm plugin exposure and find compromise indicators such as hidden administrator accounts, suspicious uploads, cron entries, and tampered files.

[![CVE-2026-1492](https://img.shields.io/badge/CVE-2026--1492-critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-1492)
[![CVSS 9.8](https://img.shields.io/badge/CVSS-9.8-critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-1492)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Quick Start

Run from the WordPress root directory, where `wp-config.php` exists:

```bash
curl -fsSLO https://raw.githubusercontent.com/limo57640-crypto/wp-user-registration-vuln-checker/main/check.sh
less check.sh
bash check.sh
```

Or pass the WordPress path:

```bash
bash check.sh /home/example/public_html
```

## What It Checks

| Area | Signal |
| --- | --- |
| WordPress core | Installed core version |
| Plugin exposure | User Registration plugin version and presence |
| Admin accounts | Visible administrators and recent admin creation |
| Hidden admins | `wp_usermeta` role/capability mismatches |
| Uploads | PHP files under `wp-content/uploads/` |
| Config and theme | Obfuscated PHP patterns in critical files |
| Cron | Suspicious scheduled tasks |
| Core folders | Unexpected files in `wp-includes` |

## Output

- `CLEAN`: no obvious indicators found.
- `SUSPICIOUS`: needs manual review.
- `COMPROMISED`: strong compromise indicators found.
- `ERROR`: script could not complete.

## What To Do If It Finds Something

1. Do not delete files immediately. Preserve evidence first.
2. Take a backup or provider snapshot.
3. Patch the plugin and WordPress stack.
4. Remove unauthorized admin accounts after preserving details.
5. Review uploads, cron, theme files, and access logs.

Full guide: https://ping7.cc/cve/wordpress-1492

Need repair help: https://ping7.cc/cve-repair

## Defensive Scope

This checker is for owned or client-approved WordPress sites only. It does not exploit the vulnerability and does not modify files.

## License

MIT
