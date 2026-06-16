# WordPress User Registration CVE-2026-1492 Checker

Read-only checker for WordPress sites that may be affected by **CVE-2026-1492** in the **User Registration & Membership** plugin.

The goal is simple: confirm plugin exposure and find compromise indicators such as hidden administrator accounts, suspicious uploads, cron entries, and tampered files.

[![CVE-2026-1492](https://img.shields.io/badge/CVE-2026--1492-critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-1492)
[![CVSS 9.8](https://img.shields.io/badge/CVSS-9.8-critical-red)](https://nvd.nist.gov/vuln/detail/CVE-2026-1492)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Browse page: https://limo57640-crypto.github.io/wp-user-registration-vuln-checker/

## Ping7 resources

- All GitHub tools: https://ping7.cc/github-tools/
- Full self-check guide: https://ping7.cc/cve/wordpress-1492/
- CVE repair service: https://ping7.cc/cve-repair/
- Sample repair report: https://ping7.cc/cve-repair/sample-report/
- Live CVE alerts: https://t.me/ping7cve

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

## Sample Output

```text
WordPress User Registration CVE-2026-1492 Checker

Checks run:     12
Suspicious:     1
Compromised:    0

STATUS: SUSPICIOUS - INVESTIGATE FURTHER
Some checks need manual review.
Guide: https://ping7.cc/cve/wordpress-1492
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Clean result |
| `1` | Suspicious finding, manual review needed |
| `2` | Strong compromise indicator found |
| `3` | Runtime error or WordPress root not found |

## Limitations

- It does not replace a full WordPress incident response.
- It can only read files and database state available to the current user.
- Deleted logs, disabled shell access, or managed-hosting restrictions can hide useful evidence.
- A clean result does not prove the site was never attacked.

## Repair Handoff

If you need help interpreting the result, send:

```text
Domain:
WordPress path or host type:
CVE: CVE-2026-1492
Plugin version:
Detector result: CLEAN / SUSPICIOUS / COMPROMISED / ERROR
Symptoms: unknown admin, upload PHP file, redirect, cron, changed theme file, or scanner result
Logs still available: yes / no
```

Do not send passwords in the first message. Send symptoms, timestamps, screenshots, and log snippets.

## What To Do If It Finds Something

1. Do not delete files immediately. Preserve evidence first.
2. Take a backup or provider snapshot.
3. Patch the plugin and WordPress stack.
4. Remove unauthorized admin accounts after preserving details.
5. Review uploads, cron, theme files, and access logs.

Need repair help: https://ping7.cc/cve-repair

## Contributing

Open an issue for a false positive, a missed defensive signal, or a hosting
environment that the checker handles poorly. Include plugin version, WordPress
version, host type, and sanitized output. Do not post passwords, API keys,
customer data, or live attack strings.

## Defensive Scope

This checker is for owned or client-approved WordPress sites only. It does not exploit the vulnerability and does not modify files.

It does not include exploit code, credential theft, unauthorized scanning, or instructions for offensive access.

## License

MIT
