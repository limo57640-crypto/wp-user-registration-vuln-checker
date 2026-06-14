# Changelog

All notable changes to this project will be documented in this file.

## [1.1.1] - 2026-06-14

### Documentation

- Added sample output, exit codes, limitations, and contribution guidance.
- Added issue templates for bug reports and defensive signal requests.
- No checker logic changed.

## [1.0.0] - 2026-05-16

### Initial release

12 IOC checks for CVE-2026-1492 (User Registration & Membership plugin):

- WordPress core version detection
- Plugin presence + version cross-reference
- Administrator user inventory
- Recent admin creation in 90-day exploit window
- Hidden admin via wp_usermeta override (the actual CVE attack signature)
- PHP files in wp-content/uploads/ (webshell drop)
- wp-config.php obfuscation/eval patterns
- Active theme functions.php tampering
- Suspicious wp_options.cron entries
- Known backdoor file names in plugins/
- wp-includes integrity (newer than wp-load.php)
- Recent user registration volume

### Sources cross-referenced

- NVD CVE-2026-1492 entry
- Patchstack plugin database
- WPScan plugin vulnerability records
- WordPress.org plugin advisory
