=== WP Fortress Guard ===
Requires at least: 6.0
Requires PHP: 7.4
Stable tag: 1.3.0

Layered WordPress hardening for general use:
- Login rate limiting and generic login errors.
- PHP/executable upload blocking.
- Apache/LiteSpeed uploads .htaccess protection.
- Theme/plugin file editor disabled.
- REST and author user-enumeration controls.
- Optional XML-RPC and Application Password restrictions.
- Security response headers that avoid a site-breaking CSP.
- Strong administrator password enforcement.
- Administrator role email alerts and a local event log.
- Read-only executable-file scanner for wp-content/uploads.
- Native WordPress update notifications from signed release artifacts.
- SHA-256 verification before an update package is installed.
- Fortress Intelligence dashboard for core/plugin/theme update posture.
- Daily official WordPress security notice monitoring.
- Optional signed Wordfence Intelligence webhook ingestion with local installed-version matching and email alerts.

This plugin reduces risk but cannot secure a compromised server, hosting account,
computer, DNS provider or stolen credentials. Keep verified off-server backups,
updates, two-factor authentication and a server/WAF layer.


== Changelog ==

= 1.3.0 =
* Added Fortress Intelligence dashboard.
* Added daily WordPress security notice monitoring.
* Added update-posture checks for WordPress core, plugins and themes.
* Added HMAC-SHA256 verified Wordfence Intelligence webhook ingestion.
* Added local matching of incoming vulnerability ranges to installed software versions.
* Added administrator email alerts for newly matched vulnerabilities.
