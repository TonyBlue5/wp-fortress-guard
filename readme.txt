=== WP Fortress Guard ===
Requires at least: 6.0
Requires PHP: 7.4
Stable tag: 1.2.0

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

This plugin reduces risk but cannot secure a compromised server, hosting account,
computer, DNS provider or stolen credentials. Keep verified off-server backups,
updates, two-factor authentication and a server/WAF layer.
