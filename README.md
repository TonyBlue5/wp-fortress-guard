# WP Fortress Guard

Layered security and hardening toolkit for WordPress maintained by Antonis
Kanaris Tools.

## Protection layers

- Login rate limiting without global shared-IP lockouts.
- Generic authentication errors.
- PHP and executable blocking in Media Uploads.
- Apache/LiteSpeed `.htaccess` protection for `wp-content/uploads`.
- Theme and plugin file editor disabled.
- Public REST user and `?author=` enumeration controls.
- Optional XML-RPC and Application Password restrictions.
- Safe HTTP security headers.
- Strong administrator password enforcement.
- Email alerts and local event logging for administrator role changes.
- Read-only scanner for executable files in uploads.
- Native WordPress update notifications with SHA-256 package verification.

## Automated compatibility checks

GitHub Actions tests every push, pull request and the latest WordPress release
daily on PHP 7.4, 8.1, 8.2, 8.3 and 8.4. A failed scheduled workflow alerts the
repository owner through GitHub.

## Releases and updates

Production packages are built only by the **Build verified release** workflow.
Each release contains:

- `wp-fortress-guard.zip`
- `wp-fortress-guard.zip.sha256`

Installed sites query the latest public GitHub Release twice per day. WordPress
offers the normal **Update now** action only when both release assets exist, and
the downloaded ZIP must match the published SHA-256 checksum.

## Important limits

No WordPress plugin can secure a compromised hosting account, server, DNS
provider, administrator computer or stolen credentials. Keep WordPress and all
extensions updated, enable 2FA, use unique passwords, maintain verified
off-server backups and add a server or edge WAF.

## License

GPL-2.0.
