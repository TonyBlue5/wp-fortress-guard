# Security Policy

Do not disclose exploitable security issues in public GitHub issues. Contact the
repository owner privately with the affected version, reproduction steps and
impact. Never include production credentials, customer data or access tokens.

Only ZIP files attached to GitHub Releases are update packages. Every package
must have a matching `.sha256` asset, and the plugin rejects an update when the
checksum does not match.
