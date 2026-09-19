# CHAINBOX — Secure File Sharing System

A production-ready, dependency-free secure file sharing system built in
native PHP 8.2+, MySQL, and Tailwind CSS (via CDN). No framework, no
Composer packages — every security control is implemented explicitly so
the code is auditable end to end.

## Directory layout

```
secure-file-sharing/
├── config/
│   └── database.php        # PDO connection factory (OUTSIDE web root)
├── includes/
│   ├── auth.php             # sessions, CSRF, login/logout, RBAC gates
│   ├── file_helpers.php     # upload validation, path safety, permissions
│   └── layout.php           # shared HTML chrome
├── public/                  # <-- point your web server's document root HERE
│   ├── index.php
│   ├── login.php
│   ├── register.php
│   ├── logout.php
│   ├── dashboard.php
│   ├── upload.php
│   ├── download.php
│   ├── share.php
│   ├── delete.php
│   ├── admin/
│   │   └── logs.php
│   └── .htaccess
├── storage/
│   └── uploads/              # actual file bytes — NEVER web-accessible
├── schema.sql
├── .env.example
└── README.md
```

**The single most important deployment rule:** your web server's document
root must point at `public/`, and nothing else. `config/`, `includes/`,
and `storage/` all live one level above `public/`, so they are not
reachable by any URL when the server is configured correctly. `.htaccess`
files in each of those directories add a second layer of denial in case
of misconfiguration, but they are a backstop, not the primary control —
correct document-root placement is.

## Setup

1. **Create the database.**
   ```bash
   mysql -u root -p < schema.sql
   ```
   Then create a least-privilege application user and grant it access
   only to `secure_file_sharing`:
   ```sql
   CREATE USER 'sfs_app'@'localhost' IDENTIFIED BY 'a-strong-password';
   GRANT SELECT, INSERT, UPDATE, DELETE ON secure_file_sharing.* TO 'sfs_app'@'localhost';
   FLUSH PRIVILEGES;
   ```

2. **Configure environment variables** (see `.env.example`). At minimum,
   set `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASS` in your web server or
   PHP-FPM pool configuration.

3. **Create the storage directory and lock down permissions:**
   ```bash
   mkdir -p storage/uploads
   chown -R www-data:www-data storage/uploads
   chmod 750 storage/uploads
   ```

4. **Point your web server's document root at `public/`.** Example Apache
   vhost:
   ```apache
   <VirtualHost *:443>
       ServerName files.example.com
       DocumentRoot /var/www/secure-file-sharing/public
       <Directory /var/www/secure-file-sharing/public>
           AllowOverride All
           Require all granted
       </Directory>
   </VirtualHost>
   ```
   For Nginx, add an explicit `location` block denying `/storage/`,
   `/config/`, and `/includes/` in addition to setting `root` to `public/`.

5. **Register the first account.** The first user to register is
   automatically granted the `admin` role; every subsequent registration
   defaults to `user`. Promote additional moderators/admins directly in
   the `users` table.

## Security controls implemented

| Control | Where |
|---|---|
| Storage isolation outside the web root | directory layout + `SFS_STORAGE_ROOT` |
| Server-side MIME whitelisting via `finfo_file()` | `includes/file_helpers.php::validate_uploaded_file()` |
| Max upload size enforcement (10 MB) | same |
| Randomized on-disk filenames (`random_bytes(16)`) | `generate_stored_filename()` |
| Path traversal prevention (`basename()` + `realpath()` containment) | `resolve_safe_storage_path()` |
| Controlled, authenticated download streaming | `download.php` |
| Role-based access control (User / Moderator / Admin) | `require_role()` |
| Per-file permission matrix (Owner / Editor / Viewer) | `user_can()` |
| CSRF protection on every state-changing form | `csrf_field()` / `verify_csrf()` |
| Session hardening: HttpOnly, SameSite, ID regeneration, idle + absolute timeout | `start_secure_session()` |
| Brute-force login lockout | `login.php` (`failed_logins` / `locked_until`) |
| Timing-safe login (dummy hash comparison for unknown users) | `login.php` |
| Full audit trail (`UPLOAD`, `DOWNLOAD`, `SHARE`, `DELETE`, `PERMISSION_CHANGE`, auth events, `ACCESS_DENIED`) | `audit_logs` table + `log_audit_event()` |
| Prepared statements everywhere (no string-built SQL) | all DB access |
| Security response headers (`X-Content-Type-Options`, CSP, etc.) | `download.php`, `public/.htaccess` |

## Notes and further hardening for a real deployment

- Serve exclusively over HTTPS; the session cookie is marked `Secure`
  automatically once `HTTPS` is detected.
- Consider moving audit logs to write-once storage (e.g. shipped to a
  SIEM) for tamper resistance beyond what a single MySQL table provides.
- Add a virus-scanning step (e.g. ClamAV) on uploaded files before they
  are made shareable, for an additional layer beyond MIME/type checks.
- Add rate limiting at the reverse-proxy layer in addition to the
  application-level login lockout implemented here.
- Rotate the `sfs_app` database credentials and Google Fonts/Tailwind CDN
  choices per your organization's supply-chain policy if operating in a
  network-restricted environment (both can be vendored locally).
