<?php
/**
 * includes/auth.php
 *
 * Session hardening, CSRF protection, login/logout helpers, and
 * role-based access control gates. Included by every page that requires
 * an authenticated session.
 */

declare(strict_types=1);

require_once __DIR__ . '/../config/database.php';

// ---------------------------------------------------------------------------
// Secure session bootstrap
// ---------------------------------------------------------------------------
function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443');

    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => $isHttps,   // only sent over HTTPS in production
        'httponly' => true,       // inaccessible to JavaScript
        'samesite' => 'Lax',      // mitigates CSRF via cross-site navigation
    ]);

    session_name('SFS_SESSID');
    session_start();

    // Absolute session lifetime + idle timeout enforcement.
    $now = time();
    $absoluteLimit = 8 * 3600;   // 8 hours max session life
    $idleLimit     = 30 * 60;    // 30 minutes idle timeout

    if (!isset($_SESSION['created_at'])) {
        $_SESSION['created_at'] = $now;
    } elseif ($now - $_SESSION['created_at'] > $absoluteLimit) {
        session_unset();
        session_destroy();
        session_start();
        $_SESSION['created_at'] = $now;
    }

    if (isset($_SESSION['last_activity']) && ($now - $_SESSION['last_activity'] > $idleLimit)) {
        session_unset();
        session_destroy();
        session_start();
        $_SESSION['created_at'] = $now;
    }
    $_SESSION['last_activity'] = $now;

    // Periodic session ID rotation to reduce fixation/hijack windows.
    if (!isset($_SESSION['last_regeneration'])) {
        $_SESSION['last_regeneration'] = $now;
    } elseif ($now - $_SESSION['last_regeneration'] > 300) { // every 5 minutes
        session_regenerate_id(true);
        $_SESSION['last_regeneration'] = $now;
    }
}

// ---------------------------------------------------------------------------
// CSRF protection
// ---------------------------------------------------------------------------
function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/** Renders a hidden input field carrying the CSRF token. */
function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') . '">';
}

/** Verifies a submitted token using timing-safe comparison; halts on failure. */
function verify_csrf(?string $submittedToken): void
{
    if (!$submittedToken || empty($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $submittedToken)) {
        http_response_code(403);
        die('Invalid or expired security token. Please refresh the page and try again.');
    }
}

// ---------------------------------------------------------------------------
// Authentication state helpers
// ---------------------------------------------------------------------------
function current_user(): ?array
{
    if (empty($_SESSION['user_id'])) {
        return null;
    }
    return [
        'id'       => (int) $_SESSION['user_id'],
        'username' => $_SESSION['username'] ?? '',
        'role'     => $_SESSION['role'] ?? 'user',
    ];
}

function is_logged_in(): bool
{
    return current_user() !== null;
}

/** Redirects to login.php if there is no authenticated session. */
function require_login(): array
{
    $user = current_user();
    if ($user === null) {
        $isAdminPage = str_contains(str_replace('\\', '/', $_SERVER['SCRIPT_NAME'] ?? ''), '/admin/');
        header('Location: ' . ($isAdminPage ? '../login.php' : 'login.php'));
        exit;
    }
    return $user;
}

/** Halts with 403 unless the current user's role is in $allowedRoles. */
function require_role(array $allowedRoles): array
{
    $user = require_login();
    if (!in_array($user['role'], $allowedRoles, true)) {
        log_audit_event(get_db_connection(), $user['id'], 'ACCESS_DENIED', null, 'role check: ' . implode(',', $allowedRoles));
        http_response_code(403);
        die('You do not have permission to access this page.');
    }
    return $user;
}

/** Logs a user in: regenerates the session ID to prevent fixation. */
function login_user(array $userRow): void
{
    session_regenerate_id(true);
    $_SESSION['user_id']            = (int) $userRow['id'];
    $_SESSION['username']           = $userRow['username'];
    $_SESSION['role']               = $userRow['role'];
    $_SESSION['created_at']         = time();
    $_SESSION['last_activity']      = time();
    $_SESSION['last_regeneration']  = time();
    $_SESSION['csrf_token']         = bin2hex(random_bytes(32));
}

function logout_user(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
}

// ---------------------------------------------------------------------------
// Shared: audit logging (kept here too so auth-related events can log
// before file_helpers.php is loaded on auth-only pages).
// ---------------------------------------------------------------------------
function log_audit_event(PDO $pdo, ?int $userId, string $action, ?int $fileId = null, ?string $details = null): void
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    $stmt = $pdo->prepare(
        'INSERT INTO audit_logs (user_id, action, file_id, ip_address, details) VALUES (:user_id, :action, :file_id, :ip, :details)'
    );
    $stmt->execute([
        ':user_id' => $userId,
        ':action'  => $action,
        ':file_id' => $fileId,
        ':ip'      => substr($ip, 0, 45),
        ':details' => $details !== null ? substr($details, 0, 500) : null,
    ]);
}
