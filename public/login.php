<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/layout.php';

start_secure_session();

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES      = 15;

$error   = null;
$success = isset($_GET['registered']) ? 'Account created. You can now sign in.' : null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf($_POST['csrf_token'] ?? null);

    $username = trim((string) ($_POST['username'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $pdo = get_db_connection();

    $stmt = $pdo->prepare('SELECT * FROM users WHERE username = :u1 OR email = :u2 LIMIT 1');
    $stmt->execute([':u1' => $username, ':u2' => $username]);
    $user = $stmt->fetch();

    // Always run password_verify against a real or dummy hash to keep
    // response timing consistent whether or not the account exists.
    $dummyHash = '$2y$12$usmR2N6E1B8kQeS9m2y8h.k3Kk1c8h9O0n1m8h9M2y8kQeS9m2y8h';
    $hashToCheck = $user['password_hash'] ?? $dummyHash;

    $isLocked = false;
    if ($user && !empty($user['locked_until']) && strtotime($user['locked_until']) > time()) {
        $isLocked = true;
    }

    if ($isLocked) {
        $error = 'This account is temporarily locked due to repeated failed attempts. Try again later.';
    } elseif ($user && password_verify($password, $hashToCheck)) {
        // Reset failed-attempt counter on success.
        $reset = $pdo->prepare('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = :id');
        $reset->execute([':id' => $user['id']]);

        login_user($user);
        log_audit_event($pdo, (int) $user['id'], 'LOGIN_SUCCESS');

        header('Location: dashboard.php');
        exit;
    } else {
        if ($user) {
            $attempts = (int) $user['failed_logins'] + 1;
            $lockUntil = null;
            if ($attempts >= MAX_FAILED_ATTEMPTS) {
                $lockUntil = date('Y-m-d H:i:s', time() + LOCKOUT_MINUTES * 60);
            }
            $upd = $pdo->prepare('UPDATE users SET failed_logins = :a, locked_until = :l WHERE id = :id');
            $upd->execute([':a' => $attempts, ':l' => $lockUntil, ':id' => $user['id']]);
            log_audit_event($pdo, (int) $user['id'], 'LOGIN_FAILURE');
        }
        $error = 'Invalid username or password.';
    }
}

render_head('Sign in');
?>
<div class="min-h-screen grid md:grid-cols-2">
    <section class="hidden md:flex flex-col justify-between bg-surface border-r border-border p-12">
        <div class="flex items-center gap-2.5">
            <span class="w-2 h-2 bg-accent rounded-full"></span>
            <span class="font-display font-semibold text-lg tracking-tight">CHAINBOX</span>
        </div>
        <div class="max-w-sm">
            <h1 class="font-display text-3xl leading-tight mb-4">Access, verified at every step.</h1>
            <p class="text-muted leading-relaxed">Role-based permissions, per-file sharing controls, and a full audit trail — built for teams that have to prove who touched what, and when.</p>
        </div>
        <div class="font-mono text-xs text-muted/60 space-y-1 leading-relaxed">
            <p>9f3c1a6e4b7d0f2a5c8e1b4d7f0a3c6e</p>
            <p>4c7f0a3e6b9d2f5a8c1e4b7d0f3a6c9e</p>
            <p>1e4b7d0f3a6c9e2b5d8f1a4c7e0b3d6f</p>
        </div>
    </section>

    <section class="flex items-center justify-center p-8">
        <div class="w-full max-w-sm">
            <h2 class="font-display text-2xl mb-1">Sign in</h2>
            <p class="text-muted text-sm mb-8">Welcome back. Enter your credentials to continue.</p>

            <?php render_flash($error, $success); ?>

            <form method="post" class="space-y-4 mt-6" novalidate>
                <?= csrf_field() ?>
                <div>
                    <label for="username" class="block text-sm text-muted mb-1.5">Username or email</label>
                    <input id="username" name="username" type="text" required autofocus
                           class="w-full bg-surface2 border border-border rounded px-3 py-2.5 text-sm focus-ring focus:border-accent outline-none">
                </div>
                <div>
                    <label for="password" class="block text-sm text-muted mb-1.5">Password</label>
                    <input id="password" name="password" type="password" required
                           class="w-full bg-surface2 border border-border rounded px-3 py-2.5 text-sm focus-ring focus:border-accent outline-none">
                </div>
                <button type="submit"
                        class="w-full bg-accent text-bg font-medium rounded px-4 py-2.5 mt-2 hover:bg-accentdim transition-colors focus-ring">
                    Sign in
                </button>
            </form>

            <p class="text-sm text-muted mt-6">Need an account?
                <a href="register.php" class="text-accent hover:underline focus-ring rounded">Create one</a>
            </p>
        </div>
    </section>
</div>
<?php render_footer(); ?>
