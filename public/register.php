<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/layout.php';

start_secure_session();

if (is_logged_in()) {
    header('Location: dashboard.php');
    exit;
}

$errors = [];
$old = ['username' => '', 'email' => ''];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    verify_csrf($_POST['csrf_token'] ?? null);

    $username = trim((string) ($_POST['username'] ?? ''));
    $email    = trim((string) ($_POST['email'] ?? ''));
    $password = (string) ($_POST['password'] ?? '');
    $confirm  = (string) ($_POST['password_confirm'] ?? '');

    $old['username'] = $username;
    $old['email']    = $email;

    if (!preg_match('/^[A-Za-z0-9_.-]{3,50}$/', $username)) {
        $errors[] = 'Username must be 3-50 characters (letters, numbers, . _ -).';
    }
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Please provide a valid email address.';
    }
    if (strlen($password) < 10) {
        $errors[] = 'Password must be at least 10 characters long.';
    }
    if (!preg_match('/[A-Z]/', $password) || !preg_match('/[0-9]/', $password)) {
        $errors[] = 'Password must include at least one uppercase letter and one number.';
    }
    if ($password !== $confirm) {
        $errors[] = 'Passwords do not match.';
    }

    if (empty($errors)) {
        $pdo = get_db_connection();

        $check = $pdo->prepare('SELECT id FROM users WHERE username = :u OR email = :e');
        $check->execute([':u' => $username, ':e' => $email]);
        if ($check->fetch()) {
            $errors[] = 'That username or email is already registered.';
        } else {
            $hash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
            $stmt = $pdo->prepare(
                'INSERT INTO users (username, email, password_hash, role) VALUES (:u, :e, :p, :r)'
            );
            // First registered account becomes admin automatically; all
            // subsequent registrations default to the least-privileged role.
            $countStmt = $pdo->query('SELECT COUNT(*) AS c FROM users');
            $isFirstUser = ((int) $countStmt->fetch()['c']) === 0;

            $stmt->execute([
                ':u' => $username,
                ':e' => $email,
                ':p' => $hash,
                ':r' => $isFirstUser ? 'admin' : 'user',
            ]);

            $newUserId = (int) $pdo->lastInsertId();
            log_audit_event($pdo, $newUserId, 'REGISTER', null, "username={$username}");

            header('Location: login.php?registered=1');
            exit;
        }
    }
}

render_head('Create account');
?>
<div class="min-h-screen grid md:grid-cols-2">
    <section class="hidden md:flex flex-col justify-between bg-surface border-r border-border p-12">
        <div class="flex items-center gap-2.5">
            <span class="w-2 h-2 bg-accent rounded-full"></span>
            <span class="font-display font-semibold text-lg tracking-tight">CHAINBOX</span>
        </div>
        <div class="max-w-sm">
            <h1 class="font-display text-3xl leading-tight mb-4">Every file gets a chain of custody.</h1>
            <p class="text-muted leading-relaxed">Uploads are fingerprinted, isolated from the web root, and every view, share, and deletion is written to an immutable audit trail.</p>
        </div>
        <div class="font-mono text-xs text-muted/60 space-y-1 leading-relaxed">
            <p>a41f9c2e0b8d4e6f1a5c3b7d9e2f0a4c</p>
            <p>7d2e5f8a1c4b6e9d0f3a2c5b8e1d4f7a</p>
            <p>2b5e8d1a4c7f0b3e6d9a2c5f8b1e4d7a</p>
        </div>
    </section>

    <section class="flex items-center justify-center p-8">
        <div class="w-full max-w-sm">
            <h2 class="font-display text-2xl mb-1">Create your account</h2>
            <p class="text-muted text-sm mb-8">Set up access to your team's secure workspace.</p>

            <?php if (!empty($errors)): ?>
                <div class="border border-danger/40 bg-danger/10 text-danger text-sm rounded px-4 py-3 mb-6 space-y-1">
                    <?php foreach ($errors as $err): ?>
                        <p><?= htmlspecialchars($err, ENT_QUOTES, 'UTF-8') ?></p>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <form method="post" class="space-y-4" novalidate>
                <?= csrf_field() ?>
                <div>
                    <label for="username" class="block text-sm text-muted mb-1.5">Username</label>
                    <input id="username" name="username" type="text" required maxlength="50"
                           value="<?= htmlspecialchars($old['username'], ENT_QUOTES, 'UTF-8') ?>"
                           class="w-full bg-surface2 border border-border rounded px-3 py-2.5 text-sm focus-ring focus:border-accent outline-none">
                </div>
                <div>
                    <label for="email" class="block text-sm text-muted mb-1.5">Email</label>
                    <input id="email" name="email" type="email" required maxlength="255"
                           value="<?= htmlspecialchars($old['email'], ENT_QUOTES, 'UTF-8') ?>"
                           class="w-full bg-surface2 border border-border rounded px-3 py-2.5 text-sm focus-ring focus:border-accent outline-none">
                </div>
                <div>
                    <label for="password" class="block text-sm text-muted mb-1.5">Password</label>
                    <input id="password" name="password" type="password" required minlength="10"
                           class="w-full bg-surface2 border border-border rounded px-3 py-2.5 text-sm focus-ring focus:border-accent outline-none">
                    <p class="text-xs text-muted/70 mt-1.5">At least 10 characters, with one uppercase letter and one number.</p>
                </div>
                <div>
                    <label for="password_confirm" class="block text-sm text-muted mb-1.5">Confirm password</label>
                    <input id="password_confirm" name="password_confirm" type="password" required minlength="10"
                           class="w-full bg-surface2 border border-border rounded px-3 py-2.5 text-sm focus-ring focus:border-accent outline-none">
                </div>
                <button type="submit"
                        class="w-full bg-accent text-bg font-medium rounded px-4 py-2.5 mt-2 hover:bg-accentdim transition-colors focus-ring">
                    Create account
                </button>
            </form>

            <p class="text-sm text-muted mt-6">Already have an account?
                <a href="login.php" class="text-accent hover:underline focus-ring rounded">Sign in</a>
            </p>
        </div>
    </section>
</div>
<?php render_footer(); ?>
