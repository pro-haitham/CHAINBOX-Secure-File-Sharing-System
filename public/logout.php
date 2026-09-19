<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';

start_secure_session();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && is_logged_in()) {
    verify_csrf($_POST['csrf_token'] ?? null);
    $user = current_user();
    log_audit_event(get_db_connection(), $user['id'], 'LOGOUT');
}

logout_user();
header('Location: login.php');
exit;
