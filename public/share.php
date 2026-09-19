<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/file_helpers.php';

start_secure_session();
$user = require_login();
$pdo = get_db_connection();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: files.php');
    exit;
}

verify_csrf($_POST['csrf_token'] ?? null);

$fileId     = filter_input(INPUT_POST, 'file_id', FILTER_VALIDATE_INT);
$targetName = trim((string) ($_POST['target_username'] ?? ''));
$permType   = (string) ($_POST['permission_type'] ?? '');
$action     = (string) ($_POST['form_action'] ?? 'grant'); // 'grant' or 'revoke'

if (!$fileId) {
    header('Location: files.php?error=' . urlencode('Invalid file reference.'));
    exit;
}

$fileRow = get_file_record($pdo, $fileId);
if ($fileRow === null) {
    header('Location: files.php?error=' . urlencode('File not found.'));
    exit;
}

// Only the owner, an admin, or a moderator may manage sharing on a file —
// editors and viewers cannot re-share, matching the permission matrix.
require_file_permission($pdo, $user, $fileRow, 'share');

if (!in_array($permType, ['viewer', 'editor'], true) && $action === 'grant') {
    header('Location: files.php?error=' . urlencode('Invalid permission type.'));
    exit;
}

if ($targetName === '') {
    header('Location: files.php?error=' . urlencode('Please provide a username to share with.'));
    exit;
}

$targetStmt = $pdo->prepare('SELECT id, username FROM users WHERE username = :u');
$targetStmt->execute([':u' => $targetName]);
$target = $targetStmt->fetch();

if (!$target) {
    header('Location: files.php?error=' . urlencode('No user found with that username.'));
    exit;
}

if ((int) $target['id'] === (int) $fileRow['owner_id']) {
    header('Location: files.php?error=' . urlencode('The file owner already has full access.'));
    exit;
}

if ($action === 'revoke') {
    $del = $pdo->prepare('DELETE FROM file_permissions WHERE file_id = :f AND user_id = :u');
    $del->execute([':f' => $fileId, ':u' => $target['id']]);

    log_audit_event($pdo, $user['id'], 'PERMISSION_CHANGE', $fileId, "revoked access for user={$target['username']}");
    header('Location: files.php?success=' . urlencode('Access revoked for ' . $target['username'] . '.'));
    exit;
}

// Grant or update permission (upsert on the unique file_id+user_id key).
$stmt = $pdo->prepare(
    'INSERT INTO file_permissions (file_id, user_id, permission_type)
     VALUES (:f, :u, :p)
     ON DUPLICATE KEY UPDATE permission_type = VALUES(permission_type), granted_at = CURRENT_TIMESTAMP'
);
$stmt->execute([':f' => $fileId, ':u' => $target['id'], ':p' => $permType]);

log_audit_event($pdo, $user['id'], 'SHARE', $fileId, "granted {$permType} to user={$target['username']}");

header('Location: files.php?success=' . urlencode('Shared with ' . $target['username'] . ' as ' . $permType . '.'));
exit;
