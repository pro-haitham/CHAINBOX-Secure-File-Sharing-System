<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/file_helpers.php';

start_secure_session();
$user = require_login();
$pdo = get_db_connection();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: dashboard.php');
    exit;
}

verify_csrf($_POST['csrf_token'] ?? null);

$fileId = filter_input(INPUT_POST, 'file_id', FILTER_VALIDATE_INT);
if (!$fileId) {
    header('Location: dashboard.php?error=' . urlencode('Invalid file reference.'));
    exit;
}

$fileRow = get_file_record($pdo, $fileId);
if ($fileRow === null) {
    header('Location: dashboard.php?error=' . urlencode('File not found.'));
    exit;
}

// Only the owner, an admin, or a moderator may delete — editors/viewers cannot.
require_file_permission($pdo, $user, $fileRow, 'delete');

$absolutePath = resolve_safe_storage_path($fileRow['stored_name']);

$pdo->beginTransaction();
try {
    // file_permissions rows cascade-delete via FK; audit_logs.file_id is
    // set to NULL on delete so the historical record is preserved.
    $stmt = $pdo->prepare('DELETE FROM files WHERE id = :id');
    $stmt->execute([':id' => $fileId]);

    log_audit_event($pdo, $user['id'], 'DELETE', null, "deleted file_id={$fileId} original_name={$fileRow['original_name']}");

    $pdo->commit();
} catch (Throwable $e) {
    $pdo->rollBack();
    error_log('[DELETE ERROR] ' . $e->getMessage());
    header('Location: dashboard.php?error=' . urlencode('Could not delete the file. Please try again.'));
    exit;
}

// Remove the physical artifact only after the DB transaction is committed.
if ($absolutePath !== null && is_file($absolutePath)) {
    @unlink($absolutePath);
}

header('Location: dashboard.php?success=' . urlencode('File deleted.'));
exit;
