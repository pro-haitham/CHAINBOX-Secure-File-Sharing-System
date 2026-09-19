<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/file_helpers.php';

start_secure_session();
$user = require_login();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: dashboard.php');
    exit;
}

verify_csrf($_POST['csrf_token'] ?? null);

$pdo = get_db_connection();

if (empty($_FILES['file'])) {
    header('Location: dashboard.php?error=' . urlencode('No file was submitted.'));
    exit;
}

$validation = validate_uploaded_file($_FILES['file']);

if (!$validation['ok']) {
    header('Location: dashboard.php?error=' . urlencode($validation['error']));
    exit;
}

if (!is_dir(SFS_STORAGE_ROOT) || !is_writable(SFS_STORAGE_ROOT)) {
    error_log('[UPLOAD ERROR] Storage directory missing or not writable: ' . SFS_STORAGE_ROOT);
    header('Location: dashboard.php?error=' . urlencode('Server storage is unavailable. Contact an administrator.'));
    exit;
}

$storedName   = generate_stored_filename($validation['ext']);
$destination  = SFS_STORAGE_ROOT . DIRECTORY_SEPARATOR . $storedName;

// Defense in depth: confirm the freshly-built destination truly resolves
// inside the storage root before we ever write to disk.
$destinationParent = realpath(dirname($destination));
if ($destinationParent !== SFS_STORAGE_ROOT) {
    error_log('[UPLOAD ERROR] Destination path failed containment check.');
    header('Location: dashboard.php?error=' . urlencode('Internal error while storing the file.'));
    exit;
}

if (!move_uploaded_file($_FILES['file']['tmp_name'], $destination)) {
    error_log('[UPLOAD ERROR] move_uploaded_file failed for ' . $destination);
    header('Location: dashboard.php?error=' . urlencode('Could not save the uploaded file.'));
    exit;
}

chmod($destination, 0640); // owner read/write, group read, no world access, not executable

$originalName = basename($_FILES['file']['name']); // strip any path info from the client-supplied name

try {
    $stmt = $pdo->prepare(
        'INSERT INTO files (original_name, stored_name, file_size, mime_type, owner_id)
         VALUES (:name, :stored, :size, :mime, :owner)'
    );
    $stmt->execute([
        ':name'   => $originalName,
        ':stored' => $storedName,
        ':size'   => (int) $_FILES['file']['size'],
        ':mime'   => $validation['mime'],
        ':owner'  => $user['id'],
    ]);
    $fileId = (int) $pdo->lastInsertId();

    log_audit_event($pdo, $user['id'], 'UPLOAD', $fileId, "original_name={$originalName}");
} catch (Throwable $e) {
    // Roll back the on-disk artifact if the DB write failed, to avoid
    // orphaned files with no ownership/permission record.
    @unlink($destination);
    error_log('[UPLOAD ERROR] DB insert failed: ' . $e->getMessage());
    header('Location: dashboard.php?error=' . urlencode('Could not record the upload. Please try again.'));
    exit;
}

header('Location: files.php?success=' . urlencode('File uploaded successfully.'));
exit;
