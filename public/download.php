<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/file_helpers.php';

start_secure_session();
$user = require_login();
$pdo = get_db_connection();

$fileId = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if (!$fileId) {
    http_response_code(400);
    die('Invalid file reference.');
}

$fileRow = get_file_record($pdo, $fileId);
if ($fileRow === null) {
    http_response_code(404);
    die('File not found.');
}

// Central RBAC gate — halts with 403 (and logs ACCESS_DENIED) if not allowed.
require_file_permission($pdo, $user, $fileRow, 'download');

// Path-traversal-proof resolution: basename() + realpath() containment
// check against the storage root, never trusting the DB value blindly.
$absolutePath = resolve_safe_storage_path($fileRow['stored_name']);
if ($absolutePath === null || !is_file($absolutePath)) {
    error_log('[DOWNLOAD ERROR] Missing or unsafe file on disk for file_id=' . $fileId);
    http_response_code(404);
    die('The requested file could not be located.');
}

log_audit_event($pdo, $user['id'], 'DOWNLOAD', $fileId, "original_name={$fileRow['original_name']}");

// Clear any buffered output that could corrupt the binary stream.
while (ob_get_level() > 0) {
    ob_end_clean();
}

$downloadName = str_replace(['"', "\r", "\n"], '', $fileRow['original_name']);

header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream'); // forces download rather than inline rendering
header('Content-Disposition: attachment; filename="' . $downloadName . '"');
header('Content-Transfer-Encoding: binary');
header('Content-Length: ' . filesize($absolutePath));
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store, no-cache, must-revalidate');
header('Pragma: no-cache');

readfile($absolutePath);
exit;
