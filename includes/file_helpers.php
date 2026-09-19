<?php
/**
 * includes/file_helpers.php
 *
 * Everything related to file upload validation, safe on-disk naming,
 * path-traversal-proof path resolution, and the file-level RBAC matrix
 * (Owner / Editor / Viewer, plus Admin / Moderator override).
 */

declare(strict_types=1);

require_once __DIR__ . '/auth.php';

// ---------------------------------------------------------------------------
// Storage location — OUTSIDE the public web root.
// public/ is the document root; storage/ is a sibling directory, so it is
// never reachable via any HTTP URL regardless of web server configuration.
// ---------------------------------------------------------------------------
define('SFS_STORAGE_ROOT', realpath(__DIR__ . '/../storage/uploads'));

define('SFS_MAX_FILE_SIZE', 10 * 1024 * 1024); // 10 MB

/**
 * Whitelist of accepted extensions mapped to the exact MIME type(s)
 * finfo_file() is expected to report for genuine files of that type.
 * $_FILES[...]['type'] (client-supplied) is NEVER trusted or consulted.
 */
const SFS_ALLOWED_TYPES = [
    'pdf'  => ['application/pdf'],
    'png'  => ['image/png'],
    'jpg'  => ['image/jpeg'],
    'jpeg' => ['image/jpeg'],
    'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
    'zip'  => ['application/zip', 'application/x-zip-compressed'],
];

// ---------------------------------------------------------------------------
// Upload validation
// ---------------------------------------------------------------------------

/**
 * Validates an entry from $_FILES against size limits and a strict,
 * server-side MIME whitelist verified with finfo_file() on the actual
 * uploaded bytes (never trusting the client-provided type or extension
 * alone).
 *
 * @return array{ok:bool, error?:string, ext?:string, mime?:string}
 */
function validate_uploaded_file(array $file): array
{
    if (!isset($file['error']) || is_array($file['error'])) {
        return ['ok' => false, 'error' => 'Malformed upload request.'];
    }

    switch ($file['error']) {
        case UPLOAD_ERR_OK:
            break;
        case UPLOAD_ERR_NO_FILE:
            return ['ok' => false, 'error' => 'No file was selected.'];
        case UPLOAD_ERR_INI_SIZE:
        case UPLOAD_ERR_FORM_SIZE:
            return ['ok' => false, 'error' => 'File exceeds the maximum allowed size.'];
        default:
            return ['ok' => false, 'error' => 'Upload failed (error code ' . (int) $file['error'] . ').'];
    }

    // Reject anything that is not a genuine HTTP upload (blocks manipulated paths).
    if (!is_uploaded_file($file['tmp_name'])) {
        return ['ok' => false, 'error' => 'Invalid upload source.'];
    }

    if ($file['size'] <= 0 || $file['size'] > SFS_MAX_FILE_SIZE) {
        return ['ok' => false, 'error' => 'File must be between 1 byte and 10 MB.'];
    }

    // Server-side, content-based MIME detection — the only source of truth.
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    if ($finfo === false) {
        return ['ok' => false, 'error' => 'Server could not inspect file contents.'];
    }
    $detectedMime = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    if ($detectedMime === false) {
        return ['ok' => false, 'error' => 'Could not determine file type.'];
    }

    // Find an allowed extension whose whitelist contains the detected MIME.
    $extFromName = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $matchedExt  = null;

    if (isset(SFS_ALLOWED_TYPES[$extFromName]) && in_array($detectedMime, SFS_ALLOWED_TYPES[$extFromName], true)) {
        $matchedExt = $extFromName;
    } else {
        // Extension was missing/wrong — fall back to matching purely by
        // detected content type against the whitelist.
        foreach (SFS_ALLOWED_TYPES as $ext => $mimes) {
            if (in_array($detectedMime, $mimes, true)) {
                $matchedExt = $ext;
                break;
            }
        }
    }

    if ($matchedExt === null) {
        return ['ok' => false, 'error' => 'File type not allowed. Permitted types: pdf, png, jpg, docx, zip.'];
    }

    return ['ok' => true, 'ext' => $matchedExt, 'mime' => $detectedMime];
}

/** Generates a cryptographically random, collision-resistant on-disk filename. */
function generate_stored_filename(string $extension): string
{
    return bin2hex(random_bytes(16)) . '.' . preg_replace('/[^a-z0-9]/', '', strtolower($extension));
}

// ---------------------------------------------------------------------------
// Path traversal prevention
// ---------------------------------------------------------------------------

/**
 * Resolves a stored filename to an absolute path that is GUARANTEED to sit
 * inside SFS_STORAGE_ROOT, or returns null if it does not. Uses basename()
 * to strip any directory component the caller might have injected, then
 * realpath() to canonicalize and verify final placement, defeating
 * '../', symlink, and null-byte style traversal attempts.
 */
function resolve_safe_storage_path(string $storedName): ?string
{
    $safeName = basename($storedName); // strips any path segments entirely

    if ($safeName === '' || $safeName !== $storedName) {
        // The name should never have contained path segments in the first
        // place — if basename() changed it, treat as tampering.
        return null;
    }

    $candidate = SFS_STORAGE_ROOT . DIRECTORY_SEPARATOR . $safeName;

    // realpath() fails (returns false) for non-existent paths, which is
    // also the correct outcome for a bogus/deleted file reference.
    $resolvedCandidate = realpath($candidate);
    if ($resolvedCandidate === false) {
        return null;
    }

    // Final containment check: resolved path must start with the storage
    // root followed by the separator (prevents "/uploads-evil" siblings).
    if (strpos($resolvedCandidate, SFS_STORAGE_ROOT . DIRECTORY_SEPARATOR) !== 0) {
        return null;
    }

    return $resolvedCandidate;
}

// ---------------------------------------------------------------------------
// Role-Based Access Control (RBAC) — file level
// ---------------------------------------------------------------------------

/** True if the user holds a global override role (can act on any file). */
function is_privileged_role(string $role): bool
{
    return in_array($role, ['admin', 'moderator'], true);
}

/** Fetches a file row by ID, or null if it does not exist. */
function get_file_record(PDO $pdo, int $fileId): ?array
{
    $stmt = $pdo->prepare('SELECT * FROM files WHERE id = :id');
    $stmt->execute([':id' => $fileId]);
    $row = $stmt->fetch();
    return $row ?: null;
}

/** Fetches the permission_type a specific user holds on a file, if any. */
function get_user_file_permission(PDO $pdo, int $fileId, int $userId): ?string
{
    $stmt = $pdo->prepare('SELECT permission_type FROM file_permissions WHERE file_id = :f AND user_id = :u');
    $stmt->execute([':f' => $fileId, ':u' => $userId]);
    $row = $stmt->fetch();
    return $row ? $row['permission_type'] : null;
}

/**
 * Central permission gate.
 *
 * @param string $action one of: 'view', 'download', 'edit', 'delete', 'share'
 */
function user_can(PDO $pdo, array $user, array $fileRow, string $action): bool
{
    // Admins and moderators can act on any file, for any action.
    if (is_privileged_role($user['role'])) {
        return true;
    }

    // The owner can do everything with their own file.
    if ((int) $fileRow['owner_id'] === (int) $user['id']) {
        return true;
    }

    $permission = get_user_file_permission($pdo, (int) $fileRow['id'], (int) $user['id']);

    switch ($action) {
        case 'view':
        case 'download':
            // Viewer or Editor permission both grant read access.
            return in_array($permission, ['viewer', 'editor'], true);
        case 'edit':
            return $permission === 'editor';
        case 'delete':
        case 'share':
            // Only the owner (checked above) or an Admin/Moderator may
            // delete a file or manage its sharing — editors cannot.
            return false;
        default:
            return false;
    }
}

/** Convenience wrapper: enforces a permission or halts with 403 + audit log. */
function require_file_permission(PDO $pdo, array $user, array $fileRow, string $action): void
{
    if (!user_can($pdo, $user, $fileRow, $action)) {
        log_audit_event($pdo, $user['id'], 'ACCESS_DENIED', (int) $fileRow['id'], "action={$action}");
        http_response_code(403);
        die('You do not have permission to perform this action on this file.');
    }
}

/** Human-friendly file size formatting for the UI. */
function format_file_size(int $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    $size = (float) $bytes;
    while ($size >= 1024 && $i < count($units) - 1) {
        $size /= 1024;
        $i++;
    }
    return round($size, $i === 0 ? 0 : 1) . ' ' . $units[$i];
}
