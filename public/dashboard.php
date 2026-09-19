<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/file_helpers.php';
require_once __DIR__ . '/../includes/layout.php';

start_secure_session();
$user = require_login();
$pdo = get_db_connection();

$error   = $_GET['error'] ?? null;
$success = $_GET['success'] ?? null;

// Files owned by the current user.
$ownedStmt = $pdo->prepare(
    'SELECT * FROM files WHERE owner_id = :uid ORDER BY created_at DESC'
);
$ownedStmt->execute([':uid' => $user['id']]);
$ownedFiles = $ownedStmt->fetchAll();

// Files shared with the current user (explicit permission grants).
$sharedStmt = $pdo->prepare(
    'SELECT f.*, fp.permission_type, u.username AS owner_username
     FROM files f
     INNER JOIN file_permissions fp ON fp.file_id = f.id
     INNER JOIN users u ON u.id = f.owner_id
     WHERE fp.user_id = :uid
     ORDER BY f.created_at DESC'
);
$sharedStmt->execute([':uid' => $user['id']]);
$sharedFiles = $sharedStmt->fetchAll();

// For each owned file, fetch its current permission grants (for the share panel).
$permsByFile = [];
if (!empty($ownedFiles)) {
    $ids = array_column($ownedFiles, 'id');
    $placeholders = implode(',', array_fill(0, count($ids), '?'));
    $permStmt = $pdo->prepare(
        "SELECT fp.file_id, fp.permission_type, u.username
         FROM file_permissions fp
         INNER JOIN users u ON u.id = fp.user_id
         WHERE fp.file_id IN ({$placeholders})
         ORDER BY u.username ASC"
    );
    $permStmt->execute($ids);
    foreach ($permStmt->fetchAll() as $row) {
        $permsByFile[$row['file_id']][] = $row;
    }
}

render_head('My files');
render_navbar($user);
render_flash($error, $success);
?>

<main class="max-w-6xl mx-auto px-6 py-10 space-y-12">

    <!-- Upload -->
    <section class="border border-border bg-surface rounded p-6">
        <h2 class="font-display text-lg mb-1">Upload a file</h2>
        <p class="text-muted text-sm mb-5">Accepted types: PDF, PNG, JPG, DOCX, ZIP — up to 10 MB. Every file is fingerprinted and content-verified before it's stored.</p>
        <form action="upload.php" method="post" enctype="multipart/form-data" class="flex flex-col sm:flex-row gap-3">
            <?= csrf_field() ?>
            <input type="file" name="file" required accept=".pdf,.png,.jpg,.jpeg,.docx,.zip"
                   class="flex-1 text-sm text-muted file:mr-4 file:py-2 file:px-4 file:rounded file:border file:border-border file:bg-surface2 file:text-ink file:text-sm hover:file:bg-border/40 file:cursor-pointer focus-ring rounded">
            <button type="submit"
                    class="bg-accent text-bg font-medium rounded px-5 py-2.5 text-sm hover:bg-accentdim transition-colors focus-ring whitespace-nowrap">
                Upload file
            </button>
        </form>
    </section>

    <!-- My files -->
    <section>
        <h2 class="font-display text-lg mb-4">My files <span class="text-muted font-sans text-sm font-normal">(<?= count($ownedFiles) ?>)</span></h2>

        <?php if (empty($ownedFiles)): ?>
            <div class="border border-dashed border-border rounded p-8 text-center text-muted text-sm">
                You haven't uploaded anything yet. Files you upload will appear here.
            </div>
        <?php else: ?>
            <div class="border border-border rounded overflow-hidden">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="bg-surface text-muted text-left border-b border-border">
                            <th class="px-4 py-3 font-medium">Name</th>
                            <th class="px-4 py-3 font-medium">Size</th>
                            <th class="px-4 py-3 font-medium">Uploaded</th>
                            <th class="px-4 py-3 font-medium">Shared with</th>
                            <th class="px-4 py-3 font-medium text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-border">
                    <?php foreach ($ownedFiles as $file): ?>
                        <tr class="hover:bg-surface2/50 transition-colors">
                            <td class="px-4 py-3">
                                <span class="text-ink"><?= htmlspecialchars($file['original_name'], ENT_QUOTES, 'UTF-8') ?></span>
                            </td>
                            <td class="px-4 py-3 font-mono text-xs text-muted"><?= htmlspecialchars(format_file_size((int) $file['file_size']), ENT_QUOTES, 'UTF-8') ?></td>
                            <td class="px-4 py-3 font-mono text-xs text-muted"><?= htmlspecialchars(date('Y-m-d H:i', strtotime($file['created_at'])), ENT_QUOTES, 'UTF-8') ?></td>
                            <td class="px-4 py-3">
                                <?php $grants = $permsByFile[$file['id']] ?? []; ?>
                                <?php if (empty($grants)): ?>
                                    <span class="text-muted/60 text-xs">Private</span>
                                <?php else: ?>
                                    <div class="flex flex-wrap gap-1.5">
                                        <?php foreach ($grants as $g): ?>
                                            <span class="inline-flex items-center gap-1 text-xs border border-border rounded px-2 py-0.5 text-muted">
                                                <?= htmlspecialchars($g['username'], ENT_QUOTES, 'UTF-8') ?>
                                                <span class="text-muted/60">· <?= htmlspecialchars($g['permission_type'], ENT_QUOTES, 'UTF-8') ?></span>
                                            </span>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endif; ?>
                            </td>
                            <td class="px-4 py-3">
                                <div class="flex items-center justify-end gap-3 text-xs">
                                    <a href="download.php?id=<?= (int) $file['id'] ?>" class="text-accent hover:underline focus-ring rounded">Download</a>
                                    <button type="button" onclick="document.getElementById('share-modal-<?= (int) $file['id'] ?>').classList.remove('hidden')"
                                            class="text-muted hover:text-ink transition-colors focus-ring rounded">Share</button>
                                    <form action="delete.php" method="post" onsubmit="return confirm('Delete this file permanently? This cannot be undone.');" class="inline">
                                        <?= csrf_field() ?>
                                        <input type="hidden" name="file_id" value="<?= (int) $file['id'] ?>">
                                        <button type="submit" class="text-danger hover:underline focus-ring rounded">Delete</button>
                                    </form>
                                </div>
                            </td>
                        </tr>

                        <!-- Share modal for this file -->
                        <tr id="share-modal-<?= (int) $file['id'] ?>" class="hidden">
                            <td colspan="5" class="bg-surface2 px-4 py-4 border-t border-border">
                                <div class="max-w-md">
                                    <h3 class="text-sm font-medium mb-3">Share "<?= htmlspecialchars($file['original_name'], ENT_QUOTES, 'UTF-8') ?>"</h3>
                                    <form action="share.php" method="post" class="flex flex-wrap items-end gap-2">
                                        <?= csrf_field() ?>
                                        <input type="hidden" name="file_id" value="<?= (int) $file['id'] ?>">
                                        <input type="hidden" name="form_action" value="grant">
                                        <div>
                                            <label class="block text-xs text-muted mb-1">Username</label>
                                            <input type="text" name="target_username" required
                                                   class="bg-bg border border-border rounded px-2.5 py-1.5 text-sm w-40 focus-ring focus:border-accent outline-none">
                                        </div>
                                        <div>
                                            <label class="block text-xs text-muted mb-1">Access</label>
                                            <select name="permission_type" class="bg-bg border border-border rounded px-2.5 py-1.5 text-sm focus-ring focus:border-accent outline-none">
                                                <option value="viewer">Viewer</option>
                                                <option value="editor">Editor</option>
                                            </select>
                                        </div>
                                        <button type="submit" class="bg-accent text-bg text-sm font-medium rounded px-3 py-1.5 hover:bg-accentdim transition-colors focus-ring">Grant access</button>
                                        <button type="button" onclick="document.getElementById('share-modal-<?= (int) $file['id'] ?>').classList.add('hidden')"
                                                class="text-muted text-sm hover:text-ink transition-colors focus-ring rounded px-2 py-1.5">Close</button>
                                    </form>

                                    <?php if (!empty($grants)): ?>
                                        <div class="mt-4 pt-4 border-t border-border space-y-2">
                                            <?php foreach ($grants as $g): ?>
                                                <div class="flex items-center justify-between text-sm">
                                                    <span class="text-muted"><?= htmlspecialchars($g['username'], ENT_QUOTES, 'UTF-8') ?> — <?= htmlspecialchars($g['permission_type'], ENT_QUOTES, 'UTF-8') ?></span>
                                                    <form action="share.php" method="post">
                                                        <?= csrf_field() ?>
                                                        <input type="hidden" name="file_id" value="<?= (int) $file['id'] ?>">
                                                        <input type="hidden" name="form_action" value="revoke">
                                                        <input type="hidden" name="target_username" value="<?= htmlspecialchars($g['username'], ENT_QUOTES, 'UTF-8') ?>">
                                                        <button type="submit" class="text-danger text-xs hover:underline focus-ring rounded">Revoke</button>
                                                    </form>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </section>

    <!-- Shared with me -->
    <section>
        <h2 class="font-display text-lg mb-4">Shared with me <span class="text-muted font-sans text-sm font-normal">(<?= count($sharedFiles) ?>)</span></h2>

        <?php if (empty($sharedFiles)): ?>
            <div class="border border-dashed border-border rounded p-8 text-center text-muted text-sm">
                Nothing has been shared with you yet.
            </div>
        <?php else: ?>
            <div class="border border-border rounded overflow-hidden">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="bg-surface text-muted text-left border-b border-border">
                            <th class="px-4 py-3 font-medium">Name</th>
                            <th class="px-4 py-3 font-medium">Owner</th>
                            <th class="px-4 py-3 font-medium">Access</th>
                            <th class="px-4 py-3 font-medium">Size</th>
                            <th class="px-4 py-3 font-medium text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-border">
                    <?php foreach ($sharedFiles as $file): ?>
                        <tr class="hover:bg-surface2/50 transition-colors">
                            <td class="px-4 py-3 text-ink"><?= htmlspecialchars($file['original_name'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td class="px-4 py-3 text-muted"><?= htmlspecialchars($file['owner_username'], ENT_QUOTES, 'UTF-8') ?></td>
                            <td class="px-4 py-3">
                                <span class="text-xs border border-border rounded px-2 py-0.5 text-muted"><?= htmlspecialchars($file['permission_type'], ENT_QUOTES, 'UTF-8') ?></span>
                            </td>
                            <td class="px-4 py-3 font-mono text-xs text-muted"><?= htmlspecialchars(format_file_size((int) $file['file_size']), ENT_QUOTES, 'UTF-8') ?></td>
                            <td class="px-4 py-3 text-right">
                                <a href="download.php?id=<?= (int) $file['id'] ?>" class="text-accent text-xs hover:underline focus-ring rounded">Download</a>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </section>

</main>
<?php render_footer(); ?>
