<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/file_helpers.php';
require_once __DIR__ . '/../includes/layout.php';

start_secure_session();
$user = require_login();
$pdo = get_db_connection();

$filesStmt = $pdo->prepare(
    'SELECT id, original_name, file_size, mime_type, created_at
     FROM files
     WHERE owner_id = :owner_id
     ORDER BY created_at DESC'
);
$filesStmt->execute([':owner_id' => $user['id']]);
$files = $filesStmt->fetchAll();

render_head('My files');
render_navbar($user);
render_flash($_GET['error'] ?? null, $_GET['success'] ?? null);
?>

<main class="max-w-6xl mx-auto px-6 py-10">
    <div class="flex items-end justify-between gap-4 mb-6">
        <div>
            <h1 class="font-display text-2xl">My files</h1>
            <p class="text-muted text-sm mt-1">Files you have uploaded.</p>
        </div>
        <a href="dashboard.php" class="text-accent text-sm hover:underline focus-ring rounded">Upload a file</a>
    </div>

    <?php if (empty($files)): ?>
        <div class="border border-dashed border-border rounded p-8 text-center text-muted text-sm">
            You haven't uploaded anything yet.
        </div>
    <?php else: ?>
        <div class="border border-border rounded overflow-hidden">
            <table class="w-full text-sm">
                <thead>
                    <tr class="bg-surface text-muted text-left border-b border-border">
                        <th class="px-4 py-3 font-medium">Name</th>
                        <th class="px-4 py-3 font-medium">Type</th>
                        <th class="px-4 py-3 font-medium">Size</th>
                        <th class="px-4 py-3 font-medium">Uploaded</th>
                        <th class="px-4 py-3 font-medium text-right">Actions</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-border">
                <?php foreach ($files as $file): ?>
                    <tr class="hover:bg-surface2/50 transition-colors">
                        <td class="px-4 py-3 text-ink">
                            <?= htmlspecialchars($file['original_name'], ENT_QUOTES, 'UTF-8') ?>
                        </td>
                        <td class="px-4 py-3 font-mono text-xs text-muted">
                            <?= htmlspecialchars($file['mime_type'], ENT_QUOTES, 'UTF-8') ?>
                        </td>
                        <td class="px-4 py-3 font-mono text-xs text-muted">
                            <?= htmlspecialchars(format_file_size((int) $file['file_size']), ENT_QUOTES, 'UTF-8') ?>
                        </td>
                        <td class="px-4 py-3 font-mono text-xs text-muted">
                            <?= htmlspecialchars(date('Y-m-d H:i', strtotime($file['created_at'])), ENT_QUOTES, 'UTF-8') ?>
                        </td>
                        <td class="px-4 py-3">
                            <div class="flex flex-wrap items-center justify-end gap-3">
                                <a href="download.php?id=<?= (int) $file['id'] ?>" class="text-accent hover:underline focus-ring rounded">Download</a>
                                <form action="share.php" method="post" class="flex flex-wrap items-center justify-end gap-2">
                                    <?= csrf_field() ?>
                                    <input type="hidden" name="file_id" value="<?= (int) $file['id'] ?>">
                                    <input type="hidden" name="form_action" value="grant">
                                    <label class="sr-only" for="target-username-<?= (int) $file['id'] ?>">Username to share with</label>
                                    <input id="target-username-<?= (int) $file['id'] ?>" type="text" name="target_username" required placeholder="Username"
                                           class="bg-bg border border-border rounded px-2.5 py-1.5 text-xs w-28 focus-ring focus:border-accent outline-none">
                                    <label class="sr-only" for="permission-<?= (int) $file['id'] ?>">Permission</label>
                                    <select id="permission-<?= (int) $file['id'] ?>" name="permission_type" class="bg-bg border border-border rounded px-2.5 py-1.5 text-xs focus-ring focus:border-accent outline-none">
                                        <option value="viewer">Viewer</option>
                                        <option value="editor">Editor</option>
                                    </select>
                                    <button type="submit" class="text-muted hover:text-ink transition-colors focus-ring rounded">Share</button>
                                </form>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</main>
<?php render_footer(); ?>
