<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/file_helpers.php';
require_once __DIR__ . '/../../includes/layout.php';

start_secure_session();
$user = require_role(['admin', 'moderator']);
$pdo = get_db_connection();

// --- Simple filtering ---
$actionFilter = $_GET['action'] ?? '';
$validActions = ['UPLOAD','DOWNLOAD','SHARE','UNSHARE','DELETE','PERMISSION_CHANGE',
                  'LOGIN_SUCCESS','LOGIN_FAILURE','LOGOUT','REGISTER','ACCESS_DENIED'];

// --- Pagination ---
$page    = max(1, (int) ($_GET['page'] ?? 1));
$perPage = 50;
$offset  = ($page - 1) * $perPage;

$where  = '';
$params = [];
if (in_array($actionFilter, $validActions, true)) {
    $where = 'WHERE al.action = :action';
    $params[':action'] = $actionFilter;
}

$countStmt = $pdo->prepare("SELECT COUNT(*) AS c FROM audit_logs al {$where}");
$countStmt->execute($params);
$totalRows = (int) $countStmt->fetch()['c'];
$totalPages = max(1, (int) ceil($totalRows / $perPage));

$sql = "SELECT al.*, u.username, f.original_name
        FROM audit_logs al
        LEFT JOIN users u ON u.id = al.user_id
        LEFT JOIN files f ON f.id = al.file_id
        {$where}
        ORDER BY al.timestamp DESC
        LIMIT :limit OFFSET :offset";

$stmt = $pdo->prepare($sql);
foreach ($params as $key => $value) {
    $stmt->bindValue($key, $value);
}
$stmt->bindValue(':limit', $perPage, PDO::PARAM_INT);
$stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$logs = $stmt->fetchAll();

$actionColors = [
    'UPLOAD'             => 'text-accent',
    'DOWNLOAD'           => 'text-ink',
    'SHARE'              => 'text-accent',
    'UNSHARE'            => 'text-warn',
    'DELETE'             => 'text-danger',
    'PERMISSION_CHANGE'  => 'text-warn',
    'LOGIN_SUCCESS'      => 'text-accent',
    'LOGIN_FAILURE'      => 'text-danger',
    'LOGOUT'             => 'text-muted',
    'REGISTER'           => 'text-accent',
    'ACCESS_DENIED'      => 'text-danger',
];

render_head('Audit log');
render_navbar($user);
?>

<main class="max-w-6xl mx-auto px-6 py-10">
    <div class="flex items-end justify-between mb-6 flex-wrap gap-4">
        <div>
            <h1 class="font-display text-2xl mb-1">Audit log</h1>
            <p class="text-muted text-sm"><?= number_format($totalRows) ?> events recorded</p>
        </div>

        <form method="get" class="flex items-center gap-2">
            <label for="action" class="text-sm text-muted">Filter</label>
            <select id="action" name="action" onchange="this.form.submit()"
                    class="bg-surface2 border border-border rounded px-3 py-1.5 text-sm focus-ring focus:border-accent outline-none">
                <option value="">All actions</option>
                <?php foreach ($validActions as $a): ?>
                    <option value="<?= $a ?>" <?= $actionFilter === $a ? 'selected' : '' ?>><?= $a ?></option>
                <?php endforeach; ?>
            </select>
        </form>
    </div>

    <div class="border border-border rounded overflow-hidden">
        <table class="w-full text-sm">
            <thead>
                <tr class="bg-surface text-muted text-left border-b border-border">
                    <th class="px-4 py-3 font-medium">Timestamp</th>
                    <th class="px-4 py-3 font-medium">User</th>
                    <th class="px-4 py-3 font-medium">Action</th>
                    <th class="px-4 py-3 font-medium">File</th>
                    <th class="px-4 py-3 font-medium">IP address</th>
                    <th class="px-4 py-3 font-medium">Details</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-border">
            <?php if (empty($logs)): ?>
                <tr><td colspan="6" class="px-4 py-8 text-center text-muted">No matching events.</td></tr>
            <?php endif; ?>
            <?php foreach ($logs as $log): ?>
                <tr class="hover:bg-surface2/50 transition-colors">
                    <td class="px-4 py-3 font-mono text-xs text-muted whitespace-nowrap"><?= htmlspecialchars(date('Y-m-d H:i:s', strtotime($log['timestamp'])), ENT_QUOTES, 'UTF-8') ?></td>
                    <td class="px-4 py-3"><?= htmlspecialchars($log['username'] ?? '(deleted user)', ENT_QUOTES, 'UTF-8') ?></td>
                    <td class="px-4 py-3">
                        <span class="font-mono text-xs <?= $actionColors[$log['action']] ?? 'text-muted' ?>"><?= htmlspecialchars($log['action'], ENT_QUOTES, 'UTF-8') ?></span>
                    </td>
                    <td class="px-4 py-3 text-muted"><?= htmlspecialchars($log['original_name'] ?? '—', ENT_QUOTES, 'UTF-8') ?></td>
                    <td class="px-4 py-3 font-mono text-xs text-muted"><?= htmlspecialchars($log['ip_address'], ENT_QUOTES, 'UTF-8') ?></td>
                    <td class="px-4 py-3 text-muted text-xs max-w-xs truncate" title="<?= htmlspecialchars((string) $log['details'], ENT_QUOTES, 'UTF-8') ?>">
                        <?= htmlspecialchars((string) ($log['details'] ?? ''), ENT_QUOTES, 'UTF-8') ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>

    <?php if ($totalPages > 1): ?>
        <div class="flex items-center justify-center gap-4 mt-6 text-sm">
            <?php if ($page > 1): ?>
                <a href="?page=<?= $page - 1 ?>&action=<?= urlencode($actionFilter) ?>" class="text-accent hover:underline focus-ring rounded">&larr; Newer</a>
            <?php endif; ?>
            <span class="text-muted font-mono text-xs">Page <?= $page ?> of <?= $totalPages ?></span>
            <?php if ($page < $totalPages): ?>
                <a href="?page=<?= $page + 1 ?>&action=<?= urlencode($actionFilter) ?>" class="text-accent hover:underline focus-ring rounded">Older &rarr;</a>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</main>
<?php render_footer(); ?>
