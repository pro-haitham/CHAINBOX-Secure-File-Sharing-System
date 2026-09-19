<?php

declare(strict_types=1);

require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/layout.php';

start_secure_session();
$user = require_role(['admin', 'moderator']);
$pdo = get_db_connection();

$stats = [
    'users' => (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn(),
    'files' => (int) $pdo->query('SELECT COUNT(*) FROM files')->fetchColumn(),
    'shared' => (int) $pdo->query('SELECT COUNT(*) FROM file_permissions')->fetchColumn(),
    'events' => (int) $pdo->query('SELECT COUNT(*) FROM audit_logs')->fetchColumn(),
];

$recentStmt = $pdo->query(
    'SELECT al.action, al.details, al.timestamp, u.username
     FROM audit_logs al
     LEFT JOIN users u ON u.id = al.user_id
     ORDER BY al.timestamp DESC
     LIMIT 8'
);
$recentEvents = $recentStmt->fetchAll();

$actionColors = [
    'DELETE' => 'text-danger',
    'LOGIN_FAILURE' => 'text-danger',
    'ACCESS_DENIED' => 'text-danger',
    'UNSHARE' => 'text-warn',
    'PERMISSION_CHANGE' => 'text-warn',
];

render_head('Admin dashboard');
render_navbar($user);
?>

<main class="max-w-6xl mx-auto px-6 py-10 space-y-10">
    <div class="flex items-end justify-between gap-4 flex-wrap">
        <div>
            <p class="font-mono text-xs uppercase tracking-widest text-accent mb-2">Administration</p>
            <h1 class="font-display text-2xl mb-1">System overview</h1>
            <p class="text-muted text-sm">Monitor users, files, sharing activity, and security events.</p>
        </div>
        <a href="logs.php" class="border border-border rounded px-4 py-2 text-sm text-muted hover:text-ink hover:bg-surface2 transition-colors focus-ring">View audit log</a>
    </div>

    <section class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" aria-label="System statistics">
        <?php foreach ([
            ['label' => 'Registered users', 'value' => $stats['users']],
            ['label' => 'Stored files', 'value' => $stats['files']],
            ['label' => 'Active shares', 'value' => $stats['shared']],
            ['label' => 'Audit events', 'value' => $stats['events']],
        ] as $stat): ?>
            <div class="border border-border bg-surface rounded p-5">
                <p class="text-muted text-xs uppercase tracking-wide mb-3"><?= htmlspecialchars($stat['label'], ENT_QUOTES, 'UTF-8') ?></p>
                <p class="font-display text-3xl"><?= number_format($stat['value']) ?></p>
            </div>
        <?php endforeach; ?>
    </section>

    <section>
        <div class="flex items-center justify-between mb-4">
            <div>
                <h2 class="font-display text-lg">Recent activity</h2>
                <p class="text-muted text-sm mt-1">The latest events recorded by CHAINBOX.</p>
            </div>
            <a href="logs.php" class="text-accent text-sm hover:underline focus-ring rounded">All events</a>
        </div>

        <div class="border border-border rounded overflow-hidden">
            <table class="w-full text-sm">
                <thead>
                    <tr class="bg-surface text-muted text-left border-b border-border">
                        <th class="px-4 py-3 font-medium">Timestamp</th>
                        <th class="px-4 py-3 font-medium">User</th>
                        <th class="px-4 py-3 font-medium">Action</th>
                        <th class="px-4 py-3 font-medium">Details</th>
                    </tr>
                </thead>
                <tbody class="divide-y divide-border">
                <?php if (empty($recentEvents)): ?>
                    <tr><td colspan="4" class="px-4 py-8 text-center text-muted">No activity recorded yet.</td></tr>
                <?php endif; ?>
                <?php foreach ($recentEvents as $event): ?>
                    <tr class="hover:bg-surface2/50 transition-colors">
                        <td class="px-4 py-3 font-mono text-xs text-muted whitespace-nowrap"><?= htmlspecialchars(date('Y-m-d H:i:s', strtotime($event['timestamp'])), ENT_QUOTES, 'UTF-8') ?></td>
                        <td class="px-4 py-3"><?= htmlspecialchars($event['username'] ?? '(deleted user)', ENT_QUOTES, 'UTF-8') ?></td>
                        <td class="px-4 py-3"><span class="font-mono text-xs <?= $actionColors[$event['action']] ?? 'text-accent' ?>"><?= htmlspecialchars($event['action'], ENT_QUOTES, 'UTF-8') ?></span></td>
                        <td class="px-4 py-3 text-muted text-xs truncate max-w-md"><?= htmlspecialchars((string) ($event['details'] ?? ''), ENT_QUOTES, 'UTF-8') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </section>
</main>
<?php render_footer(); ?>