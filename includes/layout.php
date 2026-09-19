<?php
/**
 * includes/layout.php
 *
 * Shared chrome for every public-facing page: <head>, design tokens,
 * top navigation, and the closing tags. Keeping markup here avoids
 * duplicating the Tailwind config / font imports on every page.
 */

declare(strict_types=1);

function render_head(string $title): void
{
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title><?= htmlspecialchars($title, ENT_QUOTES, 'UTF-8') ?> · CHAINBOX</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
        <script>
            tailwind.config = {
                theme: {
                    extend: {
                        colors: {
                            bg:        '#0D1117',
                            surface:   '#131A22',
                            surface2:  '#1B242E',
                            border:    '#26313C',
                            ink:       '#E6EDF3',
                            muted:     '#8B98A5',
                            accent:    '#3DDC97',
                            accentdim: '#2A9D74',
                            danger:    '#E5484D',
                            warn:      '#D4A72C',
                        },
                        fontFamily: {
                            display: ['"Space Grotesk"', 'sans-serif'],
                            sans: ['Inter', 'sans-serif'],
                            mono: ['"JetBrains Mono"', 'monospace'],
                        },
                        borderRadius: { DEFAULT: '4px' },
                    }
                }
            }
        </script>
        <style>
            body { background-color: #0D1117; }
            ::selection { background-color: #3DDC97; color: #0D1117; }
            .focus-ring:focus-visible { outline: 2px solid #3DDC97; outline-offset: 2px; }
            @media (prefers-reduced-motion: reduce) {
                * { animation: none !important; transition: none !important; }
            }
        </style>
    </head>
    <body class="bg-bg text-ink font-sans antialiased min-h-screen">
    <?php
}

/** Top navigation bar shown on every authenticated page. */
function render_navbar(array $user): void
{
    $isPrivileged = in_array($user['role'], ['admin', 'moderator'], true);
    $isAdminPage = str_contains(str_replace('\\', '/', $_SERVER['SCRIPT_NAME'] ?? ''), '/admin/');
    $dashboardHref = $isAdminPage ? '../dashboard.php' : 'dashboard.php';
    $filesHref = $isAdminPage ? '../files.php' : 'files.php';
    $adminDashboardHref = $isAdminPage ? 'dashboard.php' : 'admin/dashboard.php';
    $logsHref = $isAdminPage ? 'logs.php' : 'admin/logs.php';
    $logoutHref = $isAdminPage ? '../logout.php' : 'logout.php';
    ?>
    <header class="border-b border-border bg-surface">
        <div class="max-w-6xl mx-auto px-6 h-16 flex items-center justify-between">
            <a href="<?= $dashboardHref ?>" class="flex items-center gap-2.5 focus-ring rounded">
                <span class="w-2 h-2 bg-accent rounded-full"></span>
                <span class="font-display font-semibold text-lg tracking-tight">CHAINBOX</span>
            </a>
            <nav class="flex items-center gap-6 text-sm">
                <a href="<?= $filesHref ?>" class="text-muted hover:text-ink transition-colors focus-ring rounded">Files</a>
                <?php if ($isPrivileged): ?>
                    <a href="<?= $adminDashboardHref ?>" class="text-muted hover:text-ink transition-colors focus-ring rounded">Admin</a>
                    <a href="<?= $logsHref ?>" class="text-muted hover:text-ink transition-colors focus-ring rounded">Audit log</a>
                <?php endif; ?>
                <span class="h-4 w-px bg-border"></span>
                <div class="flex items-center gap-2 text-muted">
                    <span class="text-ink font-medium"><?= htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') ?></span>
                    <span class="font-mono text-xs px-1.5 py-0.5 border border-border rounded text-muted uppercase"><?= htmlspecialchars($user['role'], ENT_QUOTES, 'UTF-8') ?></span>
                </div>
                <form action="<?= $logoutHref ?>" method="post" class="inline">
                    <?= csrf_field() ?>
                    <button type="submit" class="text-muted hover:text-danger transition-colors focus-ring rounded">Log out</button>
                </form>
            </nav>
        </div>
    </header>
    <?php
}

/** Renders a dismissible-looking flash message block from a query flag. */
function render_flash(?string $error, ?string $success): void
{
    if ($error): ?>
        <div class="max-w-6xl mx-auto px-6 mt-6">
            <div class="border border-danger/40 bg-danger/10 text-danger text-sm rounded px-4 py-3">
                <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
            </div>
        </div>
    <?php endif;
    if ($success): ?>
        <div class="max-w-6xl mx-auto px-6 mt-6">
            <div class="border border-accent/40 bg-accent/10 text-accent text-sm rounded px-4 py-3">
                <?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?>
            </div>
        </div>
    <?php endif;
}

function render_footer(): void
{
    ?>
    </body>
    </html>
    <?php
}
