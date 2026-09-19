<?php

declare(strict_types=1);

require_once __DIR__ . '/../includes/auth.php';

start_secure_session();

header('Location: ' . (is_logged_in() ? 'dashboard.php' : 'login.php'));
exit;
