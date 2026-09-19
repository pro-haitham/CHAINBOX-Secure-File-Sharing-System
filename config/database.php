<?php
/**
 * config/database.php
 *
 * Central PDO connection factory. This file lives OUTSIDE the public web
 * root (public/) and is only ever reached via require_once from PHP,
 * never directly over HTTP.
 *
 * Credentials are read from environment variables when available, with
 * local fallbacks for development. In production, set real environment
 * variables (e.g. via your web server config or a .env loader) and never
 * commit real credentials to source control.
 */

declare(strict_types=1);

// ---------------------------------------------------------------------------
// Environment-driven configuration (override via real env vars in prod)
// ---------------------------------------------------------------------------
function load_local_env(): void
{
    $envFile = dirname(__DIR__) . DIRECTORY_SEPARATOR . '.env';
    if (!is_readable($envFile)) {
        return;
    }

    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return;
    }

    foreach ($lines as $line) {
        $trimmed = trim($line);
        if ($trimmed === '' || str_starts_with($trimmed, '#')) {
            continue;
        }

        [$name, $value] = array_pad(explode('=', $trimmed, 2), 2, '');
        $name = trim($name);
        $value = trim($value);

        if ($name === '' || ($value === '' && getenv($name) !== false)) {
            continue;
        }

        $hasValue = getenv($name) !== false || isset($_ENV[$name]) || isset($_SERVER[$name]);
        if (!$hasValue) {
            putenv($name . '=' . $value);
            $_ENV[$name] = $value;
            $_SERVER[$name] = $value;
        }
    }
}

function env_or(string $key, string $default): string
{
    $value = getenv($key);
    if ($value === false || $value === '') {
        $value = $_ENV[$key] ?? $_SERVER[$key] ?? false;
    }
    return ($value !== false && $value !== '') ? (string) $value : $default;
}

load_local_env();

/**
 * Returns a shared PDO instance connected to the application database.
 * Uses a static local instance so repeated calls within one request
 * reuse the same connection instead of opening new ones.
 */
function get_db_connection(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $host    = env_or('DB_HOST', '127.0.0.1');
    $port    = env_or('DB_PORT', '3306');
    $dbname  = env_or('DB_NAME', 'secure_file_sharing');
    $user    = env_or('DB_USER', 'sfs_app');
    $pass    = env_or('DB_PASS', 'change_me_in_env');
    $charset = 'utf8mb4';

    $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset={$charset}";

    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false, // real prepared statements
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES {$charset}",
    ];

    try {
        $pdo = new PDO($dsn, $user, $pass, $options);
    } catch (PDOException $e) {
        // Never leak DSN/credentials or raw exception details to the client.
        error_log('[DB CONNECTION ERROR] ' . $e->getMessage());
        http_response_code(500);
        die('A system error occurred. Please try again later.');
    }

    return $pdo;
}
