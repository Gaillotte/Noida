<?php
/**
 * Session handling, authorization helpers and the page chrome.
 *
 * Capabilities come from the API at login and are used only to decide what to
 * *show*. The API enforces them independently on every request, so a hidden
 * button is a courtesy, not a control.
 */

declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

require_once __DIR__ . '/api.php';

function is_authenticated(): bool
{
    return !empty($_SESSION['token']);
}

function require_login(): void
{
    if (!is_authenticated()) {
        header('Location: login.php');
        exit;
    }
}

function current_username(): string
{
    return $_SESSION['username'] ?? 'unknown';
}

function current_role(): string
{
    return $_SESSION['role'] ?? 'ReadOnly';
}

function current_display_name(): string
{
    return $_SESSION['display_name'] ?? current_username();
}

function can(string $capability): bool
{
    return in_array($capability, $_SESSION['capabilities'] ?? [], true);
}

function initials(string $name): string
{
    $parts = preg_split('/[\s_.-]+/', trim($name)) ?: [];
    $letters = '';
    foreach (array_slice($parts, 0, 2) as $part) {
        if ($part !== '') {
            $letters .= strtoupper($part[0]);
        }
    }
    return $letters !== '' ? $letters : strtoupper(substr($name, 0, 2));
}

/** Escapes for HTML. Named short because it appears on nearly every line. */
function e($value): string
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES, 'UTF-8');
}

/** Maps a KMIP state to a badge colour. Colour is never the only signal. */
function state_badge(?string $state): string
{
    $tone = match ($state) {
        'Active'                => 'green',
        'PreActive'             => 'blue',
        'Deactivated'           => 'amber',
        'Compromised',
        'DestroyedCompromised'  => 'red',
        'Destroyed'             => 'grey',
        default                 => 'grey',
    };
    return '<span class="chl-badge ' . $tone . '">' . e($state ?? 'Unknown') . '</span>';
}

function type_badge(?string $type): string
{
    $tone = match ($type) {
        'SymmetricKey' => 'blue',
        'PrivateKey'   => 'red',
        'PublicKey'    => 'green',
        'Certificate'  => 'amber',
        default        => 'grey',
    };
    return '<span class="chl-badge ' . $tone . '">' . e($type ?? 'Unknown') . '</span>';
}

function result_badge(?string $result): string
{
    $tone = $result === 'SUCCESS' ? 'green' : ($result === 'FAILURE' ? 'red' : 'grey');
    return '<span class="chl-badge ' . $tone . '">' . e($result ?? '-') . '</span>';
}

const NAV_ITEMS = [
    ['section' => 'Monitor'],
    ['file' => 'index.php',        'label' => 'Dashboard',       'icon' => '▦'],
    ['file' => 'keys.php',         'label' => 'Keys',            'icon' => '⚿'],
    ['file' => 'certificates.php', 'label' => 'Certificates',    'icon' => '▤'],
    ['section' => 'Manage'],
    ['file' => 'kmip.php',         'label' => 'KMIP',            'icon' => '⇄'],
    ['file' => 'pkcs11.php',       'label' => 'PKCS#11',         'icon' => '⌗'],
    ['section' => 'Govern'],
    ['file' => 'audit.php',        'label' => 'Audit',           'icon' => '☰'],
    ['file' => 'admin.php',        'label' => 'Administration',  'icon' => '⚙'],
];

function render_head(string $title): void
{
    $current = basename($_SERVER['PHP_SELF']);
    ?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e($title) ?> · IDEMIA CryptoHub Lite</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/idemia.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
</head>
<body>
<div class="chl-shell">
    <aside class="chl-sidebar" id="sidebar">
        <div class="chl-brand">
            <div class="chl-brand-mark">ID</div>
            <div class="chl-brand-text">
                <div class="chl-brand-name">IDEMIA</div>
                <div class="chl-brand-sub">CryptoHub Lite</div>
            </div>
        </div>
        <nav class="chl-nav">
            <?php foreach (NAV_ITEMS as $item): ?>
                <?php if (isset($item['section'])): ?>
                    <div class="chl-nav-section"><?= e($item['section']) ?></div>
                <?php else: ?>
                    <a class="chl-nav-link <?= $current === $item['file'] ? 'active' : '' ?>"
                       href="<?= e($item['file']) ?>">
                        <span class="chl-nav-icon"><?= $item['icon'] ?></span>
                        <?= e($item['label']) ?>
                    </a>
                <?php endif; ?>
            <?php endforeach; ?>
        </nav>
        <div class="chl-sidebar-foot">
            KMIP 2.1 · PKCS#11<br>
            <?= e(current_role()) ?>
        </div>
    </aside>

    <div class="chl-main">
        <header class="chl-topbar">
            <h1><?= e($title) ?></h1>
            <div class="chl-topbar-actions">
                <button class="chl-btn chl-btn-sm" onclick="toggleTheme()" id="themeBtn"
                        title="Switch theme">☀ Light</button>
                <div class="chl-user-chip">
                    <div class="chl-avatar"><?= e(initials(current_display_name())) ?></div>
                    <div>
                        <div class="chl-user-name"><?= e(current_display_name()) ?></div>
                        <div class="chl-user-role"><?= e(current_role()) ?></div>
                    </div>
                </div>
                <a class="chl-btn chl-btn-sm" href="logout.php">Sign out</a>
            </div>
        </header>
        <main class="chl-content">
    <?php
}

function render_foot(): void
{
    ?>
        </main>
    </div>
</div>
<script>
// Theme choice persists per browser. Dark is the default, per the brief, so
// the stored value only ever needs to record an explicit switch to light.
function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('chl-theme', theme);
    const btn = document.getElementById('themeBtn');
    if (btn) btn.textContent = theme === 'dark' ? '☀ Light' : '☾ Dark';
}
function toggleTheme() {
    const now = document.documentElement.getAttribute('data-theme');
    applyTheme(now === 'dark' ? 'light' : 'dark');
}
applyTheme(localStorage.getItem('chl-theme') || 'dark');

// Chart.js defaults follow the active theme so charts do not stay dark-on-light.
if (window.Chart) {
    const dark = document.documentElement.getAttribute('data-theme') === 'dark';
    Chart.defaults.color = dark ? '#9DB2CA' : '#4A6076';
    Chart.defaults.borderColor = dark ? '#23415F' : '#D6E0EC';
    Chart.defaults.font.family = 'Segoe UI, Roboto, sans-serif';
}

function filterTable(inputId, tableId) {
    const term = document.getElementById(inputId).value.toLowerCase();
    document.querySelectorAll('#' + tableId + ' tbody tr').forEach(row => {
        if (row.dataset.detail === '1') return;   // keep expanded detail rows with their parent
        row.style.display = row.textContent.toLowerCase().includes(term) ? '' : 'none';
    });
}

function toggleDetail(id) {
    const row = document.getElementById(id);
    if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
}
</script>
</body>
</html>
    <?php
}

function render_error(string $message): void
{
    echo '<div class="chl-alert">' . e($message) . '</div>';
}
