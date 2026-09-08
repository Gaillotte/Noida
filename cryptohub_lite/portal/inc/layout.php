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

/** True while this account still uses the shipped bootstrap password. */
function using_default_password(): bool
{
    return !empty($_SESSION['default_password']);
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

/**
 * A KMIP Unique Identifier, shown short and copied in full.
 *
 * Four pages printed `substr($uid, 0, 18) . '…'`, which reads as decoration
 * rather than a value: the identifier every KMIP operation needs was on screen
 * and there was no way to get it off the screen. A UUID is 36 characters and
 * showing all of them crowds out the columns people actually scan, so it stays
 * truncated - but the whole value is on the element, in the tooltip, and one
 * click away from the clipboard.
 */
function uid_chip(?string $uid, int $shown = 18): string
{
    if (!$uid) {
        return '<span class="chl-mono">&mdash;</span>';
    }
    $short = strlen($uid) > $shown ? substr($uid, 0, $shown) . '…' : $uid;
    return '<button type="button" class="chl-uid" data-uid="' . e($uid) . '"'
         . ' title="' . e($uid) . ' — click to copy">'
         . '<span>' . e($short) . '</span><span class="chl-uid-icon">⧉</span></button>';
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
    ['file' => 'kmip_client.php',  'label' => 'KMIP Client',     'icon' => '⌨'],
    ['file' => 'pkcs11.php',       'label' => 'PKCS#11',         'icon' => '⌗'],
    ['section' => 'Govern'],
    ['file' => 'audit.php',        'label' => 'Audit',           'icon' => '☰'],
    ['file' => 'admin.php',        'label' => 'Administration',  'icon' => '⚙'],
];

/**
 * Page chrome.
 *
 * `$charts` pulls in Chart.js. Only the dashboard draws a chart, and the
 * library is 200 KB, so every other page skips it rather than paying for it
 * on the chance that it might one day need one.
 *
 * Bootstrap and Chart.js are served from assets/vendor/, not from a CDN. A key
 * manager is routinely deployed where outbound HTTPS to jsdelivr.net does not
 * exist, and on a corporate network the CDN round-trip was the slowest thing
 * on the page by an order of magnitude - the portal itself answers in ~12 ms.
 */
function render_head(string $title, bool $charts = false): void
{
    $current = basename($_SERVER['PHP_SELF']);
    ?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= e($title) ?> · IDEMIA CryptoHub Lite</title>
    <link href="assets/vendor/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/idemia.css" rel="stylesheet">
    <?php if ($charts): ?>
    <script src="assets/vendor/chart.umd.min.js"></script>
    <?php endif; ?>
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
                <a class="chl-user-chip" href="account.php" title="My account"
                   style="text-decoration:none;color:inherit">
                    <div class="chl-avatar"><?= e(initials(current_display_name())) ?></div>
                    <div>
                        <div class="chl-user-name"><?= e(current_display_name()) ?></div>
                        <div class="chl-user-role"><?= e(current_role()) ?></div>
                    </div>
                </a>
                <a class="chl-btn chl-btn-sm" href="logout.php">Sign out</a>
            </div>
        </header>
        <main class="chl-content">
    <?php
    if (using_default_password() && basename($_SERVER['PHP_SELF']) !== 'account.php') {
        echo '<div class="chl-alert" role="alert">'
           . '<strong>This account is using the default password.</strong> '
           . 'It is published in the project README, so anyone who can reach this '
           . 'portal — or the KMIP port — can sign in as you. '
           . '<a href="account.php" class="chl-btn chl-btn-sm" style="margin-left:8px">'
           . 'Change it now</a>'
           . '</div>';
    }
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
        // Full UIDs live in an attribute because the cell shows a truncation.
        // Pasting a copied identifier straight into the filter is the obvious
        // thing to do with it, so search what was copied, not what is printed.
        let hay = row.textContent.toLowerCase();
        row.querySelectorAll('[data-uid]').forEach(el => { hay += ' ' + el.dataset.uid.toLowerCase(); });
        row.style.display = hay.includes(term) ? '' : 'none';
    });
}

function toggleDetail(id) {
    const row = document.getElementById(id);
    if (row) row.style.display = row.style.display === 'none' ? '' : 'none';
}

// Copying a UID. Delegated from the document so it covers rows rendered after
// load, and falls back to execCommand because the async clipboard API needs a
// secure context - localhost qualifies, a bare LAN address does not.
document.addEventListener('click', function (event) {
    const chip = event.target.closest ? event.target.closest('.chl-uid') : null;
    if (!chip) return;
    const value = chip.dataset.uid || '';

    function flash(ok) {
        const icon = chip.querySelector('.chl-uid-icon');
        if (!icon) return;
        const was = icon.textContent;
        icon.textContent = ok ? '✓' : '✕';
        chip.classList.toggle('copied', ok);
        setTimeout(() => { icon.textContent = was; chip.classList.remove('copied'); }, 1200);
    }
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(value).then(() => flash(true), () => flash(false));
        return;
    }
    const scratch = document.createElement('textarea');
    scratch.value = value;
    scratch.setAttribute('readonly', '');
    scratch.style.position = 'fixed';
    scratch.style.opacity = '0';
    document.body.appendChild(scratch);
    scratch.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    document.body.removeChild(scratch);
    flash(ok);
});
</script>
</body>
</html>
    <?php
}

function render_error(string $message): void
{
    echo '<div class="chl-alert">' . e($message) . '</div>';
}
