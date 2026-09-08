<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$api    = new ApiClient();
$result = $api->get('/api/certificates');
$certs  = $result['ok'] ? $result['data'] : [];

render_head('Certificates');

if (isset($_GET['notice'])) { echo '<div class="chl-alert info">' . e($_GET['notice']) . '</div>'; }
if (isset($_GET['error']))  { render_error($_GET['error']); }
if (!$result['ok'])         { render_error($result['error'] ?? 'Could not load certificates'); }

// Expiry is why this is its own page rather than a filter on Keys: a
// certificate that silently lapses takes a service down with it, so the
// counts lead and the table is sorted by urgency server-side.
$expired  = array_filter($certs, static fn($c) => ($c['days_remaining'] ?? null) !== null
                                                  && $c['days_remaining'] < 0);
$expiring = array_filter($certs, static fn($c) => ($c['days_remaining'] ?? null) !== null
                                                  && $c['days_remaining'] >= 0
                                                  && $c['days_remaining'] <= 30);

function expiry_badge(?int $days): string
{
    if ($days === null) { return '<span class="chl-badge grey">Unknown</span>'; }
    if ($days < 0)      { return '<span class="chl-badge red">Expired ' . abs($days) . 'd ago</span>'; }
    if ($days <= 30)    { return '<span class="chl-badge amber">' . $days . 'd left</span>'; }
    return '<span class="chl-badge green">' . $days . 'd left</span>';
}
?>

<div class="chl-stat-grid">
    <div class="chl-stat">
        <div class="chl-stat-label">Certificates</div>
        <div class="chl-stat-value"><?= count($certs) ?></div>
        <div class="chl-stat-hint">X.509 managed objects</div>
    </div>
    <div class="chl-stat <?= $expiring ? 'amber' : 'green' ?>">
        <div class="chl-stat-label">Expiring ≤ 30 days</div>
        <div class="chl-stat-value"><?= count($expiring) ?></div>
        <div class="chl-stat-hint">renew before they lapse</div>
    </div>
    <div class="chl-stat <?= $expired ? 'red' : 'green' ?>">
        <div class="chl-stat-label">Expired</div>
        <div class="chl-stat-value"><?= count($expired) ?></div>
        <div class="chl-stat-hint">already failing validation</div>
    </div>
</div>

<?php if ($expired): ?>
    <div class="chl-alert">
        <strong><?= count($expired) ?> certificate(s) have expired.</strong>
        Anything relying on them is already failing validation.
    </div>
<?php elseif ($expiring): ?>
    <div class="chl-alert warn">
        <strong><?= count($expiring) ?> certificate(s) expire within 30 days.</strong>
        Renew them before they lapse.
    </div>
<?php endif; ?>

<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Certificate Inventory</h2>
            <p class="chl-card-sub">Subject, issuer and validity parsed from the stored X.509</p>
        </div>
        <div class="chl-toolbar">
            <input class="chl-input" id="certSearch" placeholder="Search subject, issuer…"
                   oninput="filterTable('certSearch','certTable')">
            <a class="chl-btn chl-btn-sm" href="export.php?what=certificates">Export CSV</a>
        </div>
    </div>

    <?php if (!$certs): ?>
        <div class="chl-empty">
            <div class="chl-empty-title">No certificates</div>
            <div>Register or Certify one over KMIP and it will appear here.</div>
        </div>
    <?php else: ?>
        <div class="chl-table-wrap">
            <table class="chl-table" id="certTable">
                <thead><tr>
                    <th>Name</th><th>Subject</th><th>Issuer</th><th>Not After</th>
                    <th>Expiry</th><th>State</th><th></th>
                </tr></thead>
                <tbody>
                <?php foreach ($certs as $c): ?>
                    <tr>
                        <td><strong><?= e($c['name'] ?? '(unnamed)') ?></strong>
                            <div><?= uid_chip($c['uid'] ?? null) ?></div></td>
                        <td class="chl-mono"><?= e($c['subject'] ?? '—') ?></td>
                        <td class="chl-mono"><?= e($c['issuer'] ?? '—') ?></td>
                        <td class="chl-mono"><?= e(substr((string)($c['not_after'] ?? '—'), 0, 10)) ?></td>
                        <td><?= expiry_badge(isset($c['days_remaining']) ? (int)$c['days_remaining'] : null) ?></td>
                        <td><?= state_badge($c['state'] ?? null) ?></td>
                        <td>
                            <div style="display:flex;gap:5px;align-items:center">
                                <a class="chl-btn chl-btn-sm"
                                   href="kmip.php?uid=<?= urlencode((string)$c['uid']) ?>">Inspect</a>
                                <?php if (!empty($c['self_signed'])): ?>
                                    <span class="chl-badge grey" title="Issuer equals subject">self-signed</span>
                                <?php endif; ?>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<?php render_foot(); ?>
