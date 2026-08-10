<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$api = new ApiClient();

$filters = array_filter([
    'username' => $_GET['username'] ?? '',
    'action'   => $_GET['action'] ?? '',
    'result'   => $_GET['result'] ?? '',
    'limit'    => 300,
], static fn($v) => $v !== '' && $v !== null);

$result = $api->get('/api/audit', $filters);
$events = $result['ok'] ? ($result['data']['events'] ?? []) : [];
$total  = $result['ok'] ? ($result['data']['total'] ?? 0) : 0;

render_head('Audit');

// A 403 here is a role decision, not a fault; say which role is in effect so
// the reader knows whether to ask for access or report a problem.
if (!$result['ok']) {
    if (($result['status'] ?? 0) === 403) {
        echo '<div class="chl-alert warn"><strong>Audit access not permitted.</strong> '
           . 'The role <strong>' . e(current_role()) . '</strong> cannot read the audit trail. '
           . 'Administrator, SecurityOfficer or Auditor is required.</div>';
    } else {
        render_error($result['error'] ?? 'Could not load audit events');
    }
}
?>
<?php if ($result['ok']): ?>
<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Audit Trail</h2>
            <p class="chl-card-sub"><?= (int)$total ?> event(s) recorded ·
                showing <?= count($events) ?></p>
        </div>
        <div class="chl-toolbar">
            <?php if (can('audit.export')): ?>
                <a class="chl-btn chl-btn-sm" href="export.php?what=audit&fmt=csv">CSV</a>
                <a class="chl-btn chl-btn-sm" href="export.php?what=audit&fmt=excel">Excel</a>
                <a class="chl-btn chl-btn-sm" href="export.php?what=audit&fmt=json">JSON</a>
            <?php endif; ?>
        </div>
    </div>

    <div class="chl-card-body" style="border-bottom:1px solid var(--border)">
        <form class="chl-toolbar" method="get">
            <input class="chl-input" name="username" placeholder="User"
                   value="<?= e($_GET['username'] ?? '') ?>">
            <input class="chl-input" name="action" placeholder="Action"
                   value="<?= e($_GET['action'] ?? '') ?>">
            <select class="chl-select" name="result">
                <option value="">Any result</option>
                <option value="SUCCESS" <?= ($_GET['result'] ?? '') === 'SUCCESS' ? 'selected' : '' ?>>Success</option>
                <option value="FAILURE" <?= ($_GET['result'] ?? '') === 'FAILURE' ? 'selected' : '' ?>>Failure</option>
            </select>
            <button class="chl-btn chl-btn-primary chl-btn-sm" type="submit">Filter</button>
            <a class="chl-btn chl-btn-sm" href="audit.php">Reset</a>
        </form>
    </div>

    <?php if (!$events): ?>
        <div class="chl-empty">
            <div class="chl-empty-title">No audit events</div>
            <div>Activity will be recorded here as the system is used.</div>
        </div>
    <?php else: ?>
        <div class="chl-table-wrap">
            <table class="chl-table">
                <thead><tr>
                    <th>Timestamp</th><th>User</th><th>Source IP</th><th>Action</th>
                    <th>Object</th><th>Provider</th><th>Result</th><th>Detail</th>
                </tr></thead>
                <tbody>
                <?php foreach ($events as $ev): ?>
                    <tr>
                        <td class="chl-mono"><?= e(substr((string)($ev['occurred_at_iso'] ?? ''), 0, 19)) ?></td>
                        <td><strong><?= e($ev['username'] ?? '—') ?></strong></td>
                        <td class="chl-mono"><?= e($ev['source_ip'] ?? '—') ?></td>
                        <td class="chl-mono"><?= e($ev['action'] ?? '') ?></td>
                        <td class="chl-mono"><?= e($ev['object_uid'] ? substr((string)$ev['object_uid'], 0, 14) . '…' : '—') ?></td>
                        <td><?= e($ev['provider'] ?? '—') ?></td>
                        <td><?= result_badge($ev['result'] ?? null) ?></td>
                        <td style="color:var(--text-muted)"><?= e($ev['detail'] ?? '') ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>
<?php endif; ?>
<?php render_foot(); ?>
