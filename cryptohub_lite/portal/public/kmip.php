<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$api = new ApiClient();

// Detail view for a single object, reached from the table.
$selected = $_GET['uid'] ?? null;
$detail = null;
if ($selected) {
    $r = $api->get('/api/kmip/objects/' . rawurlencode($selected));
    $detail = $r['ok'] ? $r['data'] : null;
}

$result  = $api->get('/api/kmip/objects');
$objects = $result['ok'] ? $result['data'] : [];

render_head('KMIP Explorer');

if (isset($_GET['notice'])) {
    echo '<div class="chl-alert info">' . e($_GET['notice']) . '</div>';
}
if (isset($_GET['error'])) {
    render_error($_GET['error']);
}
if (!$result['ok']) {
    render_error($result['error'] ?? 'Could not load KMIP objects');
}
?>

<?php
$create_back = 'kmip.php';
require __DIR__ . '/../inc/create_key_form.php';
?>

<?php if ($detail): ?>
    <div class="chl-card">
        <div class="chl-card-head">
            <div>
                <h2 class="chl-card-title"><?= e($detail['name'] ?? $detail['uid']) ?></h2>
                <p class="chl-card-sub chl-mono"><?= e($detail['uid']) ?></p>
            </div>
            <a class="chl-btn chl-btn-sm" href="kmip.php">← All objects</a>
        </div>
        <div class="chl-card-body">
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:24px">
                <div>
                    <div class="chl-stat-label" style="margin-bottom:8px">Managed object</div>
                    <dl class="chl-attr-grid">
                        <dt>Object Type</dt><dd><?= type_badge($detail['object_type'] ?? null) ?></dd>
                        <dt>State</dt><dd><?= state_badge($detail['state'] ?? null) ?></dd>
                        <dt>Algorithm</dt><dd><?= e($detail['algorithm'] ?? '—') ?></dd>
                        <dt>Length</dt><dd><?= e($detail['length'] ?? '—') ?></dd>
                        <dt>Owner</dt><dd><?= e($detail['owner'] ?? '—') ?></dd>
                        <dt>Sensitive</dt>
                        <dd class="<?= ($detail['sensitive'] ?? false) ? 'chl-true' : 'chl-false' ?>">
                            <?= ($detail['sensitive'] ?? false) ? 'true' : 'false' ?></dd>
                        <dt>Extractable</dt>
                        <dd class="<?= ($detail['extractable'] ?? false) ? 'chl-true' : 'chl-false' ?>">
                            <?= ($detail['extractable'] ?? false) ? 'true' : 'false' ?></dd>
                        <dt>Archived</dt><dd><?= ($detail['archived'] ?? false) ? 'yes' : 'no' ?></dd>
                    </dl>
                </div>
                <div>
                    <div class="chl-stat-label" style="margin-bottom:8px">Lifecycle dates</div>
                    <dl class="chl-attr-grid">
                        <dt>Initial</dt><dd><?= e($detail['initial_date'] ?? '—') ?></dd>
                        <dt>Activation</dt><dd><?= e($detail['activation_date'] ?? '—') ?></dd>
                        <dt>Deactivation</dt><dd><?= e($detail['deactivation_date'] ?? '—') ?></dd>
                        <dt>Compromise</dt><dd><?= e($detail['compromise_date'] ?? '—') ?></dd>
                        <dt>Destroy</dt><dd><?= e($detail['destroy_date'] ?? '—') ?></dd>
                        <dt>Revocation</dt><dd><?= e($detail['revocation_reason'] ?? '—') ?></dd>
                    </dl>
                </div>
            </div>

            <?php if (!empty($detail['attributes'])): ?>
                <div class="chl-stat-label" style="margin:22px 0 8px">KMIP attributes</div>
                <div class="chl-table-wrap">
                    <table class="chl-table">
                        <thead><tr><th>Name</th><th>Index</th><th>Value</th></tr></thead>
                        <tbody>
                        <?php foreach ($detail['attributes'] as $attr): ?>
                            <tr>
                                <td class="chl-mono"><?= e($attr['attr_name'] ?? '') ?></td>
                                <td><?= e($attr['attr_index'] ?? 0) ?></td>
                                <td class="chl-mono"><?= e($attr['attr_value'] ?? '') ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>

            <?php if (!empty($detail['grants'])): ?>
                <div class="chl-stat-label" style="margin:22px 0 8px">Delegated access</div>
                <div class="chl-table-wrap">
                    <table class="chl-table">
                        <thead><tr><th>Grantee</th><th>Permission</th></tr></thead>
                        <tbody>
                        <?php foreach ($detail['grants'] as $grant): ?>
                            <tr>
                                <td><?= e($grant['grantee'] ?? '') ?></td>
                                <td><span class="chl-badge blue"><?= e($grant['permission'] ?? '') ?></span></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>

<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Managed Objects</h2>
            <p class="chl-card-sub"><?= count($objects) ?> object(s) in the metadata store</p>
        </div>
        <div class="chl-toolbar">
            <input class="chl-input" id="kmipSearch" placeholder="Search…"
                   oninput="filterTable('kmipSearch','kmipTable')">
        </div>
    </div>

    <?php if (!$objects): ?>
        <div class="chl-empty">
            <div class="chl-empty-title">No managed objects</div>
            <div>Create one over KMIP, and it will appear here.</div>
        </div>
    <?php else: ?>
        <div class="chl-table-wrap">
            <table class="chl-table" id="kmipTable">
                <thead>
                <tr>
                    <th>Name</th><th>UID</th><th>Type</th><th>State</th>
                    <th>Algorithm</th><th>Length</th><th>Owner</th><th>Actions</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($objects as $o): ?>
                    <tr>
                        <td><strong><?= e($o['name'] ?? '(unnamed)') ?></strong></td>
                        <td class="chl-mono"><?= e(substr((string)$o['uid'], 0, 18)) ?>…</td>
                        <td><?= type_badge($o['object_type'] ?? null) ?></td>
                        <td><?= state_badge($o['state'] ?? null) ?></td>
                        <td><?= e($o['algorithm'] ?? '—') ?></td>
                        <td><?= e($o['length'] ?? '—') ?></td>
                        <td><?= e($o['owner'] ?? '—') ?></td>
                        <td>
                            <div class="row-actions" style="display:flex;gap:5px;flex-wrap:wrap">
                                <a class="chl-btn chl-btn-sm"
                                   href="kmip.php?uid=<?= urlencode((string)$o['uid']) ?>">Inspect</a>
                                <?php if (can('key.lifecycle') && ($o['state'] ?? '') === 'PreActive'): ?>
                                    <form method="post" action="kmip_action.php">
                                        <input type="hidden" name="action" value="activate">
                                        <input type="hidden" name="uid" value="<?= e($o['uid']) ?>">
                                        <button class="chl-btn chl-btn-sm" type="submit">Activate</button>
                                    </form>
                                <?php endif; ?>
                                <?php if (can('key.lifecycle') && ($o['state'] ?? '') === 'Active'): ?>
                                    <form method="post" action="kmip_action.php">
                                        <input type="hidden" name="action" value="rekey">
                                        <input type="hidden" name="uid" value="<?= e($o['uid']) ?>">
                                        <button class="chl-btn chl-btn-sm" type="submit"
                                                title="Generate a replacement key">Re-Key</button>
                                    </form>
                                    <form method="post" action="kmip_action.php">
                                        <input type="hidden" name="action" value="revoke">
                                        <input type="hidden" name="uid" value="<?= e($o['uid']) ?>">
                                        <input type="hidden" name="reason" value="CessationOfOperation">
                                        <button class="chl-btn chl-btn-sm" type="submit">Revoke</button>
                                    </form>
                                <?php endif; ?>
                                <?php if (can('key.destroy') && !in_array($o['state'] ?? '', ['Destroyed','DestroyedCompromised'], true)): ?>
                                    <form method="post" action="kmip_action.php"
                                          onsubmit="return confirm('Destroy this key?

Key material is removed from the HSM. This cannot be undone, and anything encrypted under it becomes unrecoverable.')">
                                        <input type="hidden" name="action" value="destroy">
                                        <input type="hidden" name="uid" value="<?= e($o['uid']) ?>">
                                        <button class="chl-btn chl-btn-sm" type="submit">Destroy</button>
                                    </form>
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

<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Supported KMIP Operations</h2>
            <p class="chl-card-sub">41 of 53 operations implemented by the KMIP engine</p>
        </div>
    </div>
    <div class="chl-card-body">
        <div style="display:flex;flex-wrap:wrap;gap:7px">
            <?php foreach (['Create','CreateKeyPair','Register','Get','GetAttributes','Locate',
                            'Activate','Revoke','Destroy','ReKey','ReKeyKeyPair','Certify',
                            'Encrypt','Decrypt','Sign','SignatureVerify','MAC','MACVerify',
                            'Hash','DeriveKey','Validate','Archive','Recover','Check',
                            'AddAttribute','ModifyAttribute','DeleteAttribute','Query'] as $op): ?>
                <span class="chl-badge grey"><?= e($op) ?></span>
            <?php endforeach; ?>
        </div>
        <p style="margin:14px 0 0;color:var(--text-muted);font-size:12px">
            Operations are executed by the existing KMIP engine over its own TCP listener on
            port 5696. This portal reads the resulting managed objects; it does not reimplement
            KMIP.
        </p>
    </div>
</div>

<?php render_foot(); ?>
