<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$api  = new ApiClient();
$kind = $_GET['kind'] ?? '';

$result = $api->get('/api/keys', $kind ? ['kind' => $kind] : []);
$keys   = $result['ok'] ? $result['data'] : [];

render_head('Keys');
if (!$result['ok']) { render_error($result['error'] ?? 'Could not load keys'); }

$kinds = ['' => 'All types', 'SymmetricKey' => 'Symmetric', 'PrivateKey' => 'RSA / ECC private',
          'PublicKey' => 'Public', 'Certificate' => 'Certificates'];
?>
<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Key Explorer</h2>
            <p class="chl-card-sub"><?= count($keys) ?> object(s)</p>
        </div>
        <div class="chl-toolbar">
            <select class="chl-select" onchange="location.href='keys.php?kind='+this.value">
                <?php foreach ($kinds as $value => $label): ?>
                    <option value="<?= e($value) ?>" <?= $kind === $value ? 'selected' : '' ?>>
                        <?= e($label) ?></option>
                <?php endforeach; ?>
            </select>
            <input class="chl-input" id="keySearch" placeholder="Search…"
                   oninput="filterTable('keySearch','keyTable')">
            <a class="chl-btn chl-btn-sm" href="export.php?what=keys">Export CSV</a>
        </div>
    </div>

    <?php if (!$keys): ?>
        <div class="chl-empty">
            <div class="chl-empty-title">No keys found</div>
            <div>Create one over KMIP and it will appear here.</div>
        </div>
    <?php else: ?>
        <div class="chl-table-wrap">
            <table class="chl-table" id="keyTable">
                <thead><tr>
                    <th>Name</th><th>Type</th><th>Algorithm</th><th>Length</th>
                    <th>State</th><th>Owner</th><th>Created</th><th></th>
                </tr></thead>
                <tbody>
                <?php foreach ($keys as $k): ?>
                    <tr>
                        <td><strong><?= e($k['name'] ?? '(unnamed)') ?></strong>
                            <div class="chl-mono"><?= e(substr((string)$k['uid'], 0, 20)) ?>…</div></td>
                        <td><?= type_badge($k['object_type'] ?? null) ?></td>
                        <td><?= e($k['algorithm'] ?? '—') ?></td>
                        <td><?= e($k['length'] ?? '—') ?></td>
                        <td><?= state_badge($k['state'] ?? null) ?></td>
                        <td><?= e($k['owner'] ?? '—') ?></td>
                        <td class="chl-mono"><?= e(substr((string)($k['created_at'] ?? ''), 0, 19)) ?></td>
                        <td><a class="chl-btn chl-btn-sm"
                               href="kmip.php?uid=<?= urlencode((string)$k['uid']) ?>">Inspect</a></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>
<?php render_foot(); ?>
