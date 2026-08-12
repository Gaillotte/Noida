<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$api  = new ApiClient();
$kind = $_GET['kind'] ?? '';

$result = $api->get('/api/keys', $kind ? ['kind' => $kind] : []);
$keys   = $result['ok'] ? $result['data'] : [];

render_head('Key Management');

if (isset($_GET['notice'])) {
    echo '<div class="chl-alert info">' . e($_GET['notice']) . '</div>';
}
if (isset($_GET['error'])) {
    render_error($_GET['error']);
}
if (!$result['ok']) { render_error($result['error'] ?? 'Could not load keys'); }

$kinds = ['' => 'All types', 'SymmetricKey' => 'Symmetric', 'PrivateKey' => 'RSA / ECC private',
          'PublicKey' => 'Public', 'Certificate' => 'Certificates'];

// The generator is narrow and fixed; the explorer wants whatever is left. On a
// laptop the two sit side by side, and the grid collapses to one column below
// roughly 1100px rather than squeezing an eight-column table into half a screen.
?>
<div class="chl-split">
    <div>
        <?php
        $create_back = 'keys.php' . ($kind ? '?kind=' . urlencode($kind) : '');
        require __DIR__ . '/../inc/create_key_form.php';
        ?>
    </div>

    <div>
        <div class="chl-card">
            <div class="chl-card-head">
                <div>
                    <h2 class="chl-card-title">Keys on token</h2>
                    <p class="chl-card-sub"><?= count($keys) ?> key object(s)</p>
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
                    <div>Generate one on the left, or over KMIP on port 5696.</div>
                </div>
            <?php else: ?>
                <div class="chl-table-wrap">
                    <table class="chl-table" id="keyTable">
                        <thead><tr>
                            <th>Class</th><th>Label</th><th>Type</th><th>Size</th>
                            <th>CKA_ID</th><th>State</th><th>Usage</th><th></th>
                        </tr></thead>
                        <tbody>
                        <?php foreach ($keys as $k): ?>
                            <tr>
                                <td><?= type_badge($k['object_type'] ?? null) ?></td>
                                <td><strong><?= e($k['name'] ?? '(unnamed)') ?></strong>
                                    <div class="chl-mono" style="font-size:10.5px;color:var(--text-dim)">
                                        <?= e(substr((string)$k['uid'], 0, 18)) ?>…</div></td>
                                <td><span class="chl-badge grey"><?= e($k['algorithm'] ?? '—') ?></span></td>
                                <td><?= $k['length'] ? e($k['length']) . ' bit' : '—' ?></td>
                                <td class="chl-mono"><?= e($k['cka_id'] ?? '—') ?></td>
                                <td><?= state_badge($k['state'] ?? null) ?></td>
                                <td>
                                    <?php foreach ($k['usage_mask'] ?? [] as $usage): ?>
                                        <span class="chl-badge blue"><?= e($usage) ?></span>
                                    <?php endforeach; ?>
                                    <?php if (empty($k['usage_mask'])): ?>—<?php endif; ?>
                                </td>
                                <td><a class="chl-btn chl-btn-sm"
                                       href="kmip.php?uid=<?= urlencode((string)$k['uid']) ?>">Inspect</a></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>
<?php render_foot(); ?>
