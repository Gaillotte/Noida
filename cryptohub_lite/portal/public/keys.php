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
                    <p class="chl-card-sub"><?= count($keys) ?> key object(s) ·
                        material and usage. <a href="kmip.php">KMIP</a> shows the
                        same objects' lifecycle and attributes.<br/>
                        <span style="font-size:11px">Key material cannot be
                        exported &mdash; see <b>Extractable</b> below.</span></p>
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
                    <?php
                    // Named "inventory" rather than "export": "Export" invites the
                    // reading that it hands over key material, and it does not.
                    // KMIP has a real Export operation, and even that refuses a
                    // non-extractable key - which is every key created here.
                    ?>
                    <a class="chl-btn chl-btn-sm" href="export.php?what=keys"
                       title="Metadata only - uid, name, type, algorithm, size, state, owner, sensitive, extractable. Never key material.">Export inventory (CSV)</a>
                </div>
            </div>

            <?php if (!$keys): ?>
                <div class="chl-empty">
                    <div class="chl-empty-title">No keys found</div>
                    <div>Generate one on the left, or over KMIP on port 5696 —
                        both run the same <span class="chl-mono">Create</span>
                        operation on the token.</div>
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
                                    <div><?= uid_chip($k['uid'] ?? null) ?></div></td>
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
                                <?php
                                // The outbound leg of the pair, and the only
                                // route to the lifecycle actions. Labelled for
                                // where it goes rather than "Inspect", which
                                // gave no reason to click it.
                                ?>
                                <td><a class="chl-btn chl-btn-sm"
                                       href="kmip.php?uid=<?= urlencode((string)$k['uid']) ?>"
                                       title="KMIP attributes, delegated access, and the lifecycle actions">Manage →</a></td>
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
