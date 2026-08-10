<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$api     = new ApiClient();
$health  = $api->get('/api/pkcs11/health');
$slots   = $api->get('/api/pkcs11/slots');
$objects = $api->get('/api/pkcs11/objects');

$hsm      = $health['ok']  ? $health['data']  : ['available' => false, 'error' => $health['error']];
$slotList = $slots['ok']   ? $slots['data']   : [];
$objList  = $objects['ok'] ? $objects['data'] : [];

render_head('PKCS#11 Explorer');
?>

<?php if (!($hsm['available'] ?? false)): ?>
    <div class="chl-alert">
        <strong>PKCS#11 module unavailable.</strong>
        <?= e($hsm['error'] ?? 'The token could not be opened.') ?>
        <div style="margin-top:6px;color:var(--text-muted);font-size:12px">
            Library: <span class="chl-mono"><?= e($hsm['library'] ?? '—') ?></span> ·
            Token: <span class="chl-mono"><?= e($hsm['token'] ?? '—') ?></span>
        </div>
    </div>
<?php endif; ?>

<div class="chl-stat-grid">
    <div class="chl-stat <?= ($hsm['available'] ?? false) ? 'green' : 'red' ?>">
        <div class="chl-stat-label">Module</div>
        <div class="chl-stat-value" style="font-size:19px;padding-top:7px">
            <?= ($hsm['available'] ?? false) ? 'Connected' : 'Offline' ?>
        </div>
        <div class="chl-stat-hint"><?= e(basename((string)($hsm['library'] ?? ''))) ?></div>
    </div>
    <div class="chl-stat">
        <div class="chl-stat-label">Slots</div>
        <div class="chl-stat-value"><?= count($slotList) ?></div>
        <div class="chl-stat-hint">reported by the module</div>
    </div>
    <div class="chl-stat cyan">
        <div class="chl-stat-label">Objects</div>
        <div class="chl-stat-value"><?= count($objList) ?></div>
        <div class="chl-stat-hint">on the logged-in token</div>
    </div>
    <div class="chl-stat">
        <div class="chl-stat-label">Token</div>
        <div class="chl-stat-value" style="font-size:19px;padding-top:7px">
            <?= e($hsm['token'] ?? '—') ?></div>
        <div class="chl-stat-hint">configured label</div>
    </div>
</div>

<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Slots &amp; Tokens</h2>
            <p class="chl-card-sub">As reported by C_GetSlotList / C_GetTokenInfo</p>
        </div>
    </div>
    <?php if (!$slotList): ?>
        <div class="chl-empty">
            <div class="chl-empty-title">No slots reported</div>
            <div>The PKCS#11 module returned no slots.</div>
        </div>
    <?php else: ?>
        <div class="chl-table-wrap">
            <table class="chl-table">
                <thead>
                <tr><th>Slot ID</th><th>Description</th><th>Token Label</th><th>Model</th>
                    <th>Serial</th><th>Manufacturer</th><th>Status</th></tr>
                </thead>
                <tbody>
                <?php foreach ($slotList as $slot): $t = $slot['token'] ?? null; ?>
                    <tr>
                        <td class="chl-mono"><?= e($slot['slot_id'] ?? '') ?></td>
                        <td><?= e($slot['description'] ?? '') ?></td>
                        <td><strong><?= e($t['label'] ?? '—') ?></strong></td>
                        <td><?= e($t['model'] ?? '—') ?></td>
                        <td class="chl-mono"><?= e($t['serial'] ?? '—') ?></td>
                        <td><?= e($t['manufacturer'] ?? $slot['manufacturer'] ?? '—') ?></td>
                        <td>
                            <?php if (!($slot['has_token'] ?? false)): ?>
                                <span class="chl-badge grey">No token</span>
                            <?php elseif ($t['initialized'] ?? false): ?>
                                <span class="chl-badge green">Initialised</span>
                            <?php else: ?>
                                <span class="chl-badge amber">Uninitialised</span>
                            <?php endif; ?>
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
            <h2 class="chl-card-title">Token Objects</h2>
            <p class="chl-card-sub">Raw CKA_* attributes, exactly as the token reports them</p>
        </div>
        <div class="chl-toolbar">
            <input class="chl-input" id="objSearch" placeholder="Search label, class, type…"
                   oninput="filterTable('objSearch','objTable')">
        </div>
    </div>

    <?php if (!$objList): ?>
        <div class="chl-empty">
            <div class="chl-empty-title">No objects on the token</div>
            <div>Generate a key through KMIP and it will appear here.</div>
        </div>
    <?php else: ?>
        <div class="chl-table-wrap">
            <table class="chl-table" id="objTable">
                <thead>
                <tr><th>CKA_LABEL</th><th>CKA_CLASS</th><th>CKA_KEY_TYPE</th><th>CKA_ID</th>
                    <th>Sensitive</th><th>Extractable</th><th></th></tr>
                </thead>
                <tbody>
                <?php foreach ($objList as $i => $obj):
                    $a = $obj['attributes'] ?? []; ?>
                    <tr>
                        <td><strong><?= e($obj['label'] ?: '(no label)') ?></strong></td>
                        <td><span class="chl-badge blue"><?= e($obj['class'] ?? '') ?></span></td>
                        <td class="chl-mono"><?= e($obj['key_type'] ?? '—') ?></td>
                        <td class="chl-mono"><?= e($a['CKA_ID'] ?? '—') ?></td>
                        <td class="<?= !empty($a['CKA_SENSITIVE']) ? 'chl-true' : 'chl-false' ?>">
                            <?= isset($a['CKA_SENSITIVE']) ? var_export($a['CKA_SENSITIVE'], true) : '—' ?></td>
                        <td class="<?= !empty($a['CKA_EXTRACTABLE']) ? 'chl-true' : 'chl-false' ?>">
                            <?= isset($a['CKA_EXTRACTABLE']) ? var_export($a['CKA_EXTRACTABLE'], true) : '—' ?></td>
                        <td>
                            <button class="chl-btn chl-btn-sm" onclick="toggleDetail('obj<?= $i ?>')">
                                Attributes</button>
                        </td>
                    </tr>
                    <tr id="obj<?= $i ?>" data-detail="1" class="chl-detail-row" style="display:none">
                        <td colspan="7">
                            <dl class="chl-attr-grid">
                                <?php foreach ($a as $name => $value): ?>
                                    <dt><?= e($name) ?></dt>
                                    <dd class="<?= is_bool($value) ? ($value ? 'chl-true' : 'chl-false') : '' ?>">
                                        <?= is_bool($value) ? var_export($value, true) : e((string)$value) ?>
                                    </dd>
                                <?php endforeach; ?>
                            </dl>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<?php render_foot(); ?>
