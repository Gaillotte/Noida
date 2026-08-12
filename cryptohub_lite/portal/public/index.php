<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$api = new ApiClient();
$result = $api->get('/api/dashboard');
$d = $result['ok'] ? $result['data'] : [];

render_head('Dashboard');

if (!$result['ok']) {
    render_error($result['error'] ?? 'Could not load the dashboard');
}

$hsm = $d['hsm'] ?? ['available' => false, 'error' => 'unknown'];
?>

<div class="chl-stat-grid">
    <div class="chl-stat">
        <div class="chl-stat-label">Total Keys</div>
        <div class="chl-stat-value"><?= (int)($d['total_keys'] ?? 0) ?></div>
        <div class="chl-stat-hint"><?= (int)($d['symmetric_keys'] ?? 0) ?> symmetric ·
            <?= (int)($d['private_keys'] ?? 0) ?> private</div>
    </div>
    <div class="chl-stat green">
        <div class="chl-stat-label">Active Keys</div>
        <div class="chl-stat-value"><?= (int)($d['active_keys'] ?? 0) ?></div>
        <div class="chl-stat-hint">usable for protection</div>
    </div>
    <div class="chl-stat amber">
        <div class="chl-stat-label">Certificates</div>
        <div class="chl-stat-value"><?= (int)($d['certificates'] ?? 0) ?></div>
        <div class="chl-stat-hint">X.509 managed objects</div>
    </div>
    <div class="chl-stat cyan">
        <div class="chl-stat-label">KMIP Objects</div>
        <div class="chl-stat-value"><?= (int)($d['total_objects'] ?? 0) ?></div>
        <div class="chl-stat-hint">in the metadata store</div>
    </div>
    <div class="chl-stat cyan">
        <div class="chl-stat-label">PKCS#11 Objects</div>
        <div class="chl-stat-value"><?= (int)($d['pkcs11_objects'] ?? 0) ?></div>
        <div class="chl-stat-hint">on the token</div>
    </div>
    <div class="chl-stat <?= ($hsm['available'] ?? false) ? 'green' : 'red' ?>">
        <div class="chl-stat-label">HSM Status</div>
        <div class="chl-stat-value" style="font-size:20px;padding-top:6px">
            <?= ($hsm['available'] ?? false) ? 'Online' : 'Offline' ?>
        </div>
        <div class="chl-stat-hint"><?= e($hsm['token'] ?? '') ?></div>
    </div>
    <div class="chl-stat">
        <div class="chl-stat-label">Audit Events (24h)</div>
        <div class="chl-stat-value"><?= (int)($d['audit_events_24h'] ?? 0) ?></div>
        <div class="chl-stat-hint"><?= (int)($d['audit_events_total'] ?? 0) ?> total</div>
    </div>
    <div class="chl-stat green">
        <div class="chl-stat-label">System Health</div>
        <div class="chl-stat-value" style="font-size:20px;padding-top:6px">Nominal</div>
        <div class="chl-stat-hint"><?= e($d['system']['database'] ?? '-') ?> ·
            KMIP <?= e($d['system']['kmip_version'] ?? '-') ?></div>
    </div>
</div>

<?php if (!($hsm['available'] ?? false)): ?>
    <div class="chl-alert">
        <strong>HSM unavailable.</strong>
        <?= e($hsm['error'] ?? 'The PKCS#11 module could not be loaded.') ?>
        <div style="margin-top:5px;color:var(--text-muted)">
            KMIP metadata remains readable; operations requiring the token will fail
            until this is resolved.
        </div>
    </div>
<?php endif; ?>

<?php
// A brand-new deployment has an empty store, and the charts below are all
// zeroes — which reads as "broken" rather than "nothing created yet". These
// are the same first steps as the README's "Initialising the UI" section,
// shown where someone who just signed in will actually look.
$is_first_run = ((int)($d['total_objects'] ?? 0) === 0);
if ($is_first_run):
?>
    <div class="chl-card" style="margin-bottom:20px">
        <div class="chl-card-head">
            <div>
                <h2 class="chl-card-title">Getting Started</h2>
                <p class="chl-card-sub">No managed objects exist yet — these are the first steps</p>
            </div>
        </div>
        <div class="chl-card-body">
            <ol style="margin:0;padding-left:22px;font-size:13px;line-height:2">
                <li>
                    <a href="account.php">Change the default administrator password</a>
                    <?php if (!using_default_password()): ?>
                        <span class="chl-badge green" style="margin-left:6px">done</span>
                    <?php endif; ?>
                </li>
                <li>
                    Confirm the token is online —
                    <?php if ($hsm['available'] ?? false): ?>
                        <span class="chl-badge green">online</span>
                        <span style="color:var(--text-muted)">
                            (<?= e($hsm['token'] ?? '') ?>)</span>
                    <?php else: ?>
                        <span class="chl-badge red">offline</span>
                        <span style="color:var(--text-muted)">
                            see <a href="pkcs11.php">PKCS#11</a></span>
                    <?php endif; ?>
                </li>
                <?php if (can('key.create')): ?>
                    <li><a href="kmip.php">Create your first key</a> from the KMIP page
                        (AES-256 is a sensible default)</li>
                <?php else: ?>
                    <li>Ask an Operator or Administrator to create the first key — your
                        <?= e(current_role()) ?> role is read-only</li>
                <?php endif; ?>
                <li><a href="keys.php">Review it under Keys</a>, then
                    <a href="audit.php">check the audit trail</a> recorded the operation</li>
                <?php if (can('user.manage')): ?>
                    <li><a href="admin.php">Create per-person accounts</a> so the audit trail
                        names real users rather than a shared administrator</li>
                <?php endif; ?>
            </ol>
        </div>
    </div>
<?php endif; ?>

<div class="chl-chart-grid">
    <div class="chl-card">
        <div class="chl-card-head">
            <div>
                <h2 class="chl-card-title">Objects by State</h2>
                <p class="chl-card-sub">KMIP lifecycle distribution</p>
            </div>
        </div>
        <div class="chl-card-body">
            <div class="chl-chart-box"><canvas id="stateChart"></canvas></div>
        </div>
    </div>

    <div class="chl-card">
        <div class="chl-card-head">
            <div>
                <h2 class="chl-card-title">Objects by Algorithm</h2>
                <p class="chl-card-sub">Cryptographic algorithm in use</p>
            </div>
        </div>
        <div class="chl-card-body">
            <div class="chl-chart-box"><canvas id="algChart"></canvas></div>
        </div>
    </div>
</div>

<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Object Inventory</h2>
            <p class="chl-card-sub">Breakdown by managed object type</p>
        </div>
        <a class="chl-btn chl-btn-sm" href="kmip.php">Open KMIP Explorer</a>
    </div>
    <div class="chl-card-body">
        <div class="chl-chart-box" style="height:220px"><canvas id="typeChart"></canvas></div>
    </div>
</div>

<script>
const byState = <?= json_encode($d['by_state'] ?? [], JSON_UNESCAPED_SLASHES) ?>;
const byAlg   = <?= json_encode($d['by_algorithm'] ?? [], JSON_UNESCAPED_SLASHES) ?>;

// Palette keeps the lifecycle meaning: green active, amber retired, red
// compromised — so the chart says the same thing the badges do.
const stateColours = {
    Active: '#00A86B', PreActive: '#1E88E5', Deactivated: '#F5A623',
    Compromised: '#D0021B', Destroyed: '#6B829C', DestroyedCompromised: '#8B1A2B'
};

function emptyMessage(canvasId, text) {
    const canvas = document.getElementById(canvasId);
    canvas.parentElement.innerHTML =
        '<div class="chl-empty"><div class="chl-empty-title">' + text + '</div>' +
        '<div>Create a key to populate this chart.</div></div>';
}

if (Object.keys(byState).length === 0) {
    emptyMessage('stateChart', 'No objects yet');
} else {
    new Chart(document.getElementById('stateChart'), {
        type: 'doughnut',
        data: {
            labels: Object.keys(byState),
            datasets: [{
                data: Object.values(byState),
                backgroundColor: Object.keys(byState).map(k => stateColours[k] || '#29B6F6'),
                borderWidth: 0
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { position: 'right' } }, cutout: '62%'
        }
    });
}

if (Object.keys(byAlg).length === 0) {
    emptyMessage('algChart', 'No algorithms recorded');
} else {
    new Chart(document.getElementById('algChart'), {
        type: 'bar',
        data: {
            labels: Object.keys(byAlg),
            datasets: [{ label: 'Objects', data: Object.values(byAlg),
                         backgroundColor: '#1E88E5', borderRadius: 5 }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
        }
    });
}

new Chart(document.getElementById('typeChart'), {
    type: 'bar',
    data: {
        labels: ['Symmetric', 'Private', 'Public', 'Certificates', 'Secret Data'],
        datasets: [{
            label: 'Count',
            data: [<?= (int)($d['symmetric_keys'] ?? 0) ?>, <?= (int)($d['private_keys'] ?? 0) ?>,
                   <?= (int)($d['public_keys'] ?? 0) ?>, <?= (int)($d['certificates'] ?? 0) ?>,
                   <?= (int)($d['secret_data'] ?? 0) ?>],
            backgroundColor: ['#1E88E5', '#D0021B', '#00A86B', '#F5A623', '#29B6F6'],
            borderRadius: 5
        }]
    },
    options: {
        indexAxis: 'y', responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }
    }
});
</script>

<?php render_foot(); ?>
