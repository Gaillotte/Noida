<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_once __DIR__ . '/../inc/kmip.php';
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
// The Generate key card used to sit here as well as on the Keys page. Create
// and CreateKeyPair are genuine KMIP operations, so it was not out of place —
// but at the top of this page it pushed the things only this page offers (the
// attribute and grant detail, and the lifecycle actions) below the fold, and
// having the same form in two places made the two pages look interchangeable
// when they answer different questions. Generation now lives on the Keys page
// alone, reached from the header button below.
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
            <p class="chl-card-sub"><?= count($objects) ?> object(s) ·
                lifecycle, attributes and delegated access.
                <a href="keys.php">Keys</a> lists the same objects by their key
                material.</p>
        </div>
        <div class="chl-toolbar">
            <input class="chl-input" id="kmipSearch" placeholder="Search…"
                   oninput="filterTable('kmipSearch','kmipTable')">
            <?php if (can('key.create')): ?>
                <?php
                // The return leg of the pair. Creating a key is a KMIP
                // operation (Create / CreateKeyPair), so this is a signpost to
                // where the form lives rather than an admission that it is
                // somebody else's job.
                ?>
                <a class="chl-btn chl-btn-sm chl-btn-primary" href="keys.php"
                   title="Create and CreateKeyPair run on the Keys page">Generate key →</a>
            <?php endif; ?>
        </div>
    </div>

    <?php if (!$objects): ?>
        <div class="chl-empty">
            <div class="chl-empty-title">No managed objects</div>
            <div>Generate one on the <a href="keys.php">Keys</a> page, or create
                it over KMIP on port 5696 — either way it appears here, with its
                full lifecycle.</div>
        </div>
    <?php else: ?>
        <div class="chl-table-wrap">
            <table class="chl-table" id="kmipTable">
                <thead>
                <?php
                // Algorithm and Length are deliberately not here. They are the
                // key's material, which the Keys page lists alongside CKA_ID,
                // size and usage flags — and they are still on the Inspect
                // panel above. Repeating them made the two tables look like the
                // same view of the same thing, which buried what is actually
                // only here: the KMIP identifier, the owner, and the lifecycle.
                ?>
                <tr>
                    <th>Name</th><th>UID</th><th>Type</th><th>State</th>
                    <th>Owner</th><th>Actions</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($objects as $o): ?>
                    <tr>
                        <td><strong><?= e($o['name'] ?? '(unnamed)') ?></strong></td>
                        <td><?= uid_chip($o['uid'] ?? null) ?></td>
                        <td><?= type_badge($o['object_type'] ?? null) ?></td>
                        <td><?= state_badge($o['state'] ?? null) ?></td>
                        <td><?= e($o['owner'] ?? '—') ?></td>
                        <td>
                            <div style="display:flex;gap:5px;flex-wrap:wrap;align-items:center">
                                <a class="chl-btn chl-btn-sm"
                                   href="kmip.php?uid=<?= urlencode((string)$o['uid']) ?>">Inspect</a>
                                <?php $back = 'kmip.php'; require __DIR__ . '/../inc/lifecycle_actions.php'; ?>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>

<?php
// Asked of the engine rather than listed here. The badge list used to be
// hardcoded and had drifted from the count beside it — the card said 41
// operations while showing 28 of them. /api/kmip/operations reads the
// dispatcher's handler table, which is what actually decides whether an
// operation runs, so the two can no longer disagree.
$ops_result = $api->get('/api/kmip/operations');
$ops = $ops_result['ok'] ? $ops_result['data'] : null;
?>
<?php if ($ops): ?>
<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Supported KMIP Operations</h2>
            <p class="chl-card-sub"><?= (int)$ops['implemented_count'] ?> of
                <?= (int)$ops['total'] ?> operations implemented by the KMIP engine &mdash;
                <b>every one of them can be run from this portal</b>, on the
                <a href="kmip_client.php">KMIP Client</a> page. Some also have
                buttons and forms of their own &mdash; which take exactly the same
                route to the engine.</p>
        </div>
    </div>
    <div class="chl-card-body">
        <?php
        // A legend, because three states rendered as coloured pills are not
        // self-explanatory - and the first question the card provoked was
        // whether a grey badge meant KMIP does not define the operation. It
        // does not: grey/green are both implemented.
        ?>
        <?php
        // This legend has been wrong twice, in opposite directions, so it is
        // worth being exact about what the colours now mean.
        //
        // They once implied green was portal-only and unavailable to a KMIP
        // client; that was backwards. It was then reworded to say amber meant
        // "KMIP client only - no portal route", which was true until the KMIP
        // Client Application shipped. It is not true now: that page drives all
        // 41 over real TTLV, so every implemented operation is reachable from a
        // browser. What is left for the colour to say is only whether an
        // operation has a screen built around it, or is run from the generic
        // form - which is a statement about the user interface, not about
        // capability.
        ?>
        <p style="margin:0 0 12px;font-size:12px;color:var(--text-muted)">
            <b>All <?= (int)($ops['implemented_count'] ?? 0) ?> implemented operations
            can be run from this portal</b> and by any KMIP client on port 5696 &mdash;
            and they all take <b>one path</b>: TTLV on 5696, through the dispatcher,
            into the hash-chained audit log. Nothing here reaches the engine any other
            way. The colour is about the <i>interface</i> only: whether a page has a
            screen built around the operation, or you drive it from the generic form.
        </p>
        <div style="display:flex;flex-wrap:wrap;gap:18px;align-items:center;
                    padding-bottom:14px;margin-bottom:16px;
                    border-bottom:1px solid var(--border);font-size:11.5px;
                    color:var(--text-muted)">
            <span><span class="chl-badge green">Example &#9679;</span>
                &nbsp;<b>has a button or form here</b></span>
            <span><span class="chl-badge amber">Example &#9675;</span>
                &nbsp;drive it from the <b><a href="kmip_client.php">KMIP Client</a></b> page.
                A hollow dot marks the reads whose information these pages still
                <i>display</i> without performing the operation</span>
            <span><span class="chl-badge grey"
                       style="opacity:.6;text-decoration:line-through">Example</span>
                &nbsp;<b>not implemented</b> &mdash; unavailable to anyone</span>
        </div>

        <?php
        // Grouped by what each operation is for. A flat run of 41 badges gave no
        // sense of why the set is so broad — in particular that the protocol
        // does not only administer keys, it will use them on the caller's
        // behalf, which is the whole reason the key can stay in the HSM.
        // The groups come from the API so this page holds no operation list.
        ?>
        <?php foreach ($ops['groups'] as $group): ?>
            <div style="margin-bottom:20px">
                <div class="chl-stat-label" style="margin-bottom:4px">
                    <?= e($group['title']) ?>
                    (<?= count($group['operations']) ?>)
                </div>
                <p style="margin:0 0 8px;color:var(--text-muted);font-size:12px">
                    <?= e($group['description']) ?></p>
                <div style="display:flex;flex-wrap:wrap;gap:7px">
                    <?php foreach ($group['operations'] as $op): ?>
                        <?php
                        // The API used to return plain strings here and now returns
                        // {name, rest}. Both are accepted so that a portal container
                        // restarted ahead of the API still renders instead of erroring.
                        $name  = is_array($op) ? ($op['name'] ?? '') : $op;
                        $rest  = is_array($op) ? ($op['rest'] ?? []) : [];
                        $where = [];
                        foreach ($rest as $r) {
                            $where[] = ($r['kind'] === 'invokes' ? '' : '~ ')
                                     . $r['method'] . ' ' . $r['path'];
                        }
                        // Green means: a button or form on these pages runs it.
                        //
                        // Read from the portal's own action table, not from the
                        // REST API's route annotations. Those annotations became
                        // the wrong source when these actions moved onto the KMIP
                        // path: chl-api still has the endpoints, but the portal no
                        // longer calls them, so a badge derived from them would
                        // describe a route nobody takes.
                        //
                        // The colour is now a statement about the *interface*
                        // only. Every operation, green or amber, reaches the
                        // engine the same way - as TTLV on 5696, through the
                        // dispatcher, into the hash-chained audit log. What
                        // differs is whether this portal has built a screen
                        // around it or you drive it from the generic form.
                        $performs = in_array($name, KMIP_PORTAL_OPERATIONS, true);
                        // Kept only to mark the few reads whose information these
                        // pages still display without performing the operation.
                        $equivalent = array_values(array_filter(
                            $rest, fn($r) => ($r['kind'] ?? '') !== 'invokes'));
                        $cls = $performs ? 'green' : 'amber';
                        if ($performs) {
                            $tip = "A form or button on these pages runs it, over KMIP on 5696 - "
                                 . "the same path a third-party client takes, and the same "
                                 . "hash-chained audit entry.";
                        } elseif ($equivalent) {
                            $tip = "Run it on the KMIP Client page, or from any KMIP client on 5696."
                                 . "

These pages show the same information without performing "
                                 . "the operation - they still read the metadata store directly:
"
                                 . implode("
", array_map(
                                     fn($r) => $r['method'] . ' ' . $r['path'], $equivalent));
                        } else {
                            $tip = 'Run it on the KMIP Client page, which drives all 41, or from '
                                 . 'any KMIP client on 5696. No page here is built around it.';
                        }
                        ?>
                        <span class="chl-badge <?= $cls ?>" title="<?= e($tip) ?>">
                            <?= e($name) ?><?= $performs ? ' &#9679;' : ($equivalent ? ' &#9675;' : '') ?></span>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endforeach; ?>

        <?php if (!empty($ops['deferred'])): ?>
            <div style="border-top:1px solid var(--border);padding-top:18px">
                <div class="chl-stat-label" style="margin-bottom:4px">
                    Not implemented (<?= count($ops['deferred']) ?>)</div>
                <p style="margin:0 0 8px;color:var(--text-muted);font-size:12px">
                    <?= e($ops['deferred_reason'] ?? '') ?></p>
                <div style="display:flex;flex-wrap:wrap;gap:7px">
                    <?php foreach ($ops['deferred'] as $op): ?>
                        <?php // Struck through, so "absent" cannot be mistaken for
                              // "present but wire-only" at a glance. ?>
                        <span class="chl-badge grey"
                              style="opacity:.6;text-decoration:line-through"
                              title="Not implemented by this engine. A client calling it receives OperationNotSupported."><?= e($op) ?></span>
                    <?php endforeach; ?>
                </div>
            </div>
        <?php endif; ?>

        <p style="margin:16px 0 0;color:var(--text-muted);font-size:12px">
            Every operation is executed by the KMIP engine over its own TCP listener on
            port 5696 &mdash; including the ones driven from this portal, which reach it
            through <span class="chl-mono">chl-client-app</span>, the one service that
            speaks KMIP. A key generated from the Keys page and one created by a
            third-party client are now indistinguishable: same request, same
            authentication, same entry in the audit chain.
        </p>
    </div>
</div>

<?php
// The full definition, at the foot of the page.
//
// The old wording here drew the line at whether secret material would cross
// the portal tier, which was the honest reason some operations had no page.
// The KMIP Client Application changed that: it will run Encrypt or Get from a
// browser, plaintext and all. Pretending otherwise would make this card the
// one place in the product that still denies what another page plainly does.
// So the line is now drawn where it actually falls - a dedicated screen, or
// the generic form - and the material question is stated where it belongs, as
// the reason routine work has purpose-built pages and the rest does not.
// Counted from the portal's own action table - the same source the badges
// use, so the legend and the badges cannot disagree.
$performed = 0;
foreach (($ops['groups'] ?? []) as $g) {
    foreach ($g['operations'] as $o) {
        $n = is_array($o) ? ($o['name'] ?? '') : $o;
        if (in_array($n, KMIP_PORTAL_OPERATIONS, true)) { $performed++; }
    }
}
$legend = [
    ['green', 'Example &#9679;',
     'Has a button or form here',
     'The everyday lifecycle work &mdash; generating a key, activating, revoking, '
     . 'destroying. Purpose-built controls with sensible defaults, which then send '
     . 'exactly the KMIP request a third-party client would. Nothing secret passes '
     . 'through the browser.',
     $performed],
    ['amber', 'Example &#9675;',
     'Drive it from the KMIP Client page',
     'No screen of its own. Often that is because the operation would carry '
     . 'plaintext or key bytes through the browser; the KMIP Client page is a '
     . 'deliberate exception, for proving the engine works, which is why it asks '
     . 'for a KMIP password every time. A hollow dot marks the few &mdash; '
     . 'GetAttributes, GetAttributeList, Locate, Query &mdash; whose information '
     . 'these pages still show by reading the metadata store rather than by asking '
     . 'the engine. Those reads are the last part of this portal not yet on the '
     . 'KMIP path.',
     (int)($ops['implemented_count'] ?? 0) - $performed],
    ['grey', 'Example',
     'Nobody can &mdash; not built',
     'Session and asynchronous operations that do not suit a server which '
     . 'authenticates every request. A client calling one is told so.',
     count($ops['deferred'] ?? [])],
];
?>
<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">What the colours mean</h2>
            <p class="chl-card-sub">And why the split falls where it does</p>
        </div>
    </div>
    <div class="chl-table-wrap">
        <table class="chl-table">
            <thead><tr>
                <th style="width:110px">Colour</th>
                <th style="width:70px">How many</th>
                <th style="width:240px">Who can run it</th>
                <th>Why</th>
            </tr></thead>
            <tbody>
            <?php foreach ($legend as [$cls, $sample, $who, $why, $count]): ?>
                <tr>
                    <td><span class="chl-badge <?= $cls ?>"
                              <?= $cls === 'grey' ? 'style="opacity:.6;text-decoration:line-through"' : '' ?>><?= $sample ?></span></td>
                    <td><strong><?= $count ?></strong></td>
                    <td><strong><?= $who ?></strong></td>
                    <td style="color:var(--text-muted)"><?= $why ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <div class="chl-card-body" style="color:var(--text-muted);font-size:12px">
        <p style="margin:0 0 8px"><b>The rule:</b> an operation appears in the portal
        only when <b>nothing secret passes through it</b>.</p>
        <p style="margin:0 0 8px">
            <span class="chl-badge green" style="font-size:10px">Create</span>
            sends &ldquo;AES, 256&rdquo; and gets back an identifier &mdash; the key is
            generated inside the HSM and never leaves it, so the browser, the web tier
            and the audit log see nothing worth stealing.
            <span class="chl-badge amber" style="font-size:10px">Encrypt</span> would
            carry your plaintext, and
            <span class="chl-badge amber" style="font-size:10px">Register</span> would
            carry raw key bytes, through every one of those layers. Those stay on the
            KMIP connection, where the application talks to the engine directly.
        </p>
        <p style="margin:0">
            Not every green one is deliberate, though. The five attribute operations and
            Archive/Recover carry no secret and could reasonably be here &mdash; nobody has
            built the page. Green and amber together are the
            <?= (int)($ops['implemented_count'] ?? 0) ?> the engine implements; the counts
            come from the engine's dispatcher and this application's route table, so they
            follow the code.
        </p>
    </div>
<?php endif; ?>

<?php render_foot(); ?>
