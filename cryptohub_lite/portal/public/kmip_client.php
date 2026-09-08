<?php
/**
 * KMIP client application — run any operation against the engine.
 *
 * Every other page here reaches the engine in-process. This one asks the API to
 * open a TTLV connection to port 5696, so what runs is the genuine protocol
 * path: encoding, per-request authentication, the dispatcher, and an entry in
 * the hash-chained audit log. It is the only way to exercise from a browser
 * what a third-party client would actually do.
 *
 * The forms are not written here. /api/kmip/client/operations derives them
 * from the KMIP client's own method signatures, and this page renders whatever
 * it is given — so a new client method appears with no change to this file.
 */
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$api = new ApiClient();

/*
 * Remembering the KMIP credential.
 *
 * The engine authenticates every request itself, so this page has to present a
 * password each time - and re-typing it for twenty operations in a row is the
 * kind of friction that gets solved by picking a weak password. So it can be
 * held, with three limits that keep it honest:
 *
 *   - opt-in, never automatic;
 *   - in the PHP session, which lives on the server. It is never written to the
 *     database and never handed to the browser. It does reach the container's
 *     session store on disk, which is why this is the portal's convenience and
 *     not something the API or the engine will ever do;
 *   - discarded at sign-out, because logout.php clears the whole session.
 */
if (($_POST['forget_credential'] ?? '') !== '') {
    unset($_SESSION['kmip_credential']);
    header('Location: kmip_client.php');
    exit;
}
$remembered = $_SESSION['kmip_credential'] ?? null;

$specs  = $api->get('/api/kmip/client/operations');
$ops    = $specs['ok'] ? ($specs['data']['operations'] ?? []) : [];
$result   = null;
$error    = null;
$exchange = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $operation = $_POST['operation'] ?? '';
    $spec = null;
    foreach ($ops as $o) {
        if ($o['operation'] === $operation) { $spec = $o; break; }
    }
    if (!$spec) {
        $error = 'Unknown operation.';
    } else {
        // Only fields this operation declares are forwarded; a checkbox that
        // was not ticked simply is not present in $_POST, which is the same as
        // "leave it at the default".
        $arguments = [];
        foreach ($spec['fields'] as $f) {
            $key = 'arg_' . $f['name'];
            if ($f['type'] === 'checkbox') {
                $arguments[$f['name']] = isset($_POST[$key]);
            } elseif ($f['type'] === 'flags') {
                // Each box carries one bit; the mask is their sum. Nothing
                // ticked means the argument is not sent at all, which is not
                // the same as sending zero.
                $bits = 0;
                foreach ((array)($_POST[$key] ?? []) as $bit) {
                    $bits |= (int)$bit;
                }
                if ($bits) {
                    $arguments[$f['name']] = $bits;
                }
            } elseif (isset($_POST[$key]) && $_POST[$key] !== '') {
                $arguments[$f['name']] = $_POST[$key];
            }
        }
        // Cast to object: an empty PHP array encodes as `[]`, and the API's
        // `arguments` is a mapping, so Query and an unfiltered Locate - the two
        // operations most likely to be run first - were rejected before they
        // reached the engine.
        // A typed password always wins over a held one, so correcting a wrong
        // credential does not require finding the Forget button first.
        $user     = $_POST['kmip_user'] ?? '';
        $password = $_POST['kmip_password'] ?? '';
        if ($password === '' && $remembered && ($remembered['username'] ?? '') === $user) {
            $password = $remembered['password'];
        }

        $r = $api->post('/api/kmip/client/execute', [
            'operation' => $operation,
            'arguments' => (object)$arguments,
            'username'  => $user,
            'password'  => $password,
        ]);
        $exchange = $api->lastExchange;      // captured before interpretation
        if ($r['ok']) { $result = $r['data']; }
        else          { $error  = $r['error'] ?? 'The request failed.'; }

        // Only hold a credential the engine has just accepted. A refusal is
        // usually fine - the client authenticates on connect, so the password
        // was already good - but AuthenticationNotSuccessful (3) is exactly the
        // one that is not, and storing a typo would make it outlive itself.
        $authFailed = ($result['reason_code'] ?? null) === 3;
        if (!empty($_POST['remember_credential']) && $password !== ''
                && $r['ok'] && !$authFailed) {
            $_SESSION['kmip_credential'] = ['username' => $user, 'password' => $password];
            $remembered = $_SESSION['kmip_credential'];
        }
    }
}

$selected = $_POST['operation'] ?? ($_GET['operation'] ?? 'Query');

render_head('KMIP Client');
if (!$specs['ok']) {
    render_error($specs['error'] ?? 'Could not load the operation list');
}
?>

<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">KMIP Client Application</h2>
            <p class="chl-card-sub">
                Runs as a <b>real KMIP client</b> over TTLV on port 5696 &mdash; not the
                in-process path the rest of this portal uses. Every call is
                authenticated per request and hash-chained into the audit log.
            </p>
        </div>
    </div>
    <div class="chl-card-body">

    <?php if ($error): ?>
        <div class="chl-alert warn"><strong>Failed.</strong> <?= e($error) ?></div>
    <?php endif; ?>

    <form method="post" id="clientForm">
        <?php
        // Top-aligned, not bottom-aligned: the password cell carries an extra
        // line under its input ("Forget it", or the remember tick-box), and
        // with align-items:end that line pushed its input above the other two.
        // The labels are all one line, so aligning the tops aligns the inputs.
        ?>
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));
                    gap:16px 16px;align-items:start">
            <div>
                <label class="chl-label">Operation</label>
                <?php
                // No onchange submit. Every spec is already on the page, so
                // swapping the form is a local re-render; a round-trip here
                // reloaded the whole document just to change three inputs.
                ?>
                <select class="chl-select" name="operation" id="opSelect"
                        style="width:100%">
                    <?php foreach ($ops as $o): ?>
                        <option value="<?= e($o['operation']) ?>"
                            <?= $o['operation'] === $selected ? 'selected' : '' ?>>
                            <?= e($o['operation']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <?php
            // The engine authenticates this call itself, against its own
            // identity table. The portal session cannot be reused: the API
            // holds a JWT, not a password, and the two sides hash separately.
            ?>
            <div>
                <label class="chl-label">KMIP identity</label>
                <input class="chl-input" name="kmip_user" style="width:100%"
                       value="<?= e($_POST['kmip_user']
                                    ?? $remembered['username']
                                    ?? current_username()) ?>">
            </div>
            <div>
                <label class="chl-label">Password
                    <span style="font-weight:400;color:var(--text-muted)">
                        <?= $remembered
                            ? '&mdash; held for this sign-in'
                            : '&mdash; sent for this request only' ?></span></label>
                <input class="chl-input" name="kmip_password" type="password"
                       style="width:100%" autocomplete="off"
                       placeholder="<?= $remembered
                            ? 'using the held credential - type to override'
                            : '' ?>">
                <?php if ($remembered): ?>
                    <div style="margin-top:6px;font-size:11px;color:var(--text-muted)">
                        Held in your portal session, on the server.
                        <button class="chl-btn chl-btn-sm" type="submit"
                                name="forget_credential" value="1"
                                formnovalidate style="margin-left:4px">Forget it</button>
                    </div>
                <?php else: ?>
                    <label class="chl-check" style="margin-top:6px;font-size:11px">
                        <input type="checkbox" name="remember_credential" value="1">
                        Remember until I sign out
                    </label>
                <?php endif; ?>
            </div>
        </div>

        <div id="opFields"></div>

        <div style="margin-top:20px">
            <button class="chl-btn chl-btn-primary" type="submit"
                    name="run" value="1" id="runBtn">Run over KMIP</button>
        </div>
    </form>
    </div>
</div>

<?php if ($result !== null): ?>
    <div class="chl-card">
        <div class="chl-card-head">
            <div>
                <h2 class="chl-card-title">
                    <?= e($result['operation'] ?? '') ?> &mdash;
                    <?php if (!empty($result['ok'])): ?>
                        <span class="chl-badge green">succeeded</span>
                    <?php elseif (!empty($result['refused'])): ?>
                        <span class="chl-badge amber">refused by the server</span>
                    <?php else: ?>
                        <span class="chl-badge red">failed</span>
                    <?php endif; ?>
                </h2>
                <p class="chl-card-sub">
                    <?php if (!empty($result['refused'])): ?>
                        The server understood the request and declined it. That is an
                        answer, not a fault &mdash; <span class="chl-mono">Get</span> on a
                        non-extractable key refuses by design.
                    <?php else: ?>
                        Sent as TTLV over port 5696; look for it on the
                        <a href="audit.php">Audit</a> page as a <b>kmip</b> row.
                    <?php endif; ?>
                </p>
            </div>
        </div>
        <div class="chl-card-body">
            <?php
            // The decoded view first, the wire answer underneath. Query replies
            // with `operations: [1,2,3,...]`, which is exactly what the protocol
            // said and unreadable without the spec to hand; the API resolves
            // those against the engine's own enums.
            $readable = $result['readable'] ?? null;
            ?>
            <?php if ($readable): ?>
                <table class="chl-table" style="margin:0 0 4px">
                    <tbody>
                    <?php foreach ($readable as $row): ?>
                        <tr>
                            <th style="width:200px;vertical-align:top;text-align:left;
                                       font-weight:600;white-space:nowrap">
                                <?= e($row['label']) ?>
                                <?php if (isset($row['count'])): ?>
                                    <span class="chl-badge grey"><?= (int)$row['count'] ?></span>
                                <?php endif; ?>
                            </th>
                            <td class="chl-mono" style="font-size:12px;white-space:pre-wrap;
                                       word-break:break-word"><?= e($row['value']) ?></td>
                        </tr>
                    <?php endforeach; ?>
                    </tbody>
                </table>
            <?php endif; ?>

            <details class="chl-disclose"<?= $readable ? '' : ' open' ?>>
                <summary>Raw JSON response</summary>
                <?php
                // Without the decoded view, which is this portal's addition -
                // "raw" has to mean what the engine sent.
                $wireResult = $result;
                unset($wireResult['readable']);
                ?>
                <pre class="chl-mono" style="margin:8px 0 0;white-space:pre-wrap;
                            word-break:break-all;font-size:12px;color:var(--text-muted)"><?=
                    e(json_encode($wireResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)) ?></pre>
            </details>
        </div>
    </div>
<?php endif; ?>

<?php if (!empty($exchange)): ?>
    <?php
    // Both hops, in order, because the interesting fact is where one protocol
    // stops and the other starts. Showing only the REST call would imply the
    // whole path is HTTP; showing only the TTLV would hide how the browser got
    // there.
    $wire = $result['transport'] ?? null;
    ?>
    <div class="chl-card">
        <div class="chl-card-head">
            <div>
                <h2 class="chl-card-title">What actually happened on the network</h2>
                <p class="chl-card-sub">Two hops, two protocols &mdash; the browser speaks
                    REST to the API, the API speaks KMIP to the engine</p>
            </div>
            <button type="button" class="chl-btn chl-btn-sm" id="traceToggle"
                    aria-expanded="true" aria-controls="traceBody">Collapse</button>
        </div>

        <div class="chl-card-body" id="traceBody">
            <div class="chl-stat-label" style="margin-bottom:6px">
                Hop 1 &nbsp;<span class="chl-badge blue">REST</span>&nbsp;
                browser &rarr; API &nbsp;
                <span style="font-weight:400;color:var(--text-muted)">
                    <?= e((string)$exchange['status']) ?> ·
                    <?= e((string)$exchange['elapsed_ms']) ?> ms</span>
            </div>
            <pre class="chl-mono" style="margin:0 0 8px;white-space:pre-wrap;
                 word-break:break-all;font-size:11.5px;color:var(--text-muted)"><?php
                echo e($exchange['method'] . ' ' . $exchange['url'] . "
");
                foreach ($exchange['headers'] as $h) { echo e($h . "
"); }
                if ($exchange['body'] !== null) {
                    echo "
" . e(json_encode($exchange['body'],
                         JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                }
            ?></pre>
            <p style="margin:0 0 20px;font-size:11px;color:var(--text-muted)">
                JSON over HTTP. The bearer token and password are redacted here, not
                in the request.</p>

            <div class="chl-stat-label" style="margin-bottom:6px">
                Hop 2 &nbsp;<span class="chl-badge amber">KMIP</span>&nbsp;
                API &rarr; engine
                <?php if ($wire): ?>
                    &nbsp;<span style="font-weight:400;color:var(--text-muted)">
                        <?= e($wire['endpoint']) ?> ·
                        <?= e((string)$wire['elapsed_ms']) ?> ms ·
                        <?= count($wire['frames']) ?> frames</span>
                <?php endif; ?>
            </div>
            <?php if (!$wire): ?>
                <p style="margin:0;font-size:12px;color:var(--text-muted)">
                    No KMIP hop &mdash; the request did not reach the engine.</p>
            <?php else: ?>
                <?php foreach ($wire['frames'] as $i => $frame): ?>
                    <div style="margin-bottom:8px">
                        <div style="font-size:11px;color:var(--text-muted);margin-bottom:2px">
                            <?= $frame['direction'] === 'sent' ? '&uarr; sent' : '&darr; received' ?>
                            &nbsp;<?= (int)$frame['bytes'] ?> bytes<?php
                            if ($frame['truncated']) { echo ' (first 512 shown)'; } ?>
                        </div>
                        <pre class="chl-mono" style="margin:0;white-space:pre-wrap;
                             word-break:break-all;font-size:11px;color:var(--text-muted)"><?php
                            // Grouped in 2-byte pairs; TTLV is tag(3) type(1) length(4),
                            // so raw hex is unreadable without some spacing.
                            echo e(trim(chunk_split($frame['hex'], 32, "
")));
                        ?></pre>
                    </div>
                <?php endforeach; ?>
                <p style="margin:10px 0 0;font-size:11px;color:var(--text-muted)">
                    <?= e($wire['note']) ?>. The first exchange is the authentication
                    that every KMIP request carries. This is the same byte stream any
                    third-party KMIP client would produce &mdash; nothing here is
                    specific to this portal.
                </p>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>

<div class="chl-card">
    <div class="chl-card-body" style="font-size:12px;color:var(--text-muted)">
        <b><?= count($ops) ?> operations</b> available here &mdash; every one the engine
        implements, including the <?= max(0, count($ops) - 10) ?> that have no REST
        route and are marked amber on the <a href="kmip.php">KMIP</a> page. The forms
        are generated from the client's method signatures, so they cannot drift from
        what the client accepts.
        <br><br>
        <b>Why it asks for a password.</b> The engine authenticates this call itself,
        against its own identity table. This portal holds a session token for you, not
        your password, and the two sides hash credentials separately &mdash; so the
        session cannot be reused here. The password is sent for this one request and
        is not stored. Use an account that has signed in to the portal at least once,
        or the engine will not have a credential for it.
    </div>
</div>

<?php
// The specs the API already sent, handed to the browser verbatim. Rendering
// the form here rather than server-side is what lets the operation picker
// change without a round-trip; the POST it produces is identical either way,
// and the API still validates every field against the same spec.
$submitted = [];
foreach ($_POST as $k => $v) {
    if (str_starts_with($k, 'arg_')) { $submitted[substr($k, 4)] = $v; }
}
$jsonFlags = JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT;
?>
<script id="opSpecs" type="application/json"><?= json_encode($ops, $jsonFlags) ?></script>
<script id="opSubmitted" type="application/json"><?= json_encode(
    ['operation' => $selected, 'args' => (object)$submitted], $jsonFlags) ?></script>
<script>
(function () {
    const specs = JSON.parse(document.getElementById('opSpecs').textContent);
    const prior = JSON.parse(document.getElementById('opSubmitted').textContent);
    const select = document.getElementById('opSelect');
    const host   = document.getElementById('opFields');
    const runBtn = document.getElementById('runBtn');

    const esc = s => String(s).replace(/[&<>"']/g,
        c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

    function render(name) {
        const spec = specs.find(s => s.operation === name);
        runBtn.textContent = 'Run ' + name + ' over KMIP';
        if (!spec) { host.innerHTML = ''; return; }

        // Values only survive a reload for the operation that was actually
        // submitted - carrying a "uid" from Destroy over to Create would be
        // worse than an empty field.
        const keep = prior.operation === name ? prior.args : {};
        let html = '';
        if (spec.doc) {
            html += '<p style="margin:18px 0 4px;color:var(--text-muted);font-size:12px">'
                  + esc(spec.doc) + '</p>';
        }
        if (!spec.fields.length) {
            host.innerHTML = html + '<p style="margin:14px 0 0;color:var(--text-muted);'
                + 'font-size:12px">This operation takes no arguments.</p>';
            return;
        }
        html += '<p style="margin:12px 0 0;color:var(--text-muted);font-size:12px">'
              + 'Fields marked <span style="color:#FF6B7A">*</span> are required by the '
              + 'KMIP client method; the rest are optional and are omitted from the '
              + 'request when left blank.</p>'
              + '<div style="display:grid;grid-template-columns:repeat(auto-fit,'
              + 'minmax(240px,1fr));gap:16px;margin-top:18px">';
        for (const f of spec.fields) {
            // A mask needs the full row; twenty boxes in a 240px column is
            // unreadable.
            html += '<div' + (f.type === 'flags' ? ' style="grid-column:1/-1"' : '')
                 + '><label class="chl-label">' + esc(f.name)
                 + (f.required ? ' <span style="color:#FF6B7A">*</span>' : '')
                 + (f.hint ? ' <span style="font-weight:400;color:var(--text-muted)">&mdash; '
                             + esc(f.hint) + '</span>' : '')
                 + '</label>';
            if (f.type === 'checkbox') {
                const on = (f.name in keep) ? keep[f.name] : f.default;
                html += '<label class="chl-check" style="display:block;padding-top:6px">'
                      + '<input type="checkbox" name="arg_' + esc(f.name) + '"'
                      + (on ? ' checked' : '') + '> enabled</label>';
            } else if (f.type === 'flags') {
                // A mask is several answers at once, so it gets a grid of
                // boxes - the same shape the Generate key card on the Keys
                // page uses for the very same attribute.
                const prev = keep[f.name];
                const on = Array.isArray(prev)
                    ? prev.map(Number)
                    : f.choices.filter(c => (Number(f.default) || 0) & c.value).map(c => c.value);
                html += '<div class="chl-check-grid">';
                for (const c of f.choices) {
                    html += '<label class="chl-check"><input type="checkbox" name="arg_'
                          + esc(f.name) + '[]" value="' + c.value + '"'
                          + (on.includes(c.value) ? ' checked' : '') + '> '
                          + esc(c.label) + '</label>';
                }
                html += '</div>';
            } else if (f.type === 'enum') {
                // An enum is a number only on the wire. Offering the numbers
                // and expecting someone to know that AES is 3 is the same
                // mistake the result view used to make in the other direction.
                const chosen = String((f.name in keep) ? keep[f.name]
                             : (f.default === null || f.default === undefined ? '' : f.default));
                html += '<select class="chl-select" style="width:100%" name="arg_'
                      + esc(f.name) + '">';
                if (!f.required) html += '<option value="">not sent</option>';
                for (const c of f.choices) {
                    html += '<option value="' + c.value + '"'
                          + (String(c.value) === chosen ? ' selected' : '') + '>'
                          + esc(c.label) + ' (' + c.value + ')</option>';
                }
                html += '</select>';
            } else {
                const v = (f.name in keep) ? keep[f.name]
                        : (f.default === null || f.default === undefined ? '' : f.default);
                html += '<input class="chl-input" style="width:100%" name="arg_'
                      + esc(f.name) + '" type="' + (f.type === 'number' ? 'number' : 'text')
                      + '" value="' + esc(v) + '" placeholder="'
                      + (f.required ? 'required' : 'optional') + '">';
            }
            html += '</div>';
        }
        host.innerHTML = html + '</div>';
    }

    select.addEventListener('change', () => render(select.value));
    render(select.value);
})();

// The network trace is the point of this page, so it opens by default - but it
// is long, and someone running twenty operations in a row does not want to
// scroll past it every time. The choice is remembered per browser.
(function () {
    const button = document.getElementById('traceToggle');
    const body   = document.getElementById('traceBody');
    if (!button || !body) return;

    function apply(open) {
        body.hidden = !open;
        button.textContent = open ? 'Collapse' : 'Expand';
        button.setAttribute('aria-expanded', String(open));
    }
    let open = true;
    try { open = localStorage.getItem('chl-trace-open') !== '0'; } catch (e) { /* private mode */ }
    apply(open);

    button.addEventListener('click', () => {
        open = body.hidden;
        apply(open);
        try { localStorage.setItem('chl-trace-open', open ? '1' : '0'); } catch (e) { /* ignore */ }
    });
})();
</script>

<?php render_foot(); ?>
