<?php
/**
 * The "Generate key" card. Included by the Keys page.
 *
 * It was on the KMIP page too, which is defensible — Create and CreateKeyPair
 * are KMIP operations — but two copies of the same form made the two pages read
 * as interchangeable when they answer different questions, and on the KMIP page
 * it pushed that page's own content (attributes, grants, lifecycle actions)
 * below the fold. Generation lives here; KMIP links to it.
 *
 * Kept as a separate include rather than inlined: it is ~150 lines of form that
 * would otherwise bury the key list in keys.php, and $create_back keeps it
 * reusable if a second entry point is ever wanted again.
 *
 * The including page sets $create_back to the file it wants to return to.
 *
 * Every checkbox below maps to a PKCS#11 attribute the engine actually sets.
 * Anything the engine fixes for itself — a private key is always sensitive and
 * never extractable — is shown as fixed rather than
 * offered as a choice the system would silently ignore.
 */

declare(strict_types=1);

if (!can('key.create')) {
    return;
}

$create_back = $create_back ?? basename($_SERVER['PHP_SELF']);
?>
<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Generate key</h2>
            <p class="chl-card-sub">Created on the token, not in PHP</p>
        </div>
    </div>
    <div class="chl-card-body">
        <form method="post" action="kmip_action.php" id="createKeyForm">
            <input type="hidden" name="action" value="create" id="ckAction">
            <input type="hidden" name="back" value="<?= e($create_back) ?>">
            <input type="hidden" name="algorithm" value="AES" id="ckAlgorithm">

            <div class="chl-field">
                <label class="chl-label">Algorithm</label>
                <div class="chl-seg" id="ckSeg">
                    <button type="button" class="chl-seg-btn active" data-algorithm="AES">AES</button>
                    <button type="button" class="chl-seg-btn" data-algorithm="TDES">3DES</button>
                    <button type="button" class="chl-seg-btn" data-algorithm="RSA">RSA</button>
                    <button type="button" class="chl-seg-btn" data-algorithm="EC">ECC</button>
                    <button type="button" class="chl-seg-btn" data-algorithm="DSA">DSA</button>
                </div>
            </div>

            <div class="chl-field" id="ckLengthWrap">
                <label class="chl-label" for="ckLength">Key size</label>
                <select class="chl-select" id="ckLength" name="length"></select>
            </div>

            <div class="chl-field" id="ckCurveWrap" style="display:none">
                <label class="chl-label" for="ckCurve">Curve</label>
                <select class="chl-select" id="ckCurve" name="curve">
                    <option value="P_256">P-256 (secp256r1)</option>
                    <option value="P_384">P-384 (secp384r1)</option>
                    <option value="P_521">P-521 (secp521r1)</option>
                    <option value="P_224">P-224 (secp224r1)</option>
                    <option value="P_192">P-192 (secp192r1)</option>
                    <option value="SECP256K1">secp256k1</option>
                </select>
                <div class="chl-hint">The curve fixes the key size, so no length is sent.</div>
            </div>

            <div class="chl-field">
                <label class="chl-label" for="ckName">Label <span class="chl-req">*</span></label>
                <input class="chl-input" id="ckName" name="name" required maxlength="64"
                       placeholder="e.g. signing-key-2026">
                <div class="chl-hint">
                    KMIP <code>Name</code> and PKCS#11 <code>CKA_LABEL</code> — how you will
                    find this key later.<span id="ckPairNaming"> A key pair becomes
                    <code><span class="ckLabelEcho">label</span>_priv</code> and
                    <code><span class="ckLabelEcho">label</span>_pub</code>.</span>
                </div>
            </div>

            <div class="chl-field">
                <label class="chl-label">Key usage attributes</label>

                <div class="chl-check-grid" id="ckSymUsage">
                    <label class="chl-check"><input type="checkbox" name="encrypt" value="1" checked> CKA_ENCRYPT</label>
                    <label class="chl-check"><input type="checkbox" name="decrypt" value="1" checked> CKA_DECRYPT</label>
                    <label class="chl-check"><input type="checkbox" name="wrap" value="1"> CKA_WRAP</label>
                    <label class="chl-check"><input type="checkbox" name="unwrap" value="1"> CKA_UNWRAP</label>
                    <label class="chl-check"><input type="checkbox" name="sensitive" value="1" checked> CKA_SENSITIVE</label>
                    <label class="chl-check"><input type="checkbox" name="extractable" value="1"> CKA_EXTRACTABLE</label>
                </div>

                <div class="chl-check-grid" id="ckAsymUsage" style="display:none">
                    <label class="chl-check"><input type="checkbox" name="sign" value="1" checked> CKA_SIGN <span class="chl-hint-inline">private</span></label>
                    <label class="chl-check"><input type="checkbox" name="verify" value="1" checked> CKA_VERIFY <span class="chl-hint-inline">public</span></label>
                    <label class="chl-check"><input type="checkbox" name="derive" value="1"> CKA_DERIVE <span class="chl-hint-inline">key agreement</span></label>
                </div>

                <div class="chl-hint" id="ckAsymFixed" style="display:none">
                    The private half is always <code>CKA_SENSITIVE</code> and never
                    <code>CKA_EXTRACTABLE</code>; the public half is neither. The engine
                    fixes both, so they are not offered here.
                </div>
            </div>

            <div class="chl-field">
                <label class="chl-label">Key ID (CKA_ID)</label>
                <input class="chl-input" value="Generated on the token" disabled>
                <div class="chl-hint">
                    16 random bytes chosen by the engine. Shown in the key list once the
                    key exists — it is not something you supply.
                </div>
            </div>

            <button class="chl-btn chl-btn-primary chl-btn-block" type="submit">Generate key</button>
        </form>
    </div>
</div>

<script>
// Which sizes and which attributes apply is a property of the algorithm, so
// one table drives every dependent control rather than five ad-hoc branches.
const CK_ALGORITHMS = {
    AES:  {kind: 'symmetric', lengths: [256, 192, 128]},
    TDES: {kind: 'symmetric', lengths: [192, 128]},
    RSA:  {kind: 'keypair',   lengths: [2048, 3072, 4096]},
    DSA:  {kind: 'keypair',   lengths: [2048, 1024]},
    EC:   {kind: 'keypair',   curve: true},
};

function ckSelect(algorithm) {
    document.getElementById('ckAlgorithm').value = algorithm;
    document.querySelectorAll('#ckSeg .chl-seg-btn').forEach(button =>
        button.classList.toggle('active', button.dataset.algorithm === algorithm));
    ckSync();
}

function ckSync() {
    const algorithm = document.getElementById('ckAlgorithm').value;
    const spec = CK_ALGORITHMS[algorithm];
    const keypair = spec.kind === 'keypair';
    const curve = !!spec.curve;

    document.getElementById('ckAction').value = keypair ? 'create_keypair' : 'create';
    document.getElementById('ckCurveWrap').style.display  = curve ? '' : 'none';
    document.getElementById('ckLengthWrap').style.display = curve ? 'none' : '';
    document.getElementById('ckSymUsage').style.display   = keypair ? 'none' : '';
    document.getElementById('ckAsymUsage').style.display  = keypair ? '' : 'none';
    document.getElementById('ckAsymFixed').style.display  = keypair ? '' : 'none';

    // Disabled, not merely hidden: a hidden input still posts, and a request
    // carrying CKA_WRAP for an RSA key pair would misrepresent it in the audit
    // trail even though the engine ignores it.
    document.getElementById('ckCurve').disabled  = !curve;
    document.getElementById('ckLength').disabled = curve;
    document.querySelectorAll('#ckSymUsage input').forEach(i => i.disabled = keypair);
    document.querySelectorAll('#ckAsymUsage input').forEach(i => i.disabled = !keypair);

    const select = document.getElementById('ckLength');
    if (!curve) {
        const previous = select.value;
        select.innerHTML = '';
        spec.lengths.forEach(bits => {
            const option = document.createElement('option');
            option.value = bits;
            option.textContent = bits + ' bit';
            select.appendChild(option);
        });
        if ([...select.options].some(o => o.value === previous)) select.value = previous;
    }
    ckEcho();
}

// Shows what the two objects will be called, because the engine appends the
// suffixes and discovering "_priv" only after the fact is a surprise.
function ckEcho() {
    const keypair = CK_ALGORITHMS[document.getElementById('ckAlgorithm').value].kind === 'keypair';
    const label = document.getElementById('ckName').value || 'label';
    document.querySelectorAll('.ckLabelEcho').forEach(node => node.textContent = label);
    document.getElementById('ckPairNaming').style.display = keypair ? '' : 'none';
}

document.querySelectorAll('#ckSeg .chl-seg-btn').forEach(button =>
    button.addEventListener('click', () => ckSelect(button.dataset.algorithm)));
document.getElementById('ckName').addEventListener('input', ckEcho);
ckSync();
</script>
