<?php
/**
 * The signed-in user's own account.
 *
 * Separate from Administration because every role reaches it — an Operator or
 * Auditor has no user-management rights but must still be able to change
 * their own password.
 */

declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$api    = new ApiClient();
$notice = null;
$error  = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $current = $_POST['current_password'] ?? '';
    $new     = $_POST['new_password'] ?? '';
    $confirm = $_POST['confirm_password'] ?? '';

    if ($new !== $confirm) {
        // Checked here as well as by the browser: a mismatch should not cost
        // a round trip, and `required`/`pattern` attributes are trivially
        // bypassed.
        $error = 'The new passwords do not match.';
    } elseif (strlen($new) < 8) {
        $error = 'The new password must be at least 8 characters.';
    } else {
        $result = $api->post('/api/auth/password', [
            'current_password' => $current,
            'new_password'     => $new,
        ]);
        if ($result['ok']) {
            $notice = 'Password changed.';
            // The banner is driven by this flag; clearing it here means the
            // warning goes away immediately rather than at next sign-in.
            $_SESSION['default_password'] = false;
        } else {
            $error = $result['error'] ?? 'The password could not be changed.';
        }
    }
}

$me = $api->get('/api/auth/me');
$profile = $me['ok'] ? $me['data'] : [];

render_head('My Account');

if ($notice) { echo '<div class="chl-alert info">' . e($notice) . '</div>'; }
if ($error)  { render_error($error); }
?>

<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:20px">
    <div class="chl-card">
        <div class="chl-card-head">
            <div>
                <h2 class="chl-card-title">Change Password</h2>
                <p class="chl-card-sub">Minimum 8 characters</p>
            </div>
        </div>
        <div class="chl-card-body">
            <form method="post" autocomplete="off">
                <div class="chl-field">
                    <label class="chl-label" for="current_password">Current password</label>
                    <input class="chl-input" id="current_password" name="current_password"
                           type="password" required style="width:100%">
                </div>
                <div class="chl-field">
                    <label class="chl-label" for="new_password">New password</label>
                    <input class="chl-input" id="new_password" name="new_password"
                           type="password" required minlength="8" style="width:100%">
                </div>
                <div class="chl-field">
                    <label class="chl-label" for="confirm_password">Confirm new password</label>
                    <input class="chl-input" id="confirm_password" name="confirm_password"
                           type="password" required minlength="8" style="width:100%">
                </div>
                <button class="chl-btn chl-btn-primary" type="submit">Change password</button>
            </form>
        </div>
    </div>

    <div class="chl-card">
        <div class="chl-card-head">
            <h2 class="chl-card-title">Profile</h2>
        </div>
        <div class="chl-card-body">
            <dl class="chl-attr-grid">
                <dt>Username</dt><dd><?= e($profile['username'] ?? current_username()) ?></dd>
                <dt>Display name</dt><dd><?= e($profile['display_name'] ?? '—') ?></dd>
                <dt>Role</dt><dd><?= e($profile['role'] ?? current_role()) ?></dd>
            </dl>

            <div class="chl-stat-label" style="margin:18px 0 8px">Your capabilities</div>
            <div style="display:flex;flex-wrap:wrap;gap:5px">
                <?php foreach ($profile['capabilities'] ?? [] as $capability): ?>
                    <span class="chl-badge grey"><?= e($capability) ?></span>
                <?php endforeach; ?>
            </div>
            <p style="margin-top:14px;color:var(--text-muted);font-size:12px">
                The same account is used by KMIP clients. Changing this password changes
                the credential any KMIP client signing in as
                <strong><?= e(current_username()) ?></strong> must present.
            </p>
        </div>
    </div>
</div>

<?php render_foot(); ?>
