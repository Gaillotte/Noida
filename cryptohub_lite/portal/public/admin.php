<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$api    = new ApiClient();
$notice = null;
$error  = null;

// Mutations happen before the listing is fetched, so the table reflects them.
if ($_SERVER['REQUEST_METHOD'] === 'POST' && can('user.manage')) {
    $action = $_POST['action'] ?? '';

    if ($action === 'create') {
        $r = $api->post('/api/admin/users', [
            'username'     => trim($_POST['username'] ?? ''),
            'password'     => $_POST['password'] ?? '',
            'role'         => $_POST['role'] ?? 'ReadOnly',
            'display_name' => trim($_POST['display_name'] ?? ''),
            'email'        => trim($_POST['email'] ?? ''),
        ]);
        $r['ok'] ? $notice = 'User created.' : $error = $r['error'];

    } elseif ($action === 'role') {
        $r = $api->patch('/api/admin/users/' . rawurlencode($_POST['username'] ?? ''),
                         ['role' => $_POST['role'] ?? 'ReadOnly']);
        $r['ok'] ? $notice = 'Role updated.' : $error = $r['error'];

    } elseif ($action === 'toggle') {
        $r = $api->patch('/api/admin/users/' . rawurlencode($_POST['username'] ?? ''),
                         ['enabled' => ($_POST['enabled'] ?? '0') === '1']);
        $r['ok'] ? $notice = 'User updated.' : $error = $r['error'];

    } elseif ($action === 'reset_password') {
        $r = $api->patch('/api/admin/users/' . rawurlencode($_POST['username'] ?? ''),
                         ['password' => $_POST['password'] ?? '']);
        $r['ok'] ? $notice = 'Password reset. Tell the user to change it.' : $error = $r['error'];

    } elseif ($action === 'delete') {
        $r = $api->delete('/api/admin/users/' . rawurlencode($_POST['username'] ?? ''));
        $r['ok'] ? $notice = 'User deleted.' : $error = $r['error'];
    }
}

$rolesResult = $api->get('/api/admin/roles');
$roles = $rolesResult['ok'] ? $rolesResult['data'] : [];

$users = [];
if (can('user.manage')) {
    $usersResult = $api->get('/api/admin/users');
    $users = $usersResult['ok'] ? $usersResult['data'] : [];
    if (!$usersResult['ok'] && !$error) {
        $error = $usersResult['error'];
    }
}

render_head('Administration');

if ($notice) { echo '<div class="chl-alert info">' . e($notice) . '</div>'; }
if ($error)  { render_error($error); }

if (!can('user.manage')) {
    echo '<div class="chl-alert warn"><strong>User management not permitted.</strong> '
       . 'The role <strong>' . e(current_role()) . '</strong> cannot manage users. '
       . 'The role reference below is shown for information.</div>';
}
?>

<?php if (can('user.manage')): ?>
<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Users</h2>
            <p class="chl-card-sub"><?= count($users) ?> account(s)</p>
        </div>
    </div>
    <div class="chl-table-wrap">
        <table class="chl-table">
            <thead><tr><th>Username</th><th>Display name</th><th>Role</th>
                       <th>Status</th><th>Last sign-in</th><th></th></tr></thead>
            <tbody>
            <?php foreach ($users as $u): ?>
                <tr>
                    <td><strong><?= e($u['username']) ?></strong></td>
                    <td><?= e($u['display_name'] ?? '') ?></td>
                    <td>
                        <form method="post" style="display:flex;gap:6px;align-items:center">
                            <input type="hidden" name="action" value="role">
                            <input type="hidden" name="username" value="<?= e($u['username']) ?>">
                            <select class="chl-select" name="role" onchange="this.form.submit()">
                                <?php foreach ($roles as $role): ?>
                                    <option value="<?= e($role['name']) ?>"
                                        <?= ($u['role'] ?? '') === $role['name'] ? 'selected' : '' ?>>
                                        <?= e($role['name']) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </form>
                    </td>
                    <td>
                        <?= !empty($u['enabled'])
                            ? '<span class="chl-badge green">Enabled</span>'
                            : '<span class="chl-badge red">Disabled</span>' ?>
                    </td>
                    <td class="chl-mono">
                        <?= $u['last_login']
                            ? e(date('Y-m-d H:i', (int)$u['last_login']))
                            : 'never' ?>
                    </td>
                    <td>
                        <div style="display:flex;gap:6px">
                            <form method="post">
                                <input type="hidden" name="action" value="toggle">
                                <input type="hidden" name="username" value="<?= e($u['username']) ?>">
                                <input type="hidden" name="enabled"
                                       value="<?= !empty($u['enabled']) ? '0' : '1' ?>">
                                <button class="chl-btn chl-btn-sm" type="submit">
                                    <?= !empty($u['enabled']) ? 'Disable' : 'Enable' ?></button>
                            </form>
                            <form method="post" style="display:flex;gap:4px"
                                  onsubmit="return confirm('Reset the password for <?= e($u['username']) ?>?')">
                                <input type="hidden" name="action" value="reset_password">
                                <input type="hidden" name="username" value="<?= e($u['username']) ?>">
                                <input class="chl-input chl-btn-sm" name="password" type="password"
                                       placeholder="New password" required minlength="8"
                                       style="width:130px;padding:4px 8px;font-size:11.5px">
                                <button class="chl-btn chl-btn-sm" type="submit">Reset</button>
                            </form>
                            <?php if ($u['username'] !== current_username()): ?>
                                <form method="post"
                                      onsubmit="return confirm('Delete <?= e($u['username']) ?>? This cannot be undone.')">
                                    <input type="hidden" name="action" value="delete">
                                    <input type="hidden" name="username" value="<?= e($u['username']) ?>">
                                    <button class="chl-btn chl-btn-sm" type="submit">Delete</button>
                                </form>
                            <?php endif; ?>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<div class="chl-card">
    <div class="chl-card-head">
        <h2 class="chl-card-title">Add User</h2>
    </div>
    <div class="chl-card-body">
        <form method="post" class="chl-toolbar" style="align-items:flex-end">
            <input type="hidden" name="action" value="create">
            <div>
                <label class="chl-label">Username</label>
                <input class="chl-input" name="username" required>
            </div>
            <div>
                <label class="chl-label">Display name</label>
                <input class="chl-input" name="display_name">
            </div>
            <div>
                <label class="chl-label">Password</label>
                <!-- Minimum enforced by the API too; stated here so the rule is
                     visible before submitting rather than after. -->
                <input class="chl-input" name="password" type="password" required minlength="8">
            </div>
            <div>
                <label class="chl-label">Role</label>
                <select class="chl-select" name="role">
                    <?php foreach ($roles as $role): ?>
                        <option value="<?= e($role['name']) ?>"><?= e($role['name']) ?></option>
                    <?php endforeach; ?>
                </select>
            </div>
            <button class="chl-btn chl-btn-primary" type="submit">Create</button>
        </form>
    </div>
</div>
<?php endif; ?>

<div class="chl-card">
    <div class="chl-card-head">
        <div>
            <h2 class="chl-card-title">Roles &amp; Capabilities</h2>
            <p class="chl-card-sub">What a role governs &mdash; and what it does not</p>
        </div>
    </div>
    <?php
    // "Is this a database role or a KMIP role?" is a fair question the table
    // alone does not answer, and the honest answer is neither-and-both: these
    // gate the REST API, and two of them additionally grant admin inside the
    // KMIP engine. Nothing here is a PostgreSQL role.
    ?>
    <div class="chl-card-body" style="border-bottom:1px solid var(--border);
                font-size:12px;color:var(--text-muted)">
        <p style="margin:0 0 10px">
            These are <b>application roles</b>, checked on every REST API request.
            They are <b>not database roles</b> &mdash; PostgreSQL is reached by a
            single service account that every container shares, and no portal user
            ever holds a database credential.
        </p>
        <p style="margin:0">
            They do reach the KMIP service, but only in one specific way:
            <b>Administrator</b> and <b>SecurityOfficer</b> are projected into the
            engine's own <span class="chl-mono">admin</span> role, which grants
            unconditional access to every managed object regardless of who owns it.
            The other three roles are not projected, so over KMIP those identities
            get only what ownership and explicit grants give them. A demotion here
            takes effect for that user's KMIP client too.
        </p>
    </div>
    <div class="chl-table-wrap">
        <table class="chl-table">
            <thead><tr><th>Role</th><th>Description</th><th>Capabilities</th></tr></thead>
            <tbody>
            <?php foreach ($roles as $role): ?>
                <tr>
                    <td><strong><?= e($role['name']) ?></strong></td>
                    <td style="color:var(--text-muted)"><?= e($role['description'] ?? '') ?></td>
                    <td>
                        <div style="display:flex;flex-wrap:wrap;gap:5px">
                            <?php foreach ($role['capabilities'] ?? [] as $cap): ?>
                                <span class="chl-badge grey"><?= e($cap) ?></span>
                            <?php endforeach; ?>
                        </div>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</div>

<?php render_foot(); ?>
