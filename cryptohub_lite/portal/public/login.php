<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';

if (is_authenticated()) {
    header('Location: index.php');
    exit;
}

$error = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    $result = (new ApiClient(null))->login($username, $password);

    if ($result['ok']) {
        // Regenerated on privilege change to prevent session fixation: an
        // attacker who fixed the pre-login id must not inherit the session.
        session_regenerate_id(true);
        $_SESSION['token']        = $result['data']['access_token'];
        $_SESSION['username']     = $result['data']['username'];
        $_SESSION['role']         = $result['data']['role'];
        $_SESSION['display_name'] = $result['data']['display_name'];
        $_SESSION['capabilities'] = $result['data']['capabilities'];
        // Drives the banner on every page until the password is changed.
        $_SESSION['default_password'] = !empty($result['data']['using_default_password']);
        header('Location: index.php');
        exit;
    }

    $error = $result['error'] ?? 'Sign-in failed';
}
?>
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in · IDEMIA CryptoHub Lite</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/idemia.css" rel="stylesheet">
</head>
<body>
<div class="chl-login">
    <div class="chl-login-card">
        <div class="chl-login-brand">
            <div class="chl-login-mark">ID</div>
            <div style="font-weight:700;letter-spacing:.05em;font-size:16px">IDEMIA</div>
            <div style="color:var(--text-muted);font-size:13px">CryptoHub Lite</div>
        </div>

        <?php if ($error): ?>
            <div class="chl-alert"><?= e($error) ?></div>
        <?php endif; ?>

        <form method="post" autocomplete="off">
            <div class="chl-field">
                <label class="chl-label" for="username">Username</label>
                <input class="chl-input" id="username" name="username" required autofocus
                       value="<?= e($_POST['username'] ?? '') ?>">
            </div>
            <div class="chl-field">
                <label class="chl-label" for="password">Password</label>
                <input class="chl-input" id="password" name="password" type="password" required>
            </div>
            <button class="chl-btn chl-btn-primary" style="width:100%;justify-content:center"
                    type="submit">Sign in</button>
        </form>

        <div style="margin-top:20px;padding-top:16px;border-top:1px solid var(--border);
                    font-size:11.5px;color:var(--text-dim);text-align:center">
            Enterprise Key Management · KMIP 2.1 · PKCS#11
        </div>
    </div>
</div>
</body>
</html>
