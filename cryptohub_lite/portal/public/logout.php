<?php
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';

// Tell the API first, so the sign-out is audited while the token is still
// valid; then destroy the local session regardless of the outcome.
if (is_authenticated()) {
    (new ApiClient())->post('/api/auth/logout');
}

$_SESSION = [];
if (ini_get('session.use_cookies')) {
    $p = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000, $p['path'], $p['domain'], $p['secure'], $p['httponly']);
}
session_destroy();

header('Location: login.php');
exit;
