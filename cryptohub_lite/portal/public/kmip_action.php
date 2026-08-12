<?php
/**
 * Handles KMIP write actions posted from the explorer, then redirects back.
 *
 * Post-redirect-get, so a browser refresh after destroying a key does not
 * offer to destroy it again. The outcome is carried in the query string and
 * rendered by the page the user returns to.
 */

declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: kmip.php');
    exit;
}

$api    = new ApiClient();
$action = $_POST['action'] ?? '';
$uid    = $_POST['uid'] ?? '';
$back   = $_POST['back'] ?? 'kmip.php';

switch ($action) {
    case 'create':
        $result = $api->post('/api/kmip/objects', [
            'name'      => trim($_POST['name'] ?? ''),
            'algorithm' => $_POST['algorithm'] ?? 'AES',
            'length'    => (int)($_POST['length'] ?? 256),
            // An unticked checkbox posts nothing at all, so absence is the
            // only signal that the attribute was turned off.
            'encrypt'     => isset($_POST['encrypt']),
            'decrypt'     => isset($_POST['decrypt']),
            'wrap'        => isset($_POST['wrap']),
            'unwrap'      => isset($_POST['unwrap']),
            'sensitive'   => isset($_POST['sensitive']),
            'extractable' => isset($_POST['extractable']),
        ]);
        $ok = $result['ok'] ? 'Key created' : null;
        break;

    case 'create_keypair':
        $result = $api->post('/api/kmip/keypairs', [
            'name'      => trim($_POST['name'] ?? ''),
            'algorithm' => $_POST['algorithm'] ?? 'RSA',
            'length'    => (int)($_POST['length'] ?? 2048),
            'curve'     => $_POST['curve'] ?? 'P_256',
            'sign'      => isset($_POST['sign']),
            'verify'    => isset($_POST['verify']),
            'derive'    => isset($_POST['derive']),
        ]);
        // Both halves are named, because the pair arrives as two rows in the
        // table and it is not otherwise obvious which one is which.
        $ok = $result['ok']
            ? 'Key pair created — private ' . substr((string)($result['data']['private_uid'] ?? ''), 0, 12)
              . '…, public ' . substr((string)($result['data']['public_uid'] ?? ''), 0, 12) . '…'
            : null;
        break;

    case 'activate':
        $result = $api->post('/api/kmip/objects/' . rawurlencode($uid) . '/activate');
        $ok = $result['ok'] ? 'Object activated' : null;
        break;

    case 'revoke':
        $result = $api->post('/api/kmip/objects/' . rawurlencode($uid) . '/revoke', [
            'reason'  => $_POST['reason'] ?? 'CessationOfOperation',
            'message' => trim($_POST['message'] ?? ''),
        ]);
        $ok = $result['ok'] ? 'Object revoked' : null;
        break;

    case 'rekey':
        $result = $api->post('/api/kmip/objects/' . rawurlencode($uid) . '/rekey');
        $ok = $result['ok']
            ? 'Re-keyed; replacement is ' . substr((string)($result['data']['result'] ?? ''), 0, 18) . '…'
            : null;
        break;

    case 'destroy':
        $result = $api->delete('/api/kmip/objects/' . rawurlencode($uid));
        $ok = $result['ok'] ? 'Key material destroyed' : null;
        break;

    default:
        header('Location: ' . $back . '?error=' . urlencode('Unknown action'));
        exit;
}

$query = $result['ok']
    ? 'notice=' . urlencode($ok)
    : 'error=' . urlencode($result['error'] ?? 'The operation failed');

header('Location: ' . $back . '?' . $query);
exit;
