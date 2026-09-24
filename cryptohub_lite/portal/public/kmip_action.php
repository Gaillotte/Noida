<?php
/**
 * Handles KMIP write actions posted from the portal, then redirects back.
 *
 * Post-redirect-get, so a browser refresh after destroying a key does not
 * offer to destroy it again. The outcome is carried in the query string and
 * rendered by the page the user returns to.
 *
 * Every action here now runs over KMIP, as a real client, through
 * chl-client-app. Previously these posted to REST endpoints that called the
 * engine's handlers in-process, which skipped the OperationDispatcher: the
 * resulting key was identical, but nothing about its creation reached the
 * hash-chained audit log. Two ways to make a key, one of them invisible to an
 * auditor. There is now one way.
 */

declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_once __DIR__ . '/../inc/kmip.php';
require_login();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: kmip.php');
    exit;
}

$action = $_POST['action'] ?? '';
$uid    = $_POST['uid'] ?? '';
$back   = $_POST['back'] ?? 'kmip.php';

/** Shortens a UID for a one-line notice. */
$short = fn($value) => substr((string)$value, 0, 12) . '…';

try {
    switch ($action) {
        case 'create':
            $algorithm = $_POST['algorithm'] ?? 'AES';
            $run = kmip_run('Create', [
                'algorithm'   => KMIP_ALGORITHM[$algorithm] ?? KMIP_ALGORITHM['AES'],
                'length'      => (int)($_POST['length'] ?? 256),
                'usage_mask'  => kmip_usage_mask($_POST, ['encrypt', 'decrypt', 'wrap', 'unwrap']),
                'name'        => trim($_POST['name'] ?? ''),
                'sensitive'   => isset($_POST['sensitive']),
                'extractable' => isset($_POST['extractable']),
                // Unticked means "usable immediately", which is the default the
                // engine has always applied.
                'activate'    => !isset($_POST['inactive']),
            ]);
            $ok = 'Key created — ' . $short($run['result']);
            break;

        case 'create_keypair':
            $algorithm = $_POST['algorithm'] ?? 'RSA';
            $arguments = [
                'algorithm'  => KMIP_ALGORITHM[$algorithm] ?? KMIP_ALGORITHM['RSA'],
                'length'     => (int)($_POST['length'] ?? 2048),
                'name'       => trim($_POST['name'] ?? ''),
                'usage_mask' => kmip_usage_mask($_POST, ['sign', 'verify', 'derive']),
            ];
            // For an elliptic curve the curve *is* the size, so it travels as
            // Cryptographic Domain Parameters and the length is not meaningful.
            if (in_array($algorithm, ['EC', 'ECDSA'], true)) {
                $arguments['curve'] = KMIP_CURVE[$_POST['curve'] ?? 'P_256'] ?? KMIP_CURVE['P_256'];
            }
            $run = kmip_run('CreateKeyPair', $arguments);
            // Both halves are named, because the pair arrives as two rows in
            // the table and it is not otherwise obvious which one is which.
            [$public, $private] = array_pad((array)$run['result'], 2, '');
            $ok = 'Key pair created — public ' . $short($public)
                . ', private ' . $short($private);
            break;

        case 'activate':
            kmip_run('Activate', ['uid' => $uid]);
            $ok = 'Object activated';
            break;

        case 'revoke':
            $reason = $_POST['reason'] ?? 'CessationOfOperation';
            kmip_run('Revoke', [
                'uid'     => $uid,
                'reason'  => KMIP_REVOCATION_REASON[$reason]
                             ?? KMIP_REVOCATION_REASON['CessationOfOperation'],
                'message' => trim($_POST['message'] ?? ''),
            ]);
            $ok = 'Object revoked';
            break;

        case 'rekey':
            $run = kmip_run('ReKey', ['uid' => $uid]);
            $ok = 'Re-keyed; replacement is ' . $short($run['result']);
            break;

        case 'destroy':
            kmip_run('Destroy', ['uid' => $uid]);
            $ok = 'Key material destroyed';
            break;

        default:
            header('Location: ' . $back . '?error=' . urlencode('Unknown action'));
            exit;
    }
} catch (KmipCredentialMissing $exc) {
    // Distinct from a refusal: nothing was attempted, and the fix is to sign
    // in again rather than to change the request.
    header('Location: ' . $back . '?error=' . urlencode($exc->getMessage()));
    exit;
} catch (RuntimeException $exc) {
    header('Location: ' . $back . '?error=' . urlencode($exc->getMessage()));
    exit;
}

header('Location: ' . $back . '?notice=' . urlencode($ok));
exit;
