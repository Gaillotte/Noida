<?php
/**
 * Streams an export from the API through to the browser.
 *
 * Proxied rather than linked directly because the browser cannot attach the
 * session's bearer token to a plain download link; doing it here keeps the
 * token server-side.
 */
declare(strict_types=1);
require_once __DIR__ . '/../inc/layout.php';
require_login();

$what = $_GET['what'] ?? 'audit';
$api  = new ApiClient();

if ($what === 'audit') {
    $fmt = in_array($_GET['fmt'] ?? 'csv', ['csv', 'json', 'excel'], true) ? $_GET['fmt'] : 'csv';
    $response = $api->raw('/api/audit/export?fmt=' . urlencode($fmt));

    if ($response['status'] !== 200) {
        render_head('Export');
        render_error('Export failed (HTTP ' . $response['status'] . '). '
                   . 'The Auditor, SecurityOfficer or Administrator role is required.');
        render_foot();
        exit;
    }

    $isJson = $fmt === 'json';
    header('Content-Type: ' . ($isJson ? 'application/json' : 'text/csv'));
    header('Content-Disposition: attachment; filename="cryptohub-audit-'
           . date('Ymd-His') . ($isJson ? '.json' : '.csv') . '"');
    echo $response['body'];
    exit;
}

// Inventory exports, built here because they are views of data the API
// already returns rather than separate reports.
if ($what === 'certificates') {
    $result = $api->get('/api/certificates');
    $rows   = $result['ok'] ? $result['data'] : [];

    header('Content-Type: text/csv');
    header('Content-Disposition: attachment; filename="cryptohub-certificates-'
           . date('Ymd-His') . '.csv"');
    $out = fopen('php://output', 'w');
    fputcsv($out, ['uid', 'name', 'subject', 'issuer', 'serial', 'not_before',
                   'not_after', 'days_remaining', 'self_signed', 'state']);
    foreach ($rows as $r) {
        fputcsv($out, [$r['uid'] ?? '', $r['name'] ?? '', $r['subject'] ?? '',
                       $r['issuer'] ?? '', $r['serial'] ?? '', $r['not_before'] ?? '',
                       $r['not_after'] ?? '', $r['days_remaining'] ?? '',
                       !empty($r['self_signed']) ? 'yes' : 'no', $r['state'] ?? '']);
    }
    fclose($out);
    exit;
}

$result = $api->get('/api/keys');
$rows   = $result['ok'] ? $result['data'] : [];

header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="cryptohub-keys-' . date('Ymd-His') . '.csv"');

$out = fopen('php://output', 'w');
fputcsv($out, ['uid', 'name', 'object_type', 'algorithm', 'length', 'state',
               'owner', 'sensitive', 'extractable', 'created_at']);
foreach ($rows as $r) {
    fputcsv($out, [$r['uid'] ?? '', $r['name'] ?? '', $r['object_type'] ?? '',
                   $r['algorithm'] ?? '', $r['length'] ?? '', $r['state'] ?? '',
                   $r['owner'] ?? '', $r['sensitive'] ?? '', $r['extractable'] ?? '',
                   $r['created_at'] ?? '']);
}
fclose($out);
