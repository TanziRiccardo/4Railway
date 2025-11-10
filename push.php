<?php
require_once __DIR__ . '/lib_apns.php';

// Sicurezza di base con shared secret + facoltativo HMAC del body
function require_auth($rawBody) {
    $secret = envv('PUSH_SHARED_SECRET'); // imposta questa env su Railway
    if ($secret === '') {
        http_response_code(500);
        echo json_encode(['ok' => false, 'error' => 'missing_PUSH_SHARED_SECRET']);
        exit;
    }
    $hdr = isset($_SERVER['HTTP_X_AUTH']) ? $_SERVER['HTTP_X_AUTH'] : '';
    if (!hash_equals($secret, $hdr)) {
        http_response_code(401);
        echo json_encode(['ok' => false, 'error' => 'unauthorized']);
        exit;
    }
    // Facoltativo: verifica HMAC
    $sig = isset($_SERVER['HTTP_X_SIGNATURE']) ? $_SERVER['HTTP_X_SIGNATURE'] : '';
    if ($sig !== '') {
        // X-Signature: "sha256=<hmac>"
        $parts = explode('=', $sig, 2);
        if (count($parts) === 2 && strtolower($parts[0]) === 'sha256') {
            $calc = hash_hmac('sha256', $rawBody, $secret);
            if (!hash_equals($calc, $parts[1])) {
                http_response_code(401);
                echo json_encode(['ok' => false, 'error' => 'bad_hmac']);
                exit;
            }
        }
    }
}

header('Content-Type: application/json; charset=utf-8');

$method = $_SERVER['REQUEST_METHOD'];
if ($method === 'OPTIONS') {
    http_response_code(204);
    exit;
}
if ($method !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Method Not Allowed']);
    exit;
}

$raw = file_get_contents('php://input') ?: '';
require_auth($raw);

$in = json_decode($raw, true);
if (!is_array($in)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'invalid_json']);
    exit;
}

$tokens  = isset($in['tokens']) && is_array($in['tokens']) ? $in['tokens'] : [];
$message = isset($in['message']) && trim($in['message']) !== '' ? trim($in['message']) : 'Nuova richiesta di appuntamento';
// (opzionale) override topic per bundle alternativi
$bundleOverride = isset($in['bundle_id']) && trim($in['bundle_id']) !== '' ? trim($in['bundle_id']) : null;

if (empty($tokens)) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'tokens_required']);
    exit;
}

$bundleId = $bundleOverride ?: envv('APNS_BUNDLE_ID');
if ($bundleId === '') {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'missing_APNS_BUNDLE_ID']);
    exit;
}

// Costruisci (o riusa) il JWT
$jwtCache = ['jwt' => null, 'iat' => 0];
try {
    $jwt = apns_build_jwt($jwtCache);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'jwt_error', 'detail' => $e->getMessage()]);
    exit;
}

// Invia a tutti i token
$results = [];
foreach ($tokens as $t) {
    $t = trim($t);
    if ($t === '') continue;

    list($code, $body) = apns_send_alert($t, $message, $bundleId, $jwt);
    $results[] = ['token' => $t, 'code' => $code, 'body' => $body];

    // Se il JWT è scaduto nel frattempo, potresti rigenerarlo qui (raro in un singolo batch)
}

echo json_encode(['ok' => true, 'count' => count($results), 'results' => $results], JSON_UNESCAPED_SLASHES);
