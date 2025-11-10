<?php
// Libreria APNs: genera JWT e invia una notifica "alert" semplice

function envv($k) {
    $v = getenv($k);
    return $v === false ? '' : $v;
}

function b64url($s) {
    return rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
}

function apns_build_jwt(&$cache = null) {
    // Cache del JWT per ~20 minuti (consigli Apple)
    if (is_array($cache)) {
        if (!empty($cache['jwt']) && (time() - (int)$cache['iat']) < 1200) {
            return $cache['jwt'];
        }
    } else {
        $cache = ['jwt' => null, 'iat' => 0];
    }

    $teamId = envv('R2YZZRHWGX');
    $keyId  = envv('7H8K9M45GL');
    $p8b64  = envv('LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tDQpNSUdUQWdFQU1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhCSGt3ZHdJQkFRUWd6K0RMcFo5amczTTlyZk4wDQo0aUZsT2hTeXdIekgyZFYvcHlMK1dtTzNHTytnQ2dZSUtvWkl6ajBEQVFlaFJBTkNBQVF6QWZ5VTdOUFI4OElCDQphQW5MaGtFQ1J4MHAwSGdXbmJZdGc2VVN2bzBBWUh4dzAvMGdOMXdrNVdYQnNNSENleUI3Z3BqTFJ3S0lzZHJpDQpQQkpCa0pFdA0KLS0tLS1FTkQgUFJJVkFURSBLRVktLS0tLQ=='); // PEM .p8 in base64
    if ($teamId === '' || $keyId === '' || $p8b64 === '') {
        throw new Exception('APNS env missing (APNS_TEAM_ID, APNS_KEY_ID, APNS_P8_BASE64)');
    }

    $header   = ['alg' => 'ES256', 'kid' => $keyId];
    $claims   = ['iss' => $teamId, 'iat' => time()];
    $unsigned = b64url(json_encode($header)) . '.' . b64url(json_encode($claims));

    $p8pem = base64_decode($p8b64);
    if (!$p8pem) throw new Exception('Invalid APNS_P8_BASE64');

    $privateKey = openssl_pkey_get_private($p8pem);
    if (!$privateKey) throw new Exception('Unable to read .p8 private key');

    $sig = '';
    if (!openssl_sign($unsigned, $sig, $privateKey, 'sha256')) {
        throw new Exception('OpenSSL sign error');
    }
    $jwt = $unsigned . '.' . b64url($sig);

    $cache['jwt'] = $jwt;
    $cache['iat'] = time();
    return $jwt;
}

function apns_send_alert($deviceToken, $message, $bundleId, $jwt) {
    $payload = json_encode([
        'aps' => [
            'alert' => $message,
            'sound' => 'default'
        ]
    ]);

    $url = "https://api.push.apple.com/3/device/" . $deviceToken;
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_HTTPHEADER     => [
            "authorization: bearer ".$jwt,
            "apns-topic: ".$bundleId,
            "apns-push-type: alert",
            "content-type: application/json"
        ],
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_2TLS, // HTTP/2 obbligatorio
        CURLOPT_TIMEOUT        => 15,
        CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4 // evita eventuali problemi IPv6
    ]);

    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($body === false) {
        $body = curl_error($ch);
    }
    curl_close($ch);
    return [$code, $body];
}
