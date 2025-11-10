<?php
require_once __DIR__.'/lib_apns.php';



$queueBase = rtrim(envv('QUEUE_BASE_URL'), '/'); // es: https://TUO-SITO.altervista.org/api/push_queue
$queueSecret = envv('PUSH_QUEUE_SECRET');        // lo stesso usato su Altervista
$bundleId = envv('APNS_BUNDLE_ID');

if ($queueBase==='' || $queueSecret==='' || $bundleId==='') {
  fwrite(STDERR, "Missing env QUEUE_BASE_URL / PUSH_QUEUE_SECRET / APNS_BUNDLE_ID\n");
  exit(1);
}

$jwtCache = ['jwt'=>null, 'iat'=>0];

function http_get_json($url, $secret) {
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_HTTPHEADER     => ['X-Auth: '.$secret],
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 15,
    CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4
  ]);
  $body = curl_exec($ch);
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  if ($body === false) $body = curl_error($ch);
  curl_close($ch);
  return [$code, $body];
}
function http_post_json($url, $secret, $data) {
  $payload = json_encode($data, JSON_UNESCAPED_SLASHES);
  $ch = curl_init($url);
  curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_HTTPHEADER     => ['Content-Type: application/json', 'X-Auth: '.$secret],
    CURLOPT_POSTFIELDS     => $payload,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 15,
    CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4
  ]);
  $body = curl_exec($ch);
  $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
  if ($body === false) $body = curl_error($ch);
  curl_close($ch);
  return [$code, $body];
}

while (true) {
  // 1) prendi prossimo job
  list($code, $body) = http_get_json($queueBase.'/next.php', $queueSecret);
  if ($code === 204) { sleep(3); continue; }        // nessun job
  if ($code !== 200) { fwrite(STDERR, "next.php HTTP $code: $body\n"); sleep(5); continue; }

  $data = json_decode($body, true);
  if (!is_array($data) || empty($data['ok'])) { fwrite(STDERR, "next parse error: $body\n"); sleep(5); continue; }
  $job = $data['job'];
  $jobId = (int)$job['id'];
  $ack   = $job['ack_token'];
  $tokens = is_array($job['tokens']) ? $job['tokens'] : [];
  $message = (string)$job['message'];

  $results = [];
  $allOk = true;

  try {
    $jwt = apns_build_jwt($jwtCache);
    foreach ($tokens as $t) {
      $t = trim($t);
      if ($t==='') continue;
      list($c, $b) = apns_send_alert($t, $message, $bundleId, $jwt);
      $results[] = ['token'=>$t, 'code'=>$c, 'body'=>$b];
      if ($c !== 200) { $allOk = false; }
    }
  } catch (Exception $e) {
    $allOk = false;
    $results[] = ['error' => $e->getMessage()];
  }

  // 3) ack
  $status = $allOk ? 'done' : 'failed';
  list($ac, $ab) = http_post_json($queueBase.'/ack.php', $queueSecret, [
    'id' => $jobId,
    'ack_token' => $ack,
    'status' => $status,
    'report' => $results
  ]);
  if ($ac !== 200) {
    fwrite(STDERR, "ack HTTP $ac: $ab\n");
  }
  // piccolo respiro
  usleep(400000);
}
