<?php
// Test tooling: finds the answer of a CAPTCHA nonce by brute force, the way the test suites "solve" a CAPTCHA
// without OCR. The nonce carries only an HMAC of the answer, so this needs the site secret (the dev config's) and
// only works for the short digit answers the tests use (levels 1-3: up to 6 digits).
//   php scripts/captcha-solve.php NONCE [LENGTH]      prints the answer
// Never loaded by the guard or the panel.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
define('GV_BOOT', 1);
define('GV_NO_AUTORUN', 1);
require __DIR__ . '/../guard/guard.php';
$cfgfile = getenv('GV_DEV_CONFIG');
$cfg = require (is_string($cfgfile) && is_file($cfgfile)) ? $cfgfile : __DIR__ . '/config.dev.php';
$nonce = isset($argv[1]) ? $argv[1] : '';
$len = isset($argv[2]) ? (int)$argv[2] : 4;
if (gv_captcha_nonce_parse($nonce) === false || $len < 1 || $len > 6) { fwrite(STDERR, "bad nonce or length\n"); exit(2); }
$max = (int)pow(10, $len);
for ($i = 0; $i < $max; $i++) {
	$a = str_pad((string)$i, $len, '0', STR_PAD_LEFT);
	if (gv_captcha_answer_ok($nonce, $cfg['secret'], $a)) { echo $a, "\n"; exit(0); }
}
fwrite(STDERR, "not found\n");
exit(1);
