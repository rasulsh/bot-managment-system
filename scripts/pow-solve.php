<?php
// Test helper: solve the challenge's proof of work from the command line.
//
//   php scripts/pow-solve.php <nonce> [answer-header]
//
// Prints the counter for X-GV-P, using the difficulty carried in the nonce.
// This is what a bot would have to implement - and it is the point: a client
// that only regex-parses the page cannot get a token without doing this work.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }
define('GV_BOOT', 1);
require __DIR__ . '/../guard/challenge.php';
require __DIR__ . '/../guard/captcha.php';

$nonce = isset($argv[1]) ? (string)$argv[1] : '';
// A CAPTCHA nonce (six parts, guard/captcha.php) carries the same difficulty in its third part.
$parsed = gv_nonce_parse($nonce);
if ($parsed === false && substr_count($nonce, '.') === 5) {
	$x = explode('.', $nonce);
	$parsed = ctype_digit($x[2]) ? array($x[1], (int)$x[2]) : false;
}
if ($parsed === false) { fwrite(STDERR, "bad nonce\n"); exit(2); }
// A CAPTCHA nonce with 20 or more bits is BOUND to the typed answer (guard/captcha.php, gv_captcha_pow_ok): the proof covers
// "nonce:answer", so the second argument is the answer exactly as the X-GV-A header carries it (percent-encoded).
$subject = $nonce;
if (substr_count($nonce, '.') === 5 && $parsed[1] >= GV_CAPTCHA_BOUND_BITS) {
	$subject = $nonce . ':' . (isset($argv[2]) ? (string)$argv[2] : '');
}
for ($c = 0; $c < 100000000; $c++) {
	if (gv_pow_ok($subject, (string)$c, $parsed[1])) { echo $c . "\n"; exit(0); }
}
fwrite(STDERR, "no solution\n");
exit(1);
