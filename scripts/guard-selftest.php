<?php
// Bot Guard CLI self-test. Run: php scripts/guard-selftest.php
// Exit code 0 when every non-SKIP assertion passes, 1 otherwise.
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
if (PHP_VERSION_ID < 80000) { fwrite(STDERR, 'Bot Guard requires PHP 8.0 or newer (found ' . PHP_VERSION . ").\n"); exit(1); }

define('GV_BOOT', 1);
require __DIR__ . '/../guard/guard.php';

// Nothing in this suite may touch the repository's logs/ directory: the guard's error
// logger falls back to it when no log_dir is known, so point it at a temp dir.
$GV_TMP_LOGS = sys_get_temp_dir() . '/gv-guard-selftest-logs-' . getmypid();
gv_redis_ctx(array('log_dir' => $GV_TMP_LOGS));
register_shutdown_function(function () use ($GV_TMP_LOGS) {
	foreach ((array)glob($GV_TMP_LOGS . '/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
	@rmdir($GV_TMP_LOGS);
});

$GV_PASS = 0;
$GV_FAIL = 0;
$GV_SKIP = 0;

function t_ok($name, $cond) {
	global $GV_PASS, $GV_FAIL;
	if ($cond) {
		$GV_PASS++;
		echo "PASS  " . $name . "\n";
	} else {
		$GV_FAIL++;
		echo "FAIL  " . $name . "\n";
	}
}

function t_skip($name, $why) {
	global $GV_SKIP;
	$GV_SKIP++;
	echo "SKIP  " . $name . " (" . $why . ")\n";
}

function t_section($name) {
	echo "\n-- " . $name . "\n";
}

// A complete, clean browser facts array. Override any key per test.
function t_facts(array $over = array()) {
	$base = array(
		'ip'      => '203.0.113.7',
		'method'  => 'GET',
		'path'    => '/',
		'query'   => '',
		'params'  => array(),
		'ua'      => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
			. '(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
		'accept'  => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
		'al'      => 'en-US,en;q=0.9',
		'sf'      => 'navigate',
		'xrw'     => '',
		'xgv'     => '',
		'referer' => '',
		'hc'      => 12,
		'https'   => false,
		'cookie'  => '',
	);
	return array_merge($base, $over);
}

$secret = 'selftest-secret';

// --------------------------------------------------------------------------
t_section('Token');

$tok = gv_tok_make($secret);
$dev = gv_tok_check($tok, $secret, 604800);
t_ok('token roundtrip returns a device id', is_string($dev) && strlen($dev) === 24 && ctype_xdigit($dev));

$old  = bin2hex(random_bytes(12)) . '.' . (time() - 1000);
$old .= '.' . hash_hmac('sha256', $old, $secret);
t_ok('token expired by ttl fails', gv_tok_check($old, $secret, 100) === false);
t_ok('token inside ttl passes', gv_tok_check($old, $secret, 5000) !== false);

$parts = explode('.', $tok);
$bad   = $parts[0] . '.' . $parts[1] . '.' . strrev($parts[2]);
t_ok('token with tampered signature fails', gv_tok_check($bad, $secret, 604800) === false);
t_ok('token signed with another secret fails', gv_tok_check($tok, 'other-secret', 604800) === false);
t_ok('malformed token fails', gv_tok_check('not-a-token', $secret, 604800) === false);
t_ok('empty token fails', gv_tok_check('', $secret, 604800) === false);

// --------------------------------------------------------------------------
t_section('Nonce');

$nonce = gv_nonce_make($secret);
t_ok('nonce roundtrip passes', gv_nonce_check($nonce, $secret, 120) === true);

$oldn  = (time() - 500) . '.' . bin2hex(random_bytes(8));
$oldn .= '.' . hash_hmac('sha256', $oldn, $secret);
t_ok('nonce expired by ttl fails', gv_nonce_check($oldn, $secret, 120) === false);
t_ok('nonce with tampered signature fails', gv_nonce_check($nonce . 'x', $secret, 120) === false);
$tv = gv_test_make($secret, 600);
t_ok('test-switch cookie roundtrip passes', gv_test_ok($tv, $secret) === true);
t_ok('test-switch cookie fails with another secret', gv_test_ok($tv, $secret . 'x') === false);
t_ok('test-switch cookie expired fails', gv_test_ok(gv_test_make($secret, -5), $secret) === false);
t_ok('test-switch cookie tampered/garbage fails', gv_test_ok($tv . 'x', $secret) === false && gv_test_ok('', $secret) === false && gv_test_ok('1.2.3', $secret) === false);
t_ok('a nonce is not a valid test-switch cookie', gv_test_ok($nonce, $secret) === false);
t_ok('malformed nonce fails', gv_nonce_check('abc', $secret, 120) === false);

// --------------------------------------------------------------------------
t_section('Nonce binding, difficulty and proof of work');

$UA_A = 'Mozilla/5.0 UA-A';
$UA_B = 'curl/8.0';
$nb = gv_nonce_make($secret, $UA_A, '203.0.113.5', 8);
t_ok('a nonce carries id and difficulty', gv_nonce_parse($nb) !== false && gv_nonce_parse($nb)[1] === 8
	&& strlen(gv_nonce_parse($nb)[0]) === 16);
t_ok('a nonce verifies for the client it was issued to', gv_nonce_check($nb, $secret, 120, $UA_A, '203.0.113.5') === true);
t_ok('a nonce is rejected for another User-Agent', gv_nonce_check($nb, $secret, 120, $UA_B, '203.0.113.5') === false);
t_ok('a nonce is rejected for another IP', gv_nonce_check($nb, $secret, 120, $UA_A, '203.0.113.6') === false);
$nu = gv_nonce_make($secret, $UA_A, '', 8);
t_ok('with IP binding off the IP is ignored but the UA still counts',
	gv_nonce_check($nu, $secret, 120, $UA_A, '') === true && gv_nonce_check($nu, $secret, 120, $UA_B, '') === false);
t_ok('the difficulty cannot be edited without breaking the signature',
	gv_nonce_check(preg_replace('/\.8\./', '.0.', $nb, 1), $secret, 120, $UA_A, '203.0.113.5') === false);
t_ok('the old three-part nonce format is refused', gv_nonce_check(time() . '.abcdef0123456789.' . hash_hmac('sha256', 'x', $secret), $secret, 120) === false);
t_ok('an out-of-range difficulty is refused', gv_nonce_parse(time() . '.0123456789abcdef.25.' . str_repeat('0', 64)) === false);
t_ok('two nonces never share an id', gv_nonce_parse(gv_nonce_make($secret))[0] !== gv_nonce_parse(gv_nonce_make($secret))[0]);

$pw = gv_nonce_make($secret, $UA_A, '203.0.113.5', 12);
$solved = -1;
for ($c = 0; $c < 2000000; $c++) { if (gv_pow_ok($pw, (string)$c, 12)) { $solved = $c; break; } }
t_ok('a counter satisfying 12 bits is found and verifies', $solved >= 0 && gv_pow_ok($pw, (string)$solved, 12));
// Fixed strings, so the result is deterministic: a counter solved for one nonce
// does not (for these inputs) satisfy another.
$fx1 = 'fixed-nonce-one';
$fx2 = 'fixed-nonce-two';
$fxc = -1;
for ($c = 0; $c < 2000000; $c++) { if (gv_pow_ok($fx1, (string)$c, 16)) { $fxc = $c; break; } }
t_ok('a counter solved for one nonce does not satisfy another', $fxc >= 0 && !gv_pow_ok($fx2, (string)$fxc, 16));
t_ok('the counter just below the solution does not satisfy the nonce either',
	$fxc === 0 || !gv_pow_ok($fx1, (string)($fxc - 1), 16));
t_ok('difficulty 0 needs no proof', gv_pow_ok($pw, '', 0) === true && gv_pow_ok($pw, 'junk', 0) === true);
t_ok('a missing proof fails when work is required', gv_pow_ok($pw, '', 12) === false);
t_ok('a non-numeric counter fails', gv_pow_ok($pw, '1e3', 12) === false && gv_pow_ok($pw, '-5', 12) === false
	&& gv_pow_ok($pw, str_repeat('9', 13), 12) === false);
$ref = function ($nonce, $c, $bits) {
	$h = hash('sha256', $nonce . ':' . $c, true);
	$bin = '';
	for ($i = 0; $i < 4; $i++) { $bin .= str_pad(decbin(ord($h[$i])), 8, '0', STR_PAD_LEFT); }
	return substr($bin, 0, $bits) === str_repeat('0', $bits);
};
$agree = true;
for ($bits = 1; $bits <= 24; $bits += 3) {
	for ($c = 0; $c < 300; $c++) {
		if (gv_pow_ok($pw, (string)$c, $bits) !== $ref($pw, $c, $bits)) { $agree = false; }
	}
}
t_ok('gv_pow_ok agrees with a bit-string reference for difficulties 1-24', $agree);

t_section('CIDR matcher');

t_ok('ip inside /24 matches', gv_cidr_match('192.168.1.55', '192.168.1.0/24') === true);
t_ok('ip outside /24 does not match', gv_cidr_match('192.168.2.55', '192.168.1.0/24') === false);
t_ok('/32 exact match', gv_cidr_match('10.0.0.1', '10.0.0.1/32') === true);
t_ok('/32 neighbour does not match', gv_cidr_match('10.0.0.2', '10.0.0.1/32') === false);
t_ok('/0 matches everything', gv_cidr_match('8.8.8.8', '0.0.0.0/0') === true);
t_ok('bare address behaves as /32', gv_cidr_match('10.0.0.1', '10.0.0.1') === true);
t_ok('invalid ip returns false', gv_cidr_match('not-an-ip', '10.0.0.0/8') === false);
t_ok('invalid cidr returns false', gv_cidr_match('10.0.0.1', '10.0.0.0/99') === false);
t_ok('ipv6 input returns false', gv_cidr_match('2001:db8::1', '10.0.0.0/8') === false);

// --------------------------------------------------------------------------
t_section('Client IP resolution');

$srv = array('REMOTE_ADDR' => '198.51.100.9', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, 5.6.7.8');
t_ok('remote addr outside cdn ranges wins',
	gv_client_ip($srv, array('203.0.113.0/24')) === '198.51.100.9');
t_ok('no cdn ranges configured means remote addr wins',
	gv_client_ip($srv, array()) === '198.51.100.9');

$srv2 = array('REMOTE_ADDR' => '203.0.113.10', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, 5.6.7.8');
t_ok('remote addr inside cdn range takes last xff entry',
	gv_client_ip($srv2, array('203.0.113.0/24')) === '5.6.7.8');

$srv3 = array('REMOTE_ADDR' => '203.0.113.10', 'HTTP_X_FORWARDED_FOR' => '1.2.3.4, junk');
t_ok('invalid last xff entry falls back to remote addr',
	gv_client_ip($srv3, array('203.0.113.0/24')) === '203.0.113.10');

$srv4 = array('REMOTE_ADDR' => '203.0.113.10');
t_ok('missing xff falls back to remote addr',
	gv_client_ip($srv4, array('203.0.113.0/24')) === '203.0.113.10');

// --------------------------------------------------------------------------
t_section('Navigation and AJAX classification');

t_ok('clean browser GET is a navigation', gv_is_nav(t_facts()) === true);
t_ok('clean browser GET is not ajax', gv_is_ajax(t_facts()) === false);
t_ok('x-requested-with marks ajax', gv_is_ajax(t_facts(array('xrw' => 'XMLHttpRequest'))) === true);
t_ok('x-requested-with is never a navigation',
	gv_is_nav(t_facts(array('xrw' => 'XMLHttpRequest'))) === false);
t_ok('json GET is ajax', gv_is_ajax(t_facts(array('accept' => 'application/json'))) === true);
t_ok('post is never a navigation', gv_is_nav(t_facts(array('method' => 'POST'))) === false);

// The gate decides who must carry a token. It must not read anything the
// client chooses: Accept and X-Requested-With were the bypass.
t_ok('a browser GET is gated', gv_is_gate(t_facts()) === true);
t_ok('a GET that does not ask for HTML is gated (curl / python-requests default)',
	gv_is_gate(t_facts(array('accept' => '*/*'))) === true);
t_ok('a GET with no Accept header at all is gated', gv_is_gate(t_facts(array('accept' => ''))) === true);
t_ok('a GET claiming to be XHR is gated',
	gv_is_gate(t_facts(array('xrw' => 'XMLHttpRequest', 'accept' => 'application/json'))) === true);
// HEAD runs the application like GET. POST and the rest are gated in SHADOW
// until challenge.gate_post is switched on; OPTIONS (CORS preflight) never is.
t_ok('HEAD is gated and enforced like GET',
	gv_is_gate(t_facts(array('method' => 'HEAD'))) === true && gv_gate_enforced(t_facts(array('method' => 'HEAD')), false) === true);
t_ok('a POST is gated, but only enforced with challenge.gate_post',
	gv_is_gate(t_facts(array('method' => 'POST'))) === true
	&& gv_gate_enforced(t_facts(array('method' => 'POST')), false) === false
	&& gv_gate_enforced(t_facts(array('method' => 'POST')), true) === true);
t_ok('PUT, DELETE and unknown methods follow POST',
	gv_is_gate(t_facts(array('method' => 'PUT'))) === true && gv_gate_enforced(t_facts(array('method' => 'FOO')), false) === false);
t_ok('OPTIONS is never gated', gv_is_gate(t_facts(array('method' => 'OPTIONS'))) === false);

// gv_served: the first rule that matches AND is enforced.
$EN = function ($b, $c, $r) { return array('block' => $b, 'challenge' => $c, 'ratelimit' => $r); };
t_ok('all on: served equals decided for every rule',
	gv_served(70, false, true, 'm', 60, '', $EN(true, true, true), 0, true) === '403'
	&& gv_served(0, true, true, 'm', 60, '', $EN(true, true, true), 0, true) === '429'
	&& gv_served(0, false, true, 'm', 60, '', $EN(true, true, true), 0, true) === 'challenge'
	&& gv_served(0, false, true, 'v', 60, '', $EN(true, true, true), 0, true) === 'allow');
t_ok('rate limiting in shadow no longer cancels the challenge for a token-less client over a limit',
	gv_decide(0, true, true, 'm', 60, '') === '429'
	&& gv_served(0, true, true, 'm', 60, '', $EN(true, true, false), 0, true) === 'challenge');
t_ok('blocking in shadow no longer cancels the challenge for a high-scoring token-less client',
	gv_decide(90, false, true, 'm', 60, '') === '403'
	&& gv_served(90, false, true, 'm', 60, '', $EN(false, true, true), 0, true) === 'challenge');
t_ok('...nor the rate limit', gv_served(90, true, true, 'v', 60, '', $EN(false, true, true), 0, true) === '429');
t_ok('everything off: always allow, whatever matched',
	gv_served(90, true, true, 'm', 60, 'deny', $EN(false, false, false), 0, true) === 'allow');
t_ok('a valid token over a shadowed limit is allowed', gv_served(0, true, true, 'v', 60, '', $EN(true, true, false), 0, true) === 'allow');
t_ok('holdout suppresses the score block and the challenge, never a 429 or a deny',
	gv_served(90, false, true, 'm', 60, '', $EN(true, true, true), 1, true) === 'allow'
	&& gv_served(90, true, true, 'm', 60, '', $EN(true, true, true), 1, true) === '429'
	&& gv_served(0, false, true, 'v', 60, 'deny', $EN(true, true, true), 1, true) === '403');
t_ok('an operator deny needs enforce.block and applies to any method',
	gv_served(0, false, true, 'v', 60, 'deny', $EN(true, false, false), 0, false) === '403'
	&& gv_served(0, false, true, 'v', 60, 'deny', $EN(false, true, true), 0, false) === 'allow');
t_ok('page rules off for the method (a POST without gate_post): no challenge, no score block, still 429',
	gv_served(90, false, true, 'm', 60, '', $EN(true, true, true), 0, false) === 'allow'
	&& gv_served(90, true, true, 'm', 60, '', $EN(true, true, true), 0, false) === '429');
t_ok('a hard_block_score of 0 or less cannot block everybody through the mask',
	gv_served(0, false, true, 'v', 0, '', $EN(false, true, true), 0, true) === 'allow');

// Exemptions a client cannot award itself.
$EXP = array('/admin/', '/payment-callback');
$EXQ = array('route' => array('payment/', 'api/'));
$FC  = array('/', '/index.php');
$ex  = function ($path, $params = array()) use ($EXP, $EXQ, $FC) {
	return gv_is_exempt(t_facts(array('path' => $path, 'params' => $params)), $EXP, $EXQ, $FC);
};
t_ok('a real exempt path and a real front-controller route are exempt',
	$ex('/admin/index.php') && $ex('/index.php', array('route' => 'payment/zarinpal/callback')) && $ex('/', array('route' => 'api/torob')));
t_ok('?route=payment/x appended to an SEO URL is NOT an exemption',
	!$ex('/product/ps5-slim', array('route' => 'payment/x')) && !$ex('/category/games', array('route' => 'api/x')));
t_ok('a dot segment, an empty segment or an encoded slash/dot never matches an exempt prefix',
	!$ex('/admin/../product/x') && !$ex('/admin/./x') && !$ex('/admin//x') && !$ex('//admin/x')
	&& !$ex('/admin/%2e%2e/product/x') && !$ex('/admin/..%2fproduct') && !$ex('/admin/x\\..\\y'));
t_ok('without a path list (old callers) parameter exemptions behave as before',
	gv_is_exempt(t_facts(array('path' => '/product/x', 'params' => array('route' => 'payment/x'))), $EXP, $EXQ) === true);
t_ok('the front-controller list has a default', gv_cfg_defaults(array())['exempt_params_paths'] === array('/', '/index.php'));

// One spelling per address; IPv6 counted per /64.
t_ok('IPv4 is its own key and its own network', gv_ip_canon('203.0.113.7') === '203.0.113.7' && gv_ip_net('203.0.113.7') === '203.0.113.7');
t_ok('IPv6 spellings collapse to one',
	gv_ip_canon('2001:DB8::7') === '2001:db8::7' && gv_ip_canon('2001:0db8:0:0:0:0:0:7') === '2001:db8::7');
t_ok('an IPv4-mapped IPv6 address is the IPv4 address', gv_ip_canon('::ffff:203.0.113.7') === '203.0.113.7');
t_ok('every address of one /64 shares a network key',
	gv_ip_net('2001:db8:1:2::1') === '2001:db8:1:2::/64' && gv_ip_net('2001:db8:1:2:aaaa:bbbb:cccc:dddd') === '2001:db8:1:2::/64'
	&& gv_ip_net('2001:db8:1:3::1') !== gv_ip_net('2001:db8:1:2::1'));
t_ok('garbage is returned unchanged, never an exception',
	gv_ip_canon('not:an:ip') === 'not:an:ip' && gv_ip_net('') === '' && gv_ip_canon('') === '');

// Cookie candidates.
t_ok('an array cookie (_gv[]=x) yields no candidate and no warning', gv_cookie_values('_gv', array('_gv' => array('x')), '_gv[]=x') === array());
t_ok('PHP\'s pick comes first, then every other value of the same name from the raw header',
	gv_cookie_values('_gv', array('_gv' => 'stale'), 'a=1; _gv=stale; _gv=fresh; b=2') === array('stale', 'fresh'));
t_ok('other cookies and look-alike names are ignored', gv_cookie_values('_gv', array(), 'x_gv=1; _gvx=2; _gv =ok') === array('ok'));
t_ok('at most four candidates, and an oversized header is not parsed',
	count(gv_cookie_values('_gv', array(), '_gv=a; _gv=b; _gv=c; _gv=d; _gv=e; _gv=f')) === 4
	&& gv_cookie_values('_gv', array(), str_repeat('_gv=a; ', 4000)) === array());

// Hand-edited config values.
$hc = gv_cfg_defaults(array('limits' => array('device' => 0, 'ip' => '1,200', 'window' => -5, 'ip_ua' => '250', 'bot' => 'x'),
	'token_ttl' => 'x', 'nonce_ttl' => 0, 'enforce' => array('block' => 'false', 'challenge' => 'on', 'ratelimit' => 0)));
t_ok('a limit that is not a positive whole number falls back to its default',
	$hc['limits']['device'] === 150 && $hc['limits']['ip'] === 1200 && $hc['limits']['window'] === 300 && $hc['limits']['bot'] === 600);
t_ok('a numeric string limit is accepted as its number', $hc['limits']['ip_ua'] === 250);
t_ok('a non-numeric lifetime falls back (a token must expire)', $hc['token_ttl'] === 604800 && $hc['nonce_ttl'] === 120);
t_ok("enforce 'false' / 0 read as off and 'on' as on", $hc['enforce']['block'] === false && $hc['enforce']['ratelimit'] === false && $hc['enforce']['challenge'] === true);

// One nonce, one device.
t_ok('a token made from a nonce id has a device id derived from it, the same every time',
	gv_tok_check(gv_tok_make('s3', 'aabbccddeeff0011'), 's3', 60) === gv_tok_check(gv_tok_make('s3', 'aabbccddeeff0011'), 's3', 60)
	&& gv_tok_check(gv_tok_make('s3', 'aabbccddeeff0011'), 's3', 60) !== gv_tok_check(gv_tok_make('s3', 'aabbccddeeff0012'), 's3', 60)
	&& preg_match('/^[0-9a-f]{24}$/', gv_tok_check(gv_tok_make('s3', 'aabbccddeeff0011'), 's3', 60)) === 1);
t_ok('the derived device id depends on the secret', gv_tok_check(gv_tok_make('s3', 'aabbccddeeff0011'), 's3', 60) !== gv_tok_check(gv_tok_make('s4', 'aabbccddeeff0011'), 's4', 60));
t_ok('without a nonce id the device id is random', gv_tok_check(gv_tok_make('s3'), 's3', 60) !== gv_tok_check(gv_tok_make('s3'), 's3', 60));
$fut = (time() + 600) . '.' . '00112233aabbccdd' . '.0';
$fut .= '.' . hash_hmac('sha256', $fut . '|' . gv_nonce_bind('ua', ''), 's3');
t_ok('a nonce dated well in the future is refused', gv_nonce_check($fut, 's3', 120, 'ua', '') === false);
$near = (time() + 10) . '.' . '00112233aabbccdd' . '.0';
$near .= '.' . hash_hmac('sha256', $near . '|' . gv_nonce_bind('ua', ''), 's3');
t_ok('a few seconds of clock skew are tolerated', gv_nonce_check($near, 's3', 120, 'ua', '') === true);

// Settings that would switch the guard off, or the shop, in one click.
t_ok('the overlay refuses an exempt path that covers the whole site',
	gv_overlay_validate('exempt_paths', array('/'))[0] === false && gv_overlay_validate('exempt_paths', array('/a'))[0] === false
	&& gv_overlay_validate('exempt_paths', array('/admin/'))[0] === true);
t_ok('the overlay refuses a bot fragment that matches every browser',
	gv_overlay_validate('known_bots', array('a'))[0] === false && gv_overlay_validate('known_bots', array('mozilla'))[0] === false
	&& gv_overlay_validate('preview_bots', array('chrome'))[0] === false && gv_overlay_validate('known_bots', array('bingbot'))[0] === true);
t_ok('the overlay refuses a honeypot on the home page', gv_overlay_validate('honeypot_path', '/')[0] === false && gv_overlay_validate('honeypot_path', '/old-archive')[0] === true);
t_ok('proof-of-work is capped where a phone can still solve it', gv_overlay_validate('challenge.pow_bits', 24)[0] === false && gv_overlay_validate('challenge.pow_bits', 22)[0] === true);
t_ok('gate_post and the unverified-bot budget are tunable; trust_headers still is not',
	gv_overlay_validate('challenge.gate_post', true) === array(true, true) && gv_overlay_validate('limits.bot_unverified', 50) === array(true, 50)
	&& gv_overlay_validate('challenge.trust_headers', true)[0] === false);
$lr = gv_log_row(t_facts(array('method' => str_repeat('M', 500), 'sf' => str_repeat('s', 9000))), gv_state_new(), 'allow', 0, microtime(true));
t_ok('the method and Sec-Fetch-Mode are capped in the log row', strlen($lr['m']) === 16 && strlen($lr['sf']) === 32);
t_ok('trust_headers restores the old rule: only a navigation is gated',
	gv_is_gate(t_facts(), true) === true
	&& gv_is_gate(t_facts(array('accept' => '*/*')), true) === false
	&& gv_is_gate(t_facts(array('xrw' => 'XMLHttpRequest')), true) === false);
t_ok('a header-less GET with no token is challenged, not allowed',
	gv_decide(0, false, gv_is_gate(t_facts(array('accept' => '*/*'))), 'm', 60, '') === 'challenge');
t_ok('a hard score blocks a scripted GET that does not ask for HTML',
	gv_decide(60, false, gv_is_gate(t_facts(array('accept' => '*/*'))), 'm', 60, '') === '403');

// Defaults of the keys added with the gate.
$gate_cfg = gv_cfg_defaults(array());
t_ok('trust_headers defaults to off', $gate_cfg['challenge']['trust_headers'] === false);
t_ok('the long-window device budgets and the preview budget have defaults',
	$gate_cfg['limits']['device_hour'] === 400 && $gate_cfg['limits']['device_day'] === 1500
	&& $gate_cfg['limits']['preview'] === 20 && $gate_cfg['limits']['bot_unverified'] === 300
	&& $gate_cfg['limits']['mint'] === 300 && $gate_cfg['challenge']['gate_post'] === false);
t_ok('a config file without them still gets them (old installs keep working)',
	gv_cfg_defaults(array('limits' => array('device' => 7)))['limits']['device_hour'] === 400
	&& gv_cfg_defaults(array('limits' => array('device' => 7)))['limits']['device'] === 7);
t_ok('preview_bots defaults to an empty list and is forced to a list',
	$gate_cfg['preview_bots'] === array() && gv_cfg_defaults(array('preview_bots' => 'x'))['preview_bots'] === array());
t_ok('every default known bot has a suffix list to be verified against',
	count(array_diff((require __DIR__ . '/../guard/config.php')['known_bots'],
		array_keys((require __DIR__ . '/../guard/config.php')['bot_suffixes']))) === 0);
t_ok('the Google ad and inspection crawlers match a default known bot',
	gv_match_bot('AdsBot-Google (+http://www.google.com/adsbot.html)',
		(require __DIR__ . '/../guard/config.php')['known_bots']) === 'adsbot-google'
	&& gv_match_bot('Mozilla/5.0 (compatible; Google-InspectionTool/1.0;)',
		(require __DIR__ . '/../guard/config.php')['known_bots']) === 'google-inspectiontool');
t_ok('the overlay accepts the new limits and refuses a zero',
	gv_overlay_validate('limits.device_hour', 200) === array(true, 200)
	&& gv_overlay_validate('limits.device_day', 900) === array(true, 900)
	&& gv_overlay_validate('limits.preview', 30) === array(true, 30)
	&& gv_overlay_validate('limits.device_day', 0)[0] === false);
t_ok('the overlay accepts preview_bots and has no key for trust_headers',
	gv_overlay_validate('preview_bots', array('telegrambot'))[0] === true
	&& gv_overlay_validate('challenge.trust_headers', true)[0] === false);

// --------------------------------------------------------------------------
t_section('Static scoring');

$r = gv_score(t_facts(), false);
t_ok('clean full browser scores 0 with no reasons', $r[0] === 0 && $r[1] === array());

$r = gv_score(t_facts(array('ua' => '')), false);
t_ok('empty UA scores 40 as UA_EMPTY', $r[0] === 40 && $r[1] === array('UA_EMPTY'));

$r = gv_score(t_facts(array('ua' => 'python-requests/2.31.0')), false);
t_ok('scripted UA scores 30 as UA_SCRIPT', $r[0] === 30 && $r[1] === array('UA_SCRIPT'));

$r = gv_score(t_facts(array('ua' => 'curl/8.5.0')), false);
t_ok('curl UA scores 30 as UA_SCRIPT', $r[0] === 30 && $r[1] === array('UA_SCRIPT'));

$r = gv_score(t_facts(array('sf' => '')), false);
t_ok('Chrome 126 without Sec-Fetch-Mode scores 20 as NO_SF', $r[0] === 20 && $r[1] === array('NO_SF'));

$r = gv_score(t_facts(array('ua' => 'Mozilla/5.0 (compatible; Chrome/60.0)', 'sf' => '')), false);
t_ok('old Chrome without Sec-Fetch-Mode is not penalised', $r[0] === 0 && $r[1] === array());

$r = gv_score(t_facts(array('al' => '')), false);
t_ok('navigation without Accept-Language scores 15 as NO_AL', $r[0] === 15 && $r[1] === array('NO_AL'));

$r = gv_score(t_facts(array('al' => '', 'accept' => 'application/json')), false);
t_ok('non-navigation without Accept-Language is not penalised', $r[0] === 0 && $r[1] === array());

$r = gv_score(t_facts(array('hc' => 3)), false);
t_ok('fewer than 5 headers scores 15 as FEW_HDR', $r[0] === 15 && $r[1] === array('FEW_HDR'));

$r = gv_score(t_facts(), true);
t_ok('honeypot history scores 40 as HP_HIST', $r[0] === 40 && $r[1] === array('HP_HIST'));

$r = gv_score(t_facts(array('ua' => '', 'al' => '', 'hc' => 2)), false);
t_ok('empty UA plus no Accept-Language plus few headers reaches the block score',
	$r[0] === 70 && $r[1] === array('UA_EMPTY', 'NO_AL', 'FEW_HDR'));

// --------------------------------------------------------------------------
t_section('Exemptions and known bots');

$ex = array('/internal-cron.php', '/rest/');
t_ok('exact exempt path matches', gv_is_exempt(t_facts(array('path' => '/internal-cron.php')), $ex, array()) === true);
t_ok('exempt path prefix matches', gv_is_exempt(t_facts(array('path' => '/rest/v2/posts')), $ex, array()) === true);
t_ok('other path is not exempt', gv_is_exempt(t_facts(array('path' => '/shop')), $ex, array()) === false);

$ep = array('route' => array('payment/', 'api/'));
t_ok('exempt param prefix matches',
	gv_is_exempt(t_facts(array('params' => array('route' => 'payment/callback'))), array(), $ep) === true);
t_ok('other param value is not exempt',
	gv_is_exempt(t_facts(array('params' => array('route' => 'product/product'))), array(), $ep) === false);

$bots = array('googlebot', 'bingbot');
t_ok('googlebot UA matches', gv_match_bot('Mozilla/5.0 (compatible; Googlebot/2.1)', $bots) === 'googlebot');
t_ok('browser UA does not match a bot', gv_match_bot(t_facts()['ua'], $bots) === '');
t_ok('empty UA does not match a bot', gv_match_bot('', $bots) === '');

// --------------------------------------------------------------------------
t_section('RESP serialization');

t_ok('gv_resp_encode produces the exact RESP byte string',
	gv_resp_encode(array('INCR', 'gv:x')) === "*2\r\n\$4\r\nINCR\r\n\$4\r\ngv:x\r\n");
t_ok('gv_resp_encode handles three arguments',
	gv_resp_encode(array('SETEX', 'gv:hp:1.2.3.4', '1')) === "*3\r\n\$5\r\nSETEX\r\n\$13\r\ngv:hp:1.2.3.4\r\n\$1\r\n1\r\n");

// --------------------------------------------------------------------------
t_section('Redis degraded mode');

$t = microtime(true);
$conn = gv_redis_connect(array('host' => '127.0.0.1', 'port' => 63999, 'timeout' => 0.05, 'breaker_ttl' => 0));
$took = microtime(true) - $t;
t_ok('connect to a closed port returns false', $conn === false);
t_ok('connect to a closed port fails in under 0.2 s (took '
	. number_format($took, 4) . ' s)', $took < 0.2);
t_ok('commands on a false connection return false', gv_redis_cmd(false, array('PING')) === false);
t_ok('counter bump on a false connection returns 0', gv_bump(false, 'gv:x', 60) === 0);

// --------------------------------------------------------------------------
t_section('Logger');

$tmp = sys_get_temp_dir() . '/gv-selftest-' . getmypid();
$facts = t_facts(array('referer' => 'https://example.com/a/b?c=d'));
$state = array('tok' => 'v', 'dev' => 'abc123', 'sc' => 15, 'rs' => array('FEW_HDR'),
	'cd' => 1, 'ciu' => 2, 'ci' => 3, 'rd' => 0, 'hp' => 0, 'bot' => '',
	'botv' => 'ok', 'rep' => -20, 'ml' => 30, 'clf' => 12, 'esc' => 15,
	'hold' => 0, 'ovr' => '');
gv_log(gv_log_row($facts, $state, 'allow', 0, microtime(true) - 0.01), $tmp);

$file = $tmp . '/guard-' . date('Ymd') . '.jsonl';
t_ok('log file was created', is_file($file));

$lines = is_file($file) ? file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : array();
t_ok('log file holds exactly one line', count($lines) === 1);

$row = count($lines) === 1 ? json_decode($lines[0], true) : null;
t_ok('log line is valid JSON', is_array($row));

$schema = array('v', 'rid', 'ts', 'ip', 'ua', 'uah', 'm', 'p', 'q', 'aj', 'nav', 'gate', 'tok',
	'dev', 'sf', 'al', 'hc', 'sc', 'esc', 'rs', 'cd', 'cdh', 'cdd', 'ciu', 'ci', 'rd', 'hp', 'bot',
	'ref', 'botv', 'rep', 'ml', 'clf', 'hold', 'ovr', 'act', 'sh', 'ms');
t_ok('log line carries every schema key in order', is_array($row) && array_keys($row) === $schema);
t_ok('referer is reduced to its host', is_array($row) && $row['ref'] === 'example.com');
t_ok('navigation and ajax flags are recorded',
	is_array($row) && $row['nav'] === 1 && $row['aj'] === 0);
t_ok('guard wall time is recorded', is_array($row) && $row['ms'] >= 10 && $row['ms'] < 1000);

t_ok('phase 2 verdicts appear in the log row',
	is_array($row) && $row['botv'] === 'ok' && $row['rep'] === -20 && $row['ml'] === 30);
t_ok('static and effective scores are both logged',
	is_array($row) && $row['sc'] === 15 && $row['esc'] === 15);
t_ok('phase 3 fields appear in the log row',
	is_array($row) && $row['clf'] === 12 && $row['hold'] === 0 && $row['ovr'] === '');

if (is_file($file)) { @unlink($file); }
if (is_dir($tmp)) { @rmdir($tmp); }

// --------------------------------------------------------------------------
t_section('Phase 2 score folding (shadow-first)');

$shadow_cfg = gv_cfg_defaults(array());
t_ok('signals default to off', $shadow_cfg['signals']['reputation'] === false
	&& $shadow_cfg['signals']['ml'] === false);
t_ok('ml_weight defaults to 0.4', $shadow_cfg['ml_weight'] === 0.4);
t_ok('bot_suffixes defaults cover googlebot and bingbot',
	isset($shadow_cfg['bot_suffixes']['googlebot'])
	&& isset($shadow_cfg['bot_suffixes']['bingbot']));
t_ok('a phase 1 config without signals still merges cleanly',
	gv_cfg_defaults(array('secret' => 'x'))['signals']['ml'] === false);

// Rounding must not depend on the PHP version (8.4 removed round()'s pre-rounding).
t_ok('gv_round_int: 0.7 * 85 is 60, not 59 (binary noise below .5)', gv_round_int(0.7 * 85) === 60);
t_ok('gv_round_int: the boundaries that differ between PHP versions',
	gv_round_int(50 * 0.29) === 15 && gv_round_int(90 * 0.35) === 32 && gv_round_int(25 * 0.58) === 15 && gv_round_int(45 * 0.70) === 32);
t_ok('gv_round_int: halves go away from zero', gv_round_int(0.5) === 1 && gv_round_int(1.5) === 2 && gv_round_int(-0.5) === -1 && gv_round_int(-1.5) === -2);
t_ok('gv_round_int: ordinary values', gv_round_int(59.4) === 59 && gv_round_int(59.6) === 60 && gv_round_int(0) === 0 && gv_round_int(-59.4) === -59);
$rnd_cfg = array('signals' => array('reputation' => false, 'ml' => true, 'clf' => false), 'ml_weight' => 0.7, 'clf_weight' => 0.5);
t_ok('effective score: ml level 85 at weight 0.7 reaches 60 on every PHP version', gv_effective_score(0, 0, 85, -1, $rnd_cfg) === 60);
t_ok('with signals off a positive reputation does not move the score',
	gv_effective_score(20, 60, -1, -1, $shadow_cfg) === 20);
t_ok('with signals off an anomaly level does not move the score',
	gv_effective_score(20, 0, 100, -1, $shadow_cfg) === 20);
t_ok('with signals off effective equals static even with both verdicts',
	gv_effective_score(20, 60, 100, -1, $shadow_cfg) === 20);

$on_cfg = gv_cfg_defaults(array('signals' => array('reputation' => true, 'ml' => true)));
t_ok('with reputation on a positive verdict is added',
	gv_effective_score(20, 45, -1, -1, $on_cfg) === 65);
t_ok('with reputation on a negative verdict rescues the score',
	gv_effective_score(30, -20, -1, -1, $on_cfg) === 10);
t_ok('with ml on the level scales by ml_weight',
	gv_effective_score(20, 0, 80, -1, $on_cfg) === 52);
t_ok('an ml level of -1 means no verdict and contributes nothing',
	gv_effective_score(20, 0, -1, -1, $on_cfg) === 20);
t_ok('an ml level of 0 is a real verdict and contributes zero',
	gv_effective_score(20, 0, 0, -1, $on_cfg) === 20);
t_ok('both signals fold together',
	gv_effective_score(10, 30, 50, -1, $on_cfg) === 60);

$rep_only = gv_cfg_defaults(array('signals' => array('reputation' => true)));
t_ok('one toggle on does not enable the other',
	gv_effective_score(20, 10, 100, -1, $rep_only) === 30);

$weighted = gv_cfg_defaults(array('signals' => array('ml' => true), 'ml_weight' => 1.0));
t_ok('ml_weight is honoured', gv_effective_score(0, 0, 70, -1, $weighted) === 70);

// --- classifier signal ----------------------------------------------------
t_ok('clf defaults to off', $shadow_cfg['signals']['clf'] === false);
t_ok('clf_weight defaults to 0.5', $shadow_cfg['clf_weight'] === 0.5);
t_ok('with clf off a classifier level does not move the score',
	gv_effective_score(20, 0, -1, 100, $shadow_cfg) === 20);

$clf_cfg = gv_cfg_defaults(array('signals' => array('clf' => true)));
t_ok('with clf on the level scales by clf_weight',
	gv_effective_score(20, 0, -1, 80, $clf_cfg) === 60);
t_ok('a clf level of -1 means no verdict and contributes nothing',
	gv_effective_score(20, 0, -1, -1, $clf_cfg) === 20);
t_ok('a clf level of 0 is a real verdict and contributes zero',
	gv_effective_score(20, 0, -1, 0, $clf_cfg) === 20);
t_ok('clf alone does not enable the other signals',
	gv_effective_score(20, 40, 100, 0, $clf_cfg) === 20);

$all_on = gv_cfg_defaults(array('signals' => array(
	'reputation' => true, 'ml' => true, 'clf' => true)));
t_ok('all three signals fold together',
	gv_effective_score(10, 20, 50, 40, $all_on) === 70);
t_ok('with every signal on and no verdicts the score is untouched',
	gv_effective_score(25, 0, -1, -1, $all_on) === 25);
t_ok('clf_weight is honoured',
	gv_effective_score(0, 0, -1, 60, gv_cfg_defaults(array(
		'signals' => array('clf' => true), 'clf_weight' => 1.0))) === 60);
t_ok('a classifier level can flip a borderline device once enabled',
	gv_decide(gv_effective_score(40, 0, -1, 50, $clf_cfg), false, true, 'v', 60, '') === '403'
	&& gv_decide(gv_effective_score(40, 0, -1, 50, $shadow_cfg), false, true, 'v', 60, '') === 'allow');

// --------------------------------------------------------------------------
t_section('Phase 4 request id and outcome capture');

$rid = gv_rid();
t_ok('gv_rid returns 12 hex characters',
	is_string($rid) && strlen($rid) === 12 && ctype_xdigit($rid));
$rids = array();
for ($i = 0; $i < 5000; $i++) { $rids[gv_rid()] = 1; }
t_ok('gv_rid is unique across 5000 calls', count($rids) === 5000);

t_ok('capture_outcomes defaults to false',
	gv_cfg_defaults(array())['capture_outcomes'] === false);
t_ok('a phase 1-3 config without capture_outcomes still merges',
	gv_cfg_defaults(array('secret' => 'x'))['capture_outcomes'] === false);

// gv_declared_length reads headers_list(), which is empty under CLI, so the
// parsing itself is tested through the same helper the function uses.
t_ok('an absent Content-Length yields null', gv_declared_length() === null);
t_ok('gv_request_ms returns null without REQUEST_TIME_FLOAT',
	!isset($_SERVER['REQUEST_TIME_FLOAT']) ? gv_request_ms() === null : true);

// The decision line now carries the schema version and the correlation id.
$rid_facts = t_facts(array('rid' => $rid));
$rid_state = array('tok' => 'm', 'dev' => '', 'sc' => 0, 'rs' => array(),
	'cd' => 0, 'ciu' => 0, 'ci' => 0, 'rd' => 0, 'hp' => 0, 'bot' => '',
	'botv' => '', 'rep' => 0, 'ml' => -1, 'clf' => -1, 'esc' => 0,
	'hold' => 0, 'ovr' => '');
$rid_row = gv_log_row($rid_facts, $rid_state, 'allow', 0, microtime(true));
$rid_keys = array_keys($rid_row);
t_ok('the decision line starts with v then rid then ts',
	array_slice($rid_keys, 0, 3) === array('v', 'rid', 'ts'));
t_ok('the schema version is 5', $rid_row['v'] === 5);
t_ok('a hand-built state without the schema 5 keys logs them as 0',
	$rid_row['gate'] === 0 && $rid_row['cdh'] === 0 && $rid_row['cdd'] === 0);
t_ok('the decision line carries the request id', $rid_row['rid'] === $rid);
t_ok('a facts array without a rid still logs cleanly',
	gv_log_row(t_facts(), $rid_state, 'allow', 0, microtime(true))['rid'] === '');

// The outcome row shape, written through the real writer.
$out_dir = sys_get_temp_dir() . '/gv-selftest-out-' . getmypid();
$out_row = array('o' => 1, 'rid' => $rid, 'st' => 404, 'by' => 1183,
	'dur' => 38.4, 'ts' => round(microtime(true), 3));
gv_log_outcome($out_row, $out_dir);
$out_file = $out_dir . '/guard-' . date('Ymd') . '.jsonl';
t_ok('gv_log_outcome writes to the same daily file', is_file($out_file));
$out_lines = is_file($out_file) ? file($out_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : array();
t_ok('the outcome writer appended exactly one line', count($out_lines) === 1);
$out_back = count($out_lines) === 1 ? json_decode($out_lines[0], true) : null;
t_ok('the outcome line is valid JSON', is_array($out_back));
t_ok('the outcome line has exactly the six documented keys in order',
	is_array($out_back) && array_keys($out_back) === array('o', 'rid', 'st', 'by', 'dur', 'ts'));
t_ok('the outcome line round-trips its values',
	is_array($out_back) && $out_back['o'] === 1 && $out_back['rid'] === $rid
	&& $out_back['st'] === 404 && $out_back['by'] === 1183 && $out_back['dur'] === 38.4);

gv_log_outcome(array('o' => 1, 'rid' => $rid, 'st' => 200, 'by' => null,
	'dur' => null, 'ts' => round(microtime(true), 3)), $out_dir);
$out_lines = file($out_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$null_back = json_decode($out_lines[1], true);
t_ok('an undeclared length is logged as null, never guessed',
	is_array($null_back) && array_key_exists('by', $null_back) && $null_back['by'] === null);
t_ok('a missing duration is logged as null',
	is_array($null_back) && $null_back['dur'] === null);

t_ok('an unwritable outcome directory fails silently',
	gv_log_outcome($out_row, '/proc/nonexistent/gv') === null);
t_ok('an empty outcome directory fails silently',
	gv_log_outcome($out_row, '') === null);
if (is_file($out_file)) { @unlink($out_file); }
if (is_dir($out_dir)) { @rmdir($out_dir); }

// --------------------------------------------------------------------------
t_section('Phase 4 capture safety (static analysis of guard/outcome.php)');

// Tokenise the capture file and inspect ONLY the shutdown closure body.
//
// Scoping matters twice over: comments and string literals are stripped, so the
// notes that MENTION these traps do not trip the check while a real call would;
// and the file-level `if (!defined('GV_BOOT')) { http_response_code(404); exit; }`
// guard that every guard/*.php carries is correctly excluded, because it can
// only run when the file is fetched directly over the web - a context in which
// there is no application response to protect.
$cap_src = file_get_contents(__DIR__ . '/../guard/outcome.php');
$cap_all = token_get_all($cap_src);

$closure_start = -1;
foreach ($cap_all as $index => $tk) {
	if (is_array($tk) && $tk[0] === T_STRING
		&& strtolower($tk[1]) === 'register_shutdown_function') {
		$closure_start = $index;
		break;
	}
}
t_ok('the shutdown closure was located for inspection', $closure_start >= 0);

// Collect the closure body: from its opening brace to the matching close.
$cap_code = array();
if ($closure_start >= 0) {
	$depth = 0;
	$started = false;
	for ($i = $closure_start; $i < count($cap_all); $i++) {
		$tk = $cap_all[$i];
		$text = is_array($tk) ? $tk[1] : $tk;
		if ($text === '{') { $depth++; $started = true; }
		if ($started) {
			if (is_array($tk)) {
				if ($tk[0] !== T_COMMENT && $tk[0] !== T_DOC_COMMENT
					&& $tk[0] !== T_INLINE_HTML && $tk[0] !== T_CONSTANT_ENCAPSED_STRING) {
					$cap_code[] = array('t' => $tk[0], 's' => $tk[1]);
				}
			} else {
				$cap_code[] = array('t' => null, 's' => $tk);
			}
		}
		if ($text === '}') {
			$depth--;
			if ($started && $depth === 0) { break; }
		}
	}
}
t_ok('the closure body is non-trivial and balanced', count($cap_code) > 20);

$cap_names = array();
foreach ($cap_code as $tk) {
	if ($tk['t'] === T_STRING || $tk['t'] === T_ECHO || $tk['t'] === T_PRINT
		|| $tk['t'] === T_EXIT) {
		$cap_names[] = strtolower($tk['s']);
	}
}

$forbidden = array('echo', 'print', 'print_r', 'var_dump', 'printf', 'vprintf',
	'header', 'header_remove', 'setcookie', 'setrawcookie', 'ob_start',
	'ob_end_flush', 'ob_end_clean', 'ob_flush', 'ob_get_clean', 'flush',
	'exit', 'die', 'readfile', 'fpassthru', 'passthru');
$hits = array();
foreach ($forbidden as $bad) {
	if (in_array($bad, $cap_names, true)) { $hits[] = $bad; }
}
t_ok('the shutdown closure calls nothing that can touch the response'
	. (count($hits) ? ' (found: ' . implode(', ', $hits) . ')' : ''), count($hits) === 0);

// http_response_code is allowed only as a READ, with no argument.
$writes_status = false;
for ($i = 0; $i < count($cap_code); $i++) {
	if ($cap_code[$i]['t'] !== T_STRING) { continue; }
	if (strtolower($cap_code[$i]['s']) !== 'http_response_code') { continue; }
	// The next two significant tokens must be exactly '(' and ')'.
	$next = array();
	for ($j = $i + 1; $j < count($cap_code) && count($next) < 2; $j++) {
		if ($cap_code[$j]['t'] === T_WHITESPACE) { continue; }
		$next[] = $cap_code[$j]['s'];
	}
	if ($next !== array('(', ')')) { $writes_status = true; }
}
t_ok('http_response_code is only ever read, never written', $writes_status === false);
t_ok('the closure does read the status code', in_array('http_response_code', $cap_names, true));
t_ok('the closure writes exactly one log line',
	count(array_keys($cap_names, 'gv_log_outcome', true)) === 1);

t_ok('the capture file registers exactly one shutdown function',
	substr_count($cap_src, 'register_shutdown_function(') === 1);
t_ok('the shutdown closure captures by value, never by reference',
	strpos($cap_src, 'use (&') === false);
t_ok('the shutdown closure body is wrapped in a catch-all',
	preg_match('/register_shutdown_function\(function \(\) use \([^)]*\) \{\s*try \{/', $cap_src) === 1);
t_ok('the capture file catches Throwable, not just Exception',
	strpos($cap_src, 'catch (\\Throwable $e)') !== false);
t_ok('the capture file never buffers the response',
	strpos(implode(' ', $cap_names), 'ob_') === false);

// The hook must be armed on every gv_run path that returns, and on none that
// exits. Checked structurally against the source rather than by inspection.
$run_src = file_get_contents(__DIR__ . '/../guard/guard.php');
$run_body = substr($run_src, strpos($run_src, 'function gv_run('));
$run_lines = explode("\n", $run_body);
$armed_returns = 0;
$bare_returns = 0;
$armed_exits = 0;
for ($i = 0; $i < count($run_lines); $i++) {
	$line = trim($run_lines[$i]);
	if (strpos($line, 'gv_arm_outcome(') === 0) {
		$after = isset($run_lines[$i + 1]) ? trim($run_lines[$i + 1]) : '';
		if (strpos($after, 'return;') === 0) { $armed_returns++; }
		if (strpos($after, 'exit;') === 0) { $armed_exits++; }
		continue;
	}
	if (strpos($line, 'return;') === 0) {
		$before = $i > 0 ? trim($run_lines[$i - 1]) : '';
		if (strpos($before, 'gv_arm_outcome(') !== 0) { $bare_returns++; }
	}
}
t_ok('every return path in gv_run arms outcome capture (' . $armed_returns . ' armed)',
	$armed_returns === 7 && $bare_returns === 0);
t_ok('no exit path arms outcome capture', $armed_exits === 0);

// --------------------------------------------------------------------------
t_section('Phase 3 operator overrides');

t_ok('no override leaves the decision alone',
	gv_decide(0, false, true, 'v', 60, '') === 'allow');
t_ok('a deny override forces 403 on a clean request',
	gv_decide(0, false, true, 'v', 60, 'deny') === '403');
t_ok('a deny override forces 403 on a non-navigation too',
	gv_decide(0, false, false, 'v', 60, 'deny') === '403');
t_ok('a deny override wins over the rate rule',
	gv_decide(0, true, true, 'v', 60, 'deny') === '403');
t_ok('a deny override wins over the challenge rule',
	gv_decide(0, false, true, 'm', 60, 'deny') === '403');
t_ok('an unknown override value is ignored',
	gv_decide(0, false, true, 'v', 60, 'maybe') === 'allow');
t_ok('override reads in degraded mode return no signal',
	gv_override(false, '203.0.113.1', 'devA') === '');

// --------------------------------------------------------------------------
t_section('Fail-open on a stalled Redis read');

// A server that accepts the connection and then never answers. The write
// succeeds, the read times out, and gv_r_get returns false rather than null -
// which is exactly the case that used to be mistaken for a 'bad' verdict.
$stall_errno  = 0;
$stall_errstr = '';
$stall = @stream_socket_server('tcp://127.0.0.1:0', $stall_errno, $stall_errstr);
if (!$stall) {
	t_skip('a stalled redis read yields no verdict', 'could not open a local listening socket');
} else {
	$stall_name = stream_socket_get_name($stall, false);
	$stall_port = (int)substr($stall_name, strrpos($stall_name, ':') + 1);
	$stall_conn = gv_redis_connect(array('host' => '127.0.0.1', 'port' => $stall_port, 'breaker_ttl' => 0,
		'timeout' => 0.05));
	t_ok('connecting to a silent server succeeds', $stall_conn !== false);
	if ($stall_conn) {
		$t_start = microtime(true);
		$stall_reply = gv_r_get($stall_conn, 'gv:botbad:203.0.113.5');
		$stall_took = microtime(true) - $t_start;
		t_ok('a stalled read returns false, not null', $stall_reply === false);
		t_ok('a stalled read gives up quickly (' . number_format($stall_took, 3) . ' s)',
			$stall_took < 1.0);
		t_ok('a stalled read yields no bot verdict rather than a bad one',
			gv_bot_verdict($stall_conn, '203.0.113.5') === '');
		t_ok('a stalled read yields no operator override either',
			gv_override($stall_conn, '203.0.113.5', 'devA') === '');
		gv_redis_close($stall_conn);
	}
	fclose($stall);
}

// --------------------------------------------------------------------------
t_section('Phase 3 holdout membership');

t_ok('holdout is off by default', gv_is_holdout('devA', 'salt', 0) === false);
t_ok('a negative percentage is treated as off', gv_is_holdout('devA', 'salt', -3) === false);
t_ok('an empty identity is never in the holdout', gv_is_holdout('', 'salt', 5) === false);

$ident = 'devA';
$first = gv_is_holdout($ident, 'salt', 5);
$stable = true;
for ($i = 0; $i < 200; $i++) {
	if (gv_is_holdout($ident, 'salt', 5) !== $first) { $stable = false; break; }
}
t_ok('membership is deterministic for the same identity', $stable);

$hits_salt_a = 0;
$hits_salt_b = 0;
for ($i = 0; $i < 2000; $i++) {
	if (gv_is_holdout('dev' . $i, 'salt-a', 5)) { $hits_salt_a++; }
	if (gv_is_holdout('dev' . $i, 'salt-b', 5)) { $hits_salt_b++; }
}
t_ok('changing the salt reshuffles membership', $hits_salt_a !== $hits_salt_b);

// Rate across many synthetic identities should land near the configured target.
$sample = 20000;
$rates  = array();
foreach (array(1, 2, 5) as $pct) {
	$hits = 0;
	for ($i = 0; $i < $sample; $i++) {
		if (gv_is_holdout('device-' . $i, 'measure-salt', $pct)) { $hits++; }
	}
	$rates[$pct] = 100.0 * $hits / $sample;
}
t_ok('1 percent lands near target (' . number_format($rates[1], 2) . '%)',
	abs($rates[1] - 1.0) < 0.5);
t_ok('2 percent lands near target (' . number_format($rates[2], 2) . '%)',
	abs($rates[2] - 2.0) < 0.7);
t_ok('5 percent lands near target (' . number_format($rates[5], 2) . '%)',
	abs($rates[5] - 5.0) < 1.0);

$clamped = 0;
$at_five = 0;
for ($i = 0; $i < 5000; $i++) {
	if (gv_is_holdout('device-' . $i, 'measure-salt', 90)) { $clamped++; }
	if (gv_is_holdout('device-' . $i, 'measure-salt', 5)) { $at_five++; }
}
t_ok('a percentage above 5 is clamped to 5', $clamped === $at_five);
t_ok('the clamped rate stays near 5 percent (' . number_format(100.0 * $clamped / 5000, 2) . '%)',
	abs(100.0 * $clamped / 5000 - 5.0) < 1.0);

// --------------------------------------------------------------------------
t_section('Holdout enforcement gate (FIX #12 pt1)');

// The holdout suppresses the guard's own classifier decisions only; an operator
// deny is an action, not a classification, and a 429 is resource protection -
// neither is ever held out.
t_ok('a held-out classifier 403 is suppressed',
	gv_holdout_suppresses(1, '', '403') === true);
t_ok('a held-out challenge is suppressed',
	gv_holdout_suppresses(1, '', 'challenge') === true);
t_ok('a held-out operator deny is NOT suppressed, so it still enforces',
	gv_holdout_suppresses(1, 'deny', '403') === false);
t_ok('a held-out 429 is never suppressed',
	gv_holdout_suppresses(1, '', '429') === false);
t_ok('outside the holdout nothing is suppressed',
	gv_holdout_suppresses(0, '', '403') === false
	&& gv_holdout_suppresses(0, 'deny', '403') === false);
t_ok('an identity in the holdout slice with ovr=deny produces an enforced 403',
	gv_decide(0, false, true, 'v', 60, 'deny') === '403'
	&& gv_holdout_suppresses(1, 'deny', gv_decide(0, false, true, 'v', 60, 'deny')) === false);

// --------------------------------------------------------------------------
t_section('Phase 2 decision engine');

t_ok('a clean tokened navigation is allowed', gv_decide(0, false, true, 'v', 60, '') === 'allow');
t_ok('a hard score blocks a navigation', gv_decide(60, false, true, 'v', 60, '') === '403');
t_ok('a hard score never blocks a non-navigation',
	gv_decide(90, false, false, 'v', 60, '') === 'allow');
t_ok('an over-limit counter returns 429', gv_decide(0, true, true, 'v', 60, '') === '429');
t_ok('a token-less navigation is challenged', gv_decide(0, false, true, 'm', 60, '') === 'challenge');
t_ok('a token-less non-navigation is never challenged',
	gv_decide(0, false, false, 'm', 60, '') === 'allow');
t_ok('the score rule wins over the rate rule',
	gv_decide(60, true, true, 'm', 60, '') === '403');
t_ok('the rate rule wins over the challenge rule',
	gv_decide(0, true, true, 'm', 60, '') === '429');

// Reputation flipping a borderline decision, end to end through both functions.
// Note the flip lands on 403, not challenge: the challenge rule is gated on the
// token, not on the score, so a device that already holds a token can only be
// moved by the hard-score rule.
$borderline_sc = 40;
t_ok('a borderline tokened device is allowed while reputation is shadowed',
	gv_decide(gv_effective_score($borderline_sc, 30, -1, -1, $shadow_cfg), false, true, 'v', 60, '') === 'allow');
t_ok('the same device is blocked once reputation is enabled',
	gv_decide(gv_effective_score($borderline_sc, 30, -1, -1, $on_cfg), false, true, 'v', 60, '') === '403');
t_ok('an anomaly level alone can flip the same borderline device',
	gv_decide(gv_effective_score($borderline_sc, 0, 60, -1, $on_cfg), false, true, 'v', 60, '') === '403');
t_ok('a trustworthy reputation keeps a scored device out of the block',
	gv_decide(gv_effective_score(65, -20, -1, -1, $on_cfg), false, true, 'v', 60, '') === 'allow');

// --------------------------------------------------------------------------
t_section('Redis roundtrip (optional)');

$redis_bin = trim((string)@shell_exec('command -v redis-server 2>/dev/null'));
if ($redis_bin === '') {
	t_skip('redis INCR/EXPIRE roundtrip', 'redis-server not installed in this environment');
} else {
	$port = 63790;
	$pid  = sys_get_temp_dir() . '/gv-selftest-redis-' . getmypid() . '.pid';
	@shell_exec(escapeshellarg($redis_bin) . ' --port ' . $port . ' --bind 127.0.0.1'
		. ' --save "" --appendonly no --daemonize yes --pidfile ' . escapeshellarg($pid)
		. ' >/dev/null 2>&1');
	$conn = false;
	for ($i = 0; $i < 50 && !$conn; $i++) {
		$conn = gv_redis_connect(array('host' => '127.0.0.1', 'port' => $port, 'timeout' => 0.2));
		if (!$conn) { usleep(100000); }
	}
	if (!$conn) {
		t_skip('redis INCR/EXPIRE roundtrip', 'local redis-server did not start');
	} else {
		$key = 'gv:selftest:' . getmypid();
		gv_redis_cmd($conn, array('DEL', $key));
		t_ok('redis PING replies PONG', gv_redis_cmd($conn, array('PING')) === 'PONG');
		t_ok('redis INCR returns 1 on a fresh key', gv_r_incr($conn, $key) === 1);
		t_ok('redis INCR returns 2 on the second call', gv_r_incr($conn, $key) === 2);
		t_ok('redis EXPIRE returns 1', gv_r_expire($conn, $key, 60) === 1);
		t_ok('redis TTL is set', (int)gv_redis_cmd($conn, array('TTL', $key)) > 0);
		t_ok('redis GET returns the bulk string', gv_r_get($conn, $key) === '2');
		t_ok('redis GET on a missing key returns null', gv_r_get($conn, $key . ':missing') === null);
		t_ok('redis SETEX returns OK', gv_r_setex($conn, $key . ':hp', 60, '1') === 'OK');
		t_ok('redis error reply returns false', gv_redis_cmd($conn, array('INCR')) === false);
		t_ok('counter bump against live redis counts up', gv_bump($conn, $key . ':b', 60) === 1
			&& gv_bump($conn, $key . ':b', 60) === 2);

		// FIX #10: a counter is created with its TTL in one atomic command, so a
		// key can never exist without an expiry (which became a permanent 429
		// once it crossed the limit).
		$nxk = $key . ':nx';
		gv_redis_cmd($conn, array('DEL', $nxk));
		t_ok('gv_r_set_nx_ex creates a fresh key and returns OK',
			gv_r_set_nx_ex($conn, $nxk, 60, 1) === 'OK');
		t_ok('the created key already carries a ttl',
			(int)gv_redis_cmd($conn, array('TTL', $nxk)) > 0);
		t_ok('gv_r_set_nx_ex on an existing key returns null and leaves it intact',
			gv_r_set_nx_ex($conn, $nxk, 60, 99) === null && gv_r_get($conn, $nxk) === '1');
		$bk = $key . ':bump';
		gv_redis_cmd($conn, array('DEL', $bk));
		t_ok('gv_bump sets a ttl on the very first hit',
			gv_bump($conn, $bk, 60) === 1 && (int)gv_redis_cmd($conn, array('TTL', $bk)) > 0);
		t_ok('gv_bump keeps counting at the same threshold past the first hit',
			gv_bump($conn, $bk, 60) === 2 && gv_bump($conn, $bk, 60) === 3);
		gv_redis_cmd($conn, array('DEL', $nxk, $bk));

		// --- Phase 2 verdict reads against a live keyspace -----------------
		$vip = '203.0.113.77';
		t_ok('no verdict reads as an empty string', gv_bot_verdict($conn, $vip) === '');
		gv_r_setex($conn, 'gv:botok:' . $vip, 60, '1');
		t_ok('a botok verdict reads as ok', gv_bot_verdict($conn, $vip) === 'ok');
		gv_r_setex($conn, 'gv:botbad:' . $vip, 60, '1');
		t_ok('a botbad verdict wins over botok', gv_bot_verdict($conn, $vip) === 'bad');
		gv_redis_cmd($conn, array('DEL', 'gv:botbad:' . $vip));
		gv_redis_cmd($conn, array('DEL', 'gv:botok:' . $vip));
		t_ok('deleting both verdicts returns to no signal', gv_bot_verdict($conn, $vip) === '');
		t_ok('verdict reads in degraded mode return no signal',
			gv_bot_verdict(false, $vip) === '');

		// A revoked bot claim: +35 lands in the static score, so it counts even
		// with every signal toggle off. A typical impersonator sends a bare
		// Googlebot UA with no Accept-Language and few headers.
		$fake_sc = 15 + 15 + 35;                  // NO_AL plus FEW_HDR plus BOT_FAKE
		t_ok('a revoked bot claim blocks even with every signal toggle off',
			gv_decide(gv_effective_score($fake_sc, 0, -1, -1, $shadow_cfg), false, true, 'm', 60, '') === '403');
		t_ok('the same headers without BOT_FAKE are only challenged',
			gv_decide(gv_effective_score(30, 0, -1, -1, $shadow_cfg), false, true, 'm', 60, '') === 'challenge');
		t_ok('BOT_FAKE alone does not block: an impersonator is still judged on its merits',
			gv_decide(gv_effective_score(35, 0, -1, -1, $shadow_cfg), false, true, 'm', 60, '') === 'challenge');

		// --- operator overrides against a live keyspace --------------------
		$odev = 'overridedev';
		$oip  = '203.0.113.88';
		t_ok('no override keys reads as no signal', gv_override($conn, $oip, $odev) === '');
		gv_r_setex($conn, 'gv:deny:' . $oip, 60, '1');
		t_ok('an ip deny is read even without a device',
			gv_override($conn, $oip, '') === 'deny');
		gv_r_setex($conn, 'gv:allow:' . $odev, 60, '1');
		t_ok('a device allow wins over an ip deny',
			gv_override($conn, $oip, $odev) === 'allow');
		gv_r_setex($conn, 'gv:deny:' . $odev, 60, '1');
		t_ok('a device allow wins over a device deny',
			gv_override($conn, $oip, $odev) === 'allow');
		gv_redis_cmd($conn, array('DEL', 'gv:allow:' . $odev));
		t_ok('removing the allow leaves the device deny in force',
			gv_override($conn, $oip, $odev) === 'deny');
		gv_redis_cmd($conn, array('DEL', 'gv:deny:' . $odev, 'gv:deny:' . $oip));
		t_ok('device keys are not read for an empty device id',
			gv_override($conn, $oip, '') === '');

		// A stuck customer who never completed the handshake has only an ip, so
		// gv:allow:{ip} must be honoured and must beat gv:deny:{ip}.
		gv_r_setex($conn, 'gv:allow:' . $oip, 60, '1');
		t_ok('an ip allow is read even without a device',
			gv_override($conn, $oip, '') === 'allow');
		gv_r_setex($conn, 'gv:deny:' . $oip, 60, '1');
		t_ok('an ip allow beats an ip deny',
			gv_override($conn, $oip, '') === 'allow');
		t_ok('an ip allow still applies when a device id is present',
			gv_override($conn, $oip, $odev) === 'allow');
		gv_redis_cmd($conn, array('DEL', 'gv:allow:' . $oip, 'gv:deny:' . $oip));

		$vdev = 'selftestdev';
		gv_r_setex($conn, 'gv:rep:' . $vdev, 60, '-20');
		gv_r_setex($conn, 'gv:ml:' . $vdev, 60, '75');
		t_ok('a signed reputation round-trips through redis',
			(int)gv_r_get($conn, 'gv:rep:' . $vdev) === -20);
		t_ok('an anomaly level round-trips through redis',
			(int)gv_r_get($conn, 'gv:ml:' . $vdev) === 75);
		t_ok('a missing reputation is not numeric and folds as neutral',
			is_numeric(gv_r_get($conn, 'gv:rep:missing')) === false);

		gv_redis_cmd($conn, array('FLUSHALL'));
		gv_redis_cmd($conn, array('SHUTDOWN', 'NOSAVE'));
		gv_redis_close($conn);
	}
	if (is_file($pid)) { @unlink($pid); }
}

// --------------------------------------------------------------------------
echo "\n";
echo "PASS " . $GV_PASS . "  FAIL " . $GV_FAIL . "  SKIP " . $GV_SKIP . "\n";
exit($GV_FAIL === 0 ? 0 : 1);
