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
t_section('PHP 8.4+ compatibility');
// A typed parameter with a null default ("array $x = null") is deprecated from
// PHP 8.4 and prints a notice on every request. Only the newest CI job would
// see it; this scan catches it on any PHP.
$cmp_bad = array();
foreach (array_merge(glob(__DIR__ . '/../guard/*.php'), glob(__DIR__ . '/../panel/*.php'), glob(__DIR__ . '/../panel/views/*.php'), glob(__DIR__ . '/*.php'), array(__DIR__ . '/../prepend.php')) as $cmp_f) {
	if (preg_match_all('/function\s+\w+\s*\([^)]*?(?<![?\w])(?:array|string|int|float|bool|callable|iterable|object|[A-Z]\w*)\s+\$\w+\s*=\s*null/i', file_get_contents($cmp_f), $m)) {
		$cmp_bad[] = basename($cmp_f);
	}
}
t_ok('no implicitly nullable typed parameter' . ($cmp_bad ? ' (' . implode(', ', $cmp_bad) . ')' : ''), !$cmp_bad);

t_section('Log storage settings');
t_ok('log storage defaults: no skipped path, 60 days, no cap, 200 MiB floor',
	gv_cfg_defaults(array())['log_skip_paths'] === array() && gv_cfg_defaults(array())['log_retention_days'] === 60
	&& gv_cfg_defaults(array())['log_max_mb'] === 0 && gv_cfg_defaults(array())['log_min_free_mb'] === 200);
t_ok('a hand-edited invalid value falls back to the default',
	gv_cfg_defaults(array('log_retention_days' => 0, 'log_max_mb' => -5, 'log_min_free_mb' => 'lots'))['log_retention_days'] === 60
	&& gv_cfg_defaults(array('log_max_mb' => -5))['log_max_mb'] === 0 && gv_cfg_defaults(array('log_min_free_mb' => 'lots'))['log_min_free_mb'] === 200);
t_ok('the overlay accepts the log settings and refuses a skip of the whole site',
	gv_overlay_validate('log_skip_paths', array('/gv-admin/'))[0] === true && gv_overlay_validate('log_skip_paths', array('/'))[0] === false
	&& gv_overlay_validate('log_retention_days', 0)[0] === false && gv_overlay_validate('log_retention_days', 365)[0] === true
	&& gv_overlay_validate('log_max_mb', 0)[0] === true && gv_overlay_validate('log_min_free_mb', -1)[0] === false);
t_ok('gv_path_has_prefix refuses dot segments and encoded slashes',
	gv_path_has_prefix('/gv-admin/index.php', array('/gv-admin/')) && !gv_path_has_prefix('/gv-admin/../x', array('/gv-admin/'))
	&& !gv_path_has_prefix('/gv-admin%2f..%2fx', array('/gv-admin')) && !gv_path_has_prefix('/other', array('/gv-admin/')));
$ls_dir = sys_get_temp_dir() . '/gv-ls-' . getmypid();
@mkdir($ls_dir);
gv_log_policy(array('skip' => true, 'min_free' => 0));
gv_log(array('a' => 1), $ls_dir); gv_log_outcome(array('o' => 1), $ls_dir);
t_ok('skip policy: gv_log and gv_log_outcome write nothing', glob($ls_dir . '/guard-*.jsonl') === array());
gv_log_policy(array('skip' => false, 'min_free' => 0));
gv_log(array('a' => 1), $ls_dir);
t_ok('policy cleared: the line is written', count(glob($ls_dir . '/guard-*.jsonl')) === 1);
foreach ((array)glob($ls_dir . '/{,.}*', GLOB_BRACE) as $ls_f) { if (is_file($ls_f)) { @unlink($ls_f); } }
@rmdir($ls_dir);

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
	$armed_returns === 8 && $bare_returns === 0);
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
t_section('Access rules');

function t_rule(array $over = array()) {
	return array_merge(array(
		'id' => 'r-test1', 'name' => 'test', 'enabled' => true, 'mode' => 'enforce', 'action' => 'block',
		'priority' => 100, 'skip_verified_bots' => true,
		'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('badbot')),
		'path' => null, 'expires_at' => 0, 'pow_bits' => 0, 'note' => '', 'created_by' => '',
		'created_at' => 0, 'updated_at' => 0,
	), $over);
}
function t_cond($type, array $values, $op = 'include') {
	return array('op' => $op, 'type' => $type, 'values' => $values);
}
function t_rule_hit(array $rule, $ua, $path = '/') {
	return gv_rule_matches($rule, array('ua' => $ua, 'path' => $path));
}
$now = 1800000000;

// Every UA condition type, both ops, case-insensitive.
t_ok('exact matches the whole UA, any case',
	t_rule_hit(t_rule(array('ua' => t_cond('exact', array('CurL/8.0')))), 'curl/8.0'));
t_ok('exact does not match a longer UA',
	!t_rule_hit(t_rule(array('ua' => t_cond('exact', array('curl/8.0')))), 'curl/8.0.1'));
t_ok('exact does not match a UA with a trailing newline',
	!t_rule_hit(t_rule(array('ua' => t_cond('exact', array('curl')))), "curl\n"));
t_ok('contains matches inside the UA',
	t_rule_hit(t_rule(array('ua' => t_cond('contains', array('HeadlessChrome')))), 'Mozilla/5.0 headlesschrome/120'));
t_ok('contains takes a regex metacharacter literally',
	!t_rule_hit(t_rule(array('ua' => t_cond('contains', array('a.c')))), 'abc')
	&& t_rule_hit(t_rule(array('ua' => t_cond('contains', array('a.c')))), 'xa.cx'));
t_ok('prefix matches only at the start',
	t_rule_hit(t_rule(array('ua' => t_cond('prefix', array('Go-http')))), 'go-http-client/1.1')
	&& !t_rule_hit(t_rule(array('ua' => t_cond('prefix', array('Go-http')))), 'x Go-http-client'));
t_ok('regex matches with the case-insensitive flag',
	t_rule_hit(t_rule(array('ua' => t_cond('regex', array('^python-(requests|urllib)/\d')))), 'Python-Requests/2.31'));
t_ok('regex values are alternatives of one pattern',
	t_rule_hit(t_rule(array('ua' => t_cond('regex', array('^aaa$', '^bbb$')))), 'bbb'));
t_ok('any of several values matches (include)',
	t_rule_hit(t_rule(array('ua' => t_cond('contains', array('one', 'two', 'three')))), 'xx two xx'));
t_ok('exclude matches when NO value matches',
	t_rule_hit(t_rule(array('ua' => t_cond('contains', array('mozilla'), 'exclude'))), 'curl/8')
	&& !t_rule_hit(t_rule(array('ua' => t_cond('contains', array('mozilla'), 'exclude'))), 'Mozilla/5.0'));

// <empty> means a missing or blank UA.
$empty_rule = t_rule(array('ua' => t_cond('exact', array(GV_RULE_EMPTY))));
t_ok('<empty> matches a missing UA', t_rule_hit($empty_rule, ''));
t_ok('<empty> matches a blank UA', t_rule_hit($empty_rule, "  \t"));
t_ok('<empty> does not match a real UA', !t_rule_hit($empty_rule, 'curl/8'));
t_ok('<empty> next to other values: either one matches',
	t_rule_hit(t_rule(array('ua' => t_cond('contains', array('curl', GV_RULE_EMPTY)))), '')
	&& t_rule_hit(t_rule(array('ua' => t_cond('contains', array('curl', GV_RULE_EMPTY)))), 'curl/8'));
t_ok('exclude <empty> matches every non-blank UA',
	t_rule_hit(t_rule(array('ua' => t_cond('exact', array(GV_RULE_EMPTY), 'exclude'))), 'curl/8')
	&& !t_rule_hit(t_rule(array('ua' => t_cond('exact', array(GV_RULE_EMPTY), 'exclude'))), ''));

// Path conditions and AND.
$pr = t_rule(array('ua' => null, 'path' => t_cond('prefix', array('/admin'))));
t_ok('a path prefix matches the raw path', t_rule_hit($pr, 'x', '/admin/login') && !t_rule_hit($pr, 'x', '/shop'));
t_ok('path exclude matches everything outside the prefix',
	t_rule_hit(t_rule(array('ua' => null, 'path' => t_cond('prefix', array('/api/'), 'exclude'))), 'x', '/shop'));
$both = t_rule(array('path' => t_cond('prefix', array('/admin'))));
t_ok('UA and path are AND-ed',
	t_rule_hit($both, 'a badbot b', '/admin') && !t_rule_hit($both, 'a badbot b', '/shop')
	&& !t_rule_hit($both, 'nice', '/admin'));

// A pattern engine error is "no match", never an exception, whatever the op.
$old_bt = ini_get('pcre.backtrack_limit');
$old_jit = ini_get('pcre.jit');
ini_set('pcre.jit', '0');
ini_set('pcre.backtrack_limit', '100');
$evil_inc = t_rule(array('ua' => t_cond('regex', array('(a+)+$'))));
$evil_exc = t_rule(array('ua' => t_cond('regex', array('(a+)+$'), 'exclude')));
$ua_evil = str_repeat('a', 40) . '!';
t_ok('a backtrack-limit error counts as no match (include)', !t_rule_hit($evil_inc, $ua_evil));
t_ok('a backtrack-limit error counts as no match (exclude too)', !t_rule_hit($evil_exc, $ua_evil));
t_ok('the error is reported in guard-errors.log',
	is_file($GV_TMP_LOGS . '/guard-errors.log') && strpos((string)file_get_contents($GV_TMP_LOGS . '/guard-errors.log'), 'rules_pcre') !== false);
ini_set('pcre.backtrack_limit', (string)$old_bt);
ini_set('pcre.jit', (string)$old_jit);

// Validation: what the panel writes is what the guard reads.
$v = gv_rule_validate(t_rule(), true);
t_ok('a well-formed rule validates', $v[0] === true);
foreach (array(
	'no condition'            => array('ua' => null, 'path' => null),
	'bad mode'                => array('mode' => 'maybe'),
	'bad action'              => array('action' => 'nuke'),
	'name too long'           => array('name' => str_repeat('n', 81)),
	'empty name'              => array('name' => '  '),
	'bad id'                  => array('id' => 'Bad Id!'),
	'pow_bits 5 is below 12'  => array('pow_bits' => 5),
	'pow_bits 30 is above 22' => array('pow_bits' => 30),
	'non-int priority'        => array('priority' => '5'),
	'non-bool enabled'        => array('enabled' => 'yes'),
	'bad op'                  => array('ua' => array('op' => 'maybe', 'type' => 'exact', 'values' => array('x'))),
	'bad type'                => array('ua' => t_cond('fuzzy', array('x'))),
	'no values'               => array('ua' => t_cond('exact', array())),
	'51 values'               => array('ua' => t_cond('exact', array_map('strval', range(1, 51)))),
	'value of 301 chars'      => array('ua' => t_cond('contains', array(str_repeat('a', 301)))),
	'control char in value'   => array('ua' => t_cond('contains', array("a\nb"))),
	'path without slash'      => array('ua' => null, 'path' => t_cond('prefix', array('admin'))),
	'path with regex type'    => array('ua' => null, 'path' => t_cond('regex', array('/a'))),
	'broken regex'            => array('ua' => t_cond('regex', array('(unclosed'))),
	'regex backreference'     => array('ua' => t_cond('regex', array('(a)\1'))),
	'catastrophic regex'      => array('ua' => t_cond('regex', array('(a+)+$'))),
	'slow but not failing regex' => array('ua' => t_cond('regex', array('(.{1,50}){3}!x'))),
) as $label => $over) {
	$r = gv_rule_validate(t_rule($over), true);
	t_ok('rejected: ' . $label, $r[0] === false);
}
$r = gv_rule_validate(t_rule(array('ua' => t_cond('regex', array('ok', '(.{1,50}){3}!x')))), true);
t_ok('a slow regex is refused with code regex_slow and the measured time', $r[0] === false && $r[1]['ua'] === 'regex_slow' && preg_match('/value 2: one match took [\\d.]+ ms/', $r[2]['ua']) === 1);
$r = gv_rule_validate(t_rule(array('ua' => t_cond('regex', array('ok', '(bad')))), true);
t_ok('a regex error names the offending value', $r[0] === false && isset($r[2]['ua']) && strpos($r[2]['ua'], 'value 2') === 0);
t_ok('the guard-side check does not compile (deep off): a bad regex is caught by the panel',
	gv_rule_validate(t_rule(array('ua' => t_cond('regex', array('(unclosed')))), false)[0] === true);
foreach (array('^python-(requests|urllib)/\\d', 'headless(chrome)?', '^(?:curl|wget)/', '(libwww|okhttp|java)/\\d', '^$') as $fine) {
	t_ok('an ordinary regex is accepted by the timing check: ' . $fine, gv_rule_validate(t_rule(array('ua' => t_cond('regex', array($fine)))), true)[0] === true);
}
t_ok('the regex timing limit is 1 ms', GV_RULES_MAX_MATCH_US === 1000);
t_ok('a regex of 301 chars is refused', gv_rule_validate(t_rule(array('ua' => t_cond('regex', array(str_repeat('a', 301))))), true)[0] === false);
$l = gv_rules_validate_list(array(t_rule(), t_rule()), true);
t_ok('duplicate ids in one list are refused', $l[0] === false);
t_ok('more than 200 rules are refused', gv_rules_validate_list(array_fill(0, 201, t_rule()), false)[0] === false);

// Reading the file: invalid = no rules; one bad rule is dropped alone.
$rf = $GV_TMP_LOGS . '/rules-test.json';
@mkdir($GV_TMP_LOGS, 0775, true);
t_ok('a missing file means no rules', gv_rules_read($GV_TMP_LOGS . '/nope.json') === array());
foreach (array('' => 'empty', 'not json' => 'not json', '[1,2]' => 'a list', '{"rules":"x"}' => 'rules not a list',
	'{"rules":{"a":1}}' => 'rules a map', 'null' => 'null') as $body => $label) {
	file_put_contents($rf, $body);
	t_ok('an invalid file means no rules: ' . $label, gv_rules_read($rf) === array());
}
file_put_contents($rf, str_repeat(' ', GV_RULES_MAX_BYTES + 1));
t_ok('an oversized file means no rules', gv_rules_read($rf) === array());
$good2 = t_rule(array('id' => 'r-test2', 'priority' => 10));
$bad = t_rule(array('id' => 'r-bad', 'mode' => 'nope'));
file_put_contents($rf, json_encode(array('rules' => array(t_rule(), $bad, $good2, t_rule()))));
$read = gv_rules_read($rf);
t_ok('one bad rule and one duplicate are dropped, the rest stay', count($read) === 2);
t_ok('rules come back sorted by priority', $read[0]['id'] === 'r-test2');

// The panel's stamp (a checksum of the rules text) lets the guard skip validation.
$stamp_rules = array(t_rule(array('id' => 'r-s1', 'priority' => 5)), t_rule(array('id' => 'r-s2', 'priority' => 9)));
$stamped = gv_rules_encode($stamp_rules);
file_put_contents($rf, $stamped);
t_ok('a stamped file is read back whole', gv_rules_read($rf) === $stamp_rules);
t_ok('the stamped file is still plain JSON a hand can read', is_array(json_decode($stamped, true)) && json_decode($stamped, true)['v'] === 1);
file_put_contents($rf, preg_replace('/"crc":"[0-9a-f]{8}"/', '"crc":"00000000"', $stamped));
t_ok('a wrong checksum falls back to full validation and still works', count(gv_rules_read($rf)) === 2);
$tampered = str_replace('"mode":"enforce"', '"mode":"bogus!!"', $stamped);
file_put_contents($rf, $tampered);
t_ok('a tampered stamped file fails the check and its invalid rules are dropped by full validation', gv_rules_read($rf) === array());
t_ok('a truncated stamped file is no rules, not an error', (function () use ($rf, $stamped) { file_put_contents($rf, substr($stamped, 0, 120)); return gv_rules_read($rf) === array(); })());

// First match by priority, disabled and expired are ignored.
$rl = array(
	t_rule(array('id' => 'r-a', 'priority' => 10, 'ua' => t_cond('contains', array('zzz')))),
	t_rule(array('id' => 'r-b', 'priority' => 20, 'action' => 'challenge')),
	t_rule(array('id' => 'r-c', 'priority' => 30, 'action' => 'log')),
);
$f = t_facts(array('ua' => 'x badbot x'));
t_ok('the first matching rule by priority wins', gv_rules_match($f, $rl, $now)['id'] === 'r-b');
t_ok('match_all lists every live match in order', count(gv_rules_match_all($f, $rl, $now)) === 2);
$rl[1]['enabled'] = false;
t_ok('a disabled rule is skipped', gv_rules_match($f, $rl, $now)['id'] === 'r-c');
$rl[2]['expires_at'] = $now - 1;
t_ok('an expired rule is skipped', gv_rules_match($f, $rl, $now) === null);
$rl[2]['expires_at'] = $now + 100;
t_ok('a rule that has not expired yet matches', gv_rules_match($f, $rl, $now)['id'] === 'r-c');
t_ok('no rules, no match', gv_rules_match($f, array(), $now) === null);

// What a rule demands (mode, action, token, gate).
$blk = t_rule(array('action' => 'block'));
$chl = t_rule(array('action' => 'challenge'));
$log = t_rule(array('action' => 'log'));
$mon = t_rule(array('mode' => 'monitor', 'action' => 'block'));
t_ok('an enforced block serves 403 whatever the token',
	gv_rule_act($blk, 'v', true, true) === array('403', '403'));
t_ok('a monitor rule never acts', gv_rule_act($mon, 'm', true, true) === array('', ''));
t_ok('a log rule never acts', gv_rule_act($log, 'm', true, true) === array('', ''));
t_ok('a challenge without a token is served', gv_rule_act($chl, 'm', true, true) === array('challenge', 'challenge'));
t_ok('a challenge with a bad token is served', gv_rule_act($chl, 'b', true, true) === array('challenge', 'challenge'));
t_ok('a client holding a valid token is never challenged again (no loop)',
	gv_rule_act($chl, 'v', true, true) === array('', ''));
t_ok('a POST with gate_post off is a shadow challenge: intended, not served',
	gv_rule_act($chl, 'm', true, false) === array('challenge', ''));
t_ok('a request outside the gate is never challenged', gv_rule_act($chl, 'm', false, true) === array('', ''));
t_ok('an enforced block or challenge replaces the bot pass', gv_rule_overrides_pass($blk) && gv_rule_overrides_pass($chl));
t_ok('a monitor or log rule leaves the bot pass alone', !gv_rule_overrides_pass($mon) && !gv_rule_overrides_pass($log));
t_ok('the log reason is RULE:<id> when enforcing, SH_RULE:<id> in monitor',
	gv_rule_reason($blk) === 'RULE:r-test1' && gv_rule_reason($mon) === 'SH_RULE:r-test1');

// The starter set is valid, disabled and in monitor mode.
$starter = gv_rules_validate_list(gv_rules_starter(), true);
t_ok('the starter set validates', $starter[0] === true && count($starter[1]) === 16);
$all_off = true;
foreach (gv_rules_starter() as $s) { if ($s['enabled'] !== false || $s['mode'] !== 'monitor') { $all_off = false; } }
t_ok('every starter rule is disabled and in monitor mode', $all_off);
$ua_samples = array('python-requests/2.31.0' => 'st-pyreq', 'curl/8.4.0' => 'st-curl', '' => 'st-empty',
	'Mozilla/5.0 HeadlessChrome/120.0' => 'st-headless', 'Java/17.0.2' => 'st-java');
foreach ($ua_samples as $ua => $id) {
	$hit = false;
	foreach (gv_rules_starter() as $s) { if ($s['id'] === $id && gv_rule_matches($s, array('ua' => $ua, 'path' => '/'))) { $hit = true; } }
	t_ok('starter ' . $id . ' matches its client', $hit);
}
$browser_hit = false;
foreach (gv_rules_starter() as $s) { if (gv_rule_matches($s, t_facts())) { $browser_hit = true; } }
t_ok('no starter rule matches a current Chrome', !$browser_hit);

// Verified-bot skip, including the degraded-mode policy.
t_ok('a verified verdict skips a rule that asks for it', gv_rule_bot_skip($blk, 'ok', true) === 'verified');
t_ok('a verified verdict does not skip a rule with skip_verified_bots off', gv_rule_bot_skip(array_merge($blk, array('skip_verified_bots' => false)), 'ok', true) === '');
t_ok('an unverified claim (no verdict, Redis alive) is not skipped', gv_rule_bot_skip($blk, '', true) === '');
t_ok('a refuted claim is not skipped', gv_rule_bot_skip($blk, 'bad', true) === '');
t_ok('a refuted claim is not skipped even if Redis then dies', gv_rule_bot_skip($blk, 'bad', false) === '');
t_ok('Redis down and no verdict: the known-bot claim counts as verified (degraded)', gv_rule_bot_skip($blk, '', false) === 'degraded');
t_ok('Redis down, rule with skip_verified_bots off: not skipped', gv_rule_bot_skip(array_merge($blk, array('skip_verified_bots' => false)), '', false) === '');

// The generated cache: guard/rules.cache.php.
$cf_json = $GV_TMP_LOGS . '/cache-rules.json';
$cf_cache = gv_rules_cache_path($cf_json);
putenv('GV_RULES=' . $cf_json);
t_ok('the cache path sits next to the JSON', $cf_cache === $GV_TMP_LOGS . '/cache-rules.cache.php');
@unlink($cf_json); @unlink($cf_cache);
t_ok('no rules.json means no rules (even if a cache exists)', (function () use ($cf_cache) { file_put_contents($cf_cache, '<?php return array(array("id" => "zzz"));'); return gv_rules_load() === array(); })());
$c_rules = array(
	t_rule(array('id' => 'r-c2', 'priority' => 20, 'ua' => t_cond('regex', array('^zz', 'yy$')))),
	t_rule(array('id' => 'r-c1', 'priority' => 10)),
	t_rule(array('id' => 'r-off', 'priority' => 5, 'enabled' => false)),
	t_rule(array('id' => 'r-c3', 'priority' => 30, 'ua' => t_cond('exact', array(GV_RULE_EMPTY, 'x')), 'path' => t_cond('prefix', array('/a')))),
);
file_put_contents($cf_json, gv_rules_encode($c_rules));
$src = gv_rules_cache_source($c_rules);
file_put_contents($cf_cache, $src);
$loaded = gv_rules_load();
t_ok('the cache holds enabled rules only, sorted by priority', array_column($loaded, 'id') === array('r-c1', 'r-c2', 'r-c3'));
t_ok('the cache carries the compiled pattern and blank flag', isset($loaded[1]['ua']['pat']) && $loaded[1]['ua']['blank'] === false && $loaded[2]['ua']['blank'] === true);
t_ok('a cached rule matches exactly like the JSON rule', gv_rule_matches($loaded[0], array('ua' => 'x badbot', 'path' => '/')) && gv_rule_matches($loaded[1], array('ua' => 'zzabc', 'path' => '/'))
	&& gv_rule_matches($loaded[2], array('ua' => '', 'path' => '/a/b')) && !gv_rule_matches($loaded[2], array('ua' => '', 'path' => '/b')));
$cache_idents = array();
foreach (token_get_all(substr($src, strpos($src, 'return array'))) as $tk) {
	if (is_array($tk) && $tk[0] === T_STRING) { $cache_idents[] = strtolower($tk[1]); }
}
t_ok('the cache is generated PHP: a pure array literal (no function call, only true/false/null) guarded by GV_BOOT',
	strpos($src, "if (!defined('GV_BOOT'))") !== false && array_diff($cache_idents, array('true', 'false', 'null')) === array());
t_ok('the cache source is valid PHP that returns an array', (function () use ($cf_cache) { $r = include $cf_cache; return is_array($r) && count($r) === 3; })());
t_ok('with no enabled rule the cache is an empty array and the guard has nothing to do',
	(function () use ($cf_cache) { file_put_contents($cf_cache, gv_rules_cache_source(array(t_rule(array('enabled' => false))))); touch($cf_cache, time() + 5); return gv_rules_load() === array(); })());
file_put_contents($cf_cache, $src);
touch($cf_json, time() + 10);
touch($cf_cache, time() - 10);
$stale_log = $GV_TMP_LOGS . '/guard-errors.log';
@unlink($stale_log);
foreach ((array)glob($GV_TMP_LOGS . '/.err-rules_cache_stale') as $m) { @unlink($m); }
$from_json = gv_rules_load();
t_ok('a cache older than rules.json is not used: the JSON is read directly', count($from_json) === 4);
t_ok('...and the stale cache is reported once in guard-errors.log', is_file($stale_log) && substr_count((string)file_get_contents($stale_log), 'rules_cache_stale') === 1);
gv_rules_load();
t_ok('...rate-limited: a second request adds no second line', substr_count((string)file_get_contents($stale_log), 'rules_cache_stale') === 1);
@unlink($cf_cache);
t_ok('a missing cache falls back to the JSON too', count(gv_rules_load()) === 4);
file_put_contents($cf_cache, '<?php return "not an array";');
touch($cf_cache, time() + 20);
t_ok('a cache that returns a non-array falls back to the JSON', count(gv_rules_load()) === 4);
file_put_contents($cf_cache, '<?php this is broken (');
touch($cf_cache, time() + 20);
t_ok('a cache file that fails to parse is no rules, never a 500', gv_rules_load() === array());
@unlink($cf_json); @unlink($cf_cache); @unlink($stale_log);
putenv('GV_RULES');

// Rules add no Redis round trip: the request-path functions take no connection.
$no_conn = true;
foreach (array('gv_rules_match', 'gv_rule_act', 'gv_rule_matches', 'gv_rule_ua_eval') as $fn) {
	foreach ((new ReflectionFunction($fn))->getParameters() as $p) {
		if (stripos($p->getName(), 'conn') !== false) { $no_conn = false; }
	}
}
t_ok('rule evaluation takes no Redis connection (no extra round trip)', $no_conn);
@unlink($rf);

// --------------------------------------------------------------------------
t_section('GeoIP lookup and country / ASN conditions');

require_once __DIR__ . '/geo-fixture.php';
$GEO_TMP = sys_get_temp_dir() . '/gv-geo-selftest-' . getmypid();
@mkdir($GEO_TMP, 0775, true);
register_shutdown_function(function () use ($GEO_TMP) {
	foreach ((array)glob($GEO_TMP . '/*/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
	foreach ((array)glob($GEO_TMP . '/*', GLOB_ONLYDIR) as $d) { @rmdir($d); }
	foreach ((array)glob($GEO_TMP . '/*') as $f) { if (is_file($f)) { @unlink($f); } }
	@rmdir($GEO_TMP);
});
// A fresh directory with the given files; points the lookup at it and forgets what was open.
function t_geo_dir($name, array $files) {
	global $GEO_TMP;
	$d = $GEO_TMP . '/' . $name;
	@mkdir($d, 0775, true);
	foreach ($files as $fn => $bytes) { file_put_contents($d . '/' . $fn, $bytes); }
	putenv('GV_GEO_DIR=' . $d);
	gv_geo_state(true);
	return $d;
}
$g4 = array(gf_cidr4('1.0.0.0/24'), gf_cidr4('5.0.0.0/8'), gf_cidr4('10.0.0.0/8'), gf_cidr4('11.0.0.0/8'),
	gf_cidr4('127.0.0.0/8'), array(4294967295, 4294967295, 'ZZ'));
$g4[0][] = 'AA'; $g4[1][] = 'IR'; $g4[2][] = 'AB'; $g4[3][] = 'BB'; $g4[4][] = 'US';
$a6 = gf_cidr6('2001:db8::/32'); $a6[] = 'DE';
$b6 = gf_cidr6('2a00::/12'); $b6[] = 'IR';
$digits = array('0000000000000000', '0000000000009999', 'TT');           // ASCII-digit keys: must compare as bytes
$c6 = array(str_repeat("\xff", 16), str_repeat("\xff", 16), 'YY');
$g6 = array($digits, $a6, $b6, $c6);
usort($g6, function ($x, $y) { return strcmp($x[0], $y[0]); });
t_geo_dir('ok', array('country.bin' => gf_pack(1, $g4, $g6)));
$cc = function ($ip) { return gv_geo_country($ip, true); };
t_ok('geo: an address inside a range resolves', $cc('5.1.2.3') === 'IR' && $cc('127.0.0.1') === 'US');
t_ok('geo: the first and last address of a range', $cc('5.0.0.0') === 'IR' && $cc('5.255.255.255') === 'IR' && $cc('1.0.0.0') === 'AA' && $cc('1.0.0.255') === 'AA');
t_ok('geo: adjacent ranges do not bleed into each other', $cc('10.255.255.255') === 'AB' && $cc('11.0.0.0') === 'BB');
t_ok('geo: the very last IPv4 address (first and last record of the file)', $cc('255.255.255.255') === 'ZZ');
t_ok('geo: a gap or an address below the first range is unknown', $cc('0.0.0.1') === '' && $cc('4.255.255.255') === '' && $cc('20.0.0.1') === '' && $cc('126.255.255.255') === '');
t_ok('geo: IPv6 ranges', $cc('2001:db8::1') === 'DE' && $cc('2a01::1') === 'IR' && $cc('2b00::1') === '' && $cc('2001:db9::') === '');
t_ok('geo: the last IPv6 address', $cc('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff') === 'YY');
t_ok('geo: IPv4-mapped IPv6 is the IPv4 address it carries', $cc('::ffff:127.0.0.1') === 'US' && $cc('::ffff:20.0.0.1') === '');
t_ok('geo: keys made of ASCII digits compare as bytes, not as numbers', $cc(inet_ntop('0000000000005555')) === 'TT' && $cc(inet_ntop('0000000000009999')) === 'TT' && $cc(inet_ntop('0000000000009a00')) === '');
t_ok('geo: not an address, empty, whitespace: unknown, no exception', $cc('not-an-ip') === '' && $cc('') === '' && $cc(' ') === '' && $cc('999.1.1.1') === '');
t_ok('geo: the header is read back (counts, source name)', (function () {
	$h = gv_geo_header_parse(file_get_contents(gv_geo_file(GV_GEO_COUNTRY), false, null, 0, 128));
	return $h && $h['v4'] === 6 && $h['v6'] === 4 && $h['kind'] === 1 && $h['source'] === 'fixture.dat' && $h['built'] === 1700000000;
})());
t_ok('geo: the lookup is memoised for the request and marks that a lookup ran', gv_geo_ran()['cc'] === true && gv_geo_ran()['asn'] === false);

// ASN file
t_geo_dir('asn', array('asn.bin' => gf_pack(2, array(array(16777216, 33554431, 13335), array(84215040, 84215295, 4200000000)), array())));
t_ok('geo: ASN lookup, incl. an AS number above 2^31', gv_geo_asn('1.2.3.4', true) === 13335 && gv_geo_asn('5.5.5.5', true) === 4200000000 && gv_geo_asn('9.9.9.9', true) === 0);

// Broken files never throw and never match.
$good = gf_pack(1, $g4, $g6);
$errlog = $GV_TMP_LOGS . '/guard-errors.log';
@unlink($errlog);
foreach ((array)glob($GV_TMP_LOGS . '/.err-geo_*') as $mk) { @unlink($mk); }
t_geo_dir('nofile', array());
t_ok('geo: a missing file is unknown (and logged, rate-limited)', gv_geo_country('5.1.2.4') === '' && $cc('5.1.2.3') === '' && is_file($errlog) && strpos(file_get_contents($errlog), 'geo_missing') !== false);
t_geo_dir('magic', array('country.bin' => 'XXXX' . substr($good, 4)));
t_ok('geo: wrong magic is unknown', $cc('5.1.2.3') === '');
t_geo_dir('ver', array('country.bin' => substr($good, 0, 4) . "\x00\x02" . substr($good, 6)));
t_ok('geo: an unknown format version is unknown', $cc('5.1.2.3') === '');
t_geo_dir('trunc', array('country.bin' => substr($good, 0, 128 + 25)));
t_ok('geo: a truncated file is unknown', $cc('5.1.2.3') === '');
t_geo_dir('short', array('country.bin' => 'GVRG'));
t_ok('geo: a file shorter than the header is unknown', $cc('5.1.2.3') === '');
t_geo_dir('empty', array('country.bin' => ''));
t_ok('geo: an empty file is unknown', $cc('5.1.2.3') === '');
t_geo_dir('kind', array('country.bin' => gf_pack(2, array(array(1, 2, 5)), array())));
t_ok('geo: an ASN file used as the country file is refused', $cc('0.0.0.1') === '' && strpos(file_get_contents($errlog), 'geo_corrupt') !== false);
t_geo_dir('junk', array('country.bin' => substr($good, 0, 128) . str_repeat("\xff", 60)));
t_ok('geo: a header that promises more than the file holds is unknown', $cc('5.1.2.3') === '');
t_geo_dir('ok2', array('country.bin' => $good));
t_ok('geo: a good file after a bad one works again (state reset)', $cc('5.1.2.3') === 'IR');

// Unknown never matches, include or exclude.
$cr = function ($op, array $v) { return t_rule(array('ua' => null, 'country' => array('op' => $op, 'type' => 'code', 'values' => $v))); };
$ar = function ($op, array $v) { return t_rule(array('ua' => null, 'asn' => array('op' => $op, 'type' => 'number', 'values' => $v))); };
$m = function (array $r, array $f) { return gv_rule_matches($r, $f); };
t_ok('country include: matches a listed country only', $m($cr('include', array('IR', 'TR')), array('cc' => 'TR')) && !$m($cr('include', array('IR')), array('cc' => 'US')));
t_ok('country exclude: matches every placed country outside the list', $m($cr('exclude', array('IR')), array('cc' => 'US')) && !$m($cr('exclude', array('IR')), array('cc' => 'IR')));
t_ok('UNKNOWN country: never matches include, never matches exclude',
	!$m($cr('include', array('IR')), array('cc' => '')) && !$m($cr('exclude', array('IR')), array('cc' => '')));
t_ok('asn include / exclude and UNKNOWN asn (0)',
	$m($ar('include', array('13335')), array('asn' => 13335)) && !$m($ar('include', array('13335')), array('asn' => 15169))
	&& $m($ar('exclude', array('13335')), array('asn' => 15169)) && !$m($ar('exclude', array('13335')), array('asn' => 0))
	&& !$m($ar('include', array('13335')), array('asn' => 0)));
t_geo_dir('lazy', array('country.bin' => $good));
t_ok('the country comes from the file when the facts do not carry it', $m($cr('include', array('IR')), array('ip' => '5.1.2.3')) && !$m($cr('include', array('IR')), array('ip' => '127.0.0.1')));
t_ok('facts with no address and no country: unknown, no match', !$m($cr('exclude', array('IR')), array()));
t_geo_dir('none', array());
t_ok('no database: a country rule never matches, include or exclude', !$m($cr('include', array('IR')), array('ip' => '5.1.2.3')) && !$m($cr('exclude', array('IR')), array('ip' => '5.1.2.3')));

// Combined conditions, order, and the file is only opened when a rule gets that far.
t_geo_dir('combo', array('country.bin' => $good));
$combo = t_rule(array('id' => 'r-combo', 'ua' => t_cond('contains', array('scraper')), 'country' => array('op' => 'include', 'type' => 'code', 'values' => array('IR'))));
t_ok('UA + country are AND-ed', $m($combo, array('ua' => 'a scraper', 'ip' => '5.1.2.3', 'path' => '/')) && !$m($combo, array('ua' => 'a scraper', 'ip' => '127.0.0.1', 'path' => '/'))
	&& !$m($combo, array('ua' => 'nice', 'ip' => '5.1.2.3', 'path' => '/')));
t_ok('UA + country + path + asn: all four must hold', $m(t_rule(array('path' => t_cond('prefix', array('/a')), 'country' => array('op' => 'include', 'type' => 'code', 'values' => array('IR')),
	'asn' => array('op' => 'exclude', 'type' => 'number', 'values' => array('1')))), array('ua' => 'badbot', 'path' => '/a', 'cc' => 'IR', 'asn' => 7)));
t_geo_dir('lazy2', array('country.bin' => $good));
gv_rules_match(array('ua' => 'nothing', 'ip' => '5.1.2.3', 'path' => '/'), array(t_rule()), $now);
t_ok('a UA-only rule list never opens the geo file', gv_geo_ran()['cc'] === false);
gv_rules_match(array('ua' => 'x', 'ip' => '5.1.2.3', 'path' => '/'), array(t_rule(array('ua' => null, 'country' => array('op' => 'include', 'type' => 'code', 'values' => array('US'))))), $now);
t_ok('a country rule that is reached looks the country up (once)', gv_geo_ran()['cc'] === true && gv_geo_ran()['asn'] === false);
t_geo_dir('lazy3', array('country.bin' => $good));
gv_rules_match(array('ua' => 'x', 'ip' => '5.1.2.3', 'path' => '/'), array(t_rule(array('enabled' => false, 'ua' => null, 'country' => array('op' => 'include', 'type' => 'code', 'values' => array('US')))),
	t_rule(array('expires_at' => 1000, 'ua' => null, 'country' => array('op' => 'include', 'type' => 'code', 'values' => array('US'))))), $now);
t_ok('a disabled or expired country rule does not trigger a lookup', gv_geo_ran()['cc'] === false);
t_ok('first match by priority with geo rules', (function () use ($good, $now) {
	t_geo_dir('prio', array('country.bin' => $good));
	$a = t_rule(array('id' => 'r-a', 'priority' => 20, 'ua' => null, 'country' => array('op' => 'include', 'type' => 'code', 'values' => array('IR'))));
	$b = t_rule(array('id' => 'r-b', 'priority' => 10, 'ua' => null, 'country' => array('op' => 'include', 'type' => 'code', 'values' => array('IR', 'US'))));
	$w = gv_rules_match(array('ip' => '5.1.2.3'), array($b, $a), $now);
	return $w && $w['id'] === 'r-b';
})());

// Validation.
$v = function (array $over) { return gv_rule_validate(t_rule($over), true); };
t_ok('validate: a country-only rule is valid and keeps its type', $v(array('ua' => null, 'country' => t_cond('code', array('IR', 'US'))))[0] === true);
t_ok('validate: lower-case, 3-letter, numeric and empty country codes are refused',
	!$v(array('country' => t_cond('code', array('ir'))))[0] && !$v(array('country' => t_cond('code', array('IRN'))))[0]
	&& !$v(array('country' => t_cond('code', array('I1'))))[0] && !$v(array('country' => t_cond('code', array())))[0]);
t_ok('validate: bad country reports the field and the value number', (function () use ($v) { $r = $v(array('country' => t_cond('code', array('IR', 'x')))); return !$r[0] && $r[1]['country'] === 'bad_country' && $r[2]['country'] === 'value 2'; })());
t_ok('validate: ASN values are plain decimal numbers 1..4294967295',
	$v(array('asn' => t_cond('number', array('13335', '4294967295'))))[0] && !$v(array('asn' => t_cond('number', array('0'))))[0]
	&& !$v(array('asn' => t_cond('number', array('4294967296'))))[0] && !$v(array('asn' => t_cond('number', array('AS13335'))))[0]
	&& !$v(array('asn' => t_cond('number', array('-5'))))[0] && !$v(array('asn' => t_cond('number', array('1e3'))))[0]);
t_ok('validate: more than 50 country values is refused', !$v(array('country' => t_cond('code', array_map(function ($i) { return chr(65 + intdiv($i, 26)) . chr(65 + $i % 26); }, range(0, 50)))))[0]);
t_ok('validate: a rule with no condition at all is still invalid', !$v(array('ua' => null))[0]);
t_ok('validate: a rule saved before GeoIP (no country / asn keys) is valid and gets null for both', (function () {
	$r = t_rule(); unset($r['country'], $r['asn']);
	$x = gv_rule_validate($r, true);
	return $x[0] && $x[1]['country'] === null && $x[1]['asn'] === null;
})());

// The generated cache.
$gc = array(t_rule(array('id' => 'r-g1', 'priority' => 5, 'ua' => null, 'country' => t_cond('code', array('IR', 'TR'), 'exclude'), 'asn' => t_cond('number', array('13335', '15169')))));
$gsrc = gv_rules_cache_source($gc);
$gcache = $GEO_TMP . '/geo-rules.cache.php';
file_put_contents($gcache, $gsrc);
$gl = include $gcache;
t_ok('cache: country and ASN conditions carry a lookup set', $gl[0]['country']['set'] === array('IR' => true, 'TR' => true) && $gl[0]['asn']['set'] === array(13335 => true, 15169 => true));
$gids = array();
foreach (token_get_all(substr($gsrc, strpos($gsrc, 'return array'))) as $tk) { if (is_array($tk) && $tk[0] === T_STRING) { $gids[] = strtolower($tk[1]); } }
t_ok('cache: still a pure array literal with geo conditions', array_diff($gids, array('true', 'false', 'null')) === array());
t_ok('cache: a cached geo rule matches like the JSON rule',
	$m($gl[0], array('cc' => 'US', 'asn' => 13335)) === $m($gc[0], array('cc' => 'US', 'asn' => 13335))
	&& $m($gl[0], array('cc' => 'US', 'asn' => 13335)) === true && $m($gl[0], array('cc' => 'IR', 'asn' => 13335)) === false
	&& $m($gl[0], array('cc' => '', 'asn' => 13335)) === false && $m($gl[0], array('cc' => 'US', 'asn' => 0)) === false);
t_ok('cache: a cache written by the previous release (no country / asn keys) still works', (function () use ($now) {
	$old = t_rule(); unset($old['country'], $old['asn']);
	return gv_rules_match(array('ua' => 'x badbot', 'path' => '/'), array($old), $now) !== null;
})());

// Log row, config and overlay.
$row_f = t_facts();
t_ok('log row: no cc / asn key when no lookup ran', !array_key_exists('cc', gv_log_row($row_f, gv_state_new(), 'allow', 0, microtime(true))) && !array_key_exists('asn', gv_log_row($row_f, gv_state_new(), 'allow', 0, microtime(true))));
$row_geo = gv_log_row(array_merge($row_f, array('cc' => 'IR', 'asn' => 12880)), gv_state_new(), 'allow', 0, microtime(true));
t_ok('log row: cc and asn when a lookup ran', $row_geo['cc'] === 'IR' && $row_geo['asn'] === 12880);
$row_unk = gv_log_row(array_merge($row_f, array('cc' => '', 'asn' => 0)), gv_state_new(), 'allow', 0, microtime(true));
t_ok('log row: an unknown country is logged as "" (looked up, not placed)', $row_unk['cc'] === '' && $row_unk['asn'] === 0);
t_ok('config: geo.log defaults to off and is a whitelisted bool',
	gv_cfg_defaults(array())['geo'] === array('log' => false, 'upload_max_mb' => 32) && gv_overlay_validate('geo.log', true)[0] === true && gv_overlay_validate('geo.log', 'yes')[0] === false);
t_ok('config: "off" / "false" in a hand-edited geo block read as off', gv_cfg_defaults(array('geo' => array('log' => 'off')))['geo']['log'] === false && gv_cfg_defaults(array('geo' => array('log' => 'true')))['geo']['log'] === true);
t_ok('config: a damaged geo value falls back to the default', gv_cfg_defaults(array('geo' => 'x'))['geo'] === array('log' => false, 'upload_max_mb' => 32));
t_ok('config: geo.upload_max_mb is a number, not a switch: "64" stays 64, junk falls back to 32, the range is clamped',
	gv_cfg_defaults(array('geo' => array('upload_max_mb' => '64')))['geo']['upload_max_mb'] === 64 && gv_cfg_defaults(array('geo' => array('upload_max_mb' => 'x')))['geo']['upload_max_mb'] === 32
	&& gv_cfg_defaults(array('geo' => array('upload_max_mb' => 99999)))['geo']['upload_max_mb'] === 2048 && gv_cfg_defaults(array('geo' => array('upload_max_mb' => 0)))['geo']['upload_max_mb'] === 1);
putenv('GV_GEO_DIR');
gv_geo_state(true);

t_section('Log rotation: the free-disk floor is report-only unless allowed');
t_ok('log_floor_delete defaults to off and log_floor_keep_days to 7', gv_cfg_defaults(array())['log_floor_delete'] === false && gv_cfg_defaults(array())['log_floor_keep_days'] === 7);
t_ok('log_floor_delete: "off" / "false" in a hand-edited config read as off, "true" as on', gv_cfg_defaults(array('log_floor_delete' => 'off'))['log_floor_delete'] === false && gv_cfg_defaults(array('log_floor_delete' => 'false'))['log_floor_delete'] === false && gv_cfg_defaults(array('log_floor_delete' => 'true'))['log_floor_delete'] === true);
t_ok('log_floor_keep_days: below 1 or not a number falls back to 7', gv_cfg_defaults(array('log_floor_keep_days' => 0))['log_floor_keep_days'] === 7 && gv_cfg_defaults(array('log_floor_keep_days' => 'x'))['log_floor_keep_days'] === 7 && gv_cfg_defaults(array('log_floor_keep_days' => 30))['log_floor_keep_days'] === 30);
t_ok('both keys are whitelisted overlay settings with bounds (keep days 1..3650, bool only)', gv_overlay_validate('log_floor_delete', true)[0] === true && gv_overlay_validate('log_floor_delete', 'yes')[0] === false
	&& gv_overlay_validate('log_floor_keep_days', 1)[0] === true && gv_overlay_validate('log_floor_keep_days', 0)[0] === false && gv_overlay_validate('log_floor_keep_days', 3651)[0] === false);

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
t_section('IP lists: compiled allow / block files');

$IPL_TMP = sys_get_temp_dir() . '/gv-iplist-selftest-' . getmypid();
@mkdir($IPL_TMP, 0775, true);
register_shutdown_function(function () use ($IPL_TMP) {
	foreach ((array)glob($IPL_TMP . '/*/{,.}*', GLOB_BRACE) as $f) { if (is_file($f)) { @unlink($f); } }
	foreach ((array)glob($IPL_TMP . '/*', GLOB_ONLYDIR) as $d) { @rmdir($d); }
	@rmdir($IPL_TMP);
});
function t_ipl_dir($name, array $files) {
	global $IPL_TMP;
	$d = $IPL_TMP . '/' . $name;
	@mkdir($d, 0775, true);
	foreach ($files as $fn => $bytes) { file_put_contents($d . '/' . $fn, $bytes); }
	putenv('GV_LISTS_DIR=' . $d);
	gv_geo_state(true);
	return $d;
}
$MON = 0x8000;
$a4 = array(array_merge(gf_cidr4('198.51.100.0/24'), array(2 | $MON)), array_merge(gf_cidr4('203.0.113.0/24'), array(1)), array(4294967295, 4294967295, 3));
$a6 = array(array_merge(gf_cidr6('2001:db8::/32'), array(1)));
$b4 = array(array_merge(gf_cidr4('0.0.0.0/32'), array(7)), array_merge(gf_cidr4('198.51.100.0/24'), array(9)));
t_ipl_dir('ok', array('allow.bin' => gf_pack(3, $a4, $a6), 'block.bin' => gf_pack(3, $b4, array(), 1700000000, 'iplists-block')));
$ic = function ($ip) { return gv_iplist_check($ip); };
t_ok('iplist: an address inside an allow range is a hit; its index and mode come from the value',
	$ic('203.0.113.77')['allow'] === array('idx' => 1, 'monitor' => false) && $ic('203.0.113.77')['block'] === null);
t_ok('iplist: the monitor bit is read (bit 15), the index is the low 15 bits',
	$ic('198.51.100.5')['allow'] === array('idx' => 2, 'monitor' => true) && $ic('198.51.100.5')['block'] === array('idx' => 9, 'monitor' => false));
t_ok('iplist: first and last address of a range, a gap, below the first range, the very last IPv4 address',
	$ic('203.0.113.0')['allow'] !== null && $ic('203.0.113.255')['allow'] !== null && $ic('203.0.114.0')['allow'] === null && $ic('203.0.112.255')['allow'] === null
	&& $ic('255.255.255.255')['allow']['idx'] === 3 && $ic('0.0.0.0')['block']['idx'] === 7 && $ic('0.0.0.1')['block'] === null);
t_ok('iplist: IPv6, IPv4-mapped IPv6 and a miss', $ic('2001:db8::1')['allow'] !== null && $ic('2001:db9::1')['allow'] === null
	&& $ic('::ffff:203.0.113.5')['allow'] !== null && $ic('::ffff:203.0.114.5')['allow'] === null);
t_ok('iplist: an empty or malformed address is no match, no exception', $ic('') === array('allow' => null, 'block' => null) && $ic('nope')['allow'] === null && $ic('1.2.3')['block'] === null);
t_ok('iplist: the log reason carries IPL_ALLOW / IPL_BLOCK, SH_ for monitor, and the id from lists.json',
	gv_iplist_reason('allow', array('idx' => 1, 'monitor' => false)) === 'IPL_ALLOW:list1' && gv_iplist_reason('block', array('idx' => 5, 'monitor' => true)) === 'SH_IPL_BLOCK:list5');
t_ipl_dir('named', array('lists.json' => json_encode(array('v' => 1, 'lists' => array(array('id' => 'scrapers', 'idx' => 4), array('id' => 'bad id!', 'idx' => 5), array('idx' => 6))))));
t_ok('iplist: the id is looked up in lists.json on a hit; a missing, odd or absent id falls back to list<idx>',
	gv_iplist_id(4) === 'scrapers' && gv_iplist_id(5) === 'list5' && gv_iplist_id(6) === 'list6' && gv_iplist_id(99) === 'list99');
$errlog = $GV_TMP_LOGS . '/guard-errors.log';
@unlink($errlog);
foreach ((array)glob($GV_TMP_LOGS . '/.err-*') as $mk) { @unlink($mk); }
t_ipl_dir('none', array());
t_ok('iplist: no file = no list: no match and NOTHING logged (that is the normal state)', $ic('203.0.113.5') === array('allow' => null, 'block' => null) && !is_file($errlog));
$good_l = gf_pack(3, $a4, $a6);
t_ipl_dir('magic', array('allow.bin' => 'XXXX' . substr($good_l, 4)));
t_ok('iplist: wrong magic is no match', $ic('203.0.113.5')['allow'] === null);
t_ipl_dir('trunc', array('allow.bin' => substr($good_l, 0, 128 + 11)));
t_ok('iplist: a truncated file is no match, and logged once', $ic('203.0.113.5')['allow'] === null && is_file($errlog) && strpos(file_get_contents($errlog), 'geo_corrupt') !== false);
t_ipl_dir('short', array('allow.bin' => 'GVRG'));
t_ok('iplist: a file shorter than the header is no match', $ic('203.0.113.5')['allow'] === null);
t_ipl_dir('kind', array('allow.bin' => gf_pack(2, array(array(1, 2, 5)), array())));
t_ok('iplist: an ASN file used as an IP list is refused', $ic('0.0.0.1')['allow'] === null);
t_ipl_dir('vsize', array('allow.bin' => substr($good_l, 0, 7) . "\x00" . substr($good_l, 8)));
t_ok('iplist: a list file with the wrong value size is refused', $ic('203.0.113.5')['allow'] === null);
t_ipl_dir('ok3', array('allow.bin' => $good_l));
t_ok('iplist: a good file after a bad one works again (state reset)', $ic('203.0.113.5')['allow'] !== null);
t_ipl_dir('onlyblock', array('block.bin' => gf_pack(3, $b4, array())));
t_ok('iplist: only the block file present: allow is null, block works', $ic('198.51.100.9') === array('allow' => null, 'block' => array('idx' => 9, 'monitor' => false)));

// The tail search (64 records or fewer in one read) against a brute-force scan, every table size from 1 to 200.
mt_srand(5);
$bad = 0;
for ($n = 1; $n <= 200; $n += ($n < 70 ? 1 : 13)) {
	$r4 = array(); $pos = 1000;
	for ($i = 0; $i < $n; $i++) { $len = mt_rand(0, 20); $r4[] = array($pos, $pos + $len, $i + 1); $pos += $len + mt_rand(2, 30); }
	t_ipl_dir('scan' . $n, array('allow.bin' => gf_pack(3, $r4, array())));
	for ($q = 900; $q < $pos + 40; $q++) {
		$want = null;
		foreach ($r4 as $r) { if ($q >= $r[0] && $q <= $r[1]) { $want = $r[2]; break; } }
		$got = $ic(long2ip($q))['allow'];
		if (($got === null ? null : $got['idx']) !== $want) { $bad++; }
		if ($q % 7 === 0) { gv_geo_state(true); }
	}
}
t_ok('iplist: the binary search with its in-memory tail agrees with a linear scan on every address of tables of 1..200 ranges (' . $bad . ' mismatches)', $bad === 0);
$big4 = array(); $pos = 16777216;
for ($i = 0; $i < 5000; $i++) { $big4[] = array($pos, $pos + 99, ($i % 40) + 1); $pos += 150; }
t_ipl_dir('big', array('allow.bin' => gf_pack(3, $big4, array())));
$bad = 0;
for ($i = 0; $i < 5000; $i += 7) {
	$s = $big4[$i][0];
	foreach (array($s => true, $s + 99 => true, $s + 100 => false, $s - 1 => false) as $a => $want) {
		if ($i === 0 && $a === $s - 1) { continue; }
		if (($ic(long2ip($a))['allow'] !== null) !== $want) { $bad++; }
	}
}
t_ok('iplist: a 5000-range table, boundaries of every 7th range (' . $bad . ' wrong)', $bad === 0);

// What gv_run does with a hit: spelled out in the source, checked here so the guarantees cannot drift.
$gsrc = file_get_contents(__DIR__ . '/../guard/guard.php');
$strip = function ($code) { return preg_replace('#^\s*//.*$#m', '', $code); };   // code only: the comments talk about Redis and the holdout
$a1 = strpos($gsrc, '// 1b. Enforced IP block list');
$a2 = strpos($gsrc, '// 2. Verify handshake intercept');
$a3 = strpos($gsrc, '// 3a. IP lists');
$a3b = strpos($gsrc, '// 3b. Access rules');
$blk1 = ($a1 !== false && $a2 > $a1) ? $strip(substr($gsrc, $a1, $a2 - $a1)) : '';
$blk = ($a3 !== false && $a3b > $a3) ? $strip(substr($gsrc, $a3, $a3b - $a3)) : '';
t_ok('iplist: the enforced block check (1b) sits before the challenge handshake (2); the allow check (3a) after the exemptions and before the rules and every Redis call',
	$a1 !== false && $a1 < $a2 && $a2 < strpos($gsrc, 'gv_is_exempt($f', $a2) && strpos($gsrc, 'gv_is_exempt($f', $a2) < $a3 && $a3b > $a3 && strpos($gsrc, '$conn = gv_redis_connect($cfg[\'redis\'], $log);', $a3) > $a3b
	&& strpos($gsrc, 'gv_redis_connect', $a1) > $a2);
t_ok('iplist: 1b and 3a make no Redis round trip and no network request', $blk1 !== '' && $blk !== '' && !preg_match('/gv_redis|gv_bump|gv_r_|gethostby|dns_|curl_|fsockopen/', $blk1 . $blk));
t_ok('iplist: an enforced block sends 403 and exits before the handshake; an enforced allow returns before any Redis or rule code; monitor only adds a reason',
	strpos($blk1, "gv_emit(\$f, \$st, '403'") !== false && strpos($blk1, 'gv_send_403();') !== false && strpos($blk1, 'exit;') !== false
	&& strpos($blk, "gv_emit(\$f, \$st, 'allow_override'") !== false && strpos($blk, "['monitor']") !== false && strpos($blk1, "['monitor']") !== false);
t_ok('iplist: the block check keeps the exemptions and lets an enforced allow list win', strpos($blk1, 'gv_is_exempt(') !== false && strpos($blk1, "\$ipl['allow'] === null || \$ipl['allow']['monitor']") !== false);
t_ok('iplist: a block list is not applied while the secret is unconfigured (monitor-first), an allow list is', strpos($blk1, "\$cfg['secret'] !== 'CHANGE_ME'") !== false && strpos($blk, "\$cfg['secret'] !== 'CHANGE_ME'") !== false
	&& strpos($blk, "\$ipl['allow'] !== null") !== false);
t_ok('iplist: lists do not depend on enforce.block / the holdout', strpos($blk1 . $blk, "enforce'") === false && strpos($blk1 . $blk, 'holdout') === false && strpos($blk1 . $blk, 'gv_is_holdout') === false);
putenv('GV_LISTS_DIR');
gv_geo_state(true);

// --------------------------------------------------------------------------
t_section('Image CAPTCHA: image, answer, nonce, token level, rule action, headless score');

$CAP_CFG = gv_cfg_defaults(array('secret' => 'cap-secret'));
$has_gd = function_exists('imagettftext');
t_ok('captcha: the five levels carry the preset table (length, charset, warp, noise, overlap, time)',
	gv_captcha_levels() === array(
		1 => array('length' => 4, 'charset' => 'digits', 'warp' => 'low',    'noise' => 'few',    'overlap' => 'no',     'time' => 180),
		2 => array('length' => 5, 'charset' => 'digits', 'warp' => 'low',    'noise' => 'few',    'overlap' => 'no',     'time' => 150),
		3 => array('length' => 5, 'charset' => 'digits', 'warp' => 'medium', 'noise' => 'medium', 'overlap' => 'slight', 'time' => 120),
		4 => array('length' => 6, 'charset' => 'alnum',  'warp' => 'high',   'noise' => 'many',   'overlap' => 'yes',    'time' => 90),
		5 => array('length' => 7, 'charset' => 'alnum',  'warp' => 'high',   'noise' => 'many',   'overlap' => 'yes',    'time' => 60)));
$cp = function (array $c) use ($CAP_CFG) { return gv_captcha_params(array_merge($CAP_CFG, array('captcha' => array_merge($CAP_CFG['captcha'], $c)))); };
t_ok('captcha: a level sets every value; the default level is 2', $cp(array())['level'] === 2 && $cp(array('level' => 4))['length'] === 6 && $cp(array('level' => 4))['charset'] === 'alnum' && $cp(array('level' => 1))['time'] === 180);
t_ok('captcha: every value can be overridden on top of the level; "auto" and 0 mean the level; junk falls back to the level',
	$cp(array('level' => 1, 'length' => 6, 'charset' => 'alnum', 'warp' => 'high', 'noise' => 'many', 'overlap' => 'yes', 'time_limit' => 45)) === array('length' => 6, 'charset' => 'alnum', 'warp' => 'high', 'noise' => 'many', 'overlap' => 'yes', 'time' => 45, 'level' => 1)
	&& $cp(array('level' => 3, 'length' => 0, 'charset' => 'auto', 'time_limit' => 0))['length'] === 5 && $cp(array('level' => 9))['level'] === 2 && $cp(array('length' => 99, 'warp' => 'x'))['warp'] === 'low' && $cp(array('length' => 99))['length'] === 5);
t_ok('captcha: the answer alphabet has no ambiguous character: digits only, or letters without O I S Z B and digits without 0 1 2 5 8',
	gv_captcha_charset('digits') === '0123456789' && !preg_match('/[OISZB01258]/', gv_captcha_charset('alnum')) && preg_match('/^[A-Z0-9]+$/', gv_captcha_charset('alnum')) === 1);
$amb = 0; $badlen = 0;
for ($i = 0; $i < 400; $i++) {
	$a = gv_captcha_answer(6, 'alnum');
	if (preg_match('/[^34679ACDEFGHJKLMNPQRTUVWXY]/', $a)) { $amb++; }
	if (strlen($a) !== 6 || !ctype_digit(gv_captcha_answer(5, 'digits')) || strlen(gv_captcha_answer(5, 'digits')) !== 5) { $badlen++; }
}
t_ok('captcha: 400 generated answers have the right length and alphabet (' . $amb . ' / ' . $badlen . ' bad)', $amb === 0 && $badlen === 0);
t_ok('captcha: Persian and Arabic-Indic digits become Latin; spaces, zero-width and direction marks go; letters are upper-cased',
	gv_captcha_normalize('۱۲۳۴۵') === '12345' && gv_captcha_normalize('٦٧٨٩٠') === '67890' && gv_captcha_normalize(' 1 ۲ 3 ') === '123' && gv_captcha_normalize("a\xE2\x80\x8Cb\xE2\x80\x8Fc\xC2\xA0d") === 'ABCD'
	&& gv_captcha_normalize('ab3k') === 'AB3K' && gv_captcha_normalize('') === '' && strlen(gv_captcha_normalize(str_repeat('1', 500))) === 64 && gv_captcha_normalize('۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩') === '01234567890123456789');
// The image, at every level.
if (!$has_gd) {
	t_skip('captcha: image generation at every level (PNG, size, characters)', 'PHP GD is not installed here: the fallback tests below still run');
} else {
	$bad = array();
	foreach (array(1, 2, 3, 4, 5) as $lv) {
		$pp = $cp(array('level' => $lv));
		$ans = gv_captcha_answer($pp['length'], $pp['charset']);
		$png = gv_captcha_image($ans, $pp, $lv);
		$info = @getimagesizefromstring($png);
		if (substr($png, 0, 8) !== "\x89PNG\r\n\x1a\n" || !$info || $info[2] !== IMAGETYPE_PNG || $info[1] !== 76 || strlen($ans) !== $pp['length']) { $bad[] = 'level ' . $lv; }
		if ($info && $info[0] < $pp['length'] * 20) { $bad[] = 'width ' . $lv; }
	}
	t_ok('captcha: every level draws a real PNG of the right height, a width that grows with the length, and a bounded size' . ($bad ? ' (bad: ' . implode(',', $bad) . ')' : ''), !$bad);
	$p1 = $cp(array('level' => 1)); $p5 = $cp(array('level' => 5));
	$w1 = getimagesizefromstring(gv_captcha_image('1234', $p1, 1))[0]; $w5 = getimagesizefromstring(gv_captcha_image('ABCDEFG', $p5, 1))[0];
	t_ok('captcha: a longer answer is a wider image (4 chars vs 7 chars)', $w5 > $w1);
	t_ok('captcha: the same text and seed draw the same image, another seed another image, another text another image',
		gv_captcha_image('4821', $p1, 7) === gv_captcha_image('4821', $p1, 7) && gv_captcha_image('4821', $p1, 7) !== gv_captcha_image('4821', $p1, 8) && gv_captcha_image('4821', $p1, 7) !== gv_captcha_image('4822', $p1, 7));
	t_ok('captcha: a harder level draws a busier picture than an easier one (more bytes of PNG: noise, warp, overlap)', strlen(gv_captcha_image('482137', $cp(array('level' => 5, 'length' => 6)), 3)) > strlen(gv_captcha_image('482137', $cp(array('level' => 1, 'length' => 6)), 3)));
	$t0 = microtime(true);
	for ($i = 0; $i < 50; $i++) { gv_captcha_image('48213', $cp(array('level' => 3)), $i); }
	t_ok('captcha: a level 3 image takes well under 20 ms', (microtime(true) - $t0) / 50 < 0.02);
	t_ok('captcha: the shipped font and its licence are in guard/', is_file(GV_CAPTCHA_FONT) && is_file(__DIR__ . '/../guard/captcha-font.LICENSE.txt') && strpos(file_get_contents(__DIR__ . '/../guard/captcha-font.LICENSE.txt'), 'Permission is hereby granted') !== false);
}
// GD missing: the fallback.
putenv('GV_CAPTCHA_NO_GD=1');
t_ok('captcha: with GD "missing" the image is not available and nothing is drawn', gv_captcha_available() === false && gv_captcha_image('1234', $cp(array()), 1) === '');
$fb_f = array('ua' => 'ua', 'ip' => '1.2.3.4');
ob_start(); gv_captcha_serve(array_merge($CAP_CFG, array('secret' => 'cap-secret')), $fb_f, 14); $fb = ob_get_clean();
t_ok('captcha: without GD a captcha action serves the proof-of-work challenge with the requested difficulty (a four-part nonce, no image)',
	preg_match("/var N = '([0-9a-f.]+)', B = 14,/", $fb, $m) === 1 && count(explode('.', $m[1])) === 4 && strpos($fb, 'data:image') === false && strpos($fb, 'gv-cform') === false);
putenv('GV_CAPTCHA_NO_GD');
t_ok('captcha: and the GD check is back on once the knob is gone', gv_captcha_available() === $has_gd);

// The nonce: answer commitment, binding, expiry.
$cn = gv_captcha_nonce_make('cap-secret', 'ua/1', '203.0.113.5', 12, 150, '4821');
$cx = explode('.', $cn);
t_ok('captcha nonce: six parts, the PoW nonce parser refuses it and the CAPTCHA parser refuses a PoW nonce', count($cx) === 6 && gv_nonce_parse($cn) === false && gv_captcha_nonce_parse(gv_nonce_make('cap-secret', 'ua/1', '203.0.113.5', 12)) === false
	&& gv_captcha_nonce_parse($cn)[2] === 12 && gv_captcha_nonce_parse($cn)[3] === 150);
t_ok('captcha nonce: the answer is NOT in the nonce (only an HMAC of it), whatever the case or the digits typed',
	strpos($cn, '4821') === false && gv_captcha_answer_ok($cn, 'cap-secret', '4821') && gv_captcha_answer_ok($cn, 'cap-secret', ' ۴۸۲۱ ') && gv_captcha_answer_ok($cn, 'cap-secret', '٤٨٢١')
	&& !gv_captcha_answer_ok($cn, 'cap-secret', '4822') && !gv_captcha_answer_ok($cn, 'cap-secret', '') && !gv_captcha_answer_ok($cn, 'other-secret', '4821') && !gv_captcha_answer_ok('garbage', 'cap-secret', '4821'));
$cn2 = gv_captcha_nonce_make('cap-secret', 'ua/1', '203.0.113.5', 0, 60, 'ab3k');
t_ok('captcha nonce: letters are case-insensitive', gv_captcha_answer_ok($cn2, 'cap-secret', 'AB3K') && gv_captcha_answer_ok($cn2, 'cap-secret', 'aB3k') && !gv_captcha_answer_ok($cn2, 'cap-secret', 'AB3L'));
t_ok('captcha nonce: ok for its own UA and IP, bad for another UA, another IP, another secret, a flipped byte, a swapped answer commitment',
	gv_captcha_nonce_state($cn, 'cap-secret', 'ua/1', '203.0.113.5') === 'ok' && gv_captcha_nonce_state($cn, 'cap-secret', 'ua/2', '203.0.113.5') === 'bad' && gv_captcha_nonce_state($cn, 'cap-secret', 'ua/1', '203.0.113.6') === 'bad'
	&& gv_captcha_nonce_state($cn, 'x', 'ua/1', '203.0.113.5') === 'bad' && gv_captcha_nonce_state(substr($cn, 0, -1) . ($cn[strlen($cn) - 1] === '0' ? '1' : '0'), 'cap-secret', 'ua/1', '203.0.113.5') === 'bad'
	&& gv_captcha_nonce_state(implode('.', array($cx[0], $cx[1], $cx[2], $cx[3], str_repeat('0', 16), $cx[5])), 'cap-secret', 'ua/1', '203.0.113.5') === 'bad');
t_ok('captcha nonce: the time limit is part of the signed nonce: ok at 149 s, expired at 150 s, "bad" for a nonce from the future, a limit changed by the client is bad',
	gv_captcha_nonce_state($cn, 'cap-secret', 'ua/1', '203.0.113.5', (int)$cx[0] + 149) === 'ok' && gv_captcha_nonce_state($cn, 'cap-secret', 'ua/1', '203.0.113.5', (int)$cx[0] + 150) === 'exp'
	&& gv_captcha_nonce_state($cn, 'cap-secret', 'ua/1', '203.0.113.5', (int)$cx[0] - 100) === 'bad' && gv_captcha_nonce_state(implode('.', array($cx[0], $cx[1], $cx[2], '3600', $cx[4], $cx[5])), 'cap-secret', 'ua/1', '203.0.113.5') === 'bad');
t_ok('captcha nonce: without bind_ip the IP is not part of the binding (empty on both sides)', gv_captcha_nonce_state(gv_captcha_nonce_make('s', 'u', '', 0, 60, '1234'), 's', 'u', '') === 'ok');
t_ok('captcha nonce: parser limits (bits 0-24, time 1-3600, hex shapes)', gv_captcha_nonce_parse('1.' . str_repeat('a', 16) . '.25.60.' . str_repeat('b', 16) . '.' . str_repeat('c', 64)) === false
	&& gv_captcha_nonce_parse('1.' . str_repeat('a', 16) . '.12.0.' . str_repeat('b', 16) . '.' . str_repeat('c', 64)) === false && gv_captcha_nonce_parse('1.' . str_repeat('a', 16) . '.12.3601.' . str_repeat('b', 16) . '.' . str_repeat('c', 64)) === false
	&& gv_captcha_nonce_parse('1.' . str_repeat('a', 16) . '.12.60.' . str_repeat('b', 15) . '.' . str_repeat('c', 64)) === false && gv_captcha_nonce_parse('') === false);
t_ok('captcha: the escalation flag is a signed expiry that grants nothing', gv_capflag_ok(gv_capflag_make('s'), 's') && !gv_capflag_ok(gv_capflag_make('s'), 't') && !gv_capflag_ok(gv_capflag_make('s', -5), 's') && !gv_capflag_ok('x', 's') && !gv_capflag_ok('', 's'));

// Escalation flag in Redis + the degraded (Redis down) CAPTCHA: the helpers and the wiring.
$bc = array('captcha' => array('require_pow' => 1));
t_ok('captcha bits: the configured difficulty while Redis is up; require_pow off means none',
	gv_captcha_pow_bits($bc, 14, false) === 14 && gv_captcha_pow_bits(array('captcha' => array('require_pow' => 0)), 14, false) === 0);
t_ok('captcha bits: Redis down raises it to at least 20 (also with require_pow off), never lowers a higher one, never above 24',
	gv_captcha_pow_bits($bc, 14, true) === 20 && gv_captcha_pow_bits(array('captcha' => array('require_pow' => 0)), 0, true) === 20
	&& gv_captcha_pow_bits($bc, 22, true) === 22 && gv_captcha_pow_bits($bc, 30, true) === 24);
$bn = 'nonce.abc'; $bl = null;
for ($i = 0; $bl === null; $i++) { if (gv_pow_ok($bn, (string)$i, 8)) { $bl = $i; } }
t_ok('captcha pow: below 20 bits the proof covers the nonce alone (background solving), whatever the answer header says',
	gv_captcha_pow_ok($bn, 'x', (string)$bl, 8) === true && gv_captcha_pow_ok($bn, '', (string)$bl, 8) === true);
$bf = null; for ($i = 0; $i < 20000000 && $bf === null; $i++) { if (gv_pow_ok($bn . ':4821', (string)$i, 20)) { $bf = $i; } }
t_ok('captcha pow: a solved bound proof is good for ITS answer only (another guess needs its own work)',
	$bf !== null && gv_captcha_pow_ok($bn, '4821', (string)$bf, 20) === true && gv_captcha_pow_ok($bn, '4822', (string)$bf, 20) === false && gv_captcha_pow_ok($bn, '', (string)$bf, 20) === false);
$ke = array('ipn' => 'ip1', 'ua' => 'Mozilla A'); $ke2 = array('ipn' => 'ip1', 'ua' => 'Mozilla B'); $ke3 = array('ipn' => 'ip2', 'ua' => 'Mozilla A');
t_ok('escalation flag key: cesc:<md5>, stable for one ip + UA, different for another UA or another IP',
	preg_match('/^.*cesc:[0-9a-f]{32}$/', gv_cesc_key($ke)) === 1 && gv_cesc_key($ke) === gv_cesc_key($ke) && gv_cesc_key($ke) !== gv_cesc_key($ke2) && gv_cesc_key($ke) !== gv_cesc_key($ke3));
$gsrc = file_get_contents(__DIR__ . '/../guard/guard.php');
t_ok('escalation flag: written (SET .. EX 600) or read (GET) inside the handshake pipeline, read in the request pipeline: no extra connect or pipeline',
	strpos($gsrc, "array('SET', gv_cesc_key(\$f), '1', 'EX', '600')") !== false && strpos($gsrc, "array('GET', gv_cesc_key(\$f))") !== false);
$cj = gv_captcha_js('n.n', 20, array());
t_ok('captcha page script: the solver midstate is set up per subject and an answer-bound proof is solved at submit', strpos($cj, 'function setup(') !== false && strpos($cj, 'bound') !== false);
$dg = ''; ob_start(); gv_captcha_serve(array_merge($CAP_CFG, array('secret' => 'cap-secret')), array('ua' => 'ua', 'ip' => '1.2.3.4'), 20); $dg = ob_get_clean();
t_ok('captcha serve: with 20 bits the page carries B = 20 (bound proof) in a six-part nonce',
	!$has_gd || (preg_match("/var N = '([0-9a-f.]+)', B = 20,/", $dg, $m) === 1 && count(explode('.', $m[1])) === 6));
t_ok('captcha degraded length: at least 6 characters, a longer configured length is kept (max 8), the charset is untouched',
	gv_captcha_degraded_length(4) === 6 && gv_captcha_degraded_length(5) === 6 && gv_captcha_degraded_length(6) === 6 && gv_captcha_degraded_length(7) === 7 && gv_captcha_degraded_length(0) === 6);
if ($has_gd) {
	// The answer of a served page is only in the nonce as an HMAC: recover it by brute force for the digit levels.
	$len_of = function ($degraded) use ($CAP_CFG) {
		$cfg = array_merge($CAP_CFG, array('secret' => 'cap-secret', 'captcha' => array_merge($CAP_CFG['captcha'], array('level' => 1))));
		ob_start(); gv_captcha_serve($cfg, array('ua' => 'ua', 'ip' => '1.2.3.4'), 20, $degraded); $pg = ob_get_clean();
		if (!preg_match("/var N = '([0-9a-f.]+)'/", $pg, $mm)) { return 0; }
		for ($n = 3; $n <= 6; $n++) {
			for ($i = 0, $max = (int)pow(10, $n); $i < $max; $i++) {
				if (gv_captcha_answer_ok($mm[1], 'cap-secret', str_pad((string)$i, $n, '0', STR_PAD_LEFT))) { return $n; }
			}
		}
		return 0;
	};
	t_ok('captcha degraded: level 1 asks for 4 digits normally and 6 digits (same charset) when served while Redis is down', $len_of(false) === 4 && $len_of(true) === 6);
}

// Token levels: old tokens are PoW level.
$tp = gv_tok_make('tk'); $tc = gv_tok_make('tk', 'nonceid', 'c'); $tc2 = gv_tok_make('tk', 'nonceid', 'c');
t_ok('token level: a token issued the old way (three parts) is level p, a CAPTCHA token (four parts, third = c) is level c, the device id comes from the nonce', count(explode('.', $tp)) === 3 && count(explode('.', $tc)) === 4 && explode('.', $tc)[2] === 'c'
	&& gv_tok_parse($tp, 'tk', 3600)[1] === 'p' && gv_tok_parse($tc, 'tk', 3600)[1] === 'c' && gv_tok_parse($tc, 'tk', 3600)[0] === gv_tok_parse($tc2, 'tk', 3600)[0] && gv_tok_make('tk', 'nonceid') !== '');
t_ok('token level: gv_tok_check still returns the device id for both levels (every existing caller keeps working)', gv_tok_check($tp, 'tk', 3600) === gv_tok_parse($tp, 'tk', 3600)[0] && gv_tok_check($tc, 'tk', 3600) === gv_tok_parse($tc, 'tk', 3600)[0]);
$tcx = explode('.', $tc);
t_ok('token level: a PoW token cannot be upgraded to c (the signature covers the c), a c token cannot be downgraded, a wrong third part, a tampered or expired token',
	gv_tok_parse($tcx[0] . '.' . $tcx[1] . '.c.' . explode('.', $tp)[2], 'tk', 3600) === false && gv_tok_parse($tcx[0] . '.' . $tcx[1] . '.' . $tcx[3], 'tk', 3600) === false
	&& gv_tok_parse($tcx[0] . '.' . $tcx[1] . '.p.' . $tcx[3], 'tk', 3600) === false && gv_tok_parse($tc, 'other', 3600) === false && gv_tok_parse($tc, 'tk', 0) === false && gv_tok_parse('a.b.c.d.e', 'tk', 3600) === false && gv_tok_parse('', 'tk', 3600) === false);

// The rule action.
$rc = array('mode' => 'enforce', 'action' => 'captcha', 'skip_verified_bots' => true, 'pow_bits' => 0);
t_ok('captcha rule: "captcha" is a rule action and is validated like the others', in_array('captcha', gv_rule_actions(), true) && gv_rule_validate(array('id' => 'cp1', 'name' => 'c', 'enabled' => true, 'mode' => 'enforce', 'action' => 'captcha', 'priority' => 5,
	'skip_verified_bots' => true, 'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('x')), 'path' => null, 'expires_at' => 0, 'pow_bits' => 0, 'note' => ''))[0] === true);
t_ok('captcha rule: no token / a PoW-level token -> a CAPTCHA is asked; only a CAPTCHA-level token satisfies it',
	gv_rule_act($rc, 'm', true, true, '', true, true) === array('captcha', 'captcha') && gv_rule_act($rc, 'v', true, true, '', true, true) === array('captcha', 'captcha') && gv_rule_act($rc, 'b', true, true, '', true, true) === array('captcha', 'captcha')
	&& gv_rule_act($rc, 'v', true, true, 'c', true, true) === array('', ''));
t_ok('captcha rule: a non-HTML request, a request that is not gated, and a monitor rule are never asked',
	gv_rule_act($rc, 'm', true, true, '', false, true) === array('', '') && gv_rule_act($rc, 'm', false, true, '', true, true) === array('', '') && gv_rule_act(array_merge($rc, array('mode' => 'monitor')), 'm', true, true, '', true, true) === array('', ''));
t_ok('captcha rule: a token-less POST with gate_post off is a shadow (intended captcha, nothing served)', gv_rule_act($rc, 'm', true, false, '', true, true) === array('captcha', ''));
t_ok('captcha rule: without GD it is the proof-of-work challenge: any token satisfies it, no token gets the PoW page, a non-HTML request is challenged like a challenge rule',
	gv_rule_act($rc, 'm', true, true, '', true, false) === array('challenge', 'challenge') && gv_rule_act($rc, 'v', true, true, '', true, false) === array('', '') && gv_rule_act($rc, 'm', true, true, '', false, false) === array('challenge', 'challenge'));
t_ok('captcha rule: it takes the place of the bot / preview pass like block and challenge', gv_rule_overrides_pass($rc) === true && gv_rule_overrides_pass(array_merge($rc, array('action' => 'log'))) === false);
t_ok('captcha rule: a verified crawler is skipped EVEN with skip_verified_bots off; so is a known-bot UA while Redis is down; an unverified or refuted claim is not',
	gv_rule_bot_skip(array_merge($rc, array('skip_verified_bots' => false)), 'ok', true) === 'verified' && gv_rule_bot_skip(array_merge($rc, array('skip_verified_bots' => false)), '', false) === 'degraded'
	&& gv_rule_bot_skip(array_merge($rc, array('skip_verified_bots' => false)), '', true) === '' && gv_rule_bot_skip(array_merge($rc, array('skip_verified_bots' => false)), 'bad', true) === ''
	&& gv_rule_bot_skip(array_merge($rc, array('action' => 'block', 'skip_verified_bots' => false)), 'ok', true) === '');
$rcache = gv_rules_cache_source(array(array_merge($rc, array('id' => 'cp1', 'enabled' => true, 'priority' => 1, 'ua' => array('op' => 'include', 'type' => 'contains', 'values' => array('x')), 'path' => null, 'expires_at' => 0))));
t_ok('captcha rule: the generated rules cache carries the action like any other', strpos($rcache, "'action' => 'captcha'") !== false);

// Headless signals: pure scoring.
$W = gv_headless_weights($CAP_CFG);
t_ok('headless: the parser reads the fixed set (letter + whole number), ignores unknown letters, refuses the server-side "u", a bad shape or an oversized header',
	gv_headless_parse('w1.h0.t412.i1') === array('w' => 1, 'h' => 0, 't' => 412, 'i' => 1) && gv_headless_parse('w1.z9.l0') === array('w' => 1, 'l' => 0) && gv_headless_parse('u1.w1') === array('w' => 1)
	&& gv_headless_parse('w1.w0') === array('w' => 1) && gv_headless_parse('') === array() && gv_headless_parse('w1;h1') === array() && gv_headless_parse('W1') === array() && gv_headless_parse('w123456') === array() && gv_headless_parse(str_repeat('w1.', 60)) === array()
	&& gv_headless_parse('w1.' . str_repeat('l0.', 20)) === array());
t_ok('headless: each weight defaults as documented and comes from the config (captcha.w_*), an invalid value falls back',
	$W === array('w' => 40, 'h' => 40, 'm' => 25, 'l' => 15, 'c' => 20, 'p' => 10, 'g' => 15, 's' => 20, 'n' => 15, 't' => 20, 'i' => 20, 'u' => 25)
	&& gv_headless_weights(array('captcha' => array('w_webdriver' => 5, 'w_ua_headless' => 101, 'w_no_chrome' => 'x', 'w_too_fast' => 0)))['w'] === 5 && gv_headless_weights(array('captcha' => array('w_ua_headless' => 101)))['h'] === 40
	&& gv_headless_weights(array('captcha' => array('w_no_chrome' => 'x')))['c'] === 20 && gv_headless_weights(array('captcha' => array('w_too_fast' => 0)))['t'] === 0 && gv_headless_weights(array())['w'] === 40);
t_ok('headless: every signal fires with ITS weight and no other (webdriver, headless UA, mismatch, languages, chrome, plugins, webgl, screen, notification)',
	gv_headless_score(array('w' => 1), $W) === array(40, 'w') && gv_headless_score(array('l' => 1), $W) === array(15, 'l') && gv_headless_score(array('c' => 1), $W) === array(20, 'c') && gv_headless_score(array('p' => 1), $W) === array(10, 'p')
	&& gv_headless_score(array('g' => 1), $W) === array(15, 'g') && gv_headless_score(array('s' => 1), $W) === array(20, 's') && gv_headless_score(array('n' => 1), $W) === array(15, 'n') && gv_headless_score(array('m' => 1), $W) === array(25, 'm'));
t_ok('headless: a signal at 0 and a missing signal are neutral; an empty set scores 0', gv_headless_score(array('w' => 0, 'l' => 0, 'c' => 0, 'g' => 0), $W) === array(0, '') && gv_headless_score(array(), $W) === array(0, ''));
t_ok('headless: "too fast" fires below the threshold only (45 ms by default, below the 50 ms the page waits itself; the caller picks it); "no input" only when the page said 0',
	gv_headless_score(array('t' => 44), $W) === array(20, 't') && gv_headless_score(array('t' => 45), $W) === array(0, '') && gv_headless_score(array('t' => 100), $W) === array(0, '') && gv_headless_score(array('t' => 699), $W, '', 700) === array(20, 't') && gv_headless_score(array('t' => 700), $W, '', 700) === array(0, '')
	&& gv_headless_score(array('i' => 0), $W) === array(20, 'i') && gv_headless_score(array('i' => 1), $W) === array(0, ''));
t_ok('headless: the server-side check: the request UA says HeadlessChrome but the page says it does not (or the reverse) is a spoof; both agreeing is not', gv_headless_score(array('h' => 0), $W, 'Mozilla HeadlessChrome/120') === array(25, 'u')
	&& gv_headless_score(array('h' => 1), $W, 'Mozilla Chrome/120') === array(65, 'hu') && gv_headless_score(array('h' => 1), $W, 'Mozilla HeadlessChrome/120') === array(40, 'h') && gv_headless_score(array('h' => 0), $W, 'Mozilla Chrome/120') === array(0, '') && gv_headless_score(array('t' => 900), $W, 'HeadlessChrome') === array(0, ''));
t_ok('headless: a real headless Chrome (webdriver, HeadlessChrome, no languages, no chrome object, SwiftShader, 0x0) sums its weights; a normal browser scores 0',
	gv_headless_score(gv_headless_parse('w1.h1.m1.l1.c1.p1.g1.s1.n1.t30'), $W, 'HeadlessChrome') === array(40 + 40 + 25 + 15 + 20 + 10 + 15 + 20 + 15 + 20, 'whmlcpgsnt') && gv_headless_score(gv_headless_parse('w0.h0.m0.l0.c0.p0.g0.s0.n0.t1200.i1'), $W, 'Mozilla/5.0 Chrome') === array(0, ''));
t_ok('headless: a changed weight changes the score; a weight of 0 switches the signal off', gv_headless_score(array('w' => 1), array_merge($W, array('w' => 7))) === array(7, 'w') && gv_headless_score(array('w' => 1), array_merge($W, array('w' => 0))) === array(0, 'w'));
// What reaches the log: letters and a number only.
$lr = gv_log_row(array('rid' => 'r', 'ip' => '1.2.3.4', 'ua' => 'u', 'method' => 'POST', 'path' => '/', 'query' => '', 'referer' => '', 'hc' => 5, 'sf' => '', 'al' => 'en', 'xrw' => '', 'accept' => 'text/html'),
	array_merge(gv_state_new(), array('cap' => 'ok', 'ct' => 12, 'tl' => 'c', 'hs' => 105, 'hf' => 'whu')), 'token_issued', 0, microtime(true));
t_ok('log: the CAPTCHA and headless keys are short (cap, ct, tl, hs, hf) and only present when they apply; nothing else about the browser is logged',
	$lr['cap'] === 'ok' && $lr['ct'] === 12 && $lr['tl'] === 'c' && $lr['hs'] === 105 && $lr['hf'] === 'whu' && !array_key_exists('cap', gv_log_row(array('rid' => 'r', 'ip' => '1.2.3.4', 'ua' => 'u', 'method' => 'GET', 'path' => '/', 'query' => '', 'referer' => '', 'hc' => 5, 'sf' => '', 'al' => '', 'xrw' => '', 'accept' => ''), gv_state_new(), 'allow', 0, microtime(true)))
	&& !array_key_exists('hs', gv_log_row(array('rid' => 'r', 'ip' => '1.2.3.4', 'ua' => 'u', 'method' => 'GET', 'path' => '/', 'query' => '', 'referer' => '', 'hc' => 5, 'sf' => '', 'al' => '', 'xrw' => '', 'accept' => ''), gv_state_new(), 'allow', 0, microtime(true))));

// Config.
t_ok('config: captcha.* defaults (level 2, 3 attempts, 10 pages per 900 s, PoW with it, escalation and device budget off) and every key is whitelisted',
	$CAP_CFG['captcha']['level'] === 2 && $CAP_CFG['captcha']['max_attempts'] === 3 && $CAP_CFG['captcha']['ip_budget'] === 10 && $CAP_CFG['captcha']['ip_window'] === 900 && $CAP_CFG['captcha']['require_pow'] === true
	&& $CAP_CFG['captcha']['escalate_score'] === 0 && $CAP_CFG['captcha']['device_budget'] === false && !array_filter(array_keys($CAP_CFG['captcha']), function ($k) { return !isset(gv_overlay_whitelist()['captcha.' . $k]); }));
t_ok('config: captcha.* validation: level 1-5, length 0-8, enums, ranges are REJECTED not clamped, booleans are real booleans',
	gv_overlay_validate('captcha.level', 5)[0] && !gv_overlay_validate('captcha.level', 6)[0] && !gv_overlay_validate('captcha.level', 0)[0] && gv_overlay_validate('captcha.length', 0)[0] && !gv_overlay_validate('captcha.length', 9)[0]
	&& gv_overlay_validate('captcha.charset', 'alnum')[0] && !gv_overlay_validate('captcha.charset', 'letters')[0] && gv_overlay_validate('captcha.warp', 'auto')[0] && !gv_overlay_validate('captcha.noise', 'lots')[0]
	&& !gv_overlay_validate('captcha.max_attempts', 0)[0] && !gv_overlay_validate('captcha.ip_budget', 1001)[0] && !gv_overlay_validate('captcha.ip_window', 59)[0] && gv_overlay_validate('captcha.require_pow', false)[0] && !gv_overlay_validate('captcha.require_pow', 'no')[0]
	&& gv_overlay_validate('captcha.w_webdriver', 100)[0] && !gv_overlay_validate('captcha.w_webdriver', 101)[0] && !gv_overlay_validate('captcha.w_no_chrome', -1)[0] && gv_overlay_validate('captcha.escalate_score', 0)[0] && !gv_overlay_validate('captcha.escalate_score', 201)[0]);
t_ok('config: the literal weight defaults in gv_cfg_defaults are the numbers of gv_headless_weights_default()', (function () use ($CAP_CFG) {
	foreach (gv_headless_weight_keys() as $letter => $key) { if ($CAP_CFG['captcha'][$key] !== gv_headless_weights_default()[$letter]) { return false; } }
	return count(gv_headless_weight_keys()) === count(gv_headless_weights_default());
})());
t_ok('config: "off" / "false" in a hand-edited captcha block read as off', gv_cfg_defaults(array('captcha' => array('require_pow' => 'off', 'device_budget' => 'true')))['captcha']['require_pow'] === false && gv_cfg_defaults(array('captcha' => array('device_budget' => 'true')))['captcha']['device_budget'] === true
	&& gv_cfg_defaults(array('captcha' => 'x'))['captcha']['level'] === 2);
t_ok('config: the CAPTCHA page strings are whitelisted text keys with defaults', gv_overlay_validate('strings.cap_title', 'Prove it')[0] && !gv_overlay_validate('strings.cap_title', str_repeat('x', 201))[0] && isset($CAP_CFG['strings']['cap_wrong']) && isset($CAP_CFG['strings']['cap_expired']));
t_ok('config: no secret reaches the overlay through the new keys', !array_filter(array_keys(gv_overlay_whitelist()), function ($k) { return $k === 'secret' || $k === 'holdout_salt'; }));

// The page.
if ($has_gd) {
	$pg_p = $cp(array('level' => 1));
	$pg_png = gv_captcha_image('4821', $pg_p, 3);
	ob_start(); gv_captcha_render(gv_captcha_nonce_make('s', 'u', '1.1.1.1', 12, 180, '4821'), array_merge($CAP_CFG['strings'], array('cap_title' => 'T <b>x</b> "q"', 'dir' => 'rtl', 'lang' => 'fa')), 12, $pg_png, $pg_p); $pg = ob_get_clean();
	t_ok('captcha page: the image is a data URI, the answer is nowhere in the page, the nonce is, the strings are escaped, lang / dir follow the settings',
		strpos($pg, 'src="data:image/png;base64,') !== false && strpos($pg, '4821') === false && preg_match("/var N = '[0-9a-f.]{80,}', B = 12,/", $pg) === 1 && strpos($pg, '<b>x</b>') === false && strpos($pg, '&lt;b&gt;x&lt;/b&gt;') !== false
		&& strpos($pg, 'lang="fa" dir="rtl"') !== false && strpos($pg, 'inputmode="numeric"') !== false && strpos($pg, 'id="gv-ca"') !== false && strpos($pg, 'noindex') !== false);
	$pg_p5 = $cp(array('level' => 5));
	ob_start(); gv_captcha_render(gv_captcha_nonce_make('s', 'u', '1.1.1.1', 0, 60, 'AB3K7CD'), $CAP_CFG['strings'], 0, gv_captcha_image('AB3K7CD', $pg_p5, 3), $pg_p5); $pg5 = ob_get_clean();
	t_ok('captcha page: a letters-and-digits charset has no numeric keyboard; with no proof of work B is 0; the form has a "new image" button and the shipped texts',
		strpos($pg5, 'inputmode="numeric"') === false && strpos($pg5, 'B = 0,') !== false && strpos($pg5, 'id="gv-cn"') !== false && strpos($pg5, 'Please confirm you are human') !== false);
	t_ok('captcha page: the script has the solver, the signals and the answer header, and encodes the answer (a Persian keyboard)', strpos($pg, 'encodeURIComponent(inp.value)') !== false && strpos($pg, "X-GV-A") !== false && strpos($pg, "X-GV-S") !== false && strpos($pg, 'function sig(cap)') !== false
		&& strpos($pg, 'function solve(done)') !== false && strpos($pg, '}\n})();') !== false || substr_count($pg, '})();') >= 2);
}
t_ok('challenge page: the PoW script now also sends the signals and treats a 202 as "reload" (an escalation)', strpos(gv_challenge_js(), "h['X-GV-S'] = sig(false)") !== false && strpos(gv_challenge_js(), 'r.status === 202') !== false && strpos(gv_challenge_js(), '/*GV_TAIL*/') === false);
t_ok('challenge page: the signals are yes / no answers and one number: no renderer or plugin string is ever sent', preg_match('/getParameter\(ext\.UNMASKED_RENDERER_WEBGL\)\)\)\s*\?\s*1\s*:\s*0/', gv_challenge_js()) === 1 && strpos(gv_challenge_js(), "put('g', /SwiftShader") !== false && strpos(gv_challenge_js(), 'join(\'.\')') !== false);
t_ok('the guard stays fail-open for the new code: a CAPTCHA in front of no GD, a bad header, a bad nonce never throw', (function () use ($CAP_CFG) {
	try { gv_headless_parse("\x00\xff"); gv_headless_score(array('x' => 1), array()); gv_captcha_normalize("\xff\xfe"); gv_captcha_answer_ok("\xff", 's', "\xff"); gv_captcha_nonce_state("\xff", 's'); gv_tok_parse("\xff.\xfe.c.\xfd", 's', 5); return true; } catch (\Throwable $e) { return false; }
})());

// --------------------------------------------------------------------------
echo "\n";
echo "PASS " . $GV_PASS . "  FAIL " . $GV_FAIL . "  SKIP " . $GV_SKIP . "\n";
exit($GV_FAIL === 0 ? 0 : 1);
