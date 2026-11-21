<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// Self-hosted image CAPTCHA and the headless-browser signals.
//
// No external service: the image is drawn with PHP GD (the only extension this
// project allows, and optional: without it every `captcha` action falls back to
// the proof-of-work challenge) and sent inside the challenge page as a data URI.
//
// Verification is stateless where it can be. The CAPTCHA nonce carries
//   HMAC(secret, "cap|" nonce_id "|" normalised_answer)
// next to its issue time, proof-of-work difficulty and time limit, and the whole
// nonce is signed together with the UA / IP binding, exactly like the PoW nonce.
// The answer is never sent to the client. Redis adds the single use (the nonce
// claim, SET NX) and the attempt counter; with Redis down binding, expiry and
// proof of work still apply but attempts are not counted (documented replay /
// guessing window, docs/06-KNOWN-LIMITS.md).
//
// A CAPTCHA, the headless signals and the proof of work raise the cost of
// automation; they do not make headless browsers impossible (stealth plugins, OCR,
// paid solving services). The per-IP CAPTCHA budget, the device budgets and the
// proof of work are what limit volume.

define('GV_CAPTCHA_FONT', __DIR__ . '/captcha-font.ttf');

// The five presets. length, charset (digits | alnum), warp / noise / overlap level, time limit (s).
function gv_captcha_levels() {
	return array(
		1 => array('length' => 4, 'charset' => 'digits', 'warp' => 'low',    'noise' => 'few',    'overlap' => 'no',     'time' => 180),
		2 => array('length' => 5, 'charset' => 'digits', 'warp' => 'low',    'noise' => 'few',    'overlap' => 'no',     'time' => 150),
		3 => array('length' => 5, 'charset' => 'digits', 'warp' => 'medium', 'noise' => 'medium', 'overlap' => 'slight', 'time' => 120),
		4 => array('length' => 6, 'charset' => 'alnum',  'warp' => 'high',   'noise' => 'many',   'overlap' => 'yes',    'time' => 90),
		5 => array('length' => 7, 'charset' => 'alnum',  'warp' => 'high',   'noise' => 'many',   'overlap' => 'yes',    'time' => 60),
	);
}

// The effective CAPTCHA parameters: the level's preset, with every value the operator set explicitly
// on top ('auto' / 0 mean "take it from the level"). Pure.
function gv_captcha_params(array $cfg) {
	$c = (isset($cfg['captcha']) && is_array($cfg['captcha'])) ? $cfg['captcha'] : array();
	$lv = gv_captcha_levels();
	$level = isset($c['level']) ? (int)$c['level'] : 2;
	if (!isset($lv[$level])) { $level = 2; }
	$p = $lv[$level];
	$p['level'] = $level;
	if (!empty($c['length']) && (int)$c['length'] >= 3 && (int)$c['length'] <= 8) { $p['length'] = (int)$c['length']; }
	if (isset($c['charset']) && in_array($c['charset'], array('digits', 'alnum'), true)) { $p['charset'] = $c['charset']; }
	if (isset($c['warp']) && in_array($c['warp'], array('low', 'medium', 'high'), true)) { $p['warp'] = $c['warp']; }
	if (isset($c['noise']) && in_array($c['noise'], array('few', 'medium', 'many'), true)) { $p['noise'] = $c['noise']; }
	if (isset($c['overlap']) && in_array($c['overlap'], array('no', 'slight', 'yes'), true)) { $p['overlap'] = $c['overlap']; }
	if (!empty($c['time_limit']) && (int)$c['time_limit'] >= 20 && (int)$c['time_limit'] <= 900) { $p['time'] = (int)$c['time_limit']; }
	return $p;
}

// Whether the image can be drawn here. GV_CAPTCHA_NO_GD is a test knob (the suites run the
// "GD missing" case on a PHP that has GD).
function gv_captcha_available() {
	$env = getenv('GV_CAPTCHA_NO_GD');
	if (is_string($env) && $env !== '' && $env !== '0') { return false; }
	return function_exists('imagecreatetruecolor') && function_exists('imagettftext') && function_exists('imagepng')
		&& function_exists('imagettfbbox') && is_file(GV_CAPTCHA_FONT);
}

// The characters an answer is drawn from. No character that is easy to mistake for another: letters
// exclude O I S Z B (and 0 1 5 2 8 are not used with letters). Upper case only: answers are case-insensitive.
function gv_captcha_charset($charset) {
	return $charset === 'alnum' ? '34679ACDEFGHJKLMNPQRTUVWXY' : '0123456789';
}

function gv_captcha_answer($length, $charset) {
	$set = gv_captcha_charset($charset);
	$n = strlen($set);
	$out = '';
	for ($i = 0; $i < (int)$length; $i++) { $out .= $set[random_int(0, $n - 1)]; }
	return $out;
}

// What the visitor typed, ready to compare: Persian (U+06F0-06F9) and Arabic-Indic (U+0660-0669) digits
// become Latin, every space and zero-width / direction mark goes, letters are upper-cased (ASCII). Pure.
function gv_captcha_normalize($s) {
	$s = (string)$s;
	if (strlen($s) > 64) { $s = substr($s, 0, 64); }
	$map = array();
	for ($i = 0; $i < 10; $i++) {
		$map["\xDB" . chr(0xB0 + $i)] = (string)$i;          // U+06F0 + i
		$map["\xD9" . chr(0xA0 + $i)] = (string)$i;          // U+0660 + i
	}
	$s = strtr($s, $map);
	$s = preg_replace('/[\s\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}\x{00A0}]+/u', '', $s);
	return is_string($s) ? strtoupper($s) : '';
}

// The answer commitment carried in the nonce.
function gv_captcha_mac($secret, $id, $norm) {
	return substr(hash_hmac('sha256', 'cap|' . $id . '|' . $norm, $secret), 0, 16);
}

// --------------------------------------------------------------------------
// The CAPTCHA nonce: issued_at . random . bits . time_limit . answer_mac . signature
// (six parts: the PoW nonce has four, so neither parser accepts the other's).
// --------------------------------------------------------------------------

function gv_captcha_nonce_make($secret, $ua, $ip, $bits, $time, $answer) {
	$bits = max(0, min(24, (int)$bits));
	$id = bin2hex(random_bytes(8));
	$p = time() . '.' . $id . '.' . $bits . '.' . (int)$time . '.' . gv_captcha_mac($secret, $id, gv_captcha_normalize($answer));
	return $p . '.' . hash_hmac('sha256', $p . '|' . gv_nonce_bind($ua, $ip), $secret);
}

// array(issued, id, bits, time, mac) or false. Does not verify.
function gv_captcha_nonce_parse($n) {
	$x = explode('.', (string)$n);
	if (count($x) !== 6) { return false; }
	if (!ctype_digit($x[0]) || !preg_match('/^[0-9a-f]{16}$/', $x[1]) || !ctype_digit($x[2]) || !ctype_digit($x[3])
		|| !preg_match('/^[0-9a-f]{16}$/', $x[4]) || !preg_match('/^[0-9a-f]{64}$/', $x[5])) { return false; }
	if ((int)$x[2] > 24 || (int)$x[3] < 1 || (int)$x[3] > 3600) { return false; }
	return array((int)$x[0], $x[1], (int)$x[2], (int)$x[3], $x[4]);
}

// 'ok', 'bad' (malformed, wrong signature or binding) or 'exp' (valid but past its time limit). Pure.
function gv_captcha_nonce_state($n, $secret, $ua = '', $ip = '', $now = null) {
	$p = gv_captcha_nonce_parse($n);
	if ($p === false) { return 'bad'; }
	$x = explode('.', (string)$n);
	$body = $x[0] . '.' . $x[1] . '.' . $x[2] . '.' . $x[3] . '.' . $x[4];
	if (!hash_equals(hash_hmac('sha256', $body . '|' . gv_nonce_bind($ua, $ip), $secret), $x[5])) { return 'bad'; }
	$age = ($now === null ? time() : (int)$now) - $p[0];
	if ($age < -30) { return 'bad'; }
	return $age >= $p[3] ? 'exp' : 'ok';
}

// Whether a typed answer is the one the nonce commits to. Constant time. Pure.
function gv_captcha_answer_ok($n, $secret, $typed) {
	$p = gv_captcha_nonce_parse($n);
	if ($p === false) { return false; }
	$norm = gv_captcha_normalize($typed);
	if ($norm === '') { return false; }
	return hash_equals($p[4], gv_captcha_mac($secret, $p[1], $norm));
}

// The "a CAPTCHA is required" flag cookie that an escalation sets: signed expiry, nothing else.
function gv_capflag_make($secret, $ttl = 600) {
	$p = (string)(time() + (int)$ttl);
	return $p . '.' . hash_hmac('sha256', 'capflag|' . $p, $secret);
}

function gv_capflag_ok($v, $secret) {
	$x = explode('.', (string)$v);
	if (count($x) !== 2 || !ctype_digit($x[0]) || (int)$x[0] < time()) { return false; }
	return hash_equals(hash_hmac('sha256', 'capflag|' . $x[0], $secret), $x[1]);
}

function gv_capflag_cookie(array $cfg, $value, $expires, $https) {
	if (headers_sent()) { return; }
	setcookie((string)$cfg['cookie_name'] . 'c', (string)$value, array(
		'expires' => $expires, 'path' => '/', 'secure' => (bool)$https, 'httponly' => true, 'samesite' => 'Lax',
	));
}

// --------------------------------------------------------------------------
// The image
// --------------------------------------------------------------------------

function gv_captcha_levels_ranges() {
	return array(
		'warp'    => array('low' => array(8, 0), 'medium' => array(18, 3), 'high' => array(30, 6)),     // max rotation (deg), wave amplitude (px)
		'noise'   => array('few' => array(3, 60), 'medium' => array(6, 160), 'many' => array(10, 320)),   // lines, dots
		'overlap' => array('no' => 1.0, 'slight' => 0.86, 'yes' => 0.72),                                // advance as a share of the glyph width
	);
}

// Draw $text as a PNG. Returns the PNG bytes, or '' when GD is missing. $seed makes the layout repeatable
// (tests, the preview); a real page passes null. Never throws.
function gv_captcha_image($text, array $p, $seed = null) {
	if (!gv_captcha_available()) { return ''; }
	try {
		if ($seed !== null) { mt_srand((int)$seed); }
		$R = gv_captcha_levels_ranges();
		$text = (string)$text;
		$n = max(1, strlen($text));
		$size = 34;
		$adv = (int)round(($size * 0.78) * $R['overlap'][$p['overlap']]);
		$w = $n * $adv + 44;
		$h = 76;
		$im = imagecreatetruecolor($w, $h);
		$bg = imagecolorallocate($im, mt_rand(236, 250), mt_rand(236, 250), mt_rand(236, 250));
		imagefilledrectangle($im, 0, 0, $w, $h, $bg);
		// A faint background texture, so the glyphs are not the only structure in the picture.
		for ($i = 0; $i < 12; $i++) {
			$c = imagecolorallocate($im, mt_rand(205, 232), mt_rand(205, 232), mt_rand(205, 232));
			imagefilledellipse($im, mt_rand(0, $w), mt_rand(0, $h), mt_rand(20, 70), mt_rand(10, 40), $c);
		}
		$maxrot = $R['warp'][$p['warp']][0];
		$x = 22;
		for ($i = 0; $i < strlen($text); $i++) {
			$col = imagecolorallocate($im, mt_rand(10, 110), mt_rand(10, 110), mt_rand(10, 110));
			$ang = $maxrot > 0 ? mt_rand(-$maxrot, $maxrot) : 0;
			$sz = $size + mt_rand(-3, 3);
			$y = (int)($h / 2 + $sz / 2.6) + mt_rand(-6, 6);
			imagettftext($im, $sz, $ang, $x, $y, $col, GV_CAPTCHA_FONT, $text[$i]);
			$x += $adv;
		}
		// Wave distortion (medium and high warp): every column moves up or down by a sine.
		$amp = $R['warp'][$p['warp']][1];
		if ($amp > 0) {
			$out = imagecreatetruecolor($w, $h);
			imagefilledrectangle($out, 0, 0, $w, $h, $bg);
			$period = mt_rand(28, 46);
			$phase = mt_rand(0, 628) / 100.0;
			for ($cx = 0; $cx < $w; $cx++) {
				$dy = (int)round($amp * sin(2 * M_PI * $cx / $period + $phase));
				imagecopy($out, $im, $cx, $dy, $cx, 0, 1, $h);
			}
			imagedestroy($im);
			$im = $out;
		}
		list($lines, $dots) = $R['noise'][$p['noise']];
		for ($i = 0; $i < $lines; $i++) {
			$c = imagecolorallocate($im, mt_rand(60, 170), mt_rand(60, 170), mt_rand(60, 170));
			imagesetthickness($im, mt_rand(1, 2));
			imageline($im, mt_rand(0, $w), mt_rand(0, $h), mt_rand(0, $w), mt_rand(0, $h), $c);
		}
		for ($i = 0; $i < $dots; $i++) {
			$c = imagecolorallocate($im, mt_rand(40, 200), mt_rand(40, 200), mt_rand(40, 200));
			imagesetpixel($im, mt_rand(0, $w - 1), mt_rand(0, $h - 1), $c);
		}
		ob_start();
		imagepng($im, null, 6);
		$png = (string)ob_get_clean();
		imagedestroy($im);
		return $png;
	} catch (\Throwable $e) {
		if (ob_get_level() > 0) { @ob_end_clean(); }
		gv_errlog('captcha_exception', get_class($e) . ': ' . $e->getMessage());
		return '';
	}
}

// --------------------------------------------------------------------------
// Headless-browser signals
//
// The challenge JavaScript sends a small FIXED set of yes / no signals (and one number) in the header
// X-GV-S, e.g. "w0.h0.m0.l0.c0.p0.g0.s0.n0.t412.i1". Nothing else leaves the browser: no renderer string,
// no plugin list, no screen size. A missing signal is neutral. The server turns it into a score (a pure
// function, each signal has a weight in the config) and logs the score (hs) and the letters of the signals
// that fired (hf): short keys, never a raw value.
//
//   w navigator.webdriver            h HeadlessChrome in navigator.userAgent
//   m userAgentData disagrees with the UA   l navigator.languages empty
//   c window.chrome missing on a Chrome UA  p no plugins / mimeTypes on a desktop Chrome
//   g WebGL renderer is SwiftShader / llvmpipe   s screen or outer window 0x0
//   n Notification.permission vs the permissions API disagree
//   t ms from page load to submit (too fast: below 45 ms on the PoW page, whose own script waits 50 ms first;
//     below 700 ms on the CAPTCHA page, where a person types)     i 0 = no pointer / keyboard / touch event before
//                                                  submit (CAPTCHA page only)
//   u (server side) the request UA says HeadlessChrome but the page says it does not, or the reverse
// --------------------------------------------------------------------------

function gv_headless_weights_default() {
	return array('w' => 40, 'h' => 40, 'm' => 25, 'l' => 15, 'c' => 20, 'p' => 10, 'g' => 15, 's' => 20, 'n' => 15, 't' => 20, 'i' => 20, 'u' => 25);
}

// The config keys of the weights (captcha.w_<name>), by signal letter.
function gv_headless_weight_keys() {
	return array('w' => 'w_webdriver', 'h' => 'w_ua_headless', 'm' => 'w_ua_mismatch', 'l' => 'w_no_languages', 'c' => 'w_no_chrome',
		'p' => 'w_no_plugins', 'g' => 'w_webgl_soft', 's' => 'w_screen_zero', 'n' => 'w_notification', 't' => 'w_too_fast', 'i' => 'w_no_input', 'u' => 'w_ua_spoof');
}

// The weights from the config (captcha.w_*), defaults where unset. Pure.
function gv_headless_weights(array $cfg) {
	$w = gv_headless_weights_default();
	$c = (isset($cfg['captcha']) && is_array($cfg['captcha'])) ? $cfg['captcha'] : array();
	foreach (gv_headless_weight_keys() as $letter => $key) {
		if (isset($c[$key]) && is_int($c[$key]) && $c[$key] >= 0 && $c[$key] <= 100) { $w[$letter] = $c[$key]; }
	}
	return $w;
}

// The header into letter => int. Unknown letters, bad shapes and long headers give an empty array. Pure.
function gv_headless_parse($raw) {
	$raw = (string)$raw;
	if ($raw === '' || strlen($raw) > 120 || !preg_match('/^[a-z][0-9]{1,5}(\.[a-z][0-9]{1,5}){0,15}$/', $raw)) { return array(); }
	$ok = gv_headless_weights_default();
	$out = array();
	foreach (explode('.', $raw) as $part) {
		$k = $part[0];
		if (isset($ok[$k]) && $k !== 'u' && !isset($out[$k])) { $out[$k] = (int)substr($part, 1); }
	}
	return $out;
}

// array(score, flags) from parsed signals. flags is the letters that fired, in a fixed order. $too_fast_ms: the
// "t" signal fires below it. $ua: the request's own User-Agent (for the server-side "u" check). Pure.
function gv_headless_score(array $sig, array $weights, $ua = '', $too_fast_ms = 45) {
	$fired = '';
	$score = 0;
	foreach (array('w', 'h', 'm', 'l', 'c', 'p', 'g', 's', 'n') as $k) {
		if (isset($sig[$k]) && $sig[$k] === 1) { $fired .= $k; }
	}
	if (isset($sig['t']) && $sig['t'] < (int)$too_fast_ms) { $fired .= 't'; }
	if (isset($sig['i']) && $sig['i'] === 0) { $fired .= 'i'; }
	if (isset($sig['h'])) {
		$req = (stripos((string)$ua, 'HeadlessChrome') !== false);
		if ($req !== ($sig['h'] === 1)) { $fired .= 'u'; }
	}
	for ($i = 0; $i < strlen($fired); $i++) { $score += isset($weights[$fired[$i]]) ? (int)$weights[$fired[$i]] : 0; }
	return array($score, $fired);
}

// --------------------------------------------------------------------------
// The CAPTCHA page
// --------------------------------------------------------------------------

function gv_captcha_page_strings(array $s) {
	$d = array('cap_title' => 'Please confirm you are human', 'cap_sub' => 'Type the characters you see in the picture.',
		'cap_label' => 'Characters', 'cap_submit' => 'Continue', 'cap_new' => 'New image',
		'cap_wrong' => 'That is not right. Please try again.', 'cap_failed' => 'The check failed. Please get a new image.',
		'cap_expired' => 'The image has expired. Please get a new one.');
	$out = array();
	foreach ($d as $k => $v) { $out[$k] = (isset($s[$k]) && is_string($s[$k]) && $s[$k] !== '') ? $s[$k] : $v; }
	return $out;
}

// Send the CAPTCHA page (503, like the challenge page: nothing may cache it). $png: image bytes. Does not exit.
function gv_captcha_render($nonce, array $strings, $bits, $png, array $params) {
	$e = function ($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); };
	$nonce = preg_replace('/[^0-9a-f.]/', '', (string)$nonce);
	$bits = max(0, min(24, (int)$bits));
	$t = gv_captcha_page_strings($strings);
	$lang = $e(isset($strings['lang']) ? $strings['lang'] : 'en');
	$dir = $e(isset($strings['dir']) ? $strings['dir'] : 'ltr');
	$numeric = ($params['charset'] === 'digits');
	if (!headers_sent()) {
		http_response_code(503);
		header('X-LiteSpeed-Cache-Control: no-cache');
		header('Retry-After: 30');
		header('Content-Type: text/html; charset=utf-8');
		header('Cache-Control: no-store');
		header('X-Robots-Tag: noindex');
	}
	$dim = @getimagesizefromstring($png);
	$iw = $dim ? (int)$dim[0] : 240;
	$ih = $dim ? (int)$dim[1] : 76;
	echo "<!doctype html>\n<html lang=\"" . $lang . '" dir="' . $dir . "\">\n<head>\n<meta charset=\"utf-8\">\n"
		. "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<meta name=\"robots\" content=\"noindex,nofollow\">\n"
		. '<title>' . $e($t['cap_title']) . "</title>\n<style>\n"
		. "html,body{height:100%;margin:0}[hidden]{display:none!important}\n"
		. "body{display:flex;align-items:center;justify-content:center;background:#f6f7f9;color:#1c1e21;font:16px/1.7 system-ui,-apple-system,Segoe UI,Tahoma,Arial,sans-serif}\n"
		. ".gv{max-width:26rem;width:100%;padding:1.5rem;text-align:center;box-sizing:border-box}.gv h1{margin:0 0 .5rem;font-size:1.2rem;font-weight:600}\n"
		. ".gv p{margin:.25rem 0;color:#5a5f66}.gv img{max-width:100%;height:auto;border:1px solid #d5d8dd;border-radius:6px;background:#fff;margin:.75rem 0}\n"
		. ".gv input{font:inherit;font-size:1.3rem;letter-spacing:.2em;text-align:center;width:11rem;max-width:80%;padding:.4rem;border:1px solid #b6bbc2;border-radius:6px;direction:ltr}\n"
		. ".gv button{font:inherit;margin:.6rem .25rem 0;padding:.45rem 1.1rem;border:0;border-radius:6px;background:#1a56db;color:#fff;cursor:pointer}.gv button[disabled]{opacity:.6}\n"
		. ".gv a{color:#1a56db}.gv .e{color:#b42318}.gv .n{margin-top:1rem;font-size:.9rem;color:#8a8f96}\n</style>\n</head>\n<body>\n<div class=\"gv\">\n"
		. '<h1>' . $e($t['cap_title']) . "</h1>\n<p>" . $e($t['cap_sub']) . "</p>\n"
		. '<img alt="" width="' . $iw . '" height="' . $ih . '" src="data:image/png;base64,' . base64_encode($png) . "\">\n"
		. '<form id="gv-cform" autocomplete="off"><label for="gv-ca" style="position:absolute;left:-9999px">' . $e($t['cap_label']) . '</label>'
		. '<input id="gv-ca" type="text" maxlength="12" autocapitalize="characters" autocorrect="off" spellcheck="false" '
		. ($numeric ? 'inputmode="numeric" ' : '') . 'required><br>'
		. '<button id="gv-cs" type="submit">' . $e($t['cap_submit']) . '</button><button id="gv-cn" type="button">' . $e($t['cap_new']) . "</button></form>\n"
		. '<p id="gv-ce" class="e" role="alert" hidden></p>' . "\n"
		. '<noscript><p class="n">' . $e(isset($strings['noscript']) ? $strings['noscript'] : '') . "</p></noscript>\n</div>\n<script>\n"
		. gv_captcha_js($nonce, $bits, array('wrong' => $t['cap_wrong'], 'failed' => $t['cap_failed'], 'expired' => $t['cap_expired'])) . "\n</script>\n</body>\n</html>\n";
}

// Serve a CAPTCHA page for this request. $bits: the proof-of-work difficulty that rides with it (0 = none).
// Without GD it serves the proof-of-work challenge instead. Never throws, does not exit.
function gv_captcha_serve(array $cfg, array $f, $bits) {
	$p = gv_captcha_params($cfg);
	$png = '';
	$answer = '';
	if (gv_captcha_available()) {
		$answer = gv_captcha_answer($p['length'], $p['charset']);
		$png = gv_captcha_image($answer, $p);
	}
	$bind = !empty($cfg['challenge']['bind_ip']) ? $f['ip'] : '';
	if ($png === '') {
		// GD missing or the drawing failed: the existing proof-of-work challenge, with the same difficulty.
		$b = max(0, min(24, (int)$cfg['challenge']['pow_bits']));
		gv_challenge_render(gv_nonce_make($cfg['secret'], $f['ua'], $bind, $bits > 0 ? $bits : $b), $cfg['strings'], $bits > 0 ? $bits : $b);
		return;
	}
	$nonce = gv_captcha_nonce_make($cfg['secret'], $f['ua'], $bind, $bits, $p['time'], $answer);
	gv_captcha_render($nonce, $cfg['strings'], $bits, $png, $p);
}

// One CAPTCHA page counted against the per-IP budget outside the counters pipeline (the "CAPTCHA instead of a device 429"
// path only: one extra command, on a response that is a CAPTCHA page anyway).
function gv_captcha_count_page(array $cfg, array $f, $log) {
	$conn = gv_redis_connect($cfg['redis'], $log);
	if (gv_redis_alive($conn)) { gv_bump($conn, gv_key('cpi:' . $f['ipn']), (int)$cfg['captcha']['ip_window']); }
	gv_redis_close($conn);
}

// The answer POST of the CAPTCHA page. Always ends the request (exit). Order, cheapest first, nothing that needs
// Redis before the stateless checks have passed:
//   signature / binding / expiry  ->  proof of work  ->  the answer  ->  ONE Redis pipeline (attempt counter, the
//   single-use claim of a correct answer, the usual counters)  ->  token (level c) or a refusal.
// Statuses: 204 token issued, 422 wrong answer (attempts left), 410 expired, 403 refused, 429 minting limit.
// Log rows reuse the handshake actions (token_issued, nonce_bad, pow_bad, nonce_replay) and carry cap =
// ok | wrong | fail | exp | inv, plus ct (seconds to solve) and the headless score.
function gv_captcha_handshake(array $cfg, array $f, array $st, $t0, $log) {
	$secret = $cfg['secret'];
	$bind = !empty($cfg['challenge']['bind_ip']) ? $f['ip'] : '';
	$sigs = gv_headless_parse($f['xgs']);
	if ($sigs) {
		$r = gv_headless_score($sigs, gv_headless_weights($cfg), $f['ua'], 700);
		$st['hs'] = $r[0];
		$st['hf'] = $r[1];
	}
	$reply = function ($code, $act, $cap, $sh = 0) use (&$st, $f, $t0, $log) {
		$st['cap'] = $cap;
		gv_emit($f, $st, $act, $sh, $t0, $log);
		if (!headers_sent()) { http_response_code($code); }
		exit;
	};
	$state = gv_captcha_nonce_state($f['xgv'], $secret, $f['ua'], $bind);
	if ($state === 'bad') { $reply(403, 'nonce_bad', 'inv'); }
	if ($state === 'exp') { $reply(410, 'nonce_bad', 'exp'); }
	$p = gv_captcha_nonce_parse($f['xgv']);
	if ($p[2] > 0 && !gv_pow_ok($f['xgv'], $f['xgvp'], $p[2])) { $reply(403, 'pow_bad', 'inv'); }
	$correct = gv_captcha_answer_ok($f['xgv'], $secret, rawurldecode($f['xga']));
	$max = max(1, (int)$cfg['captcha']['max_attempts']);
	$window = $cfg['limits']['window'];

	$conn = gv_redis_connect($cfg['redis'], $log);
	$extra = array(array('GET', gv_key('allow:' . $f['ip'])));
	if ($correct) {
		// Single use: the claim outlives the nonce by a margin (a node whose clock runs ahead must not reopen the replay).
		$extra[] = array('SET', gv_key('nonce:' . $p[1]), '1', 'EX', (string)($p[3] + 60), 'NX');
	}
	$items = array(
		array(gv_key('riu:' . md5($f['ipn'] . '|' . substr(md5((string)$f['ua']), 0, 12))), $window),
		array(gv_key('ri:' . $f['ipn']), $window),
		array(gv_key('ca:' . $p[1]), $p[3] + 60),                 // attempts at THIS nonce: every answer counts
	);
	$mint_at = -1;
	if ($correct) { $mint_at = count($items); $items[] = array(gv_key('mint:' . $f['ipn']), $window); }
	$counts = gv_bump_many($conn, $items, $extra, $reads);
	$st['ciu'] = $counts[0];
	$st['ci'] = $counts[1];
	$tries = $counts[2];
	$allowed_ip = ($reads[0] === '1');
	$replay = ($correct && $reads[1] === null);
	$mint_n = ($mint_at >= 0) ? $counts[$mint_at] : 0;
	$mint_refused = ($mint_n > (int)$cfg['limits']['mint']) && !$allowed_ip && !empty($cfg['enforce']['ratelimit']);
	if ($mint_at >= 0 && ($replay || $mint_refused || $tries > $max) && gv_redis_alive($conn)) {
		gv_redis_cmd($conn, array('DECR', gv_key('mint:' . $f['ipn'])));
	}
	gv_finish($conn, $st);

	if (!$correct) {
		// Out of attempts: the nonce is dead (the next POST, right or wrong, is refused above), a new image is needed.
		if ($tries >= $max) { $reply(403, 'nonce_bad', 'fail'); }
		$reply(422, 'nonce_bad', 'wrong');
	}
	if ($replay) { $reply(403, 'nonce_replay', 'fail'); }
	if ($tries > $max) { $reply(403, 'nonce_bad', 'fail'); }
	if ($mint_refused) {
		$st['cap'] = 'ok';
		gv_emit($f, $st, 'mint_limited', 0, $t0, $log);
		gv_send_429();
		exit;
	}
	$token = gv_tok_make($secret, $p[1], 'c');
	$parsed = gv_tok_parse($token, $secret, $cfg['token_ttl']);
	gv_set_token_cookie($cfg, $token, $f['https']);
	gv_capflag_cookie($cfg, '', time() - 3600, $f['https']);             // the escalation flag has done its job
	if ($f['testck'] !== '') { gv_test_cookie($cfg, '', time() - 3600, $f['https']); }
	$st['tok'] = 'v';
	$st['dev'] = ($parsed === false) ? '' : $parsed[0];
	$st['tl'] = 'c';
	$st['ct'] = max(0, time() - $p[0]);
	$reply(204, 'token_issued', 'ok');
}
