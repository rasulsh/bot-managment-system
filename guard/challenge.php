<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// Token, nonce and the JavaScript challenge page.
//
// Both the token and the nonce are stateless: they carry their own timestamp
// and an HMAC over it, so no storage is needed and the handshake works
// identically with or without Redis. The token is deliberately NOT bound to
// the client IP - CGNAT and mobile carrier rotation would re-challenge real
// users on every network change.

// Issue a token: device_id . issued_at . signature.
function gv_tok_make($secret) {
	$p = bin2hex(random_bytes(12)) . '.' . time();          // device_id . issued_at
	return $p . '.' . hash_hmac('sha256', $p, $secret);
}

// Verify a token. Returns the device id on success, false otherwise.
function gv_tok_check($t, $secret, $ttl) {
	$x = explode('.', (string)$t);
	if (count($x) !== 3) return false;
	if (!hash_equals(hash_hmac('sha256', $x[0] . '.' . $x[1], $secret), $x[2])) return false;
	if ((time() - (int)$x[1]) >= $ttl) return false;
	return $x[0];                                            // device_id
}

// Issue a nonce: issued_at . random . signature.
function gv_nonce_make($secret) {
	$p = time() . '.' . bin2hex(random_bytes(8));
	return $p . '.' . hash_hmac('sha256', $p, $secret);
}

// Verify a nonce. A replay inside nonce_ttl only re-issues a token; accepted.
//
// TODO(#11): the nonce is deliberately stateless so the handshake still works
// with Redis down, and at the point it is checked (gv_run step 2) Redis is not
// yet open (step 4), so it is not single-use. A client that parses the page and
// issues one POST can mint a token; the defense against automated minting is the
// per-IP rate limit (gv:ri:{ip}), not the nonce. Making it single-use needs a
// Redis-aware handshake (open Redis earlier or reorder), a scoped change left
// for a future iteration rather than bolted on here.
function gv_nonce_check($n, $secret, $ttl) {
	$x = explode('.', (string)$n);
	if (count($x) !== 3) return false;
	if (!hash_equals(hash_hmac('sha256', $x[0] . '.' . $x[1], $secret), $x[2])) return false;
	if ((time() - (int)$x[0]) >= $ttl) return false;
	return true;
}

// Send the token cookie. Secure is set only on HTTPS so the handshake still
// completes on plain-HTTP staging hosts.
function gv_set_token_cookie(array $cfg, $token, $https) {
	if (headers_sent()) { return; }
	setcookie((string)$cfg['cookie_name'], (string)$token, array(
		'expires'  => time() + (int)$cfg['token_ttl'],
		'path'     => '/',
		'secure'   => (bool)$https,
		'httponly' => true,
		'samesite' => 'Lax',
	));
}

// Render the interstitial. Single inline document, no external assets.
function gv_challenge_render($nonce, array $strings) {
	$nonce = preg_replace('/[^0-9a-f.]/', '', (string)$nonce);   // defensive
	$lang  = htmlspecialchars(isset($strings['lang']) ? (string)$strings['lang'] : 'en', ENT_QUOTES, 'UTF-8');
	$dir   = htmlspecialchars(isset($strings['dir']) ? (string)$strings['dir'] : 'ltr', ENT_QUOTES, 'UTF-8');
	$title = htmlspecialchars(isset($strings['title']) ? (string)$strings['title'] : '', ENT_QUOTES, 'UTF-8');
	$sub   = htmlspecialchars(isset($strings['sub']) ? (string)$strings['sub'] : '', ENT_QUOTES, 'UTF-8');
	$nos   = htmlspecialchars(isset($strings['noscript']) ? (string)$strings['noscript'] : '', ENT_QUOTES, 'UTF-8');

	if (!headers_sent()) {
		http_response_code(503);
		header('Retry-After: 3');
		header('Content-Type: text/html; charset=utf-8');
		header('Cache-Control: no-store');
		header('X-Robots-Tag: noindex');
	}

	echo "<!doctype html>\n";
	echo '<html lang="' . $lang . '" dir="' . $dir . "\">\n";
	echo "<head>\n";
	echo "<meta charset=\"utf-8\">\n";
	echo "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n";
	echo "<meta name=\"robots\" content=\"noindex,nofollow\">\n";
	echo '<title>' . $title . "</title>\n";
	echo "<style>\n";
	echo "html,body{height:100%;margin:0}\n";
	echo "body{display:flex;align-items:center;justify-content:center;background:#f6f7f9;color:#1c1e21;"
		. "font:16px/1.7 system-ui,-apple-system,Segoe UI,Tahoma,Arial,sans-serif}\n";
	echo ".gv{max-width:32rem;padding:2rem;text-align:center}\n";
	echo ".gv h1{margin:0 0 .6rem;font-size:1.25rem;font-weight:600}\n";
	echo ".gv p{margin:0;color:#5a5f66}\n";
	echo ".gv .n{margin-top:1rem;font-size:.9rem;color:#8a8f96}\n";
	echo "</style>\n";
	echo "</head>\n";
	echo "<body>\n";
	echo "<div class=\"gv\">\n";
	echo '<h1>' . $title . "</h1>\n";
	echo '<p>' . $sub . "</p>\n";
	echo '<noscript><p class="n">' . $nos . "</p></noscript>\n";
	echo "</div>\n";
	echo "<script>\n";
	echo "setTimeout(function () {\n";
	echo "\tfetch(location.href, {\n";
	echo "\t\tmethod: 'POST',\n";
	echo "\t\theaders: {'X-GV': '" . $nonce . "'},\n";
	echo "\t\tcredentials: 'same-origin'\n";
	echo "\t}).then(function (r) { if (r.status === 204) { location.reload(); } });\n";
	echo "}, 400);\n";
	echo "</script>\n";
	echo "</body>\n";
	echo "</html>\n";
}
