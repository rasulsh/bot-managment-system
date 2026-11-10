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

// --------------------------------------------------------------------------
// Nonce, proof of work and the handshake
//
// What this does and does not stop (also in docs/):
//   * The nonce is bound to the User-Agent and (optionally) the client IP it was
//     issued to, so it cannot be fed to a different client.
//   * It is SINGLE USE: gv_run claims its id in Redis (SET NX), so one nonce
//     yields one token. With Redis down the handshake stays open (fail-open) and
//     only binding, expiry and proof of work apply.
//   * The client must find a counter with SHA-256(nonce:counter) below a
//     difficulty carried in the signed nonce, so a token costs real client-side
//     computation and cannot be minted by curl plus a regex.
//   * Minting is metered per IP (limits.mint) like every other request.
// A JavaScript challenge cannot stop a real headless browser, and a token can
// still be shared between machines (bounded by the per-device rate limit).
// The goal is: no replay, no cross-client reuse, a cost per token, and a hard
// cap on tokens per address - nothing more.
// --------------------------------------------------------------------------

// What a nonce is bound to: the UA, plus the client IP when bind_ip is on.
// The page load and its POST are ~400 ms apart, so binding the NONCE to the IP
// is safe even though the TOKEN deliberately is not.
function gv_nonce_bind($ua, $ip) {
	return substr(hash('sha256', (string)$ua . "\n" . (string)$ip), 0, 32);
}

// Issue a nonce: issued_at . random . difficulty_bits . signature.
// The signature covers the binding but the binding itself is not transmitted:
// the verifier recomputes it from the request, so a mismatch fails the HMAC.
function gv_nonce_make($secret, $ua = '', $ip = '', $bits = 0) {
	$bits = max(0, min(24, (int)$bits));
	$p = time() . '.' . bin2hex(random_bytes(8)) . '.' . $bits;
	return $p . '.' . hash_hmac('sha256', $p . '|' . gv_nonce_bind($ua, $ip), $secret);
}

// Split a well-formed nonce into array(id, bits), or false. Does not verify.
function gv_nonce_parse($n) {
	$x = explode('.', (string)$n);
	if (count($x) !== 4) return false;
	if (!ctype_digit($x[0]) || !preg_match('/^[0-9a-f]{16}$/', $x[1]) || !ctype_digit($x[2])) return false;
	$bits = (int)$x[2];
	if ($bits > 24) return false;
	return array($x[1], $bits);
}

// Verify signature, binding and age. Returns true/false. Replay protection and
// proof of work are separate steps (gv_run), because they need Redis / the
// counter header.
function gv_nonce_check($n, $secret, $ttl, $ua = '', $ip = '') {
	if (gv_nonce_parse($n) === false) return false;
	$x = explode('.', (string)$n);
	$p = $x[0] . '.' . $x[1] . '.' . $x[2];
	if (!hash_equals(hash_hmac('sha256', $p . '|' . gv_nonce_bind($ua, $ip), $secret), $x[3])) return false;
	if ((time() - (int)$x[0]) >= $ttl) return false;
	return true;
}

// Proof of work: SHA-256(nonce ":" counter) must start with $bits zero bits.
// One hash to verify. The nonce (signature included) is in the preimage, so a
// solved counter is worthless for any other nonce.
function gv_pow_ok($nonce, $counter, $bits) {
	$bits = (int)$bits;
	if ($bits <= 0) return true;
	if (!is_string($counter) || !preg_match('/^[0-9]{1,12}$/', $counter)) return false;
	$h = hash('sha256', (string)$nonce . ':' . $counter, true);
	$full = intdiv($bits, 8);
	for ($i = 0; $i < $full; $i++) {
		if ($h[$i] !== "\0") return false;
	}
	$rem = $bits % 8;
	if ($rem > 0 && (ord($h[$full]) >> (8 - $rem)) !== 0) return false;
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

// The inline solver: a small self-contained SHA-256 (no external asset, and no
// crypto.subtle, which does not exist on plain-HTTP origins) plus the handshake.
// The nonce prefix is hashed once (midstate); each attempt costs one compression
// in the common case. It searches in ~30 ms slices so the page stays responsive.
// Retry policy: a rejected handshake reloads the page for a fresh challenge, at
// most MAX times (counted in sessionStorage, window.name as a fallback, no
// cookies), then shows the localized failure text with a manual retry link.
function gv_challenge_js() {
	return <<<'JS'
(function () {
var N = '__N__', B = __B__, MAX = 2, SK = 'gv_r';
var K = new Uint32Array([
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
var W = new Uint32Array(64);
function compress(S, o) {
	var a = S[0], b = S[1], c = S[2], d = S[3], e = S[4], f = S[5], g = S[6], h = S[7], i, t1, t2, x, y;
	for (i = 16; i < 64; i++) {
		x = W[i - 15]; y = W[i - 2];
		W[i] = (((y >>> 17 | y << 15) ^ (y >>> 19 | y << 13) ^ (y >>> 10)) + W[i - 7] +
			((x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ (x >>> 3)) + W[i - 16]) | 0;
	}
	for (i = 0; i < 64; i++) {
		t1 = (h + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + ((e & f) ^ (~e & g)) + K[i] + W[i]) | 0;
		t2 = (((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
		h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
	}
	o[0] = (S[0] + a) | 0; o[1] = (S[1] + b) | 0; o[2] = (S[2] + c) | 0; o[3] = (S[3] + d) | 0;
	o[4] = (S[4] + e) | 0; o[5] = (S[5] + f) | 0; o[6] = (S[6] + g) | 0; o[7] = (S[7] + h) | 0;
}
function loadBlock(buf, off) {
	for (var i = 0; i < 16; i++) {
		var j = off + i * 4;
		W[i] = (buf[j] << 24) | (buf[j + 1] << 16) | (buf[j + 2] << 8) | buf[j + 3];
	}
}
var pre = N + ':', L = pre.length, mid = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
var pb = new Uint8Array(L), i0;
for (i0 = 0; i0 < L; i0++) { pb[i0] = pre.charCodeAt(i0) & 255; }
var nfull = Math.floor(L / 64), r = L - nfull * 64;
for (i0 = 0; i0 < nfull; i0++) { loadBlock(pb, i0 * 64); compress(mid, mid); }
var buf = new Uint8Array(128), st = new Uint32Array(8);
for (i0 = 0; i0 < r; i0++) { buf[i0] = pb[nfull * 64 + i0]; }
function test(c) {
	var ds = String(c), n = ds.length, tl = r + n, nb = (tl + 9 <= 64) ? 1 : 2, end = nb * 64, i;
	for (i = 0; i < n; i++) { buf[r + i] = ds.charCodeAt(i); }
	buf[tl] = 128;
	for (i = tl + 1; i < end - 8; i++) { buf[i] = 0; }
	var bits = (L + n) * 8;
	buf[end - 8] = 0; buf[end - 7] = 0; buf[end - 6] = 0; buf[end - 5] = 0;
	buf[end - 4] = (bits >>> 24) & 255; buf[end - 3] = (bits >>> 16) & 255; buf[end - 2] = (bits >>> 8) & 255; buf[end - 1] = bits & 255;
	loadBlock(buf, 0); compress(mid, st);
	if (nb === 2) { loadBlock(buf, 64); compress(st, st); }
	return (st[0] >>> (32 - B)) === 0;
}
function solve(done) {
	var c = 0;
	(function step() {
		var until = Date.now() + 30, k;
		do {
			for (k = 0; k < 256; k++, c++) { if (test(c)) { done(c); return; } }
		} while (Date.now() < until);
		setTimeout(step, 0);
	})();
}
function sget() { try { return sessionStorage.getItem(SK); } catch (e) { return window.name.indexOf(SK + '=') === 0 ? window.name.slice(SK.length + 1) : null; } }
function sset(v) { try { sessionStorage.setItem(SK, v); } catch (e) { try { window.name = SK + '=' + v; } catch (e2) {} } }
// State "failures:successes:timestamp", forgotten after a minute. failures: refused
// handshakes reloaded so far. successes: handshakes that returned 204 but still
// brought us back to a challenge - the browser is not keeping the token cookie.
function gst() { var v = sget(), p = v ? v.split(':') : [], t = +p[2] || 0; return (Date.now() - t > 60000) ? [0, 0] : [+p[0] || 0, +p[1] || 0]; }
function gput(f, s) { sset(f + ':' + s + ':' + Date.now()); }
function show(id) {
	document.getElementById('gv-wait').hidden = true;
	document.getElementById(id).hidden = false;
}
function retry() {
	var s = gst();
	if (s[0] < MAX) { gput(s[0] + 1, s[1]); location.reload(); } else { show('gv-fail'); }
}
document.getElementById('gv-retry').onclick = function (ev) { ev.preventDefault(); sset('0:0:0'); location.reload(); };
document.getElementById('gv-retry2').onclick = document.getElementById('gv-retry').onclick;
function post(counter) {
	var h = {'X-GV': N};
	if (B > 0) { h['X-GV-P'] = String(counter); }
	fetch(location.href, {method: 'POST', headers: h, credentials: 'same-origin'})
		.then(function (r) { if (r.status === 204) { var s = gst(); gput(s[0], s[1] + 1); location.reload(); } else { retry(); } })
		.catch(retry);
}
// Back on a challenge right after a successful handshake: the cookie was not kept.
// Say so instead of minting a token on every cycle.
if (gst()[1] >= 1) { show('gv-cookie'); return; }
setTimeout(function () { if (B > 0) { solve(post); } else { post(0); } }, 50);
})();
JS;
}

// Render the interstitial. Single inline document, no external assets.
function gv_challenge_render($nonce, array $strings, $bits = 0) {
	$nonce = preg_replace('/[^0-9a-f.]/', '', (string)$nonce);   // defensive
	$bits  = max(0, min(24, (int)$bits));
	$lang  = htmlspecialchars(isset($strings['lang']) ? (string)$strings['lang'] : 'en', ENT_QUOTES, 'UTF-8');
	$dir   = htmlspecialchars(isset($strings['dir']) ? (string)$strings['dir'] : 'ltr', ENT_QUOTES, 'UTF-8');
	$title = htmlspecialchars(isset($strings['title']) ? (string)$strings['title'] : '', ENT_QUOTES, 'UTF-8');
	$sub   = htmlspecialchars(isset($strings['sub']) ? (string)$strings['sub'] : '', ENT_QUOTES, 'UTF-8');
	$nos   = htmlspecialchars(isset($strings['noscript']) ? (string)$strings['noscript'] : '', ENT_QUOTES, 'UTF-8');
	$fail  = htmlspecialchars(isset($strings['failed']) ? (string)$strings['failed'] : '', ENT_QUOTES, 'UTF-8');
	$nock  = htmlspecialchars(isset($strings['nocookie']) ? (string)$strings['nocookie'] : '', ENT_QUOTES, 'UTF-8');
	$retry = htmlspecialchars(isset($strings['retry']) ? (string)$strings['retry'] : '', ENT_QUOTES, 'UTF-8');

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
	echo "[hidden]{display:none!important}\n";
	echo "body{display:flex;align-items:center;justify-content:center;background:#f6f7f9;color:#1c1e21;"
		. "font:16px/1.7 system-ui,-apple-system,Segoe UI,Tahoma,Arial,sans-serif}\n";
	echo ".gv{max-width:32rem;padding:2rem;text-align:center}\n";
	echo ".gv h1{margin:0 0 .6rem;font-size:1.25rem;font-weight:600}\n";
	echo ".gv p{margin:0;color:#5a5f66}\n";
	echo ".gv .n{margin-top:1rem;font-size:.9rem;color:#8a8f96}\n";
	echo ".gv a{color:#1a56db}\n";
	echo "</style>\n";
	echo "</head>\n";
	echo "<body>\n";
	echo "<div class=\"gv\">\n";
	echo '<h1>' . $title . "</h1>\n";
	echo '<p id="gv-wait">' . $sub . "</p>\n";
	echo '<p id="gv-fail" hidden>' . $fail . ' <a id="gv-retry" href="">' . $retry . "</a></p>\n";
	echo '<p id="gv-cookie" hidden>' . $nock . ' <a id="gv-retry2" href="">' . $retry . "</a></p>\n";
	echo '<noscript><p class="n">' . $nos . "</p></noscript>\n";
	echo "</div>\n";
	echo "<script>\n";
	echo str_replace(array('__N__', '__B__'), array($nonce, (string)$bits), gv_challenge_js()) . "\n";
	echo "</script>\n";
	echo "</body>\n";
	echo "</html>\n";
}
