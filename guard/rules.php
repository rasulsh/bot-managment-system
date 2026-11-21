<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// Access rules: one small engine for "block / challenge / log this client".
//
// guard/rules.json is written ONLY by the panel (temp file + rename) and read
// here on every request. The validation lives in this file and is the one the
// panel calls on write, exactly like gv_overlay_validate() for the config
// overlay: what the panel accepts is what the guard accepts, permanently.
//
// Evaluation is a pure function of the request facts: no Redis, no DNS, no
// file write. Anything unexpected (a bad file, a PCRE error) means "no match",
// plus one rate-limited line in guard-errors.log. A rule can never cause a 500.
//
// A rule has up to four conditions: UA, path, country, ASN (the last two read
// the compiled GeoIP files, see geo.php). All non-null conditions are AND-ed; a
// rule without any condition is invalid. First matching rule by priority wins.

define('GV_RULES_MAX', 200);
define('GV_RULES_MAX_VALUES', 50);
define('GV_RULES_MAX_VALUE_LEN', 300);
define('GV_RULES_MAX_MATCH_US', 1000);     // a regex that takes longer than this on one match is refused on save
define('GV_RULES_MAX_BYTES', 2097152);      // a larger file is ignored as a whole
define('GV_RULE_EMPTY', '<empty>');         // UA value meaning "missing or blank"

function gv_rules_path() {
	// GV_RULES lets the test harness swap the file, like GV_CONFIG.
	$env = getenv('GV_RULES');
	if (is_string($env) && $env !== '') { return $env; }
	return __DIR__ . '/rules.json';
}

function gv_rule_actions() { return array('block', 'challenge', 'log'); }
function gv_rule_ua_types() { return array('exact', 'contains', 'prefix', 'regex'); }

// Delimiter for every pattern built here. A control character cannot occur in
// a validated value, so no value can ever close the pattern early.
function gv_rule_delim() { return "\x01"; }

// Validate one condition. $types is the list of allowed "type" values.
// Returns array(true, normalised) or array(false, code, detail).
function gv_rule_cond_validate($cond, array $types, $deep) {
	if (!is_array($cond) || !gv_is_assoc($cond)) { return array(false, 'bad_condition', ''); }
	$op = isset($cond['op']) ? $cond['op'] : '';
	if ($op !== 'include' && $op !== 'exclude') { return array(false, 'bad_op', ''); }
	$type = isset($cond['type']) ? $cond['type'] : '';
	if (!is_string($type) || !in_array($type, $types, true)) { return array(false, 'bad_type', ''); }
	$values = isset($cond['values']) ? $cond['values'] : null;
	if (!is_array($values) || gv_is_assoc($values)) { return array(false, 'not_list', ''); }
	if (!$values) { return array(false, 'no_values', ''); }
	if (count($values) > GV_RULES_MAX_VALUES) { return array(false, 'too_many', ''); }
	$out = array();
	foreach ($values as $i => $v) {
		if (!is_string($v) || $v === '') { return array(false, 'not_string', ''); }
		if (strlen($v) > GV_RULES_MAX_VALUE_LEN) { return array(false, 'too_long', ''); }
		if (!preg_match('//u', $v)) { return array(false, 'not_utf8', ''); }
		if (preg_match('/[\x00-\x1F\x7F]/', $v)) { return array(false, 'control_chars', ''); }
		if (!in_array($v, $out, true)) { $out[] = $v; }
	}
	return array(true, array('op' => $op, 'type' => $type, 'values' => $out));
}

// A path condition: prefixes of the raw path, each starting with a slash.
function gv_rule_path_validate($cond, $deep) {
	$r = gv_rule_cond_validate($cond, array('prefix'), $deep);
	if (!$r[0]) { return $r; }
	foreach ($r[1]['values'] as $v) {
		if ($v[0] !== '/') { return array(false, 'must_start_slash', ''); }
	}
	return $r;
}

// Samples of current real browsers: a rule that matches any of these would
// lock real visitors out. Kept short and current; extend it, do not trust it.
function gv_rules_browser_samples() {
	return array(
		'Chrome (Windows)' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
		'Chrome (macOS)' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
		'Chrome (Linux)' => 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
		'Chrome (Android)' => 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36',
		'Firefox (Windows)' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
		'Firefox (Android)' => 'Mozilla/5.0 (Android 14; Mobile; rv:132.0) Gecko/132.0 Firefox/132.0',
		'Safari (macOS)' => 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15',
		'Safari (iPhone)' => 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1',
		'Edge (Windows)' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0',
		'Samsung Internet' => 'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-S921B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/26.0 Chrome/122.0.0.0 Mobile Safari/537.36',
	);
}

// Country condition: ISO 3166 alpha-2 codes, upper case. The panel normalises
// what the operator types; this is the strict check on what is stored.
function gv_rule_country_validate($cond, $deep) {
	$r = gv_rule_cond_validate($cond, array('code'), $deep);
	if (!$r[0]) { return $r; }
	foreach ($r[1]['values'] as $i => $v) {
		if (!preg_match('/^[A-Z]{2}$/', $v)) { return array(false, 'bad_country', 'value ' . ($i + 1)); }
	}
	return $r;
}

// ASN condition: AS numbers as decimal strings, 1 .. 4294967295 (no "AS" prefix).
function gv_rule_asn_validate($cond, $deep) {
	$r = gv_rule_cond_validate($cond, array('number'), $deep);
	if (!$r[0]) { return $r; }
	foreach ($r[1]['values'] as $i => $v) {
		if (!preg_match('/^[1-9][0-9]{0,9}$/', $v) || (int)$v > 4294967295) { return array(false, 'bad_asn', 'value ' . ($i + 1)); }
	}
	return $r;
}

// A UA condition. $deep adds the checks that cost something (compiling and
// stress-testing every regex); the panel passes true on save, the guard passes
// false on every request because the file was already checked when written.
function gv_rule_ua_validate($cond, $deep) {
	$r = gv_rule_cond_validate($cond, gv_rule_ua_types(), $deep);
	if (!$r[0]) { return $r; }
	if ($r[1]['type'] !== 'regex' || !$deep) { return $r; }
	$d = gv_rule_delim();
	$sample = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';
	// Strings built to expose catastrophic backtracking in a pattern.
	$stress = array(str_repeat('a', 4000) . '!', str_repeat('a b ', 1000) . '!', str_repeat('(', 500));
	// What the pattern costs on the strings it will really meet.
	$timed = array_merge($stress, array_slice(array_values(gv_rules_browser_samples()), 0, 4));
	foreach ($r[1]['values'] as $i => $v) {
		if ($v === GV_RULE_EMPTY) { continue; }
		if (strlen($v) > 300) { return array(false, 'too_long', ''); }
		// Backreferences break when values are joined into one alternation.
		if (preg_match('/\\\\[1-9k]/', $v)) {
			return array(false, 'regex_backref', 'value ' . ($i + 1));
		}
		$pat = $d . '(?:' . $v . ')' . $d . 'i';
		$res = @preg_match($pat, $sample);
		if ($res === false) {
			$e = error_get_last();
			$msg = $e ? preg_replace('/^preg_match\(\): /', '', (string)$e['message']) : preg_last_error_msg();
			return array(false, 'bad_regex', 'value ' . ($i + 1) . ': ' . $msg);
		}
		$worst = 0.0;
		foreach ($timed as $s) {
			@preg_match($pat, $s);                       // first run compiles; time the second and third
			if (preg_last_error() !== PREG_NO_ERROR) {
				return array(false, 'regex_costly', 'value ' . ($i + 1) . ': ' . preg_last_error_msg());
			}
			$best = null;
			for ($k = 0; $k < 2; $k++) {
				$t = hrtime(true);
				@preg_match($pat, $s);
				$us = (hrtime(true) - $t) / 1000;
				if ($best === null || $us < $best) { $best = $us; }
			}
			if ($best > $worst) { $worst = $best; }
		}
		// One match must stay under 1 ms (the best of two runs, so a hiccup on a busy
		// machine does not refuse a harmless pattern).
		if ($worst > GV_RULES_MAX_MATCH_US) {
			return array(false, 'regex_slow', 'value ' . ($i + 1) . ': one match took ' . sprintf('%.1f', $worst / 1000) . ' ms (limit 1 ms)');
		}
	}
	$joined = gv_rule_ua_compile($r[1]);
	if ($joined[0] !== '' && @preg_match($joined[0], $sample) === false) {
		return array(false, 'regex_join', preg_last_error_msg());
	}
	return $r;
}

function gv_rule_int($v, $min, $max) {
	return is_int($v) && !is_bool($v) && $v >= $min && $v <= $max;
}

// Validate one rule. Returns array(true, normalised rule) or
// array(false, array(field => code), array(field => detail)).
function gv_rule_validate($rule, $deep = false) {
	$err = array();
	$det = array();
	if (!is_array($rule) || !gv_is_assoc($rule)) { return array(false, array('_rule' => 'not_object'), array()); }
	$out = array();

	$id = isset($rule['id']) ? $rule['id'] : '';
	if (!is_string($id) || !preg_match('/^[a-z0-9][a-z0-9-]{2,15}$/', $id)) { $err['id'] = 'bad_id'; }
	$out['id'] = $id;

	$name = isset($rule['name']) ? $rule['name'] : '';
	$e = gv_overlay_text_ok($name, 80);
	if ($e === '' && trim($name) === '') { $e = 'empty'; }
	if ($e !== '') { $err['name'] = $e; }
	$out['name'] = is_string($name) ? $name : '';

	foreach (array('enabled' => true, 'skip_verified_bots' => true) as $k => $default) {
		$v = array_key_exists($k, $rule) ? $rule[$k] : $default;
		if (!is_bool($v)) { $err[$k] = 'not_bool'; $v = $default; }
		$out[$k] = $v;
	}
	$mode = isset($rule['mode']) ? $rule['mode'] : '';
	if ($mode !== 'enforce' && $mode !== 'monitor') { $err['mode'] = 'not_allowed'; }
	$out['mode'] = $mode;
	$action = isset($rule['action']) ? $rule['action'] : '';
	if (!is_string($action) || !in_array($action, gv_rule_actions(), true)) { $err['action'] = 'not_allowed'; }
	$out['action'] = $action;

	$pri = array_key_exists('priority', $rule) ? $rule['priority'] : 100;
	if (!gv_rule_int($pri, 1, 100000)) { $err['priority'] = 'out_of_range'; $pri = 100; }
	$out['priority'] = $pri;

	$conds = 0;
	foreach (array('ua', 'path', 'country', 'asn') as $k) {
		$c = array_key_exists($k, $rule) ? $rule[$k] : null;
		if ($c === null) { $out[$k] = null; continue; }
		if ($k === 'ua') { $r = gv_rule_ua_validate($c, $deep); }
		elseif ($k === 'path') { $r = gv_rule_path_validate($c, $deep); }
		elseif ($k === 'country') { $r = gv_rule_country_validate($c, $deep); }
		else { $r = gv_rule_asn_validate($c, $deep); }
		if ($r[0]) {
			$out[$k] = $r[1];
			$conds++;
		} else {
			$err[$k] = $r[1];
			if ($r[2] !== '') { $det[$k] = $r[2]; }
			$out[$k] = null;
		}
	}
	if ($conds === 0 && !$err) { $err['ua'] = 'no_condition'; }

	$exp = array_key_exists('expires_at', $rule) ? $rule['expires_at'] : 0;
	if (!gv_rule_int($exp, 0, 4102444800)) { $err['expires_at'] = 'out_of_range'; $exp = 0; }
	$out['expires_at'] = $exp;
	$bits = array_key_exists('pow_bits', $rule) ? $rule['pow_bits'] : 0;
	if (!gv_rule_int($bits, 0, 22) || ($bits !== 0 && $bits < 12)) { $err['pow_bits'] = 'out_of_range'; $bits = 0; }
	$out['pow_bits'] = $bits;

	foreach (array('note' => 300, 'created_by' => 64) as $k => $max) {
		$v = array_key_exists($k, $rule) ? $rule[$k] : '';
		$e = gv_overlay_text_ok($v, $max);
		if ($e !== '') { $err[$k] = $e; $v = ''; }
		$out[$k] = $v;
	}
	foreach (array('created_at', 'updated_at') as $k) {
		$v = array_key_exists($k, $rule) ? $rule[$k] : 0;
		if (!gv_rule_int($v, 0, 4102444800)) { $err[$k] = 'out_of_range'; $v = 0; }
		$out[$k] = $v;
	}
	if ($err) { return array(false, $err, $det); }
	return array(true, $out);
}

// Validate a whole list (what the panel writes). Returns array(true, rules) or
// array(false, array(index => array(field => code))). Ids must be unique.
function gv_rules_validate_list($list, $deep = true) {
	if (!is_array($list) || ($list && gv_is_assoc($list))) { return array(false, array(-1 => array('_list' => 'not_list'))); }
	if (count($list) > GV_RULES_MAX) { return array(false, array(-1 => array('_list' => 'too_many'))); }
	$out = array();
	$errors = array();
	$seen = array();
	foreach ($list as $i => $rule) {
		$r = gv_rule_validate($rule, $deep);
		if (!$r[0]) { $errors[$i] = $r[1]; continue; }
		if (isset($seen[$r[1]['id']])) { $errors[$i] = array('id' => 'duplicate_id'); continue; }
		$seen[$r[1]['id']] = true;
		$out[] = $r[1];
	}
	if ($errors) { return array(false, $errors); }
	return array(true, $out);
}

// The file the panel writes: {"v":1,"crc":"<crc32>","rules":[...]} in compact
// JSON. The checksum covers the rules text exactly as written and says "the
// panel validated this and nothing changed it since". A file with a good
// checksum is used as it is; anything else (hand-edited, truncated, no stamp)
// goes through full validation rule by rule. The stamp only saves time, it is
// not a permission: an unstamped file works exactly the same, slower.
// Validating 200 rules costs more than everything else the guard does.
function gv_rules_encode(array $rules) {
	$body = json_encode(array_values($rules), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	if ($body === false) { return false; }
	return '{"v":1,"crc":"' . sprintf('%08x', crc32($body)) . '","rules":' . $body . "}\n";
}

// Read guard/rules.json: validated rules sorted by priority (stable, so equal
// priorities keep file order). Missing, empty, oversized, malformed: no rules.
// One invalid rule is dropped alone and reported, the others stay.
function gv_rules_read($path = null) {
	try {
		if ($path === null) { $path = gv_rules_path(); }
		if (!is_string($path) || $path === '' || !is_file($path)) { return array(); }
		$raw = @file_get_contents($path);
		if ($raw === false || $raw === '' || strlen($raw) > GV_RULES_MAX_BYTES) { return array(); }
		// Fast path: a file stamped by the panel (see gv_rules_encode).
		if (strncmp($raw, '{"v":1,"crc":"', 14) === 0 && substr($raw, 22, 10) === '","rules":') {
			$body = rtrim(substr($raw, 32));
			if (substr($body, -1) === '}') {
				$body = substr($body, 0, -1);
				if (substr($raw, 14, 8) === sprintf('%08x', crc32($body))) {
					$list = json_decode($body, true);
					if (is_array($list) && (!$list || !gv_is_assoc($list))) { return array_slice($list, 0, GV_RULES_MAX); }
				}
			}
		}
		$data = json_decode($raw, true);
		if (!is_array($data) || !isset($data['rules']) || !is_array($data['rules'])
			|| ($data['rules'] && gv_is_assoc($data['rules']))) { return array(); }
		$out = array();
		$seen = array();
		foreach (array_slice($data['rules'], 0, GV_RULES_MAX) as $rule) {
			$r = gv_rule_validate($rule, false);
			if (!$r[0] || isset($seen[$r[1]['id']])) {
				gv_errlog('rules_bad_rule', 'rule dropped: ' . (is_array($rule) && isset($rule['id']) && is_string($rule['id']) ? preg_replace('/[^a-z0-9-]/', '', $rule['id']) : '?'));
				continue;
			}
			$seen[$r[1]['id']] = true;
			$out[] = $r[1];
		}
		usort($out, function ($a, $b) { return $a['priority'] <=> $b['priority']; });
		return $out;
	} catch (\Throwable $e) {
		return array();
	}
}

// --------------------------------------------------------------------------
// The generated cache: guard/rules.cache.php
//
// guard/rules.json stays the source of truth. On every save the panel also
// writes guard/rules.cache.php, generated ONLY by var_export() from the
// validated list: enabled rules only, already sorted, each UA condition with its
// compiled pattern and blank flag, each country / ASN condition with its lookup set. It is a plain PHP array literal, so OPcache
// keeps it in shared memory and a request pays no file read, no JSON decode, no
// validation and no pattern building. With no enabled rule it returns an empty
// array and the guard does nothing more.
// --------------------------------------------------------------------------

function gv_rules_cache_path($json_path = null) {
	if ($json_path === null) { $json_path = gv_rules_path(); }
	return (substr($json_path, -5) === '.json' ? substr($json_path, 0, -5) : $json_path) . '.cache.php';
}

// The PHP source of the cache for a validated rule list. Pure.
function gv_rules_cache_source(array $rules) {
	usort($rules, function ($a, $b) { return $a['priority'] <=> $b['priority']; });
	$out = array();
	foreach ($rules as $r) {
		if (empty($r['enabled'])) { continue; }
		$slim = array('id' => $r['id'], 'enabled' => true, 'mode' => $r['mode'], 'action' => $r['action'],
			'priority' => $r['priority'], 'skip_verified_bots' => $r['skip_verified_bots'],
			'ua' => $r['ua'], 'path' => $r['path'], 'country' => $r['country'] ?? null, 'asn' => $r['asn'] ?? null,
			'expires_at' => $r['expires_at'], 'pow_bits' => $r['pow_bits']);
		// Country and ASN values become a lookup set: one isset() per request.
		foreach (array('country', 'asn') as $g) {
			if (is_array($slim[$g])) { $slim[$g]['set'] = gv_rule_geo_set($slim[$g]); }
		}
		if (is_array($slim['ua'])) {
			$c = gv_rule_ua_compile($slim['ua']);
			$slim['ua']['pat'] = $c[0];
			$slim['ua']['blank'] = $c[1];
		}
		$out[] = $slim;
	}
	return "<?php\nif (!defined('GV_BOOT')) { exit; }\n// Generated by the panel from guard/rules.json. Do not edit: it is overwritten on every save.\n"
		. 'return ' . var_export($out, true) . ";\n";
}

// The rules the request path uses: the cache when it is at least as new as
// rules.json, otherwise rules.json itself (one rate-limited note). A missing
// rules.json means no rules whatever the cache says: the JSON is the truth.
function gv_rules_load() {
	try {
		$json = gv_rules_path();
		$jm = @filemtime($json);
		if ($jm === false) { return array(); }
		$cache = gv_rules_cache_path($json);
		$cm = @filemtime($cache);
		if ($cm !== false && $cm >= $jm) {
			$r = include $cache;
			if (is_array($r)) { return $r; }
		}
		gv_errlog('rules_cache_stale', 'rules cache stale or missing, reading rules.json directly (save the rules in the panel to rebuild it)');
		return gv_rules_read($json);
	} catch (\Throwable $e) {
		return array();
	}
}

// One pattern per condition: every value of a rule's UA condition joined into a
// single alternation. Returns array(pattern, matches_blank). The token <empty>
// is not a pattern, it is the blank-UA flag. Cached for the request.
function gv_rule_ua_compile(array $cond) {
	// A cached rule (guard/rules.cache.php) carries its compiled pattern.
	if (isset($cond['pat']) && is_string($cond['pat'])) { return array($cond['pat'], !empty($cond['blank'])); }
	static $cache = array();
	$key = $cond['type'] . "\n" . implode("\n", $cond['values']);
	if (isset($cache[$key])) { return $cache[$key]; }
	$d = gv_rule_delim();
	$parts = array();
	$blank = false;
	foreach ($cond['values'] as $v) {
		if ($v === GV_RULE_EMPTY) { $blank = true; continue; }
		$parts[] = ($cond['type'] === 'regex') ? $v : preg_quote($v, $d);
	}
	$pat = '';
	if ($parts) {
		$alt = '(?:' . implode('|', $cond['type'] === 'regex' ? array_map(function ($p) { return '(?:' . $p . ')'; }, $parts) : $parts) . ')';
		if ($cond['type'] === 'exact')       { $pat = $d . '^' . $alt . '$' . $d . 'iD'; }
		elseif ($cond['type'] === 'prefix')  { $pat = $d . '^' . $alt . $d . 'i'; }
		else                                 { $pat = $d . $alt . $d . 'i'; }
	}
	if (count($cache) > 500) { $cache = array(); }
	return $cache[$key] = array($pat, $blank);
}

// Whether a UA condition holds for this User-Agent: true, false, or null when
// the pattern engine failed (an error is "unknown", which never matches).
function gv_rule_ua_eval(array $cond, $ua) {
	$c = gv_rule_ua_compile($cond);
	$ua = (string)$ua;
	$hit = ($c[1] && trim($ua) === '');
	if (!$hit && $c[0] !== '') {
		$r = @preg_match($c[0], $ua);
		if ($r === false) {
			gv_errlog('rules_pcre', 'pattern engine error: ' . preg_last_error_msg());
			return null;
		}
		$hit = ($r === 1);
	}
	return ($cond['op'] === 'include') ? $hit : !$hit;
}

function gv_rule_path_eval(array $cond, $path) {
	$path = (string)$path;
	$hit = false;
	foreach ($cond['values'] as $v) {
		if (strncmp($path, $v, strlen($v)) === 0) { $hit = true; break; }
	}
	return ($cond['op'] === 'include') ? $hit : !$hit;
}

// The values of a country / ASN condition as a lookup set (value => true). A
// cached rule carries it; a rule read from rules.json builds it once per request.
function gv_rule_geo_set(array $cond) {
	if (isset($cond['set']) && is_array($cond['set'])) { return $cond['set']; }
	$set = array();
	foreach ($cond['values'] as $v) { $set[$v] = true; }
	return $set;
}

// Whether a country ($kind 'cc') or ASN ('asn') condition holds. The fact comes
// from $f when the caller supplies it (the panel, from a log row), otherwise from
// the compiled GeoIP file by the client address (a lazy lookup: the file is only
// opened when a rule actually gets this far). An UNKNOWN country or ASN returns
// null for include AND exclude alike, which never matches: "block everyone except
// IR" must not block a client we could not place.
function gv_rule_geo_eval(array $cond, $kind, array $f) {
	if (isset($f[$kind])) { $v = $f[$kind]; }
	else { $ip = isset($f['ip']) ? $f['ip'] : ''; $v = ($kind === 'cc') ? gv_geo_country($ip) : gv_geo_asn($ip); }
	if ($v === '' || $v === 0 || $v === null) { return null; }
	$set = isset($cond['set']) ? $cond['set'] : gv_rule_geo_set($cond);
	$hit = isset($set[$v]);
	return ($cond['op'] === 'include') ? $hit : !$hit;
}

// Whether one rule matches these facts. Conditions are AND-ed; an unknown
// result (null) counts as no match.
function gv_rule_matches(array $rule, array $f) {
	if (isset($rule['ua']) && is_array($rule['ua'])) {
		if (gv_rule_ua_eval($rule['ua'], isset($f['ua']) ? $f['ua'] : '') !== true) { return false; }
	}
	if (isset($rule['path']) && is_array($rule['path'])) {
		if (gv_rule_path_eval($rule['path'], isset($f['path']) ? $f['path'] : '') !== true) { return false; }
	}
	if (isset($rule['country']) && is_array($rule['country']) && gv_rule_geo_eval($rule['country'], 'cc', $f) !== true) { return false; }
	if (isset($rule['asn']) && is_array($rule['asn']) && gv_rule_geo_eval($rule['asn'], 'asn', $f) !== true) { return false; }
	return true;
}

function gv_rule_live(array $rule, $now) {
	if (empty($rule['enabled'])) { return false; }
	return (int)$rule['expires_at'] === 0 || (int)$rule['expires_at'] > (int)$now;
}

// The first live rule (in priority order) that matches, or null. Pure.
// The hot loop of the request path: the liveness test is inlined on purpose.
function gv_rules_match(array $f, array $rules, $now) {
	$ua = isset($f['ua']) ? (string)$f['ua'] : '';
	foreach ($rules as $rule) {
		if (empty($rule['enabled'])) { continue; }
		if ($rule['expires_at'] !== 0 && (int)$rule['expires_at'] <= $now) { continue; }
		// Cheapest first: a path prefix, then the country / ASN set (one isset() after the
		// request's single file search), and the pattern match on the UA last. A rule that
		// combines them skips its regex for every client from another country.
		if (isset($rule['path']) && gv_rule_path_eval($rule['path'], isset($f['path']) ? $f['path'] : '') !== true) { continue; }
		if (isset($rule['country']) && gv_rule_geo_eval($rule['country'], 'cc', $f) !== true) { continue; }
		if (isset($rule['asn']) && gv_rule_geo_eval($rule['asn'], 'asn', $f) !== true) { continue; }
		if (isset($rule['ua']) && gv_rule_ua_eval($rule['ua'], $ua) !== true) { continue; }
		return $rule;
	}
	return null;
}

// Every live rule that matches, in priority order: for the panel's test box.
function gv_rules_match_all(array $f, array $rules, $now) {
	$out = array();
	foreach ($rules as $rule) {
		if (gv_rule_live($rule, $now) && gv_rule_matches($rule, $f)) { $out[] = $rule; }
	}
	return $out;
}

// The log reason for a matched rule: RULE:<id> when it acts, SH_RULE:<id> in monitor.
function gv_rule_reason(array $rule) {
	return (($rule['mode'] === 'enforce') ? 'RULE:' : 'SH_RULE:') . $rule['id'];
}

// Whether a rule is skipped because the client is a known bot (the caller has
// already matched known_bots). Returns '' (not skipped), 'verified' (verdict ok)
// or 'degraded'. Pure.
//
// 'degraded': Redis is unreachable, so no verdict could be read at all. The
// existing degraded-mode policy is that a known-bot UA keeps its pass during an
// outage (docs/06-KNOWN-LIMITS.md), so the claim counts as verified for this
// purpose. Only "no verdict because Redis is down" qualifies: a verdict that WAS
// read as 'bad' or absent while Redis is alive does not skip.
function gv_rule_bot_skip(array $rule, $verdict, $redis_alive) {
	if (empty($rule['skip_verified_bots'])) { return ''; }
	if ($verdict === 'ok') { return 'verified'; }
	if ($verdict === '' && !$redis_alive) { return 'degraded'; }
	return '';
}

// What an ENFORCED rule demands of this request. Pure.
//   $tok   token state of the client ('v' = valid)
//   $gate  the request must carry a token (gv_is_gate)
//   $page  page rules are enforced for this method (gv_gate_enforced)
// Returns array(intended, served): '' for nothing. A challenge is intended for
// any gated request without a valid token, served only where the page rules
// are enforced - a POST with challenge.gate_post off is logged as a shadow
// challenge, exactly like the built-in challenge rule. A client holding a
// valid token is never challenged again, so a solved challenge cannot loop.
function gv_rule_act(array $rule, $tok, $gate, $page) {
	if ($rule['mode'] !== 'enforce') { return array('', ''); }
	if ($rule['action'] === 'block') { return array('403', '403'); }
	if ($rule['action'] === 'challenge' && $gate && $tok !== 'v') {
		return array('challenge', $page ? 'challenge' : '');
	}
	return array('', '');
}

// Whether an enforced rule takes the place of the free pass a known bot or a
// link-preview fetcher gets. A log-only rule never does.
function gv_rule_overrides_pass(array $rule) {
	return $rule['mode'] === 'enforce' && ($rule['action'] === 'block' || $rule['action'] === 'challenge');
}

// The starter set: common script and headless clients, all disabled and in
// monitor mode. Ids are fixed so installing twice adds nothing twice.
function gv_rules_starter() {
	$set = array(
		array('st-pyreq', 'python-requests', 'python-requests'),
		array('st-pyurl', 'python-urllib', 'python-urllib'),
		array('st-aiohttp', 'aiohttp', 'aiohttp'),
		array('st-httpx', 'httpx', 'httpx'),
		array('st-gohttp', 'Go-http-client', 'Go-http-client'),
		array('st-curl', 'curl', 'curl/'),
		array('st-wget', 'Wget', 'Wget'),
		array('st-scrapy', 'Scrapy', 'Scrapy'),
		array('st-headless', 'HeadlessChrome', 'HeadlessChrome'),
		array('st-phantom', 'PhantomJS', 'PhantomJS'),
		array('st-nodefetch', 'node-fetch', 'node-fetch'),
		array('st-axios', 'axios', 'axios/'),
		array('st-okhttp', 'okhttp', 'okhttp'),
		array('st-java', 'Java', 'Java/'),
		array('st-libwww', 'libwww-perl', 'libwww-perl'),
		array('st-empty', 'Empty User-Agent', GV_RULE_EMPTY),
	);
	$out = array();
	$pri = 1000;
	foreach ($set as $s) {
		$out[] = array(
			'id' => $s[0], 'name' => 'Starter: ' . $s[1], 'enabled' => false, 'mode' => 'monitor',
			'action' => 'challenge', 'priority' => $pri, 'skip_verified_bots' => true,
			'ua' => array('op' => 'include', 'type' => ($s[2] === GV_RULE_EMPTY ? 'exact' : 'contains'), 'values' => array($s[2])),
			'path' => null, 'expires_at' => 0, 'pow_bits' => 0,
			'note' => 'Starter rule. Check the monitor hits before enforcing.',
			'created_by' => 'starter', 'created_at' => 0, 'updated_at' => 0,
		);
		$pri += 10;
	}
	return $out;
}
