<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Reading: guard logs, the analyzer snapshot, and Redis verdicts.
//
// Hard rule: no function here may load a whole log file into memory. Every
// query reverse-streams with a bounded byte budget and a row cap, and reports
// when it hit either - a silently truncated result in a security console is
// worse than a slow one.

require_once __DIR__ . '/../guard/guard.php';
require_once __DIR__ . '/config_io.php';

define('GP_MAX_ROWS', 200);              // rows returned per page, hard cap
define('GP_MAX_SCAN_BYTES', 4194304);    // bytes scanned per query, hard cap
define('GP_MAX_SCAN_LINES', 40000);      // lines parsed per query, hard cap

// --------------------------------------------------------------------------
// Escaping - the rule with no exceptions
// --------------------------------------------------------------------------

// Everything the panel displays originates in the logs, and the logs are
// written by the bots this system fights. A stored XSS in the admin panel of a
// bot guard hands the attacker the console. Every echoed value goes through
// this function; there is no "this field is safe".
function gp_e($value) {
	if (is_bool($value)) { return $value ? 'true' : 'false'; }
	if ($value === null) { return ''; }
	if (is_array($value)) { $value = json_encode($value, JSON_UNESCAPED_UNICODE); }
	return htmlspecialchars((string)$value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

// A URL query value built from log data.
function gp_u($value) {
	return rawurlencode((string)$value);
}

// JSON destined for an inline <script> block.
function gp_json($value) {
	return json_encode($value, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS
		| JSON_HEX_QUOT | JSON_UNESCAPED_UNICODE);
}

// Persian digits for display only. Anything submitted back stays ASCII.
function gp_num($value, $decimals = 0) {
	$text = number_format((float)$value, (int)$decimals, '.', ',');
	return strtr($text, array('0' => '۰', '1' => '۱', '2' => '۲', '3' => '۳', '4' => '۴',
		'5' => '۵', '6' => '۶', '7' => '۷', '8' => '۸', '9' => '۹'));
}

function gp_pct($part, $whole, $decimals = 1) {
	if (!$whole) { return gp_num(0, $decimals) . '٪'; }
	return gp_num(100.0 * $part / $whole, $decimals) . '٪';
}

// A short relative age, e.g. "۳ دقیقه".
function gp_age($timestamp) {
	$seconds = max(0, time() - (int)$timestamp);
	if ($seconds < 60) { return gp_num($seconds) . ' ثانیه'; }
	if ($seconds < 3600) { return gp_num(intdiv($seconds, 60)) . ' دقیقه'; }
	if ($seconds < 86400) { return gp_num(intdiv($seconds, 3600)) . ' ساعت'; }
	return gp_num(intdiv($seconds, 86400)) . ' روز';
}

function gp_datetime($timestamp) {
	if (!$timestamp) { return ''; }
	return gp_num_raw(date('Y-m-d H:i:s', (int)$timestamp));
}

// Digit substitution without number formatting, for timestamps.
function gp_num_raw($text) {
	return strtr((string)$text, array('0' => '۰', '1' => '۱', '2' => '۲', '3' => '۳',
		'4' => '۴', '5' => '۵', '6' => '۶', '7' => '۷', '8' => '۸', '9' => '۹'));
}

// --------------------------------------------------------------------------
// Inline SVG charts
//
// Generated in PHP, no chart library, no JavaScript. Every label goes through
// gp_e() like everything else, because series names can come from log data.
// --------------------------------------------------------------------------

function gp_chart_palette() {
	return array('#059669', '#0284c7', '#d97706', '#e11d48', '#7c3aed', '#64748b');
}

// A horizontal bar chart. $items is array(label => value).
function gp_chart_bars(array $items, $options = array()) {
	if (!$items) { return '<p class="gp-help">' . gp_e(gp_t_or('no_results')) . '</p>'; }
	$max = max(1, max(array_map('intval', array_values($items))));
	$colors = isset($options['colors']) ? $options['colors'] : array();
	$default = isset($options['color']) ? $options['color'] : '#059669';
	$out = '<div class="gp-section">';
	foreach ($items as $label => $value) {
		$width = max(1.0, 100.0 * (int)$value / $max);
		$color = isset($colors[$label]) ? $colors[$label] : $default;
		$out .= '<div>'
			. '<div class="gp-row-head" style="justify-content:space-between">'
			. '<span class="gp-mono">' . gp_e($label) . '</span>'
			. '<span class="gp-stat-val">' . gp_num($value) . '</span>'
			. '</div>'
			. '<div class="gp-bar-track"><div class="gp-bar-fill" style="width:'
			. number_format($width, 1, '.', '') . '%;background:' . gp_e($color) . '"></div></div>'
			. '</div>';
	}
	return $out . '</div>';
}

// A stacked series over time. $buckets is an ordered list of
// array('label' => 'HH:00', 'values' => array(series => count)).
function gp_chart_stacked(array $buckets, array $series) {
	if (!$buckets) { return '<p class="gp-help">' . gp_e(gp_t_or('no_results')) . '</p>'; }
	$palette = gp_chart_palette();
	$colors = array();
	$i = 0;
	foreach ($series as $name) {
		$colors[$name] = $palette[$i % count($palette)];
		$i++;
	}
	$max = 1;
	foreach ($buckets as $bucket) {
		$total = 0;
		foreach ($series as $name) { $total += (int)($bucket['values'][$name] ?? 0); }
		$max = max($max, $total);
	}
	$w = 720;
	$h = 180;
	$pad = 22;
	$count = count($buckets);
	$slot = ($w - $pad * 2) / max(1, $count);
	$bar = max(2.0, min(28.0, $slot * 0.62));

	$svg = '<svg viewBox="0 0 ' . $w . ' ' . $h . '" role="img" preserveAspectRatio="none">';
	// Baseline.
	$svg .= '<line x1="' . $pad . '" y1="' . ($h - $pad) . '" x2="' . ($w - $pad)
		. '" y2="' . ($h - $pad) . '" stroke="#cbd5e1" stroke-width="1"/>';
	$index = 0;
	foreach ($buckets as $bucket) {
		// RTL: the newest bucket sits on the right, so x runs from the right edge.
		$x = $w - $pad - ($index + 1) * $slot + ($slot - $bar) / 2;
		$y = $h - $pad;
		foreach ($series as $name) {
			$value = (int)($bucket['values'][$name] ?? 0);
			if ($value <= 0) { continue; }
			$height = ($h - $pad * 2) * $value / $max;
			$y -= $height;
			$svg .= '<rect x="' . number_format($x, 2, '.', '') . '" y="'
				. number_format($y, 2, '.', '') . '" width="' . number_format($bar, 2, '.', '')
				. '" height="' . number_format($height, 2, '.', '') . '" fill="'
				. $colors[$name] . '" rx="2"><title>' . gp_e($name . ' ' . $value)
				. '</title></rect>';
		}
		if ($count <= 26 || $index % 2 === 0) {
			$svg .= '<text x="' . number_format($x + $bar / 2, 2, '.', '') . '" y="' . ($h - 6)
				. '" font-size="9" fill="#94a3b8" text-anchor="middle">'
				. gp_e($bucket['label']) . '</text>';
		}
		$index++;
	}
	$svg .= '</svg>';

	$legend = '<div class="gp-legend">';
	foreach ($series as $name) {
		$legend .= '<span><span class="gp-legend-dot" style="background:' . $colors[$name]
			. '"></span> ' . gp_e($name) . '</span>';
	}
	$legend .= '</div>';
	return '<div class="gp-chart">' . $svg . '</div>' . $legend;
}

// Two overlaid histograms, for sc against esc.
function gp_chart_histogram(array $a, array $b, $label_a, $label_b) {
	$labels = array_keys($a + $b);
	if (!$labels) { return '<p class="gp-help">' . gp_e(gp_t_or('no_results')) . '</p>'; }
	$max = 1;
	foreach ($labels as $label) {
		$max = max($max, (int)($a[$label] ?? 0), (int)($b[$label] ?? 0));
	}
	$w = 720;
	$h = 180;
	$pad = 22;
	$slot = ($w - $pad * 2) / max(1, count($labels));
	$bar = max(2.0, $slot * 0.32);

	$svg = '<svg viewBox="0 0 ' . $w . ' ' . $h . '" role="img" preserveAspectRatio="none">';
	$svg .= '<line x1="' . $pad . '" y1="' . ($h - $pad) . '" x2="' . ($w - $pad)
		. '" y2="' . ($h - $pad) . '" stroke="#cbd5e1" stroke-width="1"/>';
	$index = 0;
	foreach ($labels as $label) {
		$x = $w - $pad - ($index + 1) * $slot + ($slot - $bar * 2.2) / 2;
		foreach (array(array($a, '#0284c7', 0.0), array($b, '#d97706', $bar * 1.15)) as $pair) {
			$value = (int)($pair[0][$label] ?? 0);
			$height = ($h - $pad * 2) * $value / $max;
			if ($height < 0.5 && $value > 0) { $height = 0.5; }
			$svg .= '<rect x="' . number_format($x + $pair[2], 2, '.', '') . '" y="'
				. number_format($h - $pad - $height, 2, '.', '') . '" width="'
				. number_format($bar, 2, '.', '') . '" height="'
				. number_format($height, 2, '.', '') . '" fill="' . $pair[1] . '" rx="1">'
				. '<title>' . gp_e($label . ': ' . $value) . '</title></rect>';
		}
		$svg .= '<text x="' . number_format($x + $bar, 2, '.', '') . '" y="' . ($h - 6)
			. '" font-size="9" fill="#94a3b8" text-anchor="middle">'
			. gp_e($label) . '</text>';
		$index++;
	}
	$svg .= '</svg>';
	return '<div class="gp-chart">' . $svg . '</div>'
		. '<div class="gp-legend">'
		. '<span><span class="gp-legend-dot" style="background:#0284c7"></span> '
		. gp_e($label_a) . '</span>'
		. '<span><span class="gp-legend-dot" style="background:#d97706"></span> '
		. gp_e($label_b) . '</span></div>';
}

// gp_t() lives in the front controller; the chart helpers are also reachable
// from the self-test, where it is not defined.
function gp_t_or($key) {
	return function_exists('gp_t') ? gp_t($key) : $key;
}

// --------------------------------------------------------------------------
// Snapshot
// --------------------------------------------------------------------------

function gp_snapshot_path() {
	return __DIR__ . '/../analyzer/snapshot.json';
}

// The dashboard reads only this file, so its cost is one small JSON read
// rather than a log scan, whatever the traffic volume.
function gp_snapshot() {
	$path = gp_snapshot_path();
	if (!is_file($path)) { return null; }
	$raw = @file_get_contents($path);
	if ($raw === false || $raw === '') { return null; }
	$data = json_decode($raw, true);
	return is_array($data) ? $data : null;
}

// --------------------------------------------------------------------------
// Log reading
// --------------------------------------------------------------------------

function gp_log_dir() {
	$cfg = gv_cfg_load();
	return (string)$cfg['log_dir'];
}

function gp_log_file($date = null) {
	$date = $date ? preg_replace('/[^0-9]/', '', (string)$date) : date('Ymd');
	if (strlen($date) !== 8) { $date = date('Ymd'); }
	return rtrim(gp_log_dir(), '/\\') . '/guard-' . $date . '.jsonl';
}

// Which daily files exist, newest first, bounded.
function gp_log_dates($limit = 30) {
	$files = @glob(rtrim(gp_log_dir(), '/\\') . '/guard-*.jsonl');
	if (!is_array($files)) { return array(); }
	$dates = array();
	foreach ($files as $file) {
		if (preg_match('/guard-(\d{8})\.jsonl$/', $file, $m)) { $dates[] = $m[1]; }
	}
	rsort($dates);
	return array_slice($dates, 0, (int)$limit);
}

// Reverse-stream a daily log, applying filters, until the row cap or a byte
// budget is reached.
//
// Returns array(rows, meta) where meta carries scanned counts, whether a cap
// was hit, and the cursor for the next page. Outcome lines are joined onto
// their decision rows in the same pass.
function gp_log_query(array $filter, $cursor = 0, $limit = 50) {
	$limit = max(1, min((int)$limit, GP_MAX_ROWS));
	$file = gp_log_file(isset($filter['date']) ? $filter['date'] : null);
	$meta = array('scanned_lines' => 0, 'scanned_bytes' => 0, 'capped' => false,
		'next_cursor' => null, 'file' => basename($file), 'exists' => is_file($file));
	if (!$meta['exists']) { return array(array(), $meta); }

	$fh = @fopen($file, 'rb');
	if (!$fh) { return array(array(), $meta); }

	$size = filesize($file);
	if ($size === false) { fclose($fh); return array(array(), $meta); }

	// The cursor is a byte offset from the end of the file, so paging forward
	// is a seek rather than a re-scan. The next page resumes at the exact byte
	// where the oldest row of this page began ($last_row_start below), which is
	// what keeps pages contiguous: no boundary row is skipped and none returned
	// twice. Resuming at a chunk boundary instead dropped every not-yet-iterated
	// row in the current chunk - roughly a page's worth per page.
	$pos = max(0, $size - (int)$cursor);
	$buffer = '';
	$rows = array();
	$outcomes = array();
	$last_row_start = 0;                       // absolute byte offset of the oldest returned row
	$chunk = 65536;

	while ($pos > 0 && count($rows) < $limit
		&& $meta['scanned_bytes'] < GP_MAX_SCAN_BYTES
		&& $meta['scanned_lines'] < GP_MAX_SCAN_LINES) {
		$read = (int)min($chunk, $pos, GP_MAX_SCAN_BYTES - $meta['scanned_bytes']);
		if ($read <= 0) { break; }
		$pos -= $read;
		if (fseek($fh, $pos, SEEK_SET) !== 0) { break; }
		$data = fread($fh, $read);
		if ($data === false) { break; }
		$meta['scanned_bytes'] += strlen($data);
		$buffer = $data . $buffer;
		// $buffer now maps to file bytes [$pos, $pos + strlen($buffer)).
		$parts = explode("\n", $buffer);
		if ($pos > 0) {
			// The first element straddles this chunk's lower edge; carry it to
			// the next (older) read to be completed there. The first complete
			// line begins just past it and its stripped separator.
			$buffer = array_shift($parts);
			$base = $pos + strlen($buffer) + 1;
		} else {
			// The chunk starts at the head of the file, so the first element is a
			// complete line beginning at byte 0 and nothing older remains to read.
			$buffer = '';
			$base = 0;
		}
		// Absolute start byte offset of every element in $parts, in file order.
		$starts = array();
		$acc = $base;
		foreach ($parts as $k => $p) {
			$starts[$k] = $acc;
			$acc += strlen($p) + 1;            // +1 for the stripped "\n"
		}
		// Walk newest-first within this chunk.
		for ($i = count($parts) - 1; $i >= 0; $i--) {
			$line = trim($parts[$i]);
			if ($line === '') { continue; }
			$meta['scanned_lines']++;
			$row = json_decode($line, true);
			if (!is_array($row)) { continue; }
			if (isset($row['o']) && $row['o'] === 1) {
				if (isset($row['rid'])) { $outcomes[(string)$row['rid']] = $row; }
				continue;
			}
			if (!gp_log_match($row, $filter)) { continue; }
			$rid = isset($row['rid']) ? (string)$row['rid'] : '';
			$row['_out'] = ($rid !== '' && isset($outcomes[$rid])) ? $outcomes[$rid] : null;
			$rows[] = $row;
			$last_row_start = $starts[$i];     // decreases as we accept older rows
			if (count($rows) >= $limit) { break; }
		}
	}

	// Resume at the start of the oldest row returned, so the next scan re-enters
	// the file exactly one row older: contiguous, with no gap at the chunk
	// boundary and no duplicate of the last row shown. A row starting at byte 0
	// is the head of the file, so nothing older follows it.
	if (count($rows) >= $limit && $last_row_start > 0) {
		$meta['next_cursor'] = $size - $last_row_start;
	}
	if ($meta['scanned_bytes'] >= GP_MAX_SCAN_BYTES
		|| $meta['scanned_lines'] >= GP_MAX_SCAN_LINES) {
		$meta['capped'] = true;
	}
	fclose($fh);
	return array($rows, $meta);
}

// A decision row against the filter set. Pure.
function gp_log_match(array $row, array $f) {
	if (!empty($f['act']) && (string)($row['act'] ?? '') !== (string)$f['act']) { return false; }
	if (isset($f['sh']) && $f['sh'] !== '' && (int)($row['sh'] ?? 0) !== (int)$f['sh']) { return false; }
	if (isset($f['hold']) && $f['hold'] !== '' && (int)($row['hold'] ?? 0) !== (int)$f['hold']) { return false; }
	if (!empty($f['ovr']) && (string)($row['ovr'] ?? '') !== (string)$f['ovr']) { return false; }
	if (!empty($f['tok']) && (string)($row['tok'] ?? '') !== (string)$f['tok']) { return false; }
	if (!empty($f['dev']) && (string)($row['dev'] ?? '') !== (string)$f['dev']) { return false; }
	if (!empty($f['ip']) && (string)($row['ip'] ?? '') !== (string)$f['ip']) { return false; }
	if (!empty($f['path'])) {
		if (stripos((string)($row['p'] ?? ''), (string)$f['path']) === false) { return false; }
	}
	if (!empty($f['reason'])) {
		$reasons = isset($row['rs']) && is_array($row['rs']) ? $row['rs'] : array();
		if (!in_array((string)$f['reason'], $reasons, true)) { return false; }
	}
	if (isset($f['sc_min']) && $f['sc_min'] !== '' && (int)($row['sc'] ?? 0) < (int)$f['sc_min']) { return false; }
	if (isset($f['sc_max']) && $f['sc_max'] !== '' && (int)($row['sc'] ?? 0) > (int)$f['sc_max']) { return false; }
	if (isset($f['esc_min']) && $f['esc_min'] !== '' && (int)($row['esc'] ?? 0) < (int)$f['esc_min']) { return false; }
	if (isset($f['esc_max']) && $f['esc_max'] !== '' && (int)($row['esc'] ?? 0) > (int)$f['esc_max']) { return false; }
	if (!empty($f['status'])) {
		$out = isset($row['_out']) && is_array($row['_out']) ? $row['_out'] : null;
		if (!$out) { return false; }
		$want = (string)$f['status'];
		$got = (int)($out['st'] ?? 0);
		if ($want === '2xx' && !($got >= 200 && $got < 300)) { return false; }
		if ($want === '3xx' && !($got >= 300 && $got < 400)) { return false; }
		if ($want === '404' && $got !== 404) { return false; }
		if ($want === '4xx' && !($got >= 400 && $got < 500 && $got !== 404)) { return false; }
		if ($want === '5xx' && $got < 500) { return false; }
	}
	return true;
}

// Recent rows for one identity, device id or address.
function gp_identity_rows($identity, $limit = 60) {
	$rows = array();
	foreach (gp_log_dates(4) as $date) {
		$is_ip = filter_var($identity, FILTER_VALIDATE_IP) !== false;
		$filter = array('date' => $date);
		$filter[$is_ip ? 'ip' : 'dev'] = $identity;
		$found = gp_log_query($filter, 0, $limit - count($rows));
		$rows = array_merge($rows, $found[0]);
		if (count($rows) >= $limit) { break; }
	}
	return array_slice($rows, 0, $limit);
}

// --------------------------------------------------------------------------
// Redis reads
// --------------------------------------------------------------------------

function gp_redis() {
	static $conn = false;
	if ($conn !== false) { return $conn; }
	$cfg = gv_cfg_load();
	$conn = gv_redis_connect($cfg['redis']);
	return $conn;
}

function gp_redis_up() {
	$conn = gp_redis();
	return $conn ? true : false;
}

// Every gv: verdict touching one identity. This is what makes the identity page
// the first thing to open when a customer reports being blocked.
function gp_identity_verdicts($identity) {
	$out = array('rep' => null, 'ml' => null, 'clf' => null, 'botok' => false,
		'botbad' => false, 'honeypot' => false, 'allow_ttl' => null, 'deny_ttl' => null);
	$conn = gp_redis();
	if (!$conn) { return $out; }
	$rep = gv_r_get($conn, 'gv:rep:' . $identity);
	if (is_string($rep) && is_numeric($rep)) { $out['rep'] = (int)$rep; }
	$ml = gv_r_get($conn, 'gv:ml:' . $identity);
	if (is_string($ml) && is_numeric($ml)) { $out['ml'] = (int)$ml; }
	$clf = gv_r_get($conn, 'gv:clf:' . $identity);
	if (is_string($clf) && is_numeric($clf)) { $out['clf'] = (int)$clf; }
	$out['botok'] = gv_r_get($conn, 'gv:botok:' . $identity) === '1';
	$out['botbad'] = gv_r_get($conn, 'gv:botbad:' . $identity) === '1';
	$out['honeypot'] = gv_r_get($conn, 'gv:hp:' . $identity) === '1';
	if (gv_r_get($conn, 'gv:allow:' . $identity) === '1') {
		$out['allow_ttl'] = gp_ttl('gv:allow:' . $identity);
	}
	if (gv_r_get($conn, 'gv:deny:' . $identity) === '1') {
		$out['deny_ttl'] = gp_ttl('gv:deny:' . $identity);
	}
	return $out;
}

function gp_ttl($key) {
	$conn = gp_redis();
	if (!$conn) { return null; }
	$ttl = gv_redis_cmd($conn, array('TTL', $key));
	if ($ttl === false || $ttl === null) { return null; }
	$ttl = (int)$ttl;
	return $ttl >= 0 ? $ttl : null;
}

// Active operator overrides, bounded.
function gp_overrides_list($limit = 200) {
	$out = array();
	$conn = gp_redis();
	if (!$conn) { return $out; }
	foreach (array('allow', 'deny') as $kind) {
		$cursor = '0';
		$guard = 0;
		do {
			$reply = gp_scan($conn, $cursor, 'gv:' . $kind . ':*');
			if ($reply === null) { break; }
			list($cursor, $keys) = $reply;
			foreach ($keys as $key) {
				$identity = substr($key, strlen('gv:' . $kind . ':'));
				$out[] = array('kind' => $kind, 'identity' => $identity,
					'ttl' => gp_ttl($key));
				if (count($out) >= $limit) { return $out; }
			}
			$guard++;
		} while ($cursor !== '0' && $guard < 64);
	}
	return $out;
}

// SCAN returns a two-element array, which the Phase 1 RESP client deliberately
// does not parse. Read it here with a small dedicated parser rather than
// widening the guard's request-path client for the panel's benefit.
function gp_scan($conn, $cursor, $pattern) {
	if (!$conn) { return null; }
	$payload = gv_resp_encode(array('SCAN', (string)$cursor, 'MATCH', $pattern, 'COUNT', '200'));
	if (@fwrite($conn, $payload) === false) { return null; }
	$line = @fgets($conn);
	if ($line === false) { return null; }
	$line = rtrim($line, "\r\n");
	if (substr($line, 0, 1) !== '*') { return null; }
	if ((int)substr($line, 1) !== 2) { return null; }
	$next = gp_scan_bulk($conn);
	if ($next === null) { return null; }
	$head = @fgets($conn);
	if ($head === false || substr($head, 0, 1) !== '*') { return null; }
	$count = (int)substr(rtrim($head, "\r\n"), 1);
	$keys = array();
	for ($i = 0; $i < $count; $i++) {
		$key = gp_scan_bulk($conn);
		if ($key === null) { return null; }
		$keys[] = $key;
	}
	return array($next, $keys);
}

function gp_scan_bulk($conn) {
	$head = @fgets($conn);
	if ($head === false) { return null; }
	$head = rtrim($head, "\r\n");
	if (substr($head, 0, 1) !== '$') { return null; }
	$len = (int)substr($head, 1);
	if ($len < 0) { return ''; }
	$need = $len + 2;
	$data = '';
	while (strlen($data) < $need) {
		$part = @fread($conn, $need - strlen($data));
		if ($part === false || $part === '') { return null; }
		$data .= $part;
	}
	return substr($data, 0, $len);
}

// Write an operator override. Mirrors analyzer/ctl.py exactly, including the
// 30-day ceiling: an override without an expiry is a config change in disguise.
define('GP_OVERRIDE_MAX_TTL', 2592000);

function gp_override_set($kind, $identity, $ttl) {
	if (!in_array($kind, array('allow', 'deny'), true)) { return false; }
	$identity = (string)$identity;
	if ($identity === '' || strlen($identity) > 128) { return false; }
	if (!preg_match('/^[A-Za-z0-9._:-]+$/', $identity)) { return false; }
	$ttl = (int)$ttl;
	if ($ttl < 60 || $ttl > GP_OVERRIDE_MAX_TTL) { return false; }
	$conn = gp_redis();
	if (!$conn) { return false; }
	return gv_r_setex($conn, 'gv:' . $kind . ':' . $identity, $ttl, '1') === 'OK';
}

function gp_override_clear($identity) {
	$conn = gp_redis();
	if (!$conn) { return false; }
	if (!preg_match('/^[A-Za-z0-9._:-]+$/', (string)$identity)) { return false; }
	gv_redis_cmd($conn, array('DEL', 'gv:allow:' . $identity));
	gv_redis_cmd($conn, array('DEL', 'gv:deny:' . $identity));
	return true;
}

// --------------------------------------------------------------------------
// Kill switch
// --------------------------------------------------------------------------

function gp_killswitch_path() {
	return dirname(__DIR__) . '/guard.off';
}

function gp_killswitch_on() {
	return is_file(gp_killswitch_path());
}

function gp_killswitch_set($stop) {
	if ($stop) {
		return @file_put_contents(gp_killswitch_path(),
			"Created from the admin panel.\n") !== false;
	}
	if (!is_file(gp_killswitch_path())) { return true; }
	return @unlink(gp_killswitch_path());
}
