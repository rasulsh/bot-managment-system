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

// Every number the panel shows uses Latin digits (0-9), whatever the browser's
// language. gp_num() groups thousands for reading ("12,345"); gp_latin() does
// not, so the text can be pasted into a shell or a filter.
function gp_num($value, $decimals = 0) {
	$text = number_format((float)$value, (int)$decimals, '.', ',');
	return $text === '-0' ? '0' : $text;
}

// Latin digits, no thousands separator. $trim drops trailing zeros of a decimal
// ("1.50" -> "1.5", "2.00" -> "2").
function gp_latin($value, $decimals = 0, $trim = false) {
	$text = number_format((float)$value, (int)$decimals, '.', '');
	if ($trim && strpos($text, '.') !== false) { $text = rtrim(rtrim($text, '0'), '.'); }
	return $text === '-0' ? '0' : $text;
}

function gp_pct($part, $whole, $decimals = 1) {
	if (!$whole) { return gp_num(0, $decimals) . '%'; }
	return gp_num(100.0 * $part / $whole, $decimals) . '%';
}

// "1 hour", "6 hours": a count with its unit, singular or plural.
// $unit is one of second, minute, hour, day (lang.php: unit_<unit>_1 / _n).
function gp_plural($count, $unit) {
	$count = (int)$count;
	return gp_num($count) . ' ' . gp_t_or('unit_' . $unit . ($count === 1 ? '_1' : '_n'));
}

// A short relative age, e.g. "3 minutes".
function gp_age($timestamp) {
	$seconds = max(0, time() - (int)$timestamp);
	if ($seconds < 60) { return gp_plural($seconds, 'second'); }
	if ($seconds < 3600) { return gp_plural(intdiv($seconds, 60), 'minute'); }
	if ($seconds < 86400) { return gp_plural(intdiv($seconds, 3600), 'hour'); }
	return gp_plural(intdiv($seconds, 86400), 'day');
}

function gp_datetime($timestamp) {
	if (!$timestamp) { return ''; }
	return date('Y-m-d H:i:s', (int)$timestamp);
}

// Latin digits in text that may carry another script's digits: Persian
// (U+06F0-U+06F9) and Arabic-Indic (U+0660-U+0669) become 0-9. Used for
// formatted timestamps and stored values. Raw request data in the log explorer
// (paths, query strings, user agents) is shown exactly as received instead,
// because it is evidence: rewriting it would show a URL that was never requested.
function gp_num_raw($text) {
	static $map = null;
	if ($map === null) {
		$map = array();
		for ($i = 0; $i < 10; $i++) {
			$map[html_entity_decode('&#' . (0x06F0 + $i) . ';', ENT_QUOTES, 'UTF-8')] = (string)$i;
			$map[html_entity_decode('&#' . (0x0660 + $i) . ';', ENT_QUOTES, 'UTF-8')] = (string)$i;
		}
	}
	return strtr((string)$text, $map);
}

// --------------------------------------------------------------------------
// Log explorer helpers (used by views/logs.php)
// --------------------------------------------------------------------------

function gp_logs_qs(array $filter, array $extra = array()) {
	$query = array_merge(array('r' => 'logs'), $filter, $extra);
	return 'index.php?' . http_build_query($query);
}

function gp_log_status_badge($st) {
	$st = (int)$st;
	if ($st >= 500) { return 'gp-badge-bad'; }
	if ($st >= 400) { return 'gp-badge-warn'; }
	if ($st >= 300) { return 'gp-badge-info'; }
	if ($st >= 200) { return 'gp-badge-on'; }
	return 'gp-badge-off';
}

// One value of the detail panel. Short values print as they are; long ones
// (user agents, query strings, referers) show a preview and expand in place,
// so one long value never pushes the rest of the entry off the screen. The
// value is escaped here and nowhere else in the detail panel.
function gp_log_value($text, $limit = 160) {
	$text = (string)$text;
	if ($text === '') { return '<span class="gp-prop-empty">—</span>'; }
	$len = function_exists('mb_strlen') ? mb_strlen($text, 'UTF-8') : strlen($text);
	if ($len <= $limit) { return '<span class="gp-prop-text">' . gp_e($text) . '</span>'; }
	$preview = function_exists('mb_substr') ? mb_substr($text, 0, $limit, 'UTF-8') : substr($text, 0, $limit);
	return '<details class="gp-prop-more"><summary>'
		. '<span class="gp-prop-preview">' . gp_e($preview) . '…</span>'
		. '<span class="gp-prop-toggle">' . gp_e(gp_t('logs_show_full')) . ' (' . gp_e(gp_latin($len)) . ' '
		. gp_e(gp_t('logs_chars')) . ')</span></summary>'
		. '<span class="gp-prop-text">' . gp_e($text) . '</span></details>';
}

// Split a raw query string into name/value pairs for display. Decoding is for
// reading only; the raw string is shown next to it, unchanged. Bounded, so a
// query with thousands of parameters cannot blow up the page.
function gp_log_query_pairs($q, $max = 50) {
	$out = array();
	foreach (explode('&', (string)$q) as $part) {
		if ($part === '') { continue; }
		$eq = strpos($part, '=');
		$name = $eq === false ? $part : substr($part, 0, $eq);
		$value = $eq === false ? '' : substr($part, $eq + 1);
		$out[] = array(rawurldecode(str_replace('+', ' ', $name)), rawurldecode(str_replace('+', ' ', $value)));
		if (count($out) >= $max) { break; }
	}
	return $out;
}

// --------------------------------------------------------------------------
// Inline SVG charts
//
// Generated in PHP, no chart library, no JavaScript. Every label goes through
// gp_e() like everything else, because series names can come from log data.
// --------------------------------------------------------------------------

// Chart colours are CSS variables (see the --gp-chart-* tokens in app.src.css),
// so the same markup is right in the light and the dark theme.
function gp_chart_color($name) {
	return 'rgb(var(--gp-chart-' . $name . '))';
}

function gp_chart_palette() {
	return array(gp_chart_color('ok'), gp_chart_color('info'), gp_chart_color('warn'),
		gp_chart_color('bad'), gp_chart_color('accent'), gp_chart_color('neutral'));
}

// A horizontal bar chart. $items is array(label => value).
function gp_chart_bars(array $items, $options = array()) {
	if (!$items) { return '<p class="gp-help">' . gp_e(gp_t_or('no_results')) . '</p>'; }
	$max = max(1, max(array_map('intval', array_values($items))));
	$colors = isset($options['colors']) ? $options['colors'] : array();
	$default = isset($options['color']) ? $options['color'] : gp_chart_color('ok');
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
		. '" y2="' . ($h - $pad) . '" class="gp-chart-axis"/>';
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
				. '" height="' . number_format($height, 2, '.', '') . '" style="fill:'
				. $colors[$name] . '" rx="2"><title>' . gp_e($name . ' ' . $value)
				. '</title></rect>';
		}
		if ($count <= 26 || $index % 2 === 0) {
			$svg .= '<text x="' . number_format($x + $bar / 2, 2, '.', '') . '" y="' . ($h - 6)
				. '" class="gp-chart-label">'
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
		. '" y2="' . ($h - $pad) . '" class="gp-chart-axis"/>';
	$index = 0;
	foreach ($labels as $label) {
		$x = $w - $pad - ($index + 1) * $slot + ($slot - $bar * 2.2) / 2;
		foreach (array(array($a, gp_chart_color('info'), 0.0), array($b, gp_chart_color('warn'), $bar * 1.15)) as $pair) {
			$value = (int)($pair[0][$label] ?? 0);
			$height = ($h - $pad * 2) * $value / $max;
			if ($height < 0.5 && $value > 0) { $height = 0.5; }
			$svg .= '<rect x="' . number_format($x + $pair[2], 2, '.', '') . '" y="'
				. number_format($h - $pad - $height, 2, '.', '') . '" width="'
				. number_format($bar, 2, '.', '') . '" height="'
				. number_format($height, 2, '.', '') . '" style="fill:' . $pair[1] . '" rx="1">'
				. '<title>' . gp_e($label . ': ' . $value) . '</title></rect>';
		}
		$svg .= '<text x="' . number_format($x + $bar, 2, '.', '') . '" y="' . ($h - 6)
			. '" class="gp-chart-label">'
			. gp_e($label) . '</text>';
		$index++;
	}
	$svg .= '</svg>';
	return '<div class="gp-chart">' . $svg . '</div>'
		. '<div class="gp-legend">'
		. '<span><span class="gp-legend-dot" style="background:' . gp_chart_color('info') . '"></span> '
		. gp_e($label_a) . '</span>'
		. '<span><span class="gp-legend-dot" style="background:' . gp_chart_color('warn') . '"></span> '
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
			// Join the outcome BEFORE filtering: the 'status' filter looks at it, and
			// matching first made that filter reject every row. Outcome lines are
			// written after their decision row, so newest-first reading has already
			// seen the outcome by now.
			$rid = isset($row['rid']) ? (string)$row['rid'] : '';
			$row['_out'] = ($rid !== '' && isset($outcomes[$rid])) ? $outcomes[$rid] : null;
			if (!gp_log_match($row, $filter)) { continue; }
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

function gp_redis($reset = false) {
	static $conn = false;
	if ($reset) {
		// Drop the shared connection so the next call reopens a clean one. Used
		// when a SCAN fails mid-reply and may have left unread bytes in the
		// socket, which would otherwise be misread as later commands' replies.
		if ($conn && is_resource($conn)) { gv_redis_close($conn); }
		$conn = false;
		return false;
	}
	if ($conn !== false) { return $conn; }
	$cfg = gv_cfg_load();
	// The panel asks for the truth, not the request path's cached "Redis is
	// down", so it bypasses the circuit breaker (third argument).
	$conn = gv_redis_connect($cfg['redis'], (string)$cfg['log_dir'], false);
	return $conn;
}

// What the request path last complained about: whether the circuit breaker is
// currently open (Redis marked down) and the newest line of guard-errors.log.
// Read straight from the files the guard writes - no Redis, no outbound calls.
function gp_guard_health() {
	$cfg = gv_cfg_load();
	$dir = rtrim((string)$cfg['log_dir'], '/\\');
	$out = array('breaker' => false, 'last_error' => '');
	$ttl = isset($cfg['redis']['breaker_ttl']) ? (int)$cfg['redis']['breaker_ttl'] : 5;
	clearstatcache(true, $dir . '/.redis-down');
	$t = @filemtime($dir . '/.redis-down');
	if ($t !== false && $ttl > 0 && (time() - $t) < max($ttl, 60)) { $out['breaker'] = true; }
	$f = $dir . '/guard-errors.log';
	if (is_file($f)) {
		$size = (int)@filesize($f);
		$h = @fopen($f, 'rb');
		if ($h) {
			if ($size > 4096) { fseek($h, -4096, SEEK_END); }
			$tail = (string)stream_get_contents($h);
			fclose($h);
			$lines = array_values(array_filter(explode("\n", $tail), 'strlen'));
			if ($lines) { $out['last_error'] = substr((string)end($lines), 0, 300); }
		}
	}
	return $out;
}

// Where does the data pipeline stand? The panel can only SHOW what the guard
// wrote, so "nothing appears" has a handful of distinct causes that look the
// same on screen. This tells them apart from the filesystem alone (no Redis,
// no outbound request) and returns one verdict:
//
//   no_dir        the log directory does not exist
//   not_writable  it exists but PHP cannot write to it
//   killed        guard.off exists: the guard is switched off and logs nothing
//   never         no log file has ever received a request row
//   quiet         the newest row is more than an hour old
//   ok            a request was logged within the last hour
//
// 'never' and 'quiet' mean the guard is not seeing traffic: not loaded by PHP
// (auto_prepend_file), a stale .user.ini, or pages served from a cache
// without running PHP. docs/03-SETUP.md has the checks.
// Log storage for the dashboard: how big the logs are, how much disk is left,
// and whether guard-logrotate.sh is running. Reads directory metadata and the
// one-line logs/.last-rotate marker; never opens a log file.
// warnings: rotate_never, rotate_stale, rotate_failed, disk_low, over_cap.
function gp_log_storage($now = null) {
	$now = $now === null ? time() : (int)$now;
	$cfg = gv_cfg_load();
	$dir = rtrim((string)$cfg['log_dir'], '/\\');
	$out = array('dir' => $dir, 'total' => 0, 'today' => 0, 'live_files' => 0, 'archives' => 0,
		'oldest' => '', 'free' => null, 'disk' => null, 'min_free_mb' => (int)$cfg['log_min_free_mb'],
		'max_mb' => (int)$cfg['log_max_mb'], 'retention_days' => (int)$cfg['log_retention_days'],
		'skip_paths' => (array)$cfg['log_skip_paths'], 'rotate' => null, 'warnings' => array());
	if (!is_dir($dir)) { return $out; }
	$today = 'guard-' . date('Ymd', $now) . '.jsonl';
	$oldest_old = 0;
	foreach ((array)glob($dir . '/guard-*') as $file) {
		if (!is_file($file) || is_link($file)) { continue; }
		$size = (int)@filesize($file);
		$name = basename($file);
		$out['total'] += $size;
		if ($name === $today) { $out['today'] = $size; }
		if (substr($name, -6) === '.jsonl') {
			$out['live_files']++;
			// A finished day still uncompressed two days later means no rotation ran.
			$mt = (int)@filemtime($file);
			if ($name !== $today && $mt > 0 && ($now - $mt) > 2 * 86400) { $oldest_old = max($oldest_old, 1); }
		} elseif (substr($name, -9) === '.jsonl.gz') {
			$out['archives']++;
			$day = substr($name, 6, 8);
			if ($out['oldest'] === '' || strcmp($day, $out['oldest']) < 0) { $out['oldest'] = $day; }
		}
	}
	$free = @disk_free_space($dir);
	$disk = @disk_total_space($dir);
	$out['free'] = $free === false ? null : (float)$free;
	$out['disk'] = $disk === false ? null : (float)$disk;
	$raw = @file_get_contents($dir . '/.last-rotate');
	$rot = is_string($raw) ? json_decode(trim($raw), true) : null;
	if (is_array($rot) && isset($rot['ts']) && is_numeric($rot['ts'])) { $out['rotate'] = $rot; }

	if ($out['rotate'] === null) {
		if ($oldest_old || $out['live_files'] > 2) { $out['warnings'][] = 'rotate_never'; }
	} else {
		if ($now - (int)$out['rotate']['ts'] > 2 * 86400) { $out['warnings'][] = 'rotate_stale'; }
		if (!empty($out['rotate']['failures'])) { $out['warnings'][] = 'rotate_failed'; }
	}
	if ($out['free'] !== null && $out['min_free_mb'] > 0 && $out['free'] < $out['min_free_mb'] * 1048576) {
		$out['warnings'][] = 'disk_low';
	}
	if ($out['max_mb'] > 0 && $out['total'] > $out['max_mb'] * 1048576) { $out['warnings'][] = 'over_cap'; }
	return $out;
}

// Bytes for people: "1.4 GB". Binary units, Latin digits.
function gp_bytes($n) {
	$n = (float)$n;
	foreach (array('B', 'KB', 'MB', 'GB', 'TB') as $i => $unit) {
		if ($n < 1024 || $unit === 'TB') { return gp_num($n, $i === 0 ? 0 : 1) . ' ' . $unit; }
		$n /= 1024;
	}
	return gp_num($n) . ' TB';
}

function gp_pipeline_status($now = null) {
	$now = $now === null ? time() : (int)$now;
	$cfg = gv_cfg_load();
	$dir = rtrim((string)$cfg['log_dir'], '/\\');
	$out = array('verdict' => 'never', 'dir' => $dir, 'writable' => false, 'last_ts' => 0.0,
		'last_age' => null, 'file' => '', 'bytes' => 0, 'days' => 0, 'killed' => false);
	$out['killed'] = gp_killswitch_on();
	if (!is_dir($dir)) { $out['verdict'] = 'no_dir'; return $out; }
	$out['writable'] = is_writable($dir);
	if (!$out['writable']) { $out['verdict'] = 'not_writable'; return $out; }
	$dates = gp_log_dates(30);
	$out['days'] = count($dates);
	foreach ($dates as $date) {
		$file = $dir . '/guard-' . $date . '.jsonl';
		$size = @filesize($file);
		if ($size === false || $size < 1) { continue; }
		$h = @fopen($file, 'rb');
		if (!$h) { continue; }
		if ($size > 16384) { fseek($h, -16384, SEEK_END); }
		$tail = (string)stream_get_contents($h);
		fclose($h);
		$lines = explode("\n", $tail);
		for ($i = count($lines) - 1; $i >= 0; $i--) {
			$row = json_decode(trim($lines[$i]), true);
			if (is_array($row) && isset($row['ts']) && is_numeric($row['ts'])) {
				$out['last_ts'] = (float)$row['ts'];
				$out['file'] = basename($file);
				$out['bytes'] = (int)$size;
				break;
			}
		}
		if ($out['last_ts'] > 0) { break; }
	}
	if ($out['last_ts'] > 0) {
		$out['last_age'] = max(0, $now - (int)$out['last_ts']);
		$out['verdict'] = $out['last_age'] <= 3600 ? 'ok' : 'quiet';
	}
	// A switched-off guard explains silence better than anything else does.
	if ($out['killed'] && $out['verdict'] !== 'ok') { $out['verdict'] = 'killed'; }
	return $out;
}

// Is the guard's data reachable by an ordinary web request? True when the
// repository root or the log directory sits inside the document root, which is
// the layout docs/03-SETUP.md warns against (the .htaccess files are a safety
// net, not the plan). Cheap, filesystem-only, no outbound request. Returns the
// list of offending paths (empty = fine or unknown).
function gp_exposure_paths($docroot, array $paths) {
	$root = $docroot !== '' ? @realpath($docroot) : false;
	if ($root === false || $root === '') { return array(); }
	$root = rtrim(str_replace('\\', '/', $root), '/');
	$out = array();
	foreach ($paths as $path) {
		$real = @realpath((string)$path);
		if ($real === false) { continue; }
		$real = str_replace('\\', '/', $real);
		if ($real === $root || strncmp($real, $root . '/', strlen($root) + 1) === 0) { $out[] = $real; }
	}
	return $out;
}

function gp_exposure_warning() {
	$cfg = gv_cfg_load();
	$docroot = isset($_SERVER['DOCUMENT_ROOT']) ? (string)$_SERVER['DOCUMENT_ROOT'] : '';
	return gp_exposure_paths($docroot, array(dirname(__DIR__), (string)$cfg['log_dir']));
}

// Read-only description of how the guard reaches Redis, for the dashboard.
// Deliberately built field by field: the password and username are NEVER part
// of this array, only whether authentication is configured.
function gp_redis_info() {
	$cfg = gv_cfg_load();
	$r = isset($cfg['redis']) && is_array($cfg['redis']) ? $cfg['redis'] : array();
	$socket = isset($r['socket']) ? trim((string)$r['socket']) : '';
	return array(
		'endpoint' => $socket !== '' ? $socket
			: (isset($r['host']) ? (string)$r['host'] : '127.0.0.1') . ':' . (isset($r['port']) ? (int)$r['port'] : 6379),
		'db'       => isset($r['db']) ? (int)$r['db'] : 0,
		'prefix'   => isset($r['prefix']) ? (string)$r['prefix'] : '',
		'auth'     => (isset($r['password']) && (string)$r['password'] !== ''),
	);
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
	$rep = gv_r_get($conn, gv_key('rep:' . $identity));
	if (is_string($rep) && is_numeric($rep)) { $out['rep'] = (int)$rep; }
	$ml = gv_r_get($conn, gv_key('ml:' . $identity));
	if (is_string($ml) && is_numeric($ml)) { $out['ml'] = (int)$ml; }
	$clf = gv_r_get($conn, gv_key('clf:' . $identity));
	if (is_string($clf) && is_numeric($clf)) { $out['clf'] = (int)$clf; }
	$out['botok'] = gv_r_get($conn, gv_key('botok:' . $identity)) === '1';
	$out['botbad'] = gv_r_get($conn, gv_key('botbad:' . $identity)) === '1';
	$out['honeypot'] = gv_r_get($conn, gv_key('hp:' . $identity)) === '1';
	if (gv_r_get($conn, gv_key('allow:' . $identity)) === '1') {
		$out['allow_ttl'] = gp_ttl(gv_key('allow:' . $identity));
	}
	if (gv_r_get($conn, gv_key('deny:' . $identity)) === '1') {
		$out['deny_ttl'] = gp_ttl(gv_key('deny:' . $identity));
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
	// Deny first: a block that is hurting customers must never be the entry that
	// fell off the end of the list. And scan until Redis says the keyspace is
	// done (bounded by time, not by a fixed number of steps): with a few hundred
	// thousand counter keys in Redis the old 64-step limit ended before it had
	// seen the overrides at all, and the page showed none.
	$deadline = microtime(true) + 2.0;
	foreach (array('deny', 'allow') as $kind) {
		$cursor = '0';
		$guard = 0;
		do {
			$reply = gp_scan($conn, $cursor, gv_key($kind . ':') . '*');
			if ($reply === null) { break; }
			list($cursor, $keys) = $reply;
			foreach ($keys as $key) {
				$identity = substr($key, strlen(gv_key($kind . ':')));
				$out[] = array('kind' => $kind, 'identity' => $identity,
					'ttl' => gp_ttl($key));
				if (count($out) >= $limit) { return $out; }
			}
			$guard++;
		} while ($cursor !== '0' && microtime(true) < $deadline);
	}
	return $out;
}

// One spelling per address, the same one the guard keys on (gv_ip_canon), so an
// override typed as 2001:DB8::5 or ::ffff:1.2.3.4 lands on the key the guard
// reads. A device id or anything that is not an address is returned unchanged.
function gp_identity_canon($identity) {
	$identity = (string)$identity;
	if (filter_var($identity, FILTER_VALIDATE_IP) !== false) { return gv_ip_canon($identity); }
	return $identity;
}

// One SCAN step. Returns array(next_cursor, keys) or null. The shared client
// parses multi-bulk replies, and a transport failure closes the connection
// (fail-fast), so a bad reply can never be read as a later command's answer;
// gp_redis(true) just forgets the dead handle so the next call reconnects.
function gp_scan($conn, $cursor, $pattern) {
	if (!$conn) { return null; }
	$r = gv_redis_cmd($conn, array('SCAN', (string)$cursor, 'MATCH', $pattern, 'COUNT', '200'));
	if (!is_array($r) || count($r) !== 2 || !is_array($r[1])) {
		if (!gv_redis_alive($conn)) { gp_redis(true); }
		return null;
	}
	return array((string)$r[0], array_map('strval', $r[1]));
}

// Write an operator override. Mirrors analyzer/ctl.py exactly, including the
// 30-day ceiling: an override without an expiry is a config change in disguise.
define('GP_OVERRIDE_MAX_TTL', 2592000);

function gp_override_set($kind, $identity, $ttl) {
	if (!in_array($kind, array('allow', 'deny'), true)) { return false; }
	$identity = gp_identity_canon(is_string($identity) ? $identity : '');
	if ($identity === '' || strlen($identity) > 128) { return false; }
	if (!preg_match('/^[A-Za-z0-9._:-]+$/', $identity)) { return false; }
	$ttl = (int)$ttl;
	if ($ttl < 60 || $ttl > GP_OVERRIDE_MAX_TTL) { return false; }
	$conn = gp_redis();
	if (!$conn) { return false; }
	return gv_r_setex($conn, gv_key($kind . ':' . $identity), $ttl, '1') === 'OK';
}

function gp_override_clear($identity) {
	$conn = gp_redis();
	if (!$conn) { return false; }
	if (!is_string($identity) || !preg_match('/^[A-Za-z0-9._:-]+$/', $identity)) { return false; }
	gv_redis_cmd($conn, array('DEL', gv_key('allow:' . $identity)));
	gv_redis_cmd($conn, array('DEL', gv_key('deny:' . $identity)));
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
