<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Dashboard v2 helpers: plain functions that turn the snapshot's `dash` block (analyzer/snapshot.py) into inline SVG and small
// pieces of markup. Nothing here reads a log or a file: the numbers are already in the snapshot. Every string is in lang.php.

// The outcome classes, in stacking order (bottom to top), with their chart colour token and the lang key of their name.
// The same classes and colours as the Live and Logs pages.
function gp_dash_classes() {
	return array('a' => array('ok', 'dash_o_allowed'), 'c' => array('warn', 'dash_o_challenged'), 'p' => array('info', 'dash_o_captcha'),
		'b' => array('bad', 'dash_o_blocked'), 'r' => array('accent', 'dash_o_limited'), 'm' => array('neutral', 'dash_o_monitor'));
}

// The `dash` block of a snapshot, or array() when the snapshot is missing or older than this version of the analyzer.
function gp_dash_block($snap) {
	$d = (is_array($snap) && isset($snap['dash']) && is_array($snap['dash'])) ? $snap['dash'] : array();
	return (isset($d['v']) && (int)$d['v'] >= 1 && isset($d['hours']) && is_array($d['hours'])) ? $d : array();
}

// A rounded-up axis maximum with four equal, round steps: the step is 1, 2, 2.5, 3, 4, 5, 6, 8 or 10 x 10^k, the maximum is four steps
// (115 -> 120 in steps of 30, 7 -> 8 in steps of 2, 4300 -> 4400 in steps of 1100 is not offered, so 4800 in steps of 1200).
function gp_dash_nice_max($v) {
	$v = max(1.0, (float)$v);
	$p = pow(10, floor(log10($v / 4)));
	foreach (array(1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10) as $m) {
		$step = $m * $p;
		if ($step * 4 >= $v - 1e-9) { return max(4, (int)round($step * 4)); }
	}
	return (int)round(40 * $p);
}

// "1.2k" / "34" for an axis tick.
function gp_dash_short($n) {
	$n = (float)$n;
	if ($n >= 1000000) { return rtrim(rtrim(number_format($n / 1000000, 1, '.', ''), '0'), '.') . 'M'; }
	if ($n >= 1000) { return rtrim(rtrim(number_format($n / 1000, 1, '.', ''), '0'), '.') . 'k'; }
	return (string)(int)$n;
}

// The main chart: requests per hour, stacked by outcome, plus a line for distinct addresses. $buckets: list of
// array(t, n, a, c, p, b, r, m, ips). $days = true labels the X axis by day (the 7 d view). $uid keeps the SVG ids unique.
function gp_dash_main_chart(array $buckets, $days, $uid) {
	if (!$buckets) { return ''; }
	$cl = gp_dash_classes();
	$W = 960; $H = 292; $L = 46; $R = 12; $T = 28; $B = 30;
	$pw = $W - $L - $R; $ph = $H - $T - $B;
	$n = count($buckets);
	$max = 1;
	foreach ($buckets as $b) { $max = max($max, (int)($b['n'] ?? 0), (int)($b['ips'] ?? 0)); }
	$top = gp_dash_nice_max($max);
	$slot = $pw / $n;
	$bw = max(1.0, $slot * ($days ? 0.8 : 0.7));
	$svg = '<svg class="gp-dchart" viewBox="0 0 ' . $W . ' ' . $H . '" role="img" aria-labelledby="dch-t-' . gp_e($uid) . '">'
		. '<title id="dch-t-' . gp_e($uid) . '">' . gp_e(gp_t($days ? 'dash_main_7d' : 'dash_main_24h')) . '</title>'
		. '<defs><pattern id="dch-h-' . gp_e($uid) . '" width="5" height="5" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
		. '<rect width="5" height="5" style="fill:' . gp_chart_color('neutral') . ';fill-opacity:.35"/><line x1="0" y1="0" x2="0" y2="5" style="stroke:' . gp_chart_color('neutral') . ';stroke-width:2"/></pattern></defs>';
	// Y axis: three ticks and the unit.
	foreach (array(0, 0.25, 0.5, 0.75, 1) as $f) {
		$y = $T + $ph - $ph * $f;
		$svg .= '<line x1="' . $L . '" x2="' . ($W - $R) . '" y1="' . round($y, 1) . '" y2="' . round($y, 1) . '" class="gp-dchart-grid"/>'
			. '<text x="' . ($L - 6) . '" y="' . round($y + 3.5, 1) . '" class="gp-dchart-tick" text-anchor="end">' . gp_e(gp_dash_short($top * $f)) . '</text>';
	}
	// The unit is the axis title, above the plot area (never on a gridline).
	$svg .= '<text x="2" y="12" class="gp-dchart-unit">' . gp_e(gp_t('dash_main_unit')) . '</text>';
	$line = array();
	$prev_day = '';
	foreach ($buckets as $i => $b) {
		$x = $L + $i * $slot + ($slot - $bw) / 2;
		$y = $T + $ph;
		$tip = date($days ? 'M j H:i' : 'H:i', (int)$b['t']) . ' - ' . gp_t('dash_k_requests') . ' ' . (int)($b['n'] ?? 0);
		foreach ($cl as $k => $def) {
			$v = (int)($b[$k] ?? 0);
			if ($v <= 0) { continue; }
			$h = $ph * $v / $top;
			$y -= $h;
			$fill = $k === 'm' ? 'url(#dch-h-' . gp_e($uid) . ')' : gp_chart_color($def[0]);
			$svg .= '<rect x="' . round($x, 2) . '" y="' . round($y, 2) . '" width="' . round($bw, 2) . '" height="' . round($h, 2) . '" style="fill:' . $fill . '"><title>'
				. gp_e($tip . ', ' . gp_t($def[1]) . ' ' . $v . ', ' . gp_t('dash_main_ips') . ' ' . (int)($b['ips'] ?? 0)) . '</title></rect>';
		}
		$line[] = round($x + $bw / 2, 2) . ',' . round($T + $ph - $ph * (int)($b['ips'] ?? 0) / $top, 2);
		// X labels: every 4th hour (24 h) or the first hour of each day (7 d).
		$lab = '';
		if ($days) { $d = date('M j', (int)$b['t']); if ($d !== $prev_day && date('G', (int)$b['t']) === '0') { $lab = $d; } if ($d !== $prev_day) { $prev_day = $d; } }
		elseif ($i % 4 === 0) { $lab = date('H:00', (int)$b['t']); }
		if ($lab !== '') { $svg .= '<text x="' . round($x + $bw / 2, 1) . '" y="' . ($H - 10) . '" class="gp-dchart-tick" text-anchor="middle">' . gp_e($lab) . '</text>'; }
	}
	$svg .= '<polyline points="' . implode(' ', $line) . '" class="gp-dchart-line"/></svg>';
	return $svg;
}

// The legend of the main chart (more than one series, so it is always shown there).
function gp_dash_legend() {
	$h = '<ul class="gp-dlegend">';
	foreach (gp_dash_classes() as $k => $def) {
		$h .= '<li><span class="gp-dlegend-sw' . ($k === 'm' ? ' gp-dlegend-sw-hatch' : '') . '" style="background:' . gp_chart_color($def[0]) . '"></span>' . gp_e(gp_t($def[1])) . '</li>';
	}
	return $h . '<li><span class="gp-dlegend-line"></span>' . gp_e(gp_t('dash_main_ips')) . '</li></ul>';
}

// A sparkline for a KPI tile: one line, no axes. $vals: numbers, oldest first.
function gp_dash_spark(array $vals, $color_token, $label) {
	$vals = array_values($vals);
	$n = count($vals);
	if ($n < 2) { return ''; }
	$W = 120; $H = 28;
	$max = max(1, max($vals));
	$pts = array();
	foreach ($vals as $i => $v) { $pts[] = round($i * $W / ($n - 1), 1) . ',' . round($H - 2 - ($H - 4) * $v / $max, 1); }
	return '<svg class="gp-dspark" viewBox="0 0 ' . $W . ' ' . $H . '" preserveAspectRatio="none" role="img" aria-label="' . gp_e($label . ': ' . (int)$vals[0] . ' - ' . (int)$vals[$n - 1]) . '">'
		. '<polyline points="' . implode(' ', $pts) . '" style="stroke:' . gp_chart_color($color_token) . '" class="gp-dspark-line"/></svg>';
}

// The outcome mix of one top-list row as a stacked bar: $rec = array(key, n, a, c, b, r, m). The words are in the title.
function gp_dash_mixbar(array $rec) {
	$n = max(1, (int)$rec[1]);
	$parts = array(array(2, 'a', 'ok', 'dash_o_allowed'), array(3, 'c', 'warn', 'dash_o_challenged'), array(4, 'b', 'bad', 'dash_o_blocked'), array(5, 'r', 'accent', 'dash_o_limited'), array(6, 'm', 'neutral', 'dash_o_monitor'));
	$h = '<span class="gp-mixbar" role="img" aria-label="' . gp_e(gp_t('dash_mix')) . '">';
	$title = array();
	foreach ($parts as $p) {
		$v = isset($rec[$p[0]]) ? (int)$rec[$p[0]] : 0;
		if ($v <= 0) { continue; }
		$h .= '<span style="width:' . number_format(100.0 * $v / $n, 2, '.', '') . '%;background:' . gp_chart_color($p[2]) . '"></span>';
		$title[] = gp_t($p[3]) . ' ' . $v;
	}
	return str_replace('role="img"', 'role="img" title="' . gp_e(implode(', ', $title)) . '"', $h . '</span>');
}

// "Ready to enforce?" from the readiness numbers of one rule or list: array(code, lang key).
// none = no hit in 7 d (no evidence either way), more = too few hits to judge, review = many hits carried a valid token (people who
// solved the check, so the false-positive risk is high), ready = enough hits and almost none carried a token.
function gp_dash_ready_hint(array $r) {
	$d7 = (int)($r['d7'] ?? 0);
	if ($d7 <= 0) { return array('none', 'dash_rd_none'); }
	if ($d7 < 20) { return array('more', 'dash_rd_more'); }
	if ((float)($r['tok'] ?? 0) >= 5.0) { return array('review', 'dash_rd_review'); }
	return array('ready', 'dash_rd_is_ready');
}

function gp_dash_ready_badge($code) {
	$cls = array('ready' => 'gp-badge-on', 'review' => 'gp-badge-bad', 'more' => 'gp-badge-warn', 'none' => 'gp-badge-off');
	return $cls[$code] ?? 'gp-badge-off';
}

// The Logs / Live link for a top-list kind and value (an address, a device, a User-Agent, a path, a country, an AS number).
function gp_dash_top_link($kind, $value) {
	$field = array('ips' => 'ip', 'devices' => 'dev', 'uas' => 'ua', 'paths' => 'path', 'countries' => 'cc', 'asns' => 'asn');
	return 'index.php?r=logs&amp;' . $field[$kind] . '=' . gp_u((string)$value);
}

// The Logs link of a KPI tile (the same filter the number counts).
function gp_dash_tile_link($key) {
	$map = array('requests' => 'index.php?r=logs', 'allowed' => 'index.php?r=logs&amp;act=allow,allow_bot,allow_preview,allow_override,exempt',
		'challenged' => 'index.php?r=logs&amp;act=challenge&amp;sh=0', 'blocked' => 'index.php?r=logs&amp;act=403&amp;sh=0',
		'limited' => 'index.php?r=logs&amp;act=429&amp;sh=0', 'would_act' => 'index.php?r=logs&amp;act=403,429,challenge&amp;sh=1');
	return $map[$key] ?? 'index.php?r=logs';
}

// The status strip numbers from the live inputs: alerts by level and jobs by health. Pure.
function gp_dash_strip_counts(array $alerts, array $jobs) {
	$o = array('critical' => 0, 'warning' => 0, 'jobs_ok' => 0, 'jobs_bad' => 0, 'jobs_total' => 0);
	foreach ($alerts as $a) { if (($a['level'] ?? '') === 'critical') { $o['critical']++; } else { $o['warning']++; } }
	foreach ($jobs as $h) {
		$s = (string)($h['state'] ?? '');
		$o['jobs_total']++;
		if ($s === 'ok') { $o['jobs_ok']++; }
		elseif (in_array($s, array('failing', 'late', 'warning'), true) || (in_array($s, array('never', 'skipped'), true) && !empty($h['required']))) { $o['jobs_bad']++; }
	}
	return $o;
}
