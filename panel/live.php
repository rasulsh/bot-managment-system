<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// The Live requests page: the current daily log read as a TAIL, from a byte-offset cursor.
//
// Read only: no Redis, no writes, no side effect. The page polls index.php?r=live&poll=1 (a GET, never cached); each answer carries
// the rows that were appended since the cursor and the next cursor. The whole file is never re-read.
//
//   cursor      "YYYYMMDD.OFFSET": the daily file and the byte after the last COMPLETE line that was delivered.
//   partial     a line still being written (no "\n" yet) is not delivered and the cursor stops before it.
//   midnight    when the cursor has reached the end of its day and a later day's file exists, the next poll continues at byte 0 of
//               that file (also across days with no traffic). A truncated or replaced file (shorter than the cursor) restarts at 0.
//   caps        every poll returns at most GP_LIVE_MAX_ROWS rows and reads at most GP_LIVE_MAX_BYTES bytes; `more` says there is
//               more to read (the page asks again at once).
//   window      a fixed start / end is found with a binary search on the (increasing) time stamps, then read forward with the
//               same cursor until a row is later than the end (`done`).
//
// Outcome lines (o = 1) follow their decision row and may arrive in a later poll: they are returned separately, by request id, and
// the page merges them into the rows it already shows.

define('GP_LIVE_MAX_ROWS', 500);                 // rows per poll
define('GP_LIVE_MAX_BYTES', 1048576);            // bytes read per poll
define('GP_LIVE_INITIAL_BYTES', 2097152);        // bytes read backwards for the first load of "live"
define('GP_LIVE_MAX_WATCH', 20);

// --------------------------------------------------------------------------- cursor

function gp_live_cursor_format($date, $offset) { return $date . '.' . (int)$offset; }

// "20261123.5821" -> array('20261123', 5821), or null for anything else.
function gp_live_cursor_parse($s) {
	if (!is_string($s) || !preg_match('/^(\d{8})\.(\d{1,12})$/', $s, $m)) { return null; }
	return array($m[1], (int)$m[2]);
}

// The day files that exist, oldest first.
function gp_live_dates() {
	$d = gp_log_dates(400);
	sort($d);
	return $d;
}

// The next day file after $date, or null.
function gp_live_next_date($date, array $dates) {
	foreach ($dates as $d) { if (strcmp($d, $date) > 0) { return $d; } }
	return null;
}

// --------------------------------------------------------------------------- reading

// Read complete lines from one file starting at $offset, within the byte and row caps. Returns
// array(lines, new_offset, hit_cap, size): `lines` are raw strings, `new_offset` is just after the last COMPLETE line read. With
// $final = true (a later day's file exists) a trailing line without "\n" is taken too when it is valid JSON, and dropped otherwise.
function gp_live_read_lines($path, $offset, $max_bytes, $max_lines, $final = false) {
	clearstatcache(true, $path);                    // the file grows between polls (and in one process in the tests)
	$size = @filesize($path);
	if ($size === false) { return array(array(), $offset, false, 0); }
	if ($offset > $size) { $offset = 0; }          // truncated or replaced: start again
	$fh = @fopen($path, 'rb');
	if (!$fh) { return array(array(), $offset, false, $size); }
	$lines = array();
	$read = 0;
	$pos = $offset;
	$buf = '';
	$hit = false;
	if (fseek($fh, $offset, SEEK_SET) !== 0) { fclose($fh); return array(array(), $offset, false, $size); }
	while ($pos < $size && $read < $max_bytes && count($lines) < $max_lines) {
		$chunk = fread($fh, (int)min(65536, $max_bytes - $read, $size - $pos));
		if ($chunk === false || $chunk === '') { break; }
		$read += strlen($chunk);
		$pos += strlen($chunk);
		$buf .= $chunk;
		while (($nl = strpos($buf, "\n")) !== false) {
			$lines[] = substr($buf, 0, $nl);
			$offset += $nl + 1;
			$buf = (string)substr($buf, $nl + 1);
			if (count($lines) >= $max_lines) { $hit = true; break 2; }
		}
	}
	if ($pos < $size || $read >= $max_bytes) { $hit = $hit || ($pos < $size); }
	if ($final && $pos >= $size && $buf !== '' && is_array(json_decode($buf, true))) { $lines[] = $buf; $offset += strlen($buf); }
	elseif ($final && $pos >= $size && $buf !== '') { $offset += strlen($buf); }       // an abandoned half line: skip it
	fclose($fh);
	return array($lines, $offset, $hit, $size);
}

// Decoded lines into array(decision rows, outcomes by rid). Unreadable lines are skipped.
function gp_live_decode(array $lines) {
	$rows = array();
	$out = array();
	foreach ($lines as $line) {
		$line = trim($line);
		if ($line === '') { continue; }
		$r = json_decode($line, true);
		if (!is_array($r)) { continue; }
		if (isset($r['o']) && $r['o'] === 1) {
			if (isset($r['rid']) && is_string($r['rid'])) { $out[$r['rid']] = array('st' => $r['st'] ?? null, 'by' => $r['by'] ?? null, 'dur' => $r['dur'] ?? null); }
			continue;
		}
		$rows[] = $r;
	}
	return array($rows, $out);
}

// One poll from a cursor: the rows appended since, the outcomes seen, the next cursor. Crosses to the next day's file when the
// cursor has reached the end of its own and a later one exists. $until: stop after the first row later than this time (a fixed
// window), 0 = none. Returns array(rows, outcomes, cursor, more, info).
function gp_live_poll_raw(array $cursor, $until = 0, $max_rows = GP_LIVE_MAX_ROWS, $max_bytes = GP_LIVE_MAX_BYTES) {
	list($date, $offset) = $cursor;
	$dates = gp_live_dates();
	$rows = array();
	$outcomes = array();
	$more = false;
	$done = false;
	$bytes_left = $max_bytes;
	$info = array('bytes' => 0, 'file' => '');
	$guard = 0;
	while ($guard++ < 60) {
		$path = gp_log_file($date);
		$later = gp_live_next_date($date, $dates);
		if (!is_file($path)) {
			if ($later === null) { break; }              // nothing yet: wait at the same cursor
			$date = $later; $offset = 0; continue;      // a day without a file: go on
		}
		list($lines, $new_off, $hit, $size) = gp_live_read_lines($path, $offset, $bytes_left, $max_rows - count($rows), $later !== null);
		$info['bytes'] += max(0, $new_off - $offset);
		$info['file'] = basename($path);
		$bytes_left -= max(0, $new_off - $offset);
		$offset = $new_off;
		list($r, $o) = gp_live_decode($lines);
		foreach ($r as $row) {
			if ($until > 0 && (float)($row['ts'] ?? 0) > $until) { $done = true; break; }
			$rows[] = $row;
		}
		$outcomes = array_merge($outcomes, $o);
		if ($done) { break; }
		if ($hit || $bytes_left <= 0 || count($rows) >= $max_rows) { $more = true; break; }
		if ($offset >= $size && $later !== null) { $date = $later; $offset = 0; continue; }     // midnight (or the next day with traffic)
		break;
	}
	return array($rows, $outcomes, gp_live_cursor_format($date, $offset), $more, $info + array('done' => $done));
}

// The first load of "live": the last $minutes minutes (at most $max_rows rows), read backwards from the end of the newest file
// (and the one before it when the window crosses midnight). Returns array(rows, outcomes, cursor).
function gp_live_initial($minutes, $max_rows = 300, $now = null) {
	$now = $now === null ? microtime(true) : (float)$now;
	$cut = $now - max(1, (int)$minutes) * 60;
	$dates = gp_live_dates();
	if (!$dates) { return array(array(), array(), gp_live_cursor_format(date('Ymd'), 0)); }
	$all = array();
	$outcomes = array();
	$cursor = null;
	$budget = GP_LIVE_INITIAL_BYTES;
	for ($i = count($dates) - 1; $i >= 0 && $budget > 0; $i--) {
		$path = gp_log_file($dates[$i]);
		clearstatcache(true, $path);
		$size = (int)@filesize($path);
		$start = max(0, $size - $budget);
		$fh = @fopen($path, 'rb');
		if (!$fh) { continue; }
		fseek($fh, $start, SEEK_SET);
		$data = (string)fread($fh, $size - $start);
		fclose($fh);
		$budget -= strlen($data);
		// Whole lines only: drop the half line at the start (unless it is the head of the file) and the half line at the end.
		if ($start > 0) { $p = strpos($data, "\n"); $data = $p === false ? '' : substr($data, $p + 1); }
		$end = strrpos($data, "\n");
		$complete = $end === false ? '' : substr($data, 0, $end + 1);
		if ($cursor === null) {
			// The cursor is the end of the complete part of the newest file; a half line at the end is delivered by a later poll.
			$tail_len = strlen($data) - strlen($complete);
			$cursor = gp_live_cursor_format($dates[$i], max(0, $size - $tail_len));
		}
		list($r, $o) = gp_live_decode($complete === '' ? array() : explode("\n", rtrim($complete, "\n")));
		$outcomes = array_merge($o, $outcomes);
		$oldest = null;
		foreach ($r as $row) { if ($oldest === null || (float)($row['ts'] ?? 0) < $oldest) { $oldest = (float)($row['ts'] ?? 0); } }
		$all = array_merge($r, $all);
		// Enough: the oldest row here is already older than the window, or this file was read from its head.
		if ($oldest !== null && $oldest < $cut) { break; }
		if ($start > 0) { break; }                  // the byte budget ended inside this file
	}
	$all = array_values(array_filter($all, function ($row) use ($cut) { return (float)($row['ts'] ?? 0) >= $cut; }));
	if (count($all) > $max_rows) { $all = array_slice($all, -$max_rows); }
	return array($all, $outcomes, $cursor ?? gp_live_cursor_format($dates[count($dates) - 1], 0));
}

// The byte offset of a line start at, or just before, the first line whose time stamp is >= $ts in one file (a binary search; the
// time stamps increase down the file apart from tiny reorderings between concurrent requests, which is why it errs early: the row
// filter on the time drops the few earlier rows). Always the start of a line.
function gp_live_seek($path, $ts) {
	clearstatcache(true, $path);
	$size = (int)@filesize($path);
	if ($size <= 0) { return 0; }
	$fh = @fopen($path, 'rb');
	if (!$fh) { return 0; }
	$lo = 0;
	$hi = $size;
	$line_at = function ($from) use ($fh, $size) {      // array(start of the first line starting at or after $from, its time) or null
		if ($from > 0) {
			fseek($fh, $from - 1, SEEK_SET);              // $from may itself be a line start: look at the byte before it
			$buf = (string)fread($fh, 16384);
			$p = strpos($buf, "\n");
			if ($p === false) { return null; }
			$start = $from - 1 + $p + 1;
		} else {
			$start = 0;
		}
		if ($start >= $size) { return null; }
		fseek($fh, $start, SEEK_SET);
		$l = fgets($fh, 65536);
		$r = is_string($l) ? json_decode($l, true) : null;
		return array($start, is_array($r) ? (float)($r['ts'] ?? 0) : 0.0);
	};
	for ($i = 0; $i < 64 && $hi - $lo > 1; $i++) {
		$mid = $lo + intdiv($hi - $lo, 2);
		$l = $line_at($mid);
		if ($l === null || $l[0] >= $hi) { break; }
		if ($l[1] > 0 && $l[1] < $ts) { $lo = $l[0]; } else { $hi = $l[0]; }
	}
	fclose($fh);
	return $lo;
}

// The first cursor of a fixed window: the day file of $start and the seek inside it (never later than the first row of the window).
function gp_live_window_cursor($start_ts) {
	$date = date('Ymd', (int)$start_ts);
	$dates = gp_live_dates();
	if (!in_array($date, $dates, true)) {
		$next = gp_live_next_date($date, $dates);
		if ($next === null) { return gp_live_cursor_format($date, 0); }
		return gp_live_cursor_format($next, 0);
	}
	return gp_live_cursor_format($date, gp_live_seek(gp_log_file($date), $start_ts));
}

// --------------------------------------------------------------------------- classes, filters, watch

// The outcome class of a row, for the colours and the quick toggles: allowed, challenged, captcha, blocked, ratelimited, monitor.
// A shadow row (sh = 1) is "monitor": it WOULD have acted and did nothing.
function gp_live_class(array $row) {
	$act = (string)($row['act'] ?? '');
	if ((int)($row['sh'] ?? 0) === 1) { return 'monitor'; }
	if ($act === '403' || $act === '404_hp') { return 'blocked'; }
	if ($act === '429' || $act === 'mint_limited') { return 'ratelimited'; }
	if ($act === 'challenge') { return in_array((string)($row['cap'] ?? ''), array('show', 'esc'), true) ? 'captcha' : 'challenged'; }
	if (in_array($act, array('nonce_bad', 'nonce_replay', 'pow_bad'), true)) { return 'challenged'; }
	return 'allowed';
}

function gp_live_classes() { return array('allowed', 'challenged', 'captcha', 'blocked', 'ratelimited', 'monitor', 'crawler'); }

// Whether the row is a verified crawler (the offline verdict, or the pass it earned).
function gp_live_is_crawler(array $row) { return (string)($row['botv'] ?? '') === 'ok' || (string)($row['act'] ?? '') === 'allow_bot'; }

// The quick toggles from the request: a list of classes (none = all). Unknown names are dropped.
function gp_live_show_from($s) {
	if (!is_string($s) || $s === '') { return array(); }
	return array_values(array_intersect(gp_live_classes(), array_map('trim', explode(',', substr($s, 0, 200)))));
}

// The watched identities (addresses or device ids), bounded and validated.
function gp_live_watch_from($s) {
	$out = array();
	if (!is_string($s) || $s === '') { return $out; }
	foreach (explode(',', substr($s, 0, 4000)) as $w) {
		$w = trim($w);
		if ($w !== '' && strlen($w) <= 128 && preg_match('/^[A-Za-z0-9._:-]+$/', $w) && !in_array($w, $out, true)) { $out[] = $w; }
		if (count($out) >= GP_LIVE_MAX_WATCH) { break; }
	}
	return $out;
}

// Whether a row passes: a watched identity always does; otherwise the toggles (OR among themselves) AND the filter set.
function gp_live_row_passes(array $row, array $filter, array $show, array $watch) {
	if ($watch && (in_array((string)($row['ip'] ?? ''), $watch, true) || in_array((string)($row['dev'] ?? ''), $watch, true))) { return true; }
	if ($show) {
		$cls = gp_live_class($row);
		if (!in_array($cls, $show, true) && !(in_array('crawler', $show, true) && gp_live_is_crawler($row))) { return false; }
	}
	return gp_log_match($row, $filter);
}

// --------------------------------------------------------------------------- one poll, filtered

// The answer of one poll as an array (the JSON endpoint encodes it). $req keys: cursor, mode ('live' | 'window'), minutes, start, end,
// filter, show, watch. Never throws; an unreadable log is an empty answer.
function gp_live_answer(array $req) {
	$mode = isset($req['mode']) && $req['mode'] === 'window' ? 'window' : 'live';
	$filter = isset($req['filter']) && is_array($req['filter']) ? $req['filter'] : array();
	$show = isset($req['show']) && is_array($req['show']) ? $req['show'] : array();
	$watch = isset($req['watch']) && is_array($req['watch']) ? $req['watch'] : array();
	$cursor = isset($req['cursor']) ? gp_live_cursor_parse($req['cursor']) : null;
	$start = (int)($req['start'] ?? 0);
	$end = (int)($req['end'] ?? 0);
	$info = array('bytes' => 0, 'file' => '', 'done' => false);
	$more = false;
	$first = $cursor === null;
	if ($mode === 'window') {
		if ($start <= 0 || $end <= $start || $end - $start > 86400 * 2) { return array('ok' => false, 'error' => 'window', 'rows' => array()); }
		if ($first) { $cursor = gp_live_parse_or_null(gp_live_window_cursor($start)); }
		list($rows, $outcomes, $next, $more, $info) = gp_live_poll_raw($cursor, $end);
		$rows = array_values(array_filter($rows, function ($r) use ($start) { return (float)($r['ts'] ?? 0) >= $start; }));
		if (!$more && !$info['done']) { $info['done'] = ($end < time() - 1); }     // a window in the past ends where the log ends
	} elseif ($first) {
		list($rows, $outcomes, $next) = gp_live_initial(isset($req['minutes']) ? (int)$req['minutes'] : 5);
	} else {
		list($rows, $outcomes, $next, $more, $info) = gp_live_poll_raw($cursor);
	}
	$out = array();
	$reasons = array();
	$scanned = count($rows);
	foreach ($rows as $row) {
		// The outcome of the same poll joins before the filter: the status filter reads it.
		$rid = (string)($row['rid'] ?? '');
		$row['_out'] = ($rid !== '' && isset($outcomes[$rid])) ? $outcomes[$rid] : null;
		$watched = $watch && (in_array((string)($row['ip'] ?? ''), $watch, true) || in_array((string)($row['dev'] ?? ''), $watch, true));
		if (!gp_live_row_passes($row, $filter, $show, $watch)) { continue; }
		$out_row = gp_live_row_out($row);
		$out_row['cls'] = gp_live_class($row);
		$out_row['crawler'] = gp_live_is_crawler($row) ? 1 : 0;
		if ($watched) { $out_row['w'] = 1; }
		foreach ((array)($row['rs'] ?? array()) as $code) { if (is_string($code) && !isset($reasons[$code])) { $reasons[$code] = gp_live_reason_out($code); } }
		$out[] = $out_row;
	}
	return array('ok' => true, 'rows' => $out, 'outcomes' => $outcomes, 'cursor' => $next, 'more' => $more, 'done' => !empty($info['done']),
		'now' => round(microtime(true), 3), 'scanned' => $scanned, 'bytes' => (int)$info['bytes'], 'file' => $info['file'], 'reasons' => $reasons,
		'first' => $first);
}

function gp_live_parse_or_null($s) { $c = gp_live_cursor_parse($s); return $c === null ? array(date('Ymd'), 0) : $c; }

// A row as the page needs it: every logged field (they are all shown in Logs already), the outcome joined, nothing derived from
// anything but the row itself. Strings are what the clients sent: the page puts them in with textContent, never as markup.
function gp_live_row_out(array $row) {
	$o = isset($row['_out']) && is_array($row['_out']) ? $row['_out'] : null;
	unset($row['_out']);
	if ($o !== null) { $row['st'] = $o['st'] ?? null; $row['by'] = $o['by'] ?? null; $row['dur'] = $o['dur'] ?? null; }
	return $row;
}

// What the page needs to draw a reason badge: the full name, the explanation, the class, the monitor marker and a link.
function gp_live_reason_out($code) {
	$i = gp_reason_info($code);
	$label = gp_reason_label($code);
	$href = '';
	if ($i['ref'][0] !== '') { $t = gp_reason_target($i['ref'][0], $i['ref'][1]); $href = $t[1]; }
	return array('name' => $i['name'], 'label' => $label, 'explain' => $i['explain'] . ($i['monitor'] ? ' ' . gp_t('rsn_monitor_x') : ''),
		'class' => $i['class'], 'monitor' => $i['monitor'] ? 1 : 0, 'href' => $href, 'known' => $i['known'] ? 1 : 0);
}

// A time typed as "2026-11-23T14:30" (a datetime-local box, the SERVER's time zone) as a timestamp; 0 when it is not one.
function gp_live_parse_time($s) {
	if (!is_string($s) || !preg_match('/^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?$/', trim($s), $m)) { return 0; }
	if (!checkdate((int)$m[2], (int)$m[3], (int)$m[1]) || (int)$m[4] > 23 || (int)$m[5] > 59) { return 0; }
	$t = mktime((int)$m[4], (int)$m[5], isset($m[6]) ? (int)$m[6] : 0, (int)$m[2], (int)$m[3], (int)$m[1]);
	return $t === false ? 0 : (int)$t;
}

// The request of a poll from the query string.
function gp_live_request_from_get(array $get) {
	$filter = gp_logs_filter_from_request();
	unset($filter['date']);
	$minutes = isset($get['minutes']) && is_string($get['minutes']) && ctype_digit($get['minutes']) ? (int)$get['minutes'] : 5;
	return array(
		'mode' => (isset($get['mode']) && $get['mode'] === 'window') ? 'window' : 'live',
		'cursor' => isset($get['cursor']) && is_string($get['cursor']) ? $get['cursor'] : null,
		'minutes' => in_array($minutes, array(1, 5, 15, 60), true) ? $minutes : 5,
		'start' => gp_live_parse_time($get['start'] ?? ''), 'end' => gp_live_parse_time($get['end'] ?? ''),
		'filter' => $filter, 'show' => gp_live_show_from($get['show'] ?? ''), 'watch' => gp_live_watch_from($get['watch'] ?? ''),
	);
}
