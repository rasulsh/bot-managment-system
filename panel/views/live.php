<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Live requests. The page is a shell: everything on screen comes from index.php?r=live&poll=1 (JSON), polled by the script at the
// bottom. EVERY value that reaches the screen is a log field written by a client (User-Agent, path, query): the script puts it in
// with textContent and never as markup, and links only to same-site addresses.
$f = isset($req['filter']) && is_array($req['filter']) ? $req['filter'] : array();
$ipl_names = array_map(function ($l) { return (string)$l['id']; }, function_exists('gp_iplists_state') ? gp_iplists_state()['lists'] : array());
$flt = array(
	'act'    => array('logs_act', 'is', array('') + gp_field_options('act')),
	'method' => array('logs_method', 'is', array('GET', 'POST', 'HEAD', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')),
	'ip'     => array('logs_ip', 'is', array()),
	'dev'    => array('logs_device', 'is', array()),
	'path'   => array('logs_path', 'has', array()),
	'ua'     => array('logs_ua', 'has', array()),
	'cc'     => array('geo_cc', 'is', array()),
	'asn'    => array('geo_asn', 'is', array()),
	'reason' => array('logs_reason', 'is', array('' => '') + gp_reason_options()),
	'status' => array('logs_status', 'is', array('2xx', '3xx', '404', '4xx', '5xx')),
	'ipl'    => array('logs_ipl', 'is', array('allow', 'block')),
	'ipln'   => array('logs_ipln', 'is', $ipl_names),
	'botv'   => array('id_botv', 'is', gp_field_options('botv')),
	'tok'    => array('logs_token', 'is', gp_field_options('tok')),
);
$field = function ($key) use ($flt, $f) {
	$d = $flt[$key];
	$v = isset($f[$key]) ? $f[$key] : null;
	$dl = array_filter($d[2], 'strlen');
	if (gp_is_labelled($d[2])) { $dl = array_filter($dl, function ($x, $k) { return (string)$k !== ''; }, ARRAY_FILTER_USE_BOTH); } else { $dl = array_values($dl); }
	return '<div class="gp-field"><label class="gp-label" for="lf-' . gp_e($key) . '">' . gp_e(gp_t($d[0])) . gp_tip('flt_' . $key) . '</label><div class="gp-fgroup">'
		. gp_filter_op_select($key, $v, $d[1]) . gp_multi_input('lf-' . $key, $key, gp_filter_text($v), $dl) . '</div></div>';
};
$mode = (isset($req['mode']) && $req['mode'] === 'window') ? 'window' : 'live';
$minutes = isset($req['minutes']) ? (int)$req['minutes'] : 5;
$tz = date('T') . ' (UTC' . date('P') . ')';
$show = isset($req['show']) && is_array($req['show']) ? $req['show'] : array();
$can_quick = gp_acl_allows($role ?? '', 'overrides', 'POST');
$labels = array();
foreach (array('logs_time', 'logs_act', 'logs_request', 'logs_ip', 'logs_device', 'logs_score', 'logs_status', 'logs_reason', 'logs_method', 'logs_path', 'logs_ua',
	'geo_cc', 'geo_asn', 'logs_sc', 'logs_esc', 'id_reputation', 'id_ml', 'id_clf', 'id_botv', 'logs_token', 'logs_query', 'logs_referer', 'logs_bytes', 'logs_duration', 'logs_rid',
	'live_cls_allowed', 'live_cls_challenged', 'live_cls_captcha', 'live_cls_blocked', 'live_cls_ratelimited', 'live_cls_monitor', 'live_cls_crawler',
	'live_stat_req', 'live_stat_rate', 'live_stat_ips', 'live_stat_devs', 'live_stat_none', 'live_chart_title', 'live_chart_now', 'live_chart_secs', 'live_top_ip', 'live_top_dev', 'live_top_ua',
	'live_top_path', 'live_top_cc', 'live_top_hint', 'live_empty', 'live_waiting', 'live_state_live', 'live_state_paused', 'live_state_hover', 'live_state_hidden', 'live_state_done',
	'live_state_err', 'live_err_window', 'live_err_session', 'live_drawer_title', 'live_close', 'live_identity', 'live_open_logs', 'live_fields', 'live_quick', 'live_pause', 'live_resume',
	'live_watch_add', 'live_unwatch', 'live_watched', 'live_watch_none', 'live_rows_shown', 'live_watch', 'rsn_monitor_word', 'yes', 'no') as $k) { $labels[$k] = gp_t($k); }
$cfg = array(
	'tzOffset' => (int)date('Z'), 'labels' => $labels, 'canQuick' => $can_quick, 'csrf' => $can_quick ? gp_csrf_token() : '',
	'quick' => array_map(function ($k, $spec) { return array('key' => $k, 'label' => gp_t($spec[2])); }, array_keys(gp_quick_specs()), array_values(gp_quick_specs())),
	'quickWho' => array('ip' => gp_t('ovr_q_ip'), 'dev' => gp_t('ovr_q_dev'), 'custom' => gp_t('ovr_q_custom')),
	'fieldNames' => array('act' => gp_field_name('act'), 'tok' => gp_field_name('tok'), 'ovr' => gp_field_name('ovr'), 'botv' => gp_field_name('botv'), 'sh' => gp_field_name('sh'),
		'hold' => gp_field_name('hold'), 'cap' => gp_field_name('cap'), 'tl' => gp_field_name('tl')),
	'actNames' => (function () { $o = array(); foreach (array('allow', 'challenge', '403', '429', 'exempt', 'allow_bot', 'allow_preview', 'allow_override', '404_hp', 'token_issued', 'nonce_bad', 'nonce_replay', 'pow_bad', 'mint_limited') as $a) { $o[$a] = gp_field_value('act', $a); } return $o; })(),
	'valueNames' => array('tok' => gp_field_options('tok'), 'botv' => gp_field_options('botv'), 'sh' => gp_field_options('sh'), 'hold' => gp_field_options('hold'), 'cap' => gp_field_options('cap'),
		'ovr' => array('allow' => gp_field_value('ovr', 'allow'), 'deny' => gp_field_value('ovr', 'deny'), 'challenge' => gp_field_value('ovr', 'challenge'), 'captcha' => gp_field_value('ovr', 'captcha'))),
);
?>
<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('live_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('live_sub')) ?></p>
	<p class="gp-page-sub"><?= gp_docs_link('14-REASON-CODES.md', '', 'logs_reason_docs') ?></p>
</div>
<noscript><div class="gp-note gp-note-strong"><?= gp_e(gp_t('live_needs_js')) ?></div></noscript>

<form id="live-form" class="gp-card gp-form" method="get" action="index.php" autocomplete="off">
	<input type="hidden" name="r" value="live">
	<div class="gp-filters gp-filters-3">
		<fieldset class="gp-field gp-fieldset">
			<legend class="gp-label"><?= gp_e(gp_t('live_mode')) ?><?= gp_tip('live_mode') ?></legend>
			<div class="gp-live-radios">
			<label class="gp-check"><input type="radio" name="mode" value="live" <?= $mode === 'live' ? 'checked' : '' ?>> <?= gp_e(gp_t('live_mode_live')) ?></label>
			<label class="gp-check"><input type="radio" name="mode" value="window" <?= $mode === 'window' ? 'checked' : '' ?>> <?= gp_e(gp_t('live_mode_window')) ?></label>
			</div>
		</fieldset>
		<div class="gp-field" data-live-when="live">
			<label class="gp-label" for="live-minutes"><?= gp_e(gp_t('live_last')) ?><?= gp_tip('live_last') ?></label>
			<select class="gp-input" id="live-minutes" name="minutes">
				<?php foreach (array(1, 5, 15, 60) as $m): ?><option value="<?= $m ?>" <?= $m === $minutes ? 'selected' : '' ?>><?= gp_e(gp_plural($m, 'minute')) ?></option><?php endforeach; ?>
			</select>
		</div>
		<div class="gp-field" data-live-when="window" hidden>
			<label class="gp-label" for="live-start"><?= gp_e(gp_t('live_start')) ?><?= gp_tip('live_window') ?></label>
			<input class="gp-input gp-ltr" type="datetime-local" id="live-start" name="start" value="<?= gp_e(!empty($req['start']) ? date('Y-m-d\TH:i', (int)$req['start']) : '') ?>">
			<label class="gp-label" for="live-end"><?= gp_e(gp_t('live_end')) ?></label>
			<input class="gp-input gp-ltr" type="datetime-local" id="live-end" name="end" value="<?= gp_e(!empty($req['end']) ? date('Y-m-d\TH:i', (int)$req['end']) : '') ?>">
			<span class="gp-help"><?= gp_e(gp_t('live_tz')) ?>: <span class="gp-mono gp-ltr"><?= gp_e($tz) ?></span></span>
		</div>
		<div class="gp-field">
			<label class="gp-label" for="live-interval"><?= gp_e(gp_t('live_interval')) ?><?= gp_tip('live_interval') ?></label>
			<select class="gp-input" id="live-interval" name="interval_s">
				<?php foreach (array(2, 5, 10, 30, 0) as $iv): ?><option value="<?= $iv ?>" <?= $iv === 5 ? 'selected' : '' ?>><?= gp_e(gp_t('live_int_' . $iv)) ?></option><?php endforeach; ?>
			</select>
		</div>
		<div class="gp-field">
			<label class="gp-label" for="live-keep"><?= gp_e(gp_t('live_keep')) ?><?= gp_tip('live_keep') ?></label>
			<select class="gp-input" id="live-keep" name="keep">
				<?php foreach (array(200, 500, 1000) as $k): ?><option value="<?= $k ?>"><?= gp_num($k) ?></option><?php endforeach; ?>
			</select>
		</div>
	</div>
	<fieldset class="gp-field gp-fieldset">
		<legend class="gp-label"><?= gp_e(gp_t('live_show')) ?><?= gp_tip('live_show') ?></legend>
		<div class="gp-live-toggles">
			<?php foreach (gp_live_classes() as $c): ?>
			<label class="gp-check gp-live-toggle"><input type="checkbox" data-live-show="<?= gp_e($c) ?>" <?= in_array($c, $show, true) ? 'checked' : '' ?>> <span class="gp-live-dot gp-lc-<?= gp_e($c) ?>" aria-hidden="true"></span><?= gp_e(gp_t('live_cls_' . $c)) ?></label>
			<?php endforeach; ?>
		</div>
	</fieldset>
	<?php $adv_open = false; foreach (array_keys($flt) as $k) { if (isset($f[$k])) { $adv_open = true; } } ?>
	<details class="gp-more" <?= $adv_open ? 'open' : '' ?>>
		<summary><?= gp_e(gp_t('live_filters')) ?></summary>
		<div class="gp-filters gp-filters-3"><?php foreach (array_keys($flt) as $k) { echo $field($k); } ?></div>
	</details>
	<div class="gp-row-head">
		<button class="gp-btn gp-btn-primary" type="submit" id="live-apply"><?= gp_e(gp_t('live_apply')) ?></button>
		<button class="gp-btn gp-btn-ghost" type="button" id="live-pause" aria-pressed="false"><?= gp_e(gp_t('live_pause')) ?></button>
		<button class="gp-btn gp-btn-ghost" type="button" id="live-clear"><?= gp_e(gp_t('live_clear')) ?></button>
		<button class="gp-btn gp-btn-ghost" type="button" id="live-export"><?= gp_e(gp_t('live_export')) ?></button><?= gp_tip('live_export') ?>
		<span class="gp-badge gp-badge-off" id="live-state" role="status" aria-live="polite"></span>
	</div>
	<div class="gp-live-watchbar" id="live-watchbar"><span class="gp-label"><?= gp_e(gp_t('live_watch')) ?><?= gp_tip('live_watch') ?></span> <span id="live-watchlist"></span></div>
</form>

<div class="gp-card gp-live-strip" id="live-strip" aria-label="<?= gp_e(gp_t('live_chart_title')) ?>">
	<div class="gp-live-stats" id="live-stats"></div>
	<div class="gp-live-chart" id="live-chart"></div>
</div>

<div class="gp-live-main">
	<div class="gp-card gp-live-table">
		<div class="gp-live-row gp-live-head" aria-hidden="true">
			<span><?= gp_e(gp_t('logs_time')) ?></span><span><?= gp_e(gp_t('logs_act')) ?></span><span><?= gp_e(gp_t('logs_request')) ?></span><span><?= gp_e(gp_t('logs_ip')) ?></span>
			<span><?= gp_e(gp_t('logs_device')) ?></span><span><?= gp_e(gp_t('logs_reason')) ?></span><span><?= gp_e(gp_t('logs_score')) ?></span><span title="<?= gp_e(gp_t('logs_status')) ?>"><?= gp_e(gp_t('live_col_status')) ?></span>
		</div>
		<div id="live-rows" class="gp-live-rows" role="log" aria-live="off" aria-label="<?= gp_e(gp_t('live_title')) ?>"></div>
		<p class="gp-help gp-live-empty" id="live-empty"><?= gp_e(gp_t('live_waiting')) ?></p>
	</div>
	<aside class="gp-card gp-live-top" id="live-top" aria-label="<?= gp_e(gp_t('live_top_title')) ?>">
		<div class="gp-card-title"><?= gp_e(gp_t('live_top_title')) ?></div>
		<p class="gp-help"><?= gp_e(gp_t('live_top_hint')) ?></p>
		<div id="live-toplists"></div>
	</aside>
</div>

<aside class="gp-drawer" id="live-drawer" role="dialog" aria-modal="false" aria-labelledby="live-drawer-title" hidden>
	<div class="gp-drawer-head">
		<h2 class="gp-card-title" id="live-drawer-title"><?= gp_e(gp_t('live_drawer_title')) ?></h2>
		<button type="button" class="gp-btn gp-btn-ghost gp-btn-sm" id="live-drawer-close"><?= gp_e(gp_t('live_close')) ?></button>
	</div>
	<div id="live-drawer-body" class="gp-drawer-body"></div>
</aside>

<script type="application/json" id="live-cfg"><?= json_encode($cfg, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_INVALID_UTF8_SUBSTITUTE) ?></script>
<script>
(function () {
	'use strict';
	var cfg = JSON.parse(document.getElementById('live-cfg').textContent);
	var L = cfg.labels;
	var $ = function (id) { return document.getElementById(id); };
	var form = $('live-form'), rowsEl = $('live-rows'), emptyEl = $('live-empty'), stateEl = $('live-state');
	var CLASSES = ['allowed', 'challenged', 'captcha', 'blocked', 'ratelimited', 'monitor'];
	var st = { cursor: null, rows: [], byRid: {}, reasons: {}, timer: null, busy: false, gen: 0, userPaused: false, hover: false, hidden: document.hidden, done: false, err: false, watch: [], selected: null, lastPoll: 0 };

	function el(tag, cls, text) { var e = document.createElement(tag); if (cls) { e.className = cls; } if (text !== undefined && text !== null) { e.textContent = String(text); } return e; }
	function svgEl(tag, attrs) { var e = document.createElementNS('http://www.w3.org/2000/svg', tag); for (var k in attrs) { e.setAttribute(k, attrs[k]); } return e; }
	function pad(n) { return (n < 10 ? '0' : '') + n; }
	function sdate(ts) { return new Date((ts + cfg.tzOffset) * 1000); }          // the SERVER's wall clock, whatever the browser's zone is
	function hhmmss(ts) { var d = sdate(ts); return pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()) + ':' + pad(d.getUTCSeconds()); }
	function sameSite(h) { return typeof h === 'string' && /^index\.php\?r=[a-z]+/.test(h); }

	// ---- the watch list (kept in this browser only)
	try { st.watch = JSON.parse(localStorage.getItem('gp_live_watch') || '[]').filter(function (x) { return typeof x === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(x); }).slice(0, 20); } catch (e) { st.watch = []; }
	function saveWatch() { try { localStorage.setItem('gp_live_watch', JSON.stringify(st.watch)); } catch (e) { /* private window: the list lives until the page closes */ } }
	function renderWatch() {
		var box = $('live-watchlist'); box.textContent = '';
		if (!st.watch.length) { box.appendChild(el('span', 'gp-help', L.live_watch_none)); return; }
		st.watch.forEach(function (w) {
			var b = el('button', 'gp-chip gp-chip-btn', w); b.type = 'button'; b.title = L.live_unwatch;
			b.appendChild(el('span', 'gp-chip-x', ' ×'));
			b.addEventListener('click', function () { st.watch = st.watch.filter(function (x) { return x !== w; }); saveWatch(); renderWatch(); markWatched(); });
			box.appendChild(b);
		});
	}
	function isWatched(r) { return st.watch.indexOf(r.ip) >= 0 || (r.dev && st.watch.indexOf(r.dev) >= 0); }
	function markWatched() { st.rows.forEach(function (r) { r.w = isWatched(r) ? 1 : 0; if (r._el) { r._el.classList.toggle('gp-live-watched', !!r.w); } }); }

	// ---- the request (form -> query string)
	function showList() { var o = []; Array.prototype.forEach.call(form.querySelectorAll('[data-live-show]'), function (c) { if (c.checked) { o.push(c.getAttribute('data-live-show')); } }); return o; }
	function mode() { var m = form.querySelector('input[name=mode]:checked'); return m ? m.value : 'live'; }
	function queryParams(withCursor) {
		var p = new URLSearchParams();
		var fd = new FormData(form);
		fd.forEach(function (v, k) { if (k === 'interval_s' || k === 'keep' || k === 'r' || v === '') { return; } p.append(k, v); });
		var sh = showList(); if (sh.length) { p.set('show', sh.join(',')); }
		if (st.watch.length) { p.set('watch', st.watch.join(',')); }
		if (withCursor && st.cursor) { p.set('cursor', st.cursor); }
		return p;
	}
	function keep() { return parseInt($('live-keep').value, 10) || 200; }
	function interval() { return parseInt($('live-interval').value, 10) || 0; }

	// ---- state line and scheduling
	function setState() {
		var t = st.err ? L.live_state_err : st.done ? L.live_state_done : st.userPaused || interval() === 0 ? L.live_state_paused : st.hidden ? L.live_state_hidden : st.hover ? L.live_state_hover : L.live_state_live;
		stateEl.textContent = t;
		$('live-pause').textContent = st.userPaused ? L.live_resume : L.live_pause;
		$('live-pause').setAttribute('aria-pressed', st.userPaused ? 'true' : 'false');
	}
	function running() { return !st.userPaused && interval() > 0 && !st.hidden && !st.hover && !st.done; }
	function schedule(ms) {
		clearTimeout(st.timer); st.timer = null; setState();
		if (!running()) { return; }
		st.timer = setTimeout(poll, ms === undefined ? interval() * 1000 : ms);
	}

	// ---- one poll
	function poll(force) {
		if (st.busy || (force !== true && !running())) { return; }
		st.busy = true; var gen = st.gen;
		fetch('index.php?r=live&poll=1&' + queryParams(true).toString(), { credentials: 'same-origin', cache: 'no-store', headers: { 'Accept': 'application/json' } })
			.then(function (r) { var ct = r.headers.get('content-type') || ''; if (!r.ok || ct.indexOf('json') < 0) { throw new Error('http'); } return r.json(); })
			.then(function (d) { if (gen !== st.gen) { return; } st.err = false; handle(d); })
			.catch(function () { if (gen !== st.gen) { return; } st.err = true; schedule(Math.max(5000, interval() * 1000)); })
			.then(function () { st.busy = false; });
	}
	function handle(d) {
		if (!d || !d.ok) { st.err = false; stateEl.textContent = L.live_err_window; st.done = true; return; }
		st.cursor = d.cursor; st.lastPoll = d.now;
		for (var k in (d.reasons || {})) { st.reasons[k] = d.reasons[k]; }
		var oc = d.outcomes || {};
		for (var rid in oc) { var row = st.byRid[rid]; if (row) { row.st = oc[rid].st; row.by = oc[rid].by; row.dur = oc[rid].dur; if (row._el) { fillStatus(row); } } }
		var added = 0;
		(d.rows || []).forEach(function (r) {
			if (r.rid && st.byRid[r.rid]) { return; }
			if (oc[r.rid] && r.st === undefined) { r.st = oc[r.rid].st; }
			r.w = (r.w || isWatched(r)) ? 1 : 0;
			st.rows.push(r); if (r.rid) { st.byRid[r.rid] = r; } added++;
			var e = makeRow(r, !d.first); r._el = e; rowsEl.insertBefore(e, rowsEl.firstChild);
		});
		var max = keep();
		while (st.rows.length > max) { var old = st.rows.shift(); if (old.rid) { delete st.byRid[old.rid]; } if (old._el && old._el.parentNode) { old._el.parentNode.removeChild(old._el); } }
		if (d.done) { st.done = true; }
		emptyEl.hidden = st.rows.length > 0;
		stats(); tops();
		schedule(d.more ? 50 : undefined);
	}

	// ---- the rows
	function badgeFor(code) {
		var i = st.reasons[code] || { name: code, label: code, explain: '', class: 'gp-badge-off', monitor: 0, href: '' };
		var b = el('span', 'gp-badge gp-reason ' + String(i['class']).replace(/[^a-z-]/g, ''));
		b.title = i.explain || '';
		if (i.href && sameSite(i.href)) { var a = el('a', 'gp-reason-link', i.name); a.href = i.href; a.addEventListener('click', function (ev) { ev.stopPropagation(); }); b.appendChild(a); } else { b.appendChild(document.createTextNode(i.name)); }
		if (i.monitor) { b.appendChild(document.createTextNode(' ')); b.appendChild(el('span', 'gp-reason-mon', L.rsn_monitor_word)); }
		b.appendChild(document.createTextNode(' ')); b.appendChild(el('code', 'gp-reason-code gp-ltr', code));
		return b;
	}
	function fillStatus(r) {
		var c = r._el.querySelector('.gp-live-st'); c.textContent = '';
		if (r.st !== undefined && r.st !== null) { c.appendChild(el('span', 'gp-badge ' + (r.st >= 500 ? 'gp-badge-bad' : r.st >= 400 ? 'gp-badge-warn' : r.st >= 300 ? 'gp-badge-info' : 'gp-badge-on'), r.st)); } else { c.textContent = '—'; }
	}
	function clsWord(c) { return L['live_cls_' + c] || c; }
	function makeRow(r, fresh) {
		var e = el('div', 'gp-live-row gp-live-r-' + r.cls + (r.w ? ' gp-live-watched' : '') + (fresh ? ' gp-live-new' : ''));
		e.tabIndex = 0; e.setAttribute('role', 'button'); e.setAttribute('aria-label', L.live_drawer_title + ' ' + hhmmss(r.ts) + ' ' + (r.ip || ''));
		e.appendChild(el('time', 'gp-live-time gp-ltr', hhmmss(r.ts)));
		var act = el('span', 'gp-live-act');
		var ab = el('span', 'gp-badge gp-live-b-' + r.cls);
		ab.appendChild(document.createTextNode(clsWord(r.cls) + ' ')); ab.appendChild(el('code', 'gp-reason-code', r.act));
		act.appendChild(ab); if (r.w) { act.appendChild(el('span', 'gp-badge gp-badge-info', L.live_watched)); }
		e.appendChild(act);
		var req = el('span', 'gp-live-req gp-ltr'); req.appendChild(el('span', 'gp-log-method', r.m || '')); req.appendChild(document.createTextNode(' ')); req.appendChild(el('span', 'gp-live-path', r.p || '')); e.appendChild(req);
		var ip = el('span', 'gp-live-ip gp-ltr', r.ip || ''); if (r.cc) { ip.appendChild(document.createTextNode(' ')); ip.appendChild(el('span', 'gp-badge gp-badge-off', r.cc)); } e.appendChild(ip);
		e.appendChild(el('span', 'gp-live-dev gp-mono gp-ltr', r.dev ? String(r.dev).slice(0, 10) : '—'));
		var rs = el('span', 'gp-live-rs'); (r.rs || []).forEach(function (c) { if (typeof c === 'string') { rs.appendChild(badgeFor(c)); } }); e.appendChild(rs);
		e.appendChild(el('span', 'gp-live-score gp-ltr', (r.esc !== undefined ? r.esc : r.sc) + ''));
		e.appendChild(el('span', 'gp-live-st gp-ltr'));
		r._el = e; fillStatus(r);
		var open = function () { openDrawer(r); };
		e.addEventListener('click', open);
		e.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } });
		return e;
	}

	// ---- the header strip: numbers and the per-second chart (inline SVG)
	function stats() {
		var n = st.rows.length, cnt = {}, ips = {}, devs = {}, lo = Infinity, hi = 0;
		CLASSES.forEach(function (c) { cnt[c] = 0; });
		st.rows.forEach(function (r) { cnt[r.cls] = (cnt[r.cls] || 0) + 1; ips[r.ip] = 1; if (r.dev) { devs[r.dev] = 1; } if (r.ts < lo) { lo = r.ts; } if (r.ts > hi) { hi = r.ts; } });
		var span = Math.max(1, mode() === 'window' ? (hi - lo) : Math.min(60, Math.max(1, (st.lastPoll || hi) - (lo === Infinity ? hi : lo))));
		var recent = 0, now = mode() === 'window' ? hi : (st.lastPoll || hi);
		st.rows.forEach(function (r) { if (r.ts > now - 60) { recent++; } });
		var rate = mode() === 'window' ? (n / span) : (recent / Math.min(60, Math.max(1, span)));
		var box = $('live-stats'); box.textContent = '';
		var add = function (label, val, cls) { var s = el('div', 'gp-live-stat' + (cls ? ' ' + cls : '')); s.appendChild(el('div', 'gp-live-stat-v gp-ltr', val)); s.appendChild(el('div', 'gp-live-stat-k', label)); box.appendChild(s); };
		add(L.live_stat_req + ' (' + n + ' ' + L.live_rows_shown + ')', n);
		add(L.live_stat_rate, rate.toFixed(rate < 10 ? 1 : 0));
		CLASSES.forEach(function (c) { add(clsWord(c), cnt[c], 'gp-live-c-' + c); });
		add(L.live_stat_ips, Object.keys(ips).length); add(L.live_stat_devs, Object.keys(devs).length);
		chart(now, lo === Infinity ? now : lo, mode() === 'window');
	}
	function chart(now, lo, win) {
		var box = $('live-chart'); box.textContent = '';
		var bins = 60, t0 = win ? lo : now - 59, bw = win ? Math.max(1, ((now - lo) / bins)) : 1;
		var data = []; for (var i = 0; i < bins; i++) { data.push({ t: 0 }); }
		st.rows.forEach(function (r) { var i = Math.floor((r.ts - t0) / bw); if (i >= 0 && i < bins) { data[i].t++; data[i][r.cls] = (data[i][r.cls] || 0) + 1; } });
		var max = 1; data.forEach(function (d) { if (d.t > max) { max = d.t; } });
		var W = Math.max(300, box.clientWidth || 600), H = 70, pw = W / bins;
		var svg = svgEl('svg', { viewBox: '0 0 ' + W + ' ' + (H + 14), width: W, height: H + 14, role: 'img', 'class': 'gp-live-svg' });
		svg.setAttribute('aria-label', L.live_chart_title + ': max ' + max);
		var tt = svgEl('title', {}); tt.textContent = L.live_chart_title + ' (max ' + max + ')'; svg.appendChild(tt);
		data.forEach(function (d, i) {
			var y = H;
			CLASSES.forEach(function (c) { var v = d[c] || 0; if (!v) { return; } var h = Math.max(1, v / max * H); y -= h; svg.appendChild(svgEl('rect', { x: i * pw + 0.5, y: y, width: Math.max(1, pw - 1), height: h, 'class': 'gp-lb gp-lb-' + c })); });
		});
		svg.appendChild(svgEl('line', { x1: 0, y1: H + 0.5, x2: W, y2: H + 0.5, 'class': 'gp-lb-axis' }));
		var t1 = svgEl('text', { x: 2, y: H + 12, 'class': 'gp-lb-txt' }); t1.textContent = win ? hhmmss(lo) : '-60 ' + L.live_chart_secs; svg.appendChild(t1);
		var t2 = svgEl('text', { x: W - 2, y: H + 12, 'text-anchor': 'end', 'class': 'gp-lb-txt' }); t2.textContent = win ? hhmmss(now) : L.live_chart_now; svg.appendChild(t2);
		var t3 = svgEl('text', { x: W - 2, y: 9, 'text-anchor': 'end', 'class': 'gp-lb-txt' }); t3.textContent = max + ' / ' + (win ? Math.round(bw) + ' s' : '1 s'); svg.appendChild(t3);
		box.appendChild(svg);
		var lg = el('div', 'gp-live-legend');
		CLASSES.forEach(function (c) { var s = el('span', 'gp-live-legend-i'); s.appendChild(el('span', 'gp-live-dot gp-lc-' + c)); s.appendChild(document.createTextNode(clsWord(c))); lg.appendChild(s); });
		box.appendChild(lg);
	}

	// ---- "top right now": each entry adds a filter
	function tops() {
		var defs = [['ip', 'live_top_ip', 'ip'], ['dev', 'live_top_dev', 'dev'], ['ua', 'live_top_ua', 'ua'], ['path', 'live_top_path', 'p'], ['cc', 'live_top_cc', 'cc']];
		var box = $('live-toplists'); box.textContent = '';
		defs.forEach(function (d) {
			var m = {}; st.rows.forEach(function (r) { var v = r[d[2]]; if (v !== undefined && v !== null && v !== '') { m[v] = (m[v] || 0) + 1; } });
			var arr = Object.keys(m).map(function (k) { return [k, m[k]]; }).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 5);
			var sec = el('div', 'gp-live-top-sec'); sec.appendChild(el('div', 'gp-label', L[d[1]]));
			arr.forEach(function (x) {
				var b = el('button', 'gp-live-top-i', ''); b.type = 'button';
				b.appendChild(el('span', 'gp-live-top-v gp-mono gp-ltr', String(x[0]).slice(0, 60))); b.appendChild(el('span', 'gp-live-top-n', x[1]));
				b.title = String(x[0]); b.addEventListener('click', function () { addFilter(d[0], x[0]); });
				sec.appendChild(b);
			});
			if (!arr.length) { sec.appendChild(el('span', 'gp-help', L.live_stat_none)); }
			box.appendChild(sec);
		});
	}
	function addFilter(key, value) {
		var input = form.elements[key]; if (!input) { return; }
		var opSel = form.elements[key + '_op']; if (opSel) { opSel.value = 'is'; }
		if (key === 'ua' || key === 'path') { input.value = value; }
		else { var have = input.value.split(',').map(function (s) { return s.trim(); }).filter(Boolean); if (have.indexOf(String(value)) < 0) { have.push(String(value)); } input.value = have.join(','); }
		var det = input.closest('details'); if (det) { det.open = true; }
		restart();
	}

	// ---- the details drawer, quick actions, watch
	var FIELD_ORDER = ['ts', 'rid', 'ip', 'dev', 'm', 'p', 'q', 'ua', 'act', 'sh', 'hold', 'ovr', 'tok', 'tl', 'sc', 'esc', 'rep', 'ml', 'clf', 'botv', 'bot', 'cc', 'asn', 'cap', 'ct', 'hs', 'hf', 'gate', 'nav', 'aj', 'hc', 'sf', 'al', 'ref', 'cd', 'cdh', 'cdd', 'ciu', 'ci', 'rd', 'hp', 'st', 'by', 'dur', 'ms', 'v', 'uah'];
	var NAMES = { ts: L.logs_time, ip: L.logs_ip, dev: L.logs_device, m: L.logs_method, p: L.logs_path, q: L.logs_query, ua: L.logs_ua, sc: L.logs_sc, esc: L.logs_esc, rep: L.id_reputation, ml: L.id_ml, clf: L.id_clf, cc: L.geo_cc, asn: L.geo_asn, ref: L.logs_referer, st: L.logs_status, by: L.logs_bytes, dur: L.logs_duration + ' (ms)', rid: L.logs_rid };
	function fieldName(k) { return cfg.fieldNames[k] || NAMES[k] || k; }
	function fieldValue(k, v) {
		if (k === 'ts') { var d = sdate(v); return d.getUTCFullYear() + '-' + pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + hhmmss(v); }
		if (k === 'act') { var a = cfg.actNames[v]; return a ? a + ' (' + v + ')' : String(v); }
		var vn = cfg.valueNames[k]; if (vn && vn[v] !== undefined) { return vn[v] + ' (' + v + ')'; }
		if (v === true) { return L.yes; } if (v === false) { return L.no; }
		return String(v);
	}
	function backUrl() { var q = 'index.php?r=live&' + queryParams(false).toString(); return q.length <= 590 ? q : 'index.php?r=live'; }
	function quickForm(identity, who) {
		var f = el('form', 'gp-quick'); f.method = 'post'; f.action = 'index.php?r=overrides';
		[['csrf', cfg.csrf], ['identity', identity], ['from', 'quick'], ['back', backUrl()]].forEach(function (p) { var i = document.createElement('input'); i.type = 'hidden'; i.name = p[0]; i.value = p[1]; f.appendChild(i); });
		var w = el('span', 'gp-quick-who gp-ltr'); w.appendChild(el('b', '', who + ' ')); w.appendChild(el('span', 'gp-mono', identity)); f.appendChild(w);
		cfg.quick.forEach(function (q) { var b = el('button', 'gp-btn gp-btn-ghost gp-btn-sm', q.label); b.type = 'submit'; b.name = 'quick'; b.value = q.key; f.appendChild(b); });
		var c = el('a', 'gp-btn gp-btn-ghost gp-btn-sm', cfg.quickWho.custom); c.href = 'index.php?r=overrides&new=' + encodeURIComponent(identity) + '#override-add'; f.appendChild(c);
		return f;
	}
	function openDrawer(r) {
		st.selected = r; var body = $('live-drawer-body'); body.textContent = '';
		var head = el('div', 'gp-live-d-head'); head.appendChild(el('span', 'gp-badge gp-live-b-' + r.cls, clsWord(r.cls))); head.appendChild(el('code', 'gp-reason-code', r.act)); body.appendChild(head);
		if ((r.rs || []).length) { var rs = el('div', 'gp-live-d-rs'); r.rs.forEach(function (c) { if (typeof c === 'string') { rs.appendChild(badgeFor(c)); } }); body.appendChild(rs); }
		var ids = el('div', 'gp-live-d-links');
		[[r.dev, 'dev'], [r.ip, 'ip']].forEach(function (x) {
			if (!x[0]) { return; }
			var a = el('a', 'gp-btn gp-btn-ghost gp-btn-sm', L.live_identity + ': ' + String(x[0]).slice(0, 24)); a.href = 'index.php?r=identity&id=' + encodeURIComponent(x[0]); ids.appendChild(a);
			var w = st.watch.indexOf(x[0]) >= 0, b = el('button', 'gp-btn gp-btn-ghost gp-btn-sm', (w ? L.live_unwatch : L.live_watch_add) + ' ' + String(x[0]).slice(0, 16)); b.type = 'button';
			b.addEventListener('click', function () { if (w) { st.watch = st.watch.filter(function (y) { return y !== x[0]; }); } else if (st.watch.length < 20) { st.watch.push(x[0]); } saveWatch(); renderWatch(); markWatched(); openDrawer(r); });
			ids.appendChild(b);
		});
		var lg = el('a', 'gp-btn gp-btn-ghost gp-btn-sm', L.live_open_logs); lg.href = 'index.php?r=logs' + (r.ip ? '&ip=' + encodeURIComponent(r.ip) : ''); ids.appendChild(lg);
		body.appendChild(ids);
		if (cfg.canQuick) { body.appendChild(el('h3', 'gp-log-sec-title', L.live_quick)); if (r.ip) { body.appendChild(quickForm(r.ip, cfg.quickWho.ip)); } if (r.dev) { body.appendChild(quickForm(r.dev, cfg.quickWho.dev)); } }
		body.appendChild(el('h3', 'gp-log-sec-title', L.live_fields));
		var dl = el('dl', 'gp-props');
		var keys = FIELD_ORDER.filter(function (k) { return r[k] !== undefined && r[k] !== null && r[k] !== ''; });
		Object.keys(r).forEach(function (k) { if (k.charAt(0) !== '_' && ['rs', 'cls', 'crawler', 'w'].indexOf(k) < 0 && keys.indexOf(k) < 0 && r[k] !== null && r[k] !== '') { keys.push(k); } });
		keys.forEach(function (k) { var row = el('div', 'gp-prop'); var dt = el('dt', 'gp-prop-name', fieldName(k) + ' '); dt.appendChild(el('code', 'gp-prop-key', k)); row.appendChild(dt); row.appendChild(el('dd', 'gp-prop-val gp-ltr', fieldValue(k, r[k]))); dl.appendChild(row); });
		body.appendChild(dl);
		$('live-drawer').hidden = false; $('live-drawer-close').focus();
	}
	function closeDrawer() { $('live-drawer').hidden = true; if (st.selected && st.selected._el) { st.selected._el.focus(); } st.selected = null; }
	$('live-drawer-close').addEventListener('click', closeDrawer);
	document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !$('live-drawer').hidden) { closeDrawer(); } });

	// ---- CSV of the rows on screen (short codes, plus the reasons spelled out)
	function csvCell(v) { var s = v === undefined || v === null ? '' : (typeof v === 'object' ? JSON.stringify(v) : String(v)); if (s !== '' && '=+-@\t\r'.indexOf(s.charAt(0)) >= 0) { s = "'" + s; } return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; }
	function exportCsv() {
		var cols = ['ts', 'rid', 'ip', 'dev', 'm', 'p', 'q', 'act', 'sh', 'hold', 'ovr', 'tok', 'sc', 'esc', 'rs', 'rep', 'ml', 'clf', 'botv', 'cc', 'asn', 'st', 'by', 'dur'];
		var out = [cols.concat(['rs_names']).join(',')];
		st.rows.slice().reverse().forEach(function (r) { var line = cols.map(function (c) { return csvCell(c === 'rs' ? (r.rs || []).join(' ') : r[c]); }); line.push(csvCell((r.rs || []).map(function (c) { return (st.reasons[c] || {}).label || c; }).join(' | '))); out.push(line.join(',')); });
		var blob = new Blob(['﻿' + out.join('\r\n') + '\r\n'], { type: 'text/csv;charset=utf-8' });
		var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'guard-live.csv'; document.body.appendChild(a); a.click();
		setTimeout(function () { URL.revokeObjectURL(a.href); document.body.removeChild(a); }, 1000);
	}

	// ---- controls
	function whenModes() { var m = mode(); Array.prototype.forEach.call(form.querySelectorAll('[data-live-when]'), function (e) { e.hidden = e.getAttribute('data-live-when') !== m; }); }
	function reset() { st.gen++; st.cursor = null; st.rows = []; st.byRid = {}; st.done = false; st.err = false; st.busy = false; rowsEl.textContent = ''; emptyEl.hidden = false; closeDrawerQuiet(); stats(); tops(); }
	function closeDrawerQuiet() { $('live-drawer').hidden = true; st.selected = null; }
	function url() { return 'index.php?r=live&' + queryParams(false).toString(); }
	function restart() { reset(); try { history.replaceState(null, '', url()); } catch (e) { /* no history API */ } clearTimeout(st.timer); st.timer = null; setState(); poll(true); }
	form.addEventListener('submit', function (e) { e.preventDefault(); if (mode() === 'window' && !(form.elements.start.value && form.elements.end.value)) { stateEl.textContent = L.live_err_window; return; } restart(); });
	form.addEventListener('change', function (e) { if (e.target.name === 'mode') { whenModes(); } if (e.target.name === 'interval_s') { schedule(); } if (e.target.name === 'keep') { /* applied at the next row */ } });
	$('live-pause').addEventListener('click', function () { st.userPaused = !st.userPaused; if (st.userPaused) { clearTimeout(st.timer); st.timer = null; setState(); } else { poll(); schedule(); } });
	$('live-clear').addEventListener('click', function () { restart(); });
	$('live-export').addEventListener('click', exportCsv);
	$('live-rows').addEventListener('mouseenter', function () { st.hover = true; clearTimeout(st.timer); st.timer = null; setState(); });
	$('live-rows').addEventListener('mouseleave', function () { st.hover = false; if (running()) { poll(); } setState(); });
	document.addEventListener('visibilitychange', function () { st.hidden = document.hidden; if (st.hidden) { clearTimeout(st.timer); st.timer = null; setState(); } else if (running()) { poll(); } else { setState(); } });

	// ---- start
	renderWatch(); whenModes(); stats(); tops(); setState();
	if (mode() === 'window' && !(form.elements.start.value && form.elements.end.value)) { stateEl.textContent = L.live_err_window; } else { poll(true); }
	window.gpLive = { state: st, poll: poll, restart: restart };
})();
</script>
