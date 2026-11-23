<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; } ?>
<!doctype html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive,nosnippet">
<meta name="color-scheme" content="light dark">
<script>
// Apply the saved theme before the first paint, so there is no flash. "system"
// (nothing saved) leaves the attribute off and the OS preference decides.
(function () {
	try {
		var t = window.localStorage.getItem('gp_theme');
		if (t === 'light' || t === 'dark') { document.documentElement.setAttribute('data-theme', t); }
	} catch (e) {}
})();
</script>
<title><?= gp_e(gp_t('app_name')) ?> — <?= gp_e(gp_t('app_sub')) ?></title>
<link rel="stylesheet" href="assets/app.css">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><text y='14' font-size='14'>&#128737;</text></svg>">
</head>
<body class="gp-body"<?= (!empty($user) && ($role ?? '') !== 'admin') ? ' data-readonly="1"' : '' ?>>

<?php if (!empty($user)): ?>
<header class="gp-topbar">
	<div class="gp-topbar-inner">
		<a class="gp-brand" href="index.php?r=dashboard">
			<span class="gp-brand-mark" aria-hidden="true">&#9679;</span>
			<span class="gp-brand-text">
				<strong><?= gp_e(gp_t('app_name')) ?></strong>
				<small><?= gp_e(gp_t('app_sub')) ?></small>
			</span>
		</a>
		<form method="post" action="index.php?r=logout" class="gp-topbar-actions">
			<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
			<?php require __DIR__ . '/theme_switch.php'; ?>
			<a class="gp-user" href="index.php?r=account" title="<?= gp_e(gp_t('nav_account')) ?>"><?= gp_e($user) ?> <span class="gp-user-role">(<?= gp_e(gp_users_role_label($role ?? '')) ?>)</span></a>
			<button type="submit" class="gp-btn gp-btn-ghost"><?= gp_e(gp_t('logout')) ?></button>
		</form>
	</div>
</header>

<div class="gp-shell">
	<nav class="gp-sidenav" aria-label="<?= gp_e(gp_t('app_sub')) ?>">
		<?php
		$gp_nav = array(
			'dashboard' => array('nav_dashboard', '&#9632;'),
			'logs'      => array('nav_logs', '&#9776;'),
			'identity'  => array('id_title', '&#9678;'),
			'overrides' => array('nav_overrides', '&#9873;'),
			'rules'     => array('nav_rules', '&#9888;'),
			'geo'       => array('nav_geo', '&#9737;'),
			'iplists'   => array('nav_iplists', '&#9783;'),
			'replay'    => array('nav_replay', '&#8644;'),
			'models'    => array('nav_models', '&#9707;'),
			'settings'  => array('nav_settings', '&#9881;'),
			'config_file' => array('nav_config_file', '&#123;&#125;'),
			'jobs'      => array('nav_jobs', '&#8635;'),
			'audit'     => array('nav_audit', '&#9998;'),
			'update'    => array('nav_update', '&#8679;'),
			'users'     => array('nav_users', '&#9786;'),
			'account'   => array('nav_account', '&#9881;'),
		);
		foreach ($gp_nav as $gp_key => $gp_item):
			if (!gp_acl_allows($role ?? '', $gp_key, 'GET')) { continue; }
			$gp_active = ($route === $gp_key) ? ' gp-nav-active' : '';
		?>
		<a class="gp-nav-item<?= $gp_active ?>" href="index.php?r=<?= gp_e($gp_key) ?>">
			<span class="gp-nav-icon" aria-hidden="true"><?= $gp_item[1] ?></span>
			<span class="gp-nav-label"><?= gp_e(gp_t($gp_item[0])) ?></span>
		</a>
		<?php endforeach; ?>
	</nav>

	<main class="gp-main">
<?php else: ?>
<div class="gp-shell gp-shell-bare">
	<main class="gp-main gp-main-bare">
<?php endif; ?>

		<?php if (!empty($user) && ($role ?? '') === 'demo'): ?>
		<div class="gp-note gp-note-strong" role="status" data-demo-banner><?= gp_e(gp_t('demo_banner')) ?></div>
		<?php elseif (!empty($user) && ($role ?? '') === 'operator'): ?>
		<div class="gp-note" role="status"><?= gp_e(gp_t('operator_banner')) ?></div>
		<?php endif; ?>

		<?php
		// The view first: it draws the messages of its own sections (gp_msg). What is left (no section, or a section this page
		// does not show) is drawn here at the top, so a message is never lost.
		ob_start();
		require $view_file;
		$gp_view_html = ob_get_clean();
		$gp_top = '';
		foreach (($flash ?? array()) as $gp_m) {
			if (!empty($gp_m['section']) && !empty($GLOBALS['gp_msg_drawn'][$gp_m['section']])) { continue; }
			$gp_top .= '<div class="gp-flash gp-flash-' . gp_e($gp_m['kind']) . '" role="' . ($gp_m['kind'] === 'error' ? 'alert' : 'status') . '">' . gp_e($gp_m['message']) . '</div>';
		}
		if ($gp_top !== '') { echo '<div class="gp-msg" id="msg-top" tabindex="-1" data-gp-msg>' . $gp_top . '</div>'; }
		echo $gp_view_html;
		?>

		<?php if (!empty($user)): $gp_ver = function_exists('gp_upd_version') ? gp_upd_version() : ''; ?>
		<p class="gp-help gp-footer" style="margin-top:2rem"><?= gp_e(gp_t('footer_version')) ?>: <span class="gp-mono"><?= gp_e($gp_ver !== '' ? $gp_ver : gp_t('unknown')) ?></span></p>
		<?php endif; ?>

	</main>
</div>

<?php if (!empty($user)): ?>
<nav class="gp-bottomnav" aria-label="<?= gp_e(gp_t('app_sub')) ?>">
	<?php foreach (array('dashboard', 'logs', 'overrides', 'replay', 'settings', 'account') as $gp_key):
		if (!gp_acl_allows($role ?? '', $gp_key, 'GET')) { continue; }
		$gp_active = ($route === $gp_key) ? ' gp-nav-active' : ''; ?>
	<a class="gp-bottom-item<?= $gp_active ?>" href="index.php?r=<?= gp_e($gp_key) ?>">
		<span class="gp-nav-icon" aria-hidden="true"><?= $gp_nav[$gp_key][1] ?></span>
		<span class="gp-bottom-label"><?= gp_e(gp_t($gp_nav[$gp_key][0])) ?></span>
	</a>
	<?php endforeach; ?>
</nav>
<?php endif; ?>

<script>
// Progressive enhancement only: every action on every page works with this
// block removed (the theme then simply follows the system setting). No framework, no bundler, no network call.
(function () {
	'use strict';
	// Theme switcher: light, dark, or follow the system. The choice lives in this
	// browser (localStorage) and is applied before first paint by the head script.
	(function () {
		var buttons = document.querySelectorAll('[data-theme-set]');
		var current = function () {
			try {
				var t = window.localStorage.getItem('gp_theme');
				return (t === 'light' || t === 'dark') ? t : 'system';
			} catch (e) { return 'system'; }
		};
		var show = function (value) {
			buttons.forEach(function (b) {
				b.setAttribute('aria-pressed', b.getAttribute('data-theme-set') === value ? 'true' : 'false');
			});
		};
		show(current());
		buttons.forEach(function (button) {
			button.addEventListener('click', function () {
				var value = button.getAttribute('data-theme-set');
				try {
					if (value === 'system') { window.localStorage.removeItem('gp_theme'); }
					else { window.localStorage.setItem('gp_theme', value); }
				} catch (e) {}
				if (value === 'system') { document.documentElement.removeAttribute('data-theme'); }
				else { document.documentElement.setAttribute('data-theme', value); }
				show(value);
			});
		});
	})();
	// Read-only roles: a form that the server would answer with 403 gets its buttons disabled. This is only courtesy:
	// the permission map in panel/acl.php is what protects, and it is checked on the server for every request.
	if (document.body.hasAttribute('data-readonly')) {
		document.querySelectorAll('main form[method=post], main form[method=POST]').forEach(function (form) {
			if (form.hasAttribute('data-allow')) { return; }
			form.querySelectorAll('button, input[type=submit], input[type=file]').forEach(function (b) { b.disabled = true; });
			form.setAttribute('aria-disabled', 'true');
		});
	}
	// Confirm dialogs for anything destructive or site-wide.
	// Settings > CAPTCHA: redraw the sample image with the values typed in the form (nothing is saved).
	(function () {
		var img = document.getElementById('cap-preview'), btn = document.getElementById('cap-preview-btn');
		if (!img || !btn) { return; }
		var keys = ['level', 'length', 'charset', 'warp', 'noise', 'overlap'];
		btn.addEventListener('click', function () {
			var q = ['r=captcha_preview', '_=' + Date.now()], i, el;
			for (i = 0; i < keys.length; i++) {
				el = document.querySelector('[name="f[captcha.' + keys[i] + ']"]');
				if (el && el.value !== '') { q.push(keys[i] + '=' + encodeURIComponent(el.value)); }
			}
			img.src = 'index.php?' + q.join('&');
		});
	})();
	document.querySelectorAll('form[data-confirm]').forEach(function (form) {
		form.addEventListener('submit', function (event) {
			if (!window.confirm(form.getAttribute('data-confirm'))) {
				event.preventDefault();
			}
		});
	});
	// Expandable log rows.
	document.querySelectorAll('[data-toggle]').forEach(function (button) {
		button.addEventListener('click', function () {
			var target = document.getElementById(button.getAttribute('data-toggle'));
			if (!target) { return; }
			var hidden = target.hasAttribute('hidden');
			if (hidden) { target.removeAttribute('hidden'); }
			else { target.setAttribute('hidden', ''); }
			button.setAttribute('aria-expanded', hidden ? 'true' : 'false');
		});
	});
	// Tabs: the markup already contains every panel, stacked. With the script the
	// strip appears, only the active panel shows, the arrow keys move between tabs
	// (role=tablist), and the URL hash (#group-tab) remembers the tab. A server-side
	// error opens the tab that holds the first error (data-open) over the hash.
	document.querySelectorAll('[data-tabs]').forEach(function (box) {
		var group = box.getAttribute('data-tabs');
		var tabs = Array.prototype.slice.call(box.querySelectorAll(':scope > .gp-tablist > [role=tab]'));
		var panels = Array.prototype.slice.call(box.querySelectorAll(':scope > [role=tabpanel]'));
		if (!tabs.length) { return; }
		box.classList.add('gp-tabs-on');
		var select = function (id, focus, remember) {
			var found = false;
			tabs.forEach(function (t) { if (t.getAttribute('data-tab') === id) { found = true; } });
			if (!found) { id = tabs[0].getAttribute('data-tab'); }
			tabs.forEach(function (t) {
				var on = t.getAttribute('data-tab') === id;
				t.setAttribute('aria-selected', on ? 'true' : 'false');
				t.setAttribute('tabindex', on ? '0' : '-1');
				if (on && focus) { t.focus(); }
			});
			panels.forEach(function (p) {
				if (p.getAttribute('data-panel') === id) { p.removeAttribute('hidden'); } else { p.setAttribute('hidden', ''); }
			});
			if (remember) { try { window.history.replaceState(null, '', '#' + group + '-' + id); } catch (e) {} }
		};
		var fromHash = function () {
			var h = window.location.hash.replace(/^#/, '');
			return h.indexOf(group + '-') === 0 ? h.slice(group.length + 1) : '';
		};
		var msg = box.querySelector(':scope > [role=tabpanel] [data-gp-msg]');       // a message in context: show its tab
		select(box.getAttribute('data-open') || (msg ? msg.closest('[role=tabpanel]').getAttribute('data-panel') : '') || fromHash() || tabs[0].getAttribute('data-tab'), false, false);
		tabs.forEach(function (t, i) {
			t.addEventListener('click', function () { select(t.getAttribute('data-tab'), false, true); });
			t.addEventListener('keydown', function (e) {
				var to = -1;
				if (e.key === 'ArrowRight') { to = (i + 1) % tabs.length; }
				else if (e.key === 'ArrowLeft') { to = (i + tabs.length - 1) % tabs.length; }
				else if (e.key === 'Home') { to = 0; }
				else if (e.key === 'End') { to = tabs.length - 1; }
				if (to >= 0) { e.preventDefault(); select(tabs[to].getAttribute('data-tab'), true, true); }
			});
		});
		window.addEventListener('hashchange', function () { var id = fromHash(); if (id) { select(id, false, false); } });
	});
	// Help tooltips: hover and keyboard focus work in CSS alone. A tap toggles the
	// bubble, Esc or a tap anywhere else closes it, and the bubble is nudged back
	// inside the screen when it would be cut off at an edge.
	(function () {
		var tips = document.querySelectorAll('.gp-tip');
		// The bubble is position:fixed and placed from the button's rectangle, so a scrolling table or a card with overflow can never
		// clip it: below the button, flipped above when there is no room, and kept inside the screen sideways.
		var place = function (tip) {
			var box = tip.querySelector('.gp-tip-box');
			var btn = tip.querySelector('.gp-tip-btn');
			if (!box || !btn) { return; }
			var b = btn.getBoundingClientRect();
			var vw = document.documentElement.clientWidth, vh = window.innerHeight || document.documentElement.clientHeight;
			var w = box.offsetWidth, h = box.offsetHeight;
			var left = Math.min(Math.max(8, b.left), Math.max(8, vw - w - 8));
			var top = b.bottom + 4;
			if (top + h > vh - 8 && b.top - 4 - h >= 8) { top = b.top - 4 - h; }
			box.style.left = Math.round(left) + 'px';
			box.style.top = Math.round(top) + 'px';
		};
		var closeAll = function (except) {
			tips.forEach(function (t) { if (t !== except) { t.classList.remove('gp-open'); } });
		};
		tips.forEach(function (tip) {
			var btn = tip.querySelector('.gp-tip-btn');
			btn.addEventListener('click', function (e) {
				e.preventDefault();
				e.stopPropagation();
				closeAll(tip);
				tip.classList.toggle('gp-open');
				place(tip);
			});
			tip.addEventListener('mouseenter', function () { place(tip); });
			btn.addEventListener('focus', function () { place(tip); });
		});
		document.addEventListener('click', function (e) { if (!e.target.closest || !e.target.closest('.gp-tip')) { closeAll(null); } });
		window.addEventListener('scroll', function () { closeAll(null); }, true);     // a fixed bubble would stay behind a scrolled button
		window.addEventListener('resize', function () { closeAll(null); });
		document.addEventListener('keydown', function (e) {
			if (e.key !== 'Escape') { return; }
			closeAll(null);
			tips.forEach(function (t) { t.classList.add('gp-esc'); });
			if (document.activeElement && document.activeElement.classList && document.activeElement.classList.contains('gp-tip-btn')) { document.activeElement.blur(); }
		});
		tips.forEach(function (t) {
			t.addEventListener('mouseleave', function () { t.classList.remove('gp-esc'); });
			t.addEventListener('mouseenter', function () { t.classList.remove('gp-esc'); });
			t.addEventListener('focusin', function () { t.classList.remove('gp-esc'); });
		});
	})();
	// "Share link": copy the absolute filter URL; without clipboard access the link
	// simply opens as a normal link.
	document.querySelectorAll('[data-copy-link]').forEach(function (a) {
		a.addEventListener('click', function (e) {
			if (!navigator.clipboard || !navigator.clipboard.writeText) { return; }
			e.preventDefault();
			navigator.clipboard.writeText(new URL(a.getAttribute('href'), window.location.href).href).then(function () {
				var t = a.textContent; a.textContent = '\u2713'; window.setTimeout(function () { a.textContent = t; }, 1200);
			}, function () { window.location.href = a.href; });
		});
	});
	// A message in context: bring the first one into view and move focus to it (also when the page was not reached through the
	// #msg-... fragment, e.g. a form re-drawn with its errors after a refused save). Without JS the fragment still scrolls.
	(function () {
		var m = document.querySelector('[data-gp-msg]');
		if (!m) { return; }
		var r = m.getBoundingClientRect();
		if (r.top < 0 || r.bottom > (window.innerHeight || document.documentElement.clientHeight)) { m.scrollIntoView({ block: 'center' }); }
		try { m.focus({ preventScroll: true }); } catch (e) { m.focus(); }
	})();
	// Multi-select pick lists (data-gp-ms): the text input stays the source of truth (it is what the form submits and what works
	// without JavaScript); the checkboxes mirror its comma list and write back to it. Esc or a click outside closes the list.
	(function () {
		var boxes = document.querySelectorAll('[data-gp-ms]');
		var split = function (t) { return t.split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x !== ''; }); };
		var closeAll = function (except) {
			boxes.forEach(function (b) {
				if (b === except) { return; }
				var p = b.querySelector('[data-gp-ms-panel]'), t = b.querySelector('[data-gp-ms-toggle]');
				if (p && !p.hidden) { p.hidden = true; if (t) { t.setAttribute('aria-expanded', 'false'); } }
			});
		};
		boxes.forEach(function (box) {
			var input = box.querySelector('input[type=text]');
			var toggle = box.querySelector('[data-gp-ms-toggle]');
			var panel = box.querySelector('[data-gp-ms-panel]');
			if (!input || !toggle || !panel) { return; }
			var checks = panel.querySelectorAll('input[type=checkbox]');
			var fromInput = function () {
				var have = split(input.value).map(function (x) { return x.toLowerCase(); });
				checks.forEach(function (c) { c.checked = have.indexOf(c.value.toLowerCase()) !== -1; });
			};
			var toInput = function () {
				var keep = split(input.value).filter(function (x) {
					return !Array.prototype.some.call(checks, function (c) { return c.value.toLowerCase() === x.toLowerCase(); });
				});
				var picked = [];
				checks.forEach(function (c) { if (c.checked) { picked.push(c.value); } });
				input.value = picked.concat(keep).join(',');
			};
			var setOpen = function (open) {
				panel.hidden = !open;
				toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
				if (open) { closeAll(box); fromInput(); }
			};
			toggle.hidden = false;
			box.classList.add('gp-ms-on');                  // the button sits inside the text box; leave room for it
			toggle.addEventListener('click', function () { setOpen(panel.hidden); });
			checks.forEach(function (c) { c.addEventListener('change', toInput); });
			input.addEventListener('input', fromInput);
			box.addEventListener('keydown', function (e) {
				if (e.key === 'Escape' && !panel.hidden) { e.preventDefault(); setOpen(false); toggle.focus(); }
			});
			fromInput();
		});
		document.addEventListener('click', function (e) {
			var own = e.target && e.target.closest ? e.target.closest('[data-gp-ms]') : null;
			closeAll(own);                                   // every list except the one that was clicked in
		});
	})();
	// Upload size check (data-gp-max-bytes on a file input): the web server answers a body over ITS limit with its own error page,
	// which the panel never sees, so the size is checked here before anything is sent. The message text comes from the page
	// (data-gp-too-big, with {size} and {max} placeholders); without JavaScript the server-side checks still apply.
	document.querySelectorAll('input[type=file][data-gp-max-bytes]').forEach(function (input) {
		var max = parseInt(input.getAttribute('data-gp-max-bytes'), 10);
		var form = input.form;
		var msg = form ? form.querySelector('[data-gp-upload-msg]') : null;
		var send = form ? form.querySelector('[data-gp-upload-send]') : null;
		var mib = function (n) { return (n / 1048576).toFixed(1) + ' MiB'; };
		var check = function () {
			var f = input.files && input.files[0];
			var big = !!(f && max > 0 && f.size > max);
			if (msg) {
				msg.hidden = !big;
				msg.textContent = big ? (input.getAttribute('data-gp-too-big') || '').replace('{size}', mib(f.size)).replace('{max}', mib(max)) : '';
			}
			if (send) { send.disabled = big; }
			if (big) { input.value = ''; if (msg) { msg.setAttribute('role', 'alert'); } }
		};
		input.addEventListener('change', check);
		if (form) { form.addEventListener('submit', function (e) { check(); if (send && send.disabled) { e.preventDefault(); } }); }
	});
	// Live slider read-outs on the replay page.
	document.querySelectorAll('input[type=range][data-output]').forEach(function (input) {
		var out = document.getElementById(input.getAttribute('data-output'));
		if (!out) { return; }
		var sync = function () { out.textContent = input.value; };
		input.addEventListener('input', sync);
		sync();
	});
})();
</script>
</body>
</html>
