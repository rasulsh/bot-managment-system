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
<body class="gp-body">

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
			<span class="gp-user"><?= gp_e($user) ?></span>
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
			'replay'    => array('nav_replay', '&#8644;'),
			'models'    => array('nav_models', '&#9707;'),
			'settings'  => array('nav_settings', '&#9881;'),
			'config_file' => array('nav_config_file', '&#123;&#125;'),
			'jobs'      => array('nav_jobs', '&#8635;'),
			'audit'     => array('nav_audit', '&#9998;'),
		);
		foreach ($gp_nav as $gp_key => $gp_item):
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

		<?php foreach (($flash ?? array()) as $gp_msg): ?>
		<div class="gp-flash gp-flash-<?= gp_e($gp_msg['kind']) ?>" role="status">
			<?= gp_e($gp_msg['message']) ?>
		</div>
		<?php endforeach; ?>

		<?php require $view_file; ?>

	</main>
</div>

<?php if (!empty($user)): ?>
<nav class="gp-bottomnav" aria-label="<?= gp_e(gp_t('app_sub')) ?>">
	<?php foreach (array('dashboard', 'logs', 'overrides', 'replay', 'settings') as $gp_key):
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
	// Confirm dialogs for anything destructive or site-wide.
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
		select(box.getAttribute('data-open') || fromHash() || tabs[0].getAttribute('data-tab'), false, false);
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
		var place = function (tip) {
			var box = tip.querySelector('.gp-tip-box');
			if (!box) { return; }
			box.style.insetInlineStart = '';
			box.style.transform = '';
			var r = box.getBoundingClientRect();
			var w = document.documentElement.clientWidth;
			var shift = 0;
			if (r.right > w - 8) { shift = (w - 8) - r.right; }
			if (r.left + shift < 8) { shift = 8 - r.left; }
			if (shift) { box.style.transform = 'translateX(' + Math.round(shift) + 'px)'; }
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
