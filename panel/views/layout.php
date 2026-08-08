<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; } ?>
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
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
			'replay'    => array('nav_replay', '&#8644;'),
			'models'    => array('nav_models', '&#9707;'),
			'settings'  => array('nav_settings', '&#9881;'),
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
// block removed. No framework, no bundler, no network call.
(function () {
	'use strict';
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
