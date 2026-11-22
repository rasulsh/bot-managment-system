<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Demo role dashboard. The only variable is $demo (gp_demo_model(): numbers and fixed words, nothing else).
$kt = array('requests' => 'dash_k_requests', 'allowed' => 'dash_k_allowed', 'blocked' => 'dash_k_blocked', 'limited' => 'dash_k_limited',
	'challenged' => 'dash_k_challenged', 'challenge_success' => 'dash_k_success', 'rule_hits' => 'dash_k_rules', 'honeypot' => 'dash_k_honeypot', 'degraded' => 'dash_k_degraded');
$ct = array('captcha_shown' => 'dash_c_shown', 'captcha_solved' => 'dash_c_solved', 'captcha_failed' => 'dash_c_failed', 'captcha_expired' => 'dash_c_expired', 'captcha_solve_rate' => 'dash_c_rate');
$pct = array('challenge_success', 'captcha_solve_rate');
$tile = function ($k, $label) use ($demo, $pct) {
	$t = $demo['kpi'][$k];
	$v = $t['cur'] === null ? '—' : (in_array($k, $pct, true) ? gp_num($t['cur'], 1) . '%' : gp_num((int)$t['cur']));
	$chg = $t['change'];
	if (in_array($k, $pct, true) && $t['cur'] !== null && $t['prev'] !== null) { $chg = sprintf('%+.1f pt', $t['cur'] - $t['prev']); }
	return '<div class="gp-kpi"><div class="gp-kpi-label">' . gp_e(gp_t($label)) . '</div><div class="gp-kpi-value">' . gp_e($v) . '</div>'
		. '<div class="gp-kpi-hint">' . ($chg === '' ? '' : gp_e($chg) . ' ' . gp_e(gp_t('dash_vs_prev'))) . '</div></div>';
};
$cap_any = ((float)$demo['kpi']['captcha_shown']['cur'] + (float)$demo['kpi']['captcha_solved']['cur'] + (float)$demo['kpi']['captcha_failed']['cur'] + (float)$demo['kpi']['captcha_expired']['cur']) > 0;
$c = $demo['counts'];
?>
<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('dash_title')) ?></h1>
	<p class="gp-page-sub">
		<?php if ($demo['generated'] > 0): ?><?= gp_e(gp_t('dash_snapshot_age')) ?>: <?= gp_e(gp_age($demo['generated'])) ?> <?= gp_e(gp_t('ago')) ?>
			<?php if ($demo['stale']): ?><span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('dash_stale')) ?></span><?php endif; ?>
		<?php else: ?><?= gp_e(gp_t('dash_no_snapshot')) ?><?php endif; ?>
	</p>
</div>

<section class="gp-card" aria-label="<?= gp_e(gp_t('demo_protection')) ?>">
	<div class="gp-card-title"><?= gp_e(gp_t('demo_protection')) ?></div>
	<p><span class="gp-badge <?= $demo['protection'] === 'enforcing' ? 'gp-badge-on' : ($demo['protection'] === 'partial' ? 'gp-badge-warn' : 'gp-badge-off') ?>"><?= gp_e(gp_t('demo_mode_' . $demo['protection'])) ?></span></p>
</section>

<section aria-label="<?= gp_e(gp_t('dash_24h')) ?>">
	<h2 class="gp-card-title"><?= gp_e(gp_t('dash_24h')) ?> <span class="gp-card-sub"><?= gp_e(gp_t('dash_24h_sub')) ?></span></h2>
	<?php if (!$demo['has_data']): ?><div class="gp-note"><?= gp_e(gp_t('dash_k_none')) ?></div><?php else: ?>
	<div class="gp-grid-kpi"><?php foreach ($kt as $k => $label) { echo $tile($k, $label); } ?></div>
	<?php endif; ?>
</section>

<?php if ($demo['has_data'] && $cap_any): ?>
<section aria-label="<?= gp_e(gp_t('dash_captcha')) ?>">
	<h2 class="gp-card-title"><?= gp_e(gp_t('dash_captcha')) ?> <span class="gp-card-sub"><?= gp_e(gp_t('dash_24h_sub')) ?></span></h2>
	<div class="gp-grid-kpi"><?php foreach ($ct as $k => $label) { echo $tile($k, $label); } ?></div>
</section>
<?php endif; ?>

<section class="gp-card" aria-label="<?= gp_e(gp_t('demo_counts')) ?>">
	<div class="gp-card-title"><?= gp_e(gp_t('demo_counts')) ?></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('demo_rules')) ?></span><span class="gp-stat-val"><?= gp_num($c['rules_enabled']) ?> / <?= gp_num($c['rules_total']) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('demo_lists')) ?></span><span class="gp-stat-val"><?= gp_num($c['lists_enabled']) ?> / <?= gp_num($c['lists_total']) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('demo_jobs_ok')) ?></span><span class="gp-stat-val"><?= gp_num($c['jobs_healthy']) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('demo_jobs_bad')) ?></span><span class="gp-stat-val <?= $c['jobs_unhealthy'] > 0 ? 'gp-text-bad' : '' ?>"><?= gp_num($c['jobs_unhealthy']) ?></span></div>
</section>
