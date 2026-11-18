<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Dashboard. Reads only analyzer/snapshot.json, so it renders in the same time
// whether the site served a thousand requests yesterday or ten million.
$s = is_array($snapshot) ? $snapshot : array();
$traffic = isset($s['traffic']) && is_array($s['traffic']) ? $s['traffic'] : array();
$decisions = isset($s['decisions']) && is_array($s['decisions']) ? $s['decisions'] : array();
$funnel = isset($s['funnel']) && is_array($s['funnel']) ? $s['funnel'] : array();
$coverage = isset($s['coverage']) && is_array($s['coverage']) ? $s['coverage'] : array();
$holdout = isset($s['holdout']) && is_array($s['holdout']) ? $s['holdout'] : array();
$runs = isset($s['last_runs']) && is_array($s['last_runs']) ? $s['last_runs'] : array();
$generated = isset($s['generated_at']) ? (float)$s['generated_at'] : 0;
$snapshot_stale = $generated > 0 && (time() - $generated) > 3600;
$rate = isset($funnel['success_rate']) ? (float)$funnel['success_rate'] : null;
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('dash_title')) ?></h1>
	<p class="gp-page-sub">
		<?php if ($generated > 0): ?>
			<?= gp_e(gp_t('dash_snapshot_age')) ?>: <?= gp_e(gp_age($generated)) ?> <?= gp_e(gp_t('ago')) ?>
			<?php if ($snapshot_stale): ?>
				<span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('dash_stale')) ?></span>
			<?php endif; ?>
		<?php else: ?>
			<?= gp_e(gp_t('dash_no_snapshot')) ?>
		<?php endif; ?>
	</p>
</div>

<?php if (!empty($exposed)): ?>
<div class="gp-card gp-card-danger">
	<span class="gp-badge gp-badge-bad"><?= gp_e(gp_t('dash_exposed')) ?></span>
	<p class="gp-help"><?= gp_e(gp_t('dash_exposed_help')) ?></p>
	<p class="gp-mono" dir="ltr"><?= gp_e(implode('  ', $exposed)) ?></p>
</div>
<?php endif; ?>

<?php if (!empty($pipeline) && is_array($pipeline)):
	$pv = (string)$pipeline['verdict']; ?>
<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('pipe_title')) ?>
		<span class="gp-badge <?= $pv === 'ok' ? 'gp-badge-on' : 'gp-badge-bad' ?>"><?= gp_e(gp_t('pipe_' . $pv)) ?></span>
	</div>
	<?php if ($pipeline['last_age'] !== null): ?>
	<div class="gp-stat-row">
		<span class="gp-stat-key"><?= gp_e(gp_t('pipe_last')) ?></span>
		<span class="gp-stat-val"><?= gp_e(gp_age((float)$pipeline['last_ts'])) ?> <?= gp_e(gp_t('ago')) ?></span>
	</div>
	<?php endif; ?>
	<div class="gp-stat-row">
		<span class="gp-stat-key"><?= gp_e(gp_t('pipe_dir')) ?></span>
		<span class="gp-mono" dir="ltr"><?= gp_e($pipeline['dir']) ?></span>
	</div>
	<p class="gp-help"><?= gp_e(gp_t('pipe_snapshot_note')) ?></p>
</div>
<?php endif; ?>

<?php if (!empty($ip_open)): ?>
<div class="gp-note"><?= gp_e(gp_t('dash_ip_open')) ?></div>
<?php endif; ?>

<!-- The kill switch: the single most important control in this panel. -->
<div class="gp-kill <?= $kill ? 'gp-kill-stopped' : 'gp-kill-armed' ?>">
	<div class="gp-card-title" style="margin-bottom:.5rem">
		<span class="gp-kill-title">
			<span class="gp-pulse <?= $kill ? 'gp-pulse-bad' : 'gp-pulse-ok' ?>"></span>
			<?= gp_e($kill ? gp_t('dash_kill_on') : gp_t('dash_kill_off')) ?>
		</span>
		<span class="gp-card-sub"><?= gp_e(gp_t('dash_killswitch')) ?></span>
	</div>
	<p class="gp-help" style="margin-bottom:.75rem"><?= gp_e(gp_t('dash_kill_warn')) ?></p>
	<form method="post" action="index.php?r=dashboard"
		data-confirm="<?= gp_e(gp_t('dash_kill_confirm')) ?>">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<input type="hidden" name="killswitch" value="<?= $kill ? 'start' : 'stop' ?>">
		<button type="submit" class="gp-btn <?= $kill ? 'gp-btn-primary' : 'gp-btn-danger' ?>">
			<?= gp_e($kill ? gp_t('dash_kill_start') : gp_t('dash_kill_stop')) ?>
		</button>
	</form>
</div>

<!-- Status strip -->
<div class="gp-grid-3">
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_enforce')) ?></div>
		<?php foreach (array('block', 'challenge', 'ratelimit') as $k):
			$on = !empty($cfg['enforce'][$k]); ?>
		<div class="gp-stat-row">
			<span class="gp-stat-key gp-mono"><?= gp_e($k) ?></span>
			<span class="gp-badge <?= $on ? 'gp-badge-on' : 'gp-badge-off' ?>">
				<?= gp_e($on ? gp_t('on') : gp_t('off')) ?></span>
		</div>
		<?php endforeach; ?>
	</div>

	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_signals')) ?></div>
		<?php foreach (array('reputation', 'ml', 'clf') as $k):
			$on = !empty($cfg['signals'][$k]); ?>
		<div class="gp-stat-row">
			<span class="gp-stat-key gp-mono"><?= gp_e($k) ?></span>
			<span class="gp-badge <?= $on ? 'gp-badge-on' : 'gp-badge-off' ?>">
				<?= gp_e($on ? gp_t('on') : gp_t('off')) ?></span>
		</div>
		<?php endforeach; ?>
	</div>

	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_status')) ?></div>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('dash_redis')) ?></span>
			<span class="gp-badge <?= $redis_up ? 'gp-badge-on' : 'gp-badge-bad' ?>">
				<?= gp_e($redis_up ? gp_t('dash_redis_up') : gp_t('dash_redis_down')) ?></span>
		</div>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('dash_redis_endpoint')) ?></span>
			<span class="gp-stat-val gp-mono" dir="ltr"><?= gp_e($rinfo['endpoint']) ?></span>
		</div>
		<div class="gp-stat-row">
			<span class="gp-stat-key">db / prefix / auth</span>
			<span class="gp-stat-val gp-mono" dir="ltr"><?= gp_e($rinfo['db']) ?> /
				<?= gp_e($rinfo['prefix'] === '' ? '-' : $rinfo['prefix']) ?> /
				<?= gp_e($rinfo['auth'] ? 'on' : 'off') ?></span>
		</div>
		<?php if (!empty($health['breaker'])): ?>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('dash_breaker')) ?></span>
			<span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('dash_breaker_open')) ?></span>
		</div>
		<?php endif; ?>
		<?php if (!empty($health['last_error'])): ?>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('dash_last_error')) ?></span>
			<span class="gp-stat-val gp-mono" dir="ltr"><?= gp_e($health['last_error']) ?></span>
		</div>
		<?php endif; ?>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('dash_capture')) ?></span>
			<span class="gp-badge <?= !empty($cfg['capture_outcomes']) ? 'gp-badge-on' : 'gp-badge-off' ?>">
				<?= gp_e(!empty($cfg['capture_outcomes']) ? gp_t('on') : gp_t('off')) ?></span>
		</div>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('dash_holdout')) ?></span>
			<span class="gp-stat-val"><?= gp_num((int)($cfg['holdout_pct'] ?? 0)) ?>%</span>
		</div>
	</div>
</div>

<?php $bv = isset($s['bot_verify']) && is_array($s['bot_verify']) ? $s['bot_verify'] : array();
if (!empty($bv['unknown'])): ?>
<div class="gp-card">
	<span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('dash_verify_unknown')) ?></span>
	<span class="gp-stat-val"><?= gp_num((int)$bv['unknown']) ?></span>
	<p class="gp-help"><?= gp_e(gp_t('dash_verify_unknown_help')) ?></p>
</div>
<?php endif; ?>

<!-- Analyzer freshness -->
<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('dash_last_runs')) ?></div>
	<?php foreach (array('run_verify', 'run_nightly', 'snapshot') as $job):
		$at = isset($runs[$job]) ? (float)$runs[$job] : 0;
		$limits = array('run_verify' => 3600, 'run_nightly' => 172800, 'snapshot' => 3600);
		$stale = $at <= 0 || (time() - $at) > $limits[$job]; ?>
	<div class="gp-stat-row">
		<span class="gp-stat-key gp-mono"><?= gp_e($job) ?></span>
		<span>
			<?php if ($at > 0): ?>
				<span class="gp-stat-val"><?= gp_e(gp_age($at)) ?> <?= gp_e(gp_t('ago')) ?></span>
			<?php else: ?>
				<span class="gp-stat-val"><?= gp_e(gp_t('never')) ?></span>
			<?php endif; ?>
			<?php if ($stale): ?>
				<span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('dash_stale')) ?></span>
			<?php endif; ?>
		</span>
	</div>
	<?php endforeach; ?>
</div>

<!-- KPI cards -->
<div class="gp-grid-4">
	<div class="gp-kpi">
		<div class="gp-kpi-label"><?= gp_e(gp_t('dash_requests')) ?></div>
		<div class="gp-kpi-value"><?= gp_num((int)($traffic['requests'] ?? 0)) ?></div>
	</div>
	<div class="gp-kpi">
		<div class="gp-kpi-label"><?= gp_e(gp_t('dash_devices')) ?></div>
		<div class="gp-kpi-value"><?= gp_num((int)($traffic['devices'] ?? 0)) ?></div>
	</div>
	<div class="gp-kpi">
		<div class="gp-kpi-label"><?= gp_e(gp_t('dash_addresses')) ?></div>
		<div class="gp-kpi-value"><?= gp_num((int)($traffic['addresses'] ?? 0)) ?></div>
	</div>
	<div class="gp-kpi">
		<div class="gp-kpi-label"><?= gp_e(gp_t('dash_challenge_rate')) ?></div>
		<div class="gp-kpi-value">
			<?= $rate === null ? gp_e(gp_t('unknown')) : gp_num($rate, 1) . '%' ?>
		</div>
		<?php if ($rate !== null && $rate < 95): ?>
		<div class="gp-kpi-hint gp-text-bad">
			<?= gp_e(gp_t('dash_challenge_hint')) ?>
		</div>
		<?php else: ?>
		<div class="gp-kpi-hint"><?= gp_e(gp_t('dash_challenge_hint')) ?></div>
		<?php endif; ?>
	</div>
</div>

<div class="gp-grid-2">
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_holdout_gap')) ?></div>
		<?php if (empty($holdout['enabled'])): ?>
			<p class="gp-help"><?= gp_e(gp_t('help_holdout_pct')) ?></p>
		<?php else: ?>
			<div class="gp-stat-row">
				<span class="gp-stat-key"><?= gp_e(gp_t('logs_holdout')) ?></span>
				<span class="gp-stat-val"><?= gp_num((float)($holdout['holdout_challenge_rate'] ?? 0), 1) ?>%</span>
			</div>
			<div class="gp-stat-row">
				<span class="gp-stat-key"><?= gp_e(gp_t('dash_enforce')) ?></span>
				<span class="gp-stat-val"><?= gp_num((float)($holdout['enforced_challenge_rate'] ?? 0), 1) ?>%</span>
			</div>
		<?php endif; ?>
	</div>
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_coverage')) ?></div>
		<p class="gp-help"><?= gp_e(gp_t('dash_coverage_sub')) ?></p>
		<?php foreach (array('rep', 'ml', 'clf') as $k):
			$pc = (float)($coverage[$k] ?? 0); ?>
		<div style="margin-bottom:.5rem">
			<div class="gp-row-head" style="justify-content:space-between">
				<span class="gp-mono"><?= gp_e($k) ?></span>
				<span class="gp-stat-val"><?= gp_num($pc, 1) ?>%</span>
			</div>
			<div class="gp-bar-track"><div class="gp-bar-fill<?= $pc < 20 ? ' gp-bar-fill-warn' : '' ?>"
				style="width:<?= number_format(max(0, min(100, $pc)), 1, '.', '') ?>%"></div></div>
		</div>
		<?php endforeach; ?>
	</div>
</div>

<!-- Charts, inline SVG generated in PHP -->
<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('dash_chart_time')) ?></div>
	<?php
	$series = array('allow', 'challenge', '403', '429');
	$buckets = isset($s['timeline']) && is_array($s['timeline']) ? $s['timeline'] : array();
	echo gp_chart_stacked($buckets, $series);
	?>
</div>

<div class="gp-grid-2">
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_chart_score')) ?></div>
		<?php echo gp_chart_histogram(
			isset($s['sc_hist']) && is_array($s['sc_hist']) ? $s['sc_hist'] : array(),
			isset($s['esc_hist']) && is_array($s['esc_hist']) ? $s['esc_hist'] : array(),
			gp_t('logs_sc'), gp_t('logs_esc')); ?>
	</div>
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_decisions')) ?></div>
		<?php echo gp_chart_bars($decisions, array('colors' => array(
			'allow' => gp_chart_color('ok'), 'challenge' => gp_chart_color('info'),
			'403' => gp_chart_color('bad'), '429' => gp_chart_color('warn')))); ?>
	</div>
</div>

<div class="gp-grid-2">
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_chart_status')) ?></div>
		<?php echo gp_chart_bars(
			isset($s['status']) && is_array($s['status']) ? $s['status'] : array(),
			array('color' => gp_chart_color('info'))); ?>
	</div>
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_chart_reasons')) ?></div>
		<?php echo gp_chart_bars(
			isset($s['reasons']) && is_array($s['reasons']) ? $s['reasons'] : array(),
			array('color' => gp_chart_color('accent'))); ?>
	</div>
</div>

<?php if (!empty($traffic['degraded'])): ?>
<div class="gp-note gp-note-strong">
	<?= gp_e(gp_t('dash_degraded')) ?>:
	<?= gp_num((int)$traffic['degraded']) ?>
	(<?= gp_pct((int)$traffic['degraded'], (int)($traffic['requests'] ?: 1)) ?>)
</div>
<?php endif; ?>
