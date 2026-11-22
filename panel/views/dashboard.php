<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Dashboard, most important first:
//   1. critical alerts (only when something is wrong; every one is read LIVE, not from the snapshot)
//   2. protection state (kill switch, enforce toggles, rules, global mode)
//   3. last-24 h KPIs against the previous 24 h
//   4. top lists, each linking to the Logs page with the matching filter
//   5. details (collapsible): log storage, data pipeline, jobs, models, charts
// Heavy numbers come from analyzer/snapshot.json; anything that decides an alert does not,
// because the snapshot job is one of the things that can die.
$s = is_array($snapshot) ? $snapshot : array();
$isum = isset($isum) ? $isum : array('total' => 0, 'enabled' => 0, 'by' => array());   // enabled IP lists (index.php passes it)
$traffic = isset($s['traffic']) && is_array($s['traffic']) ? $s['traffic'] : array();
$decisions = isset($s['decisions']) && is_array($s['decisions']) ? $s['decisions'] : array();
$funnel = isset($s['funnel']) && is_array($s['funnel']) ? $s['funnel'] : array();
$coverage = isset($s['coverage']) && is_array($s['coverage']) ? $s['coverage'] : array();
$holdout = isset($s['holdout']) && is_array($s['holdout']) ? $s['holdout'] : array();
$kpi = isset($s['kpi']) && is_array($s['kpi']) ? $s['kpi'] : array();
$top = isset($s['top']) && is_array($s['top']) ? $s['top'] : array();
$generated = isset($s['generated_at']) ? (float)$s['generated_at'] : 0;
$snapshot_stale = $generated > 0 && (time() - $generated) > 3600;
$rate = isset($funnel['success_rate']) ? (float)$funnel['success_rate'] : null;
$alerts = isset($alerts) && is_array($alerts) ? $alerts : array();
$jobs = isset($jobs) && is_array($jobs) ? $jobs : array();
$cron = isset($cron) && is_array($cron) ? $cron : array('mode' => 'none', 'report' => null, 'age' => null);
$queue = isset($queue) && is_array($queue) ? $queue : array('length' => 0, 'oldest_age' => null, 'stuck' => false, 'redis' => false);
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('dash_title')) ?></h1>
	<p class="gp-page-sub">
		<?php if ($generated > 0): ?>
			<?= gp_e(gp_t('dash_snapshot_age')) ?>: <?= gp_e(gp_age($generated)) ?> <?= gp_e(gp_t('ago')) ?>
			<?php if ($snapshot_stale): ?><span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('dash_stale')) ?></span><?php endif; ?>
		<?php else: ?>
			<?= gp_e(gp_t('dash_no_snapshot')) ?>
		<?php endif; ?>
		<span class="gp-sep">·</span>
		<?= gp_e(gp_t('dash_tz')) ?>: <span class="gp-mono"><?= gp_e(date('T P')) ?></span>
		<?php if (isset($s['tz']['offset'])): ?> / <?= gp_e(gp_t('dash_tz_analyzer')) ?>: <span class="gp-mono"><?= gp_e(($s['tz']['name'] ?? '') . ' ' . sprintf('%+03d:%02d', intdiv((int)$s['tz']['offset'], 3600), abs((int)$s['tz']['offset'] % 3600) / 60)) ?></span><?php endif; ?>
	</p>
</div>

<?php /* ------------------------------------------------------------ 1. critical alerts */ ?>
<?php if ($alerts): ?>
<section class="gp-alerts" aria-label="<?= gp_e(gp_t('al_title')) ?>" role="alert">
	<div class="gp-card gp-card-danger">
		<div class="gp-card-title"><?= gp_e(gp_t('al_title')) ?>
			<span class="gp-card-sub"><?= gp_num(count($alerts)) ?></span></div>
		<ul class="gp-alert-list">
		<?php foreach ($alerts as $al):
			$crit = ($al['level'] === 'critical'); ?>
			<li class="gp-alert gp-alert-<?= $crit ? 'critical' : 'warning' ?>" data-alert="<?= gp_e($al['id']) ?>">
				<span class="gp-badge <?= $crit ? 'gp-badge-bad' : 'gp-badge-warn' ?>"><?= gp_e(gp_t($crit ? 'al_critical' : 'al_warning')) ?></span>
				<span class="gp-alert-text"><?= gp_e(gp_t($al['key'])) ?><?php if ($al['detail'] !== ''): ?>
					<span class="gp-mono gp-ltr"> — <?= gp_e($al['detail']) ?></span><?php endif; ?></span>
				<?php if ($al['link'] !== '' && gp_acl_allows($role ?? 'admin', preg_split('/[&#]/', $al['link'])[0], 'GET')): ?><a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=<?= gp_e($al['link']) ?>"><?= gp_e(gp_t('al_open')) ?></a><?php endif; ?>
			</li>
		<?php endforeach; ?>
		</ul>
	</div>
</section>
<?php endif; ?>

<?php if (!empty($ip_open)): ?>
<div class="gp-note"><?= gp_e(gp_t('dash_ip_open')) ?></div>
<?php endif; ?>

<?php /* ------------------------------------------------------------ cron setup help (some job has never run) */ ?>
<?php if (!empty($cron_card)): ?>
<div class="gp-card" id="cron-setup">
	<div class="gp-card-title"><?= gp_e(gp_t('cron_title')) ?></div>
	<p class="gp-help"><?= gp_e(gp_t('cron_help')) ?></p>
	<p class="gp-help"><?= gp_e(gp_t('cron_open')) ?> <code class="gp-mono">crontab -e</code></p>
	<pre class="gp-mono gp-ltr gp-pre"><?= gp_e(implode("\n", $cron_lines)) ?></pre>
	<p class="gp-help"><?= gp_e(gp_t('cron_source_' . $cron['mode'])) ?><?php if (in_array($cron['mode'], array('file', 'cache'), true) && $cron['age'] !== null): ?> (<?= gp_e(gp_age(time() - (int)$cron['age'])) ?> <?= gp_e(gp_t('ago')) ?>)<?php endif; ?></p>
</div>
<?php endif; ?>

<?php /* ------------------------------------------------------------ 2. protection state */ ?>
<?php $pm = $protection; ?>
<section aria-label="<?= gp_e(gp_t('dash_protection')) ?>">
<div class="gp-cardgrid">
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_protection')) ?>
			<span class="gp-badge <?= $pm['mode'] === 'enforcing' ? 'gp-badge-on' : ($pm['mode'] === 'partial' ? 'gp-badge-warn' : 'gp-badge-off') ?>"><?= gp_e(gp_t('dash_mode_' . $pm['mode'])) ?></span></div>
		<?php if ($pm['forced']): ?><p class="gp-note gp-note-strong"><?= gp_e(gp_t('dash_mode_forced')) ?></p><?php endif; ?>
		<?php foreach (array('block', 'challenge', 'ratelimit') as $k): $on = !empty($cfg['enforce'][$k]); ?>
		<div class="gp-stat-row"><span class="gp-stat-key gp-mono">enforce.<?= gp_e($k) ?></span>
			<span class="gp-badge <?= $on ? 'gp-badge-on' : 'gp-badge-off' ?>"><?= gp_e($on ? gp_t('on') : gp_t('off')) ?></span></div>
		<?php endforeach; ?>
		<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('dash_rules')) ?></span>
			<span class="gp-stat-val"><a href="index.php?r=rules"><?= gp_num($rsum['enabled']) ?> / <?= gp_num($rsum['total']) ?></a></span></div>
		<?php foreach ($rsum['by'] as $k => $n): list($rm, $ra) = explode('/', $k); ?>
		<div class="gp-stat-row"><span class="gp-stat-key gp-mono"><?= gp_e(gp_t('rules_mode_' . $rm)) ?> · <?= gp_e(gp_t('rules_act_' . $ra)) ?></span>
			<span class="gp-stat-val"><?= gp_num($n) ?></span></div>
		<?php endforeach; ?>
		<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('dash_iplists')) ?></span>
			<span class="gp-stat-val"><a href="index.php?r=iplists"><?= gp_num($isum['enabled']) ?> / <?= gp_num($isum['total']) ?></a></span></div>
		<?php foreach ($isum['by'] as $k => $n): list($it, $im) = explode('/', $k); ?>
		<div class="gp-stat-row"><span class="gp-stat-key gp-mono"><?= gp_e(gp_t('ipl_type_' . $it)) ?> · <?= gp_e(gp_t('rules_mode_' . $im)) ?></span>
			<span class="gp-stat-val"><?= gp_num($n) ?></span></div>
		<?php endforeach; ?>
	</div>
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
</div>
</section>

<?php /* ------------------------------------------------------------ 3. last 24 h */ ?>
<?php
$kcur = isset($kpi['cur']) && is_array($kpi['cur']) ? $kpi['cur'] : array();
$kprev = isset($kpi['prev']) && is_array($kpi['prev']) ? $kpi['prev'] : array();
$tiles = array('requests' => 'dash_k_requests', 'allowed' => 'dash_k_allowed', 'blocked' => 'dash_k_blocked', 'limited' => 'dash_k_limited',
	'challenged' => 'dash_k_challenged', 'challenge_success' => 'dash_k_success', 'rule_hits' => 'dash_k_rules', 'honeypot' => 'dash_k_honeypot', 'degraded' => 'dash_k_degraded');
?>
<section aria-label="<?= gp_e(gp_t('dash_24h')) ?>">
	<h2 class="gp-card-title"><?= gp_e(gp_t('dash_24h')) ?> <span class="gp-card-sub"><?= gp_e(gp_t('dash_24h_sub')) ?></span></h2>
	<?php if (!$kcur): ?><div class="gp-note"><?= gp_e(gp_t('dash_k_none')) ?></div><?php else: ?>
	<div class="gp-grid-kpi">
		<?php foreach ($tiles as $k => $label): $cv = $kcur[$k] ?? null; $pv = $kprev[$k] ?? null;
			$pct = ($k === 'challenge_success');
			$chg = $pct ? (($cv === null || $pv === null) ? '' : sprintf('%+.1f pt', $cv - $pv)) : gp_kpi_change($cv, $pv);
			$bad = in_array($k, array('blocked', 'limited', 'degraded'), true) && $chg !== '' && $chg[0] === '+'; ?>
		<div class="gp-kpi">
			<div class="gp-kpi-label"><?= gp_e(gp_t($label)) ?></div>
			<div class="gp-kpi-value"><?= $cv === null ? '—' : ($pct ? gp_e(gp_num((float)$cv, 1)) . '%' : gp_e(gp_num((int)$cv))) ?></div>
			<div class="gp-kpi-hint <?= $bad ? 'gp-text-bad' : '' ?>"><?= $chg === '' ? '' : gp_e($chg) . ' ' . gp_e(gp_t('dash_vs_prev')) ?></div>
		</div>
		<?php endforeach; ?>
	</div>
	<?php endif; ?>
</section>

<?php /* ------------------------------------------------------------ 3b. CAPTCHA (only when there is something to show) */ ?>
<?php
$ccur = isset($kcur['captcha_shown']) ? $kcur : array();
$cprev = $kprev;
$ctiles = array('captcha_shown' => 'dash_c_shown', 'captcha_solved' => 'dash_c_solved', 'captcha_failed' => 'dash_c_failed', 'captcha_expired' => 'dash_c_expired',
	'captcha_solve_rate' => 'dash_c_rate', 'captcha_median_s' => 'dash_c_median');
$cany = $ccur && ((int)$ccur['captcha_shown'] + (int)($ccur['captcha_solved'] ?? 0) + (int)($ccur['captcha_failed'] ?? 0) + (int)($ccur['captcha_expired'] ?? 0)) > 0;
?>
<?php if ($cany): ?>
<section aria-label="<?= gp_e(gp_t('dash_captcha')) ?>" id="dash-captcha">
	<h2 class="gp-card-title"><?= gp_e(gp_t('dash_captcha')) ?> <span class="gp-card-sub"><?= gp_e(gp_t('dash_24h_sub')) ?></span></h2>
	<div class="gp-grid-kpi">
		<?php foreach ($ctiles as $k => $label): $cv = $ccur[$k] ?? null; $pv = $cprev[$k] ?? null;
			$pct = ($k === 'captcha_solve_rate'); $sec = ($k === 'captcha_median_s');
			$chg = ($pct || $sec) ? (($cv === null || $pv === null) ? '' : sprintf($pct ? '%+.1f pt' : '%+.1f s', $cv - $pv)) : gp_kpi_change($cv, $pv);
			$bad = in_array($k, array('captcha_failed', 'captcha_expired'), true) && $chg !== '' && $chg[0] === '+'; ?>
		<div class="gp-kpi" data-captcha-kpi="<?= gp_e($k) ?>">
			<div class="gp-kpi-label"><?= gp_e(gp_t($label)) ?></div>
			<div class="gp-kpi-value"><?= $cv === null ? '—' : ($pct ? gp_e(gp_num((float)$cv, 1)) . '%' : ($sec ? gp_e(gp_num((float)$cv, 1)) . ' s' : gp_e(gp_num((int)$cv)))) ?></div>
			<div class="gp-kpi-hint <?= $bad ? 'gp-text-bad' : '' ?>"><?= $chg === '' ? '' : gp_e($chg) . ' ' . gp_e(gp_t('dash_vs_prev')) ?></div>
		</div>
		<?php endforeach; ?>
	</div>
	<p class="gp-help"><?= gp_e(gp_t('dash_c_hint')) ?></p>
</section>
<?php endif; ?>

<?php /* ------------------------------------------------------------ 4. top lists, each links to the Logs filter */ ?>
<?php
$lists = array(
	'rules' => array('dash_top_rules', function ($k) { return 'index.php?r=logs&reason=' . gp_u('RULE:' . $k . ',SH_RULE:' . $k); }),
	'reasons' => array('dash_top_reasons', function ($k) { return 'index.php?r=logs&reason=' . gp_u($k); }),
	'ips' => array('dash_top_ips', function ($k) { return 'index.php?r=logs&ip=' . gp_u($k); }),
	'devices' => array('dash_top_devices', function ($k) { return 'index.php?r=logs&dev=' . gp_u($k); }),
	'uas' => array('dash_top_uas', function ($k) { return 'index.php?r=logs&ua=' . gp_u($k); }),
	'paths' => array('dash_top_paths', function ($k) { return 'index.php?r=logs&path=' . gp_u($k); }),
	'countries' => array('dash_top_countries', function ($k) { return 'index.php?r=logs&cc=' . gp_u($k); }),
);
?>
<section aria-label="<?= gp_e(gp_t('dash_top')) ?>">
	<h2 class="gp-card-title"><?= gp_e(gp_t('dash_top')) ?> <span class="gp-card-sub"><?= gp_e(gp_t('dash_top_sub')) ?></span></h2>
	<div class="gp-cardgrid gp-cardgrid-3">
	<?php foreach ($lists as $lk => $ld): $rows = isset($top[$lk]) && is_array($top[$lk]) ? $top[$lk] : array(); ?>
		<div class="gp-card">
			<div class="gp-card-title"><?= gp_e(gp_t($ld[0])) ?></div>
			<?php if (!$rows): ?>
				<p class="gp-help"><?= gp_e(gp_t($lk === 'countries' ? 'dash_top_nogeo' : 'dash_top_none')) ?></p>
			<?php else: foreach ($rows as $r): ?>
			<div class="gp-stat-row">
				<a class="gp-stat-key gp-mono gp-ltr gp-truncate" href="<?= gp_e($ld[1]((string)$r[0])) ?>"><?= gp_e((string)$r[0]) ?></a>
				<span class="gp-stat-val"><?= gp_e(gp_num((int)$r[1])) ?></span>
			</div>
			<?php endforeach; endif; ?>
		</div>
	<?php endforeach; ?>
	</div>
</section>

<?php /* ------------------------------------------------------------ 5. details */ ?>
<details class="gp-more gp-details">
	<summary><?= gp_e(gp_t('dash_details')) ?></summary>

	<div class="gp-cardgrid">
	<?php /* jobs */ ?>
	<div class="gp-card gp-span-all">
		<div class="gp-card-title"><?= gp_e(gp_t('dash_jobs')) ?>
			<a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=jobs"><?= gp_e(gp_t('al_open')) ?></a></div>
		<div class="gp-table-wrap"><table class="gp-table">
			<thead><tr><th><?= gp_e(gp_t('job_c_job')) ?></th><th><?= gp_e(gp_t('job_c_state')) ?></th><th><?= gp_e(gp_t('job_c_success')) ?></th><th><?= gp_e(gp_t('job_c_next')) ?></th></tr></thead>
			<tbody>
			<?php foreach ($jobs as $jn => $h): ?>
			<tr><td class="gp-mono"><a href="index.php?r=jobs&amp;job=<?= gp_u($jn) ?>"><?= gp_e($jn) ?></a></td>
				<td><span class="gp-badge <?= gp_job_badge($h['state']) ?>"><?= gp_e(gp_t('job_s_' . $h['state'])) ?></span></td>
				<td class="gp-mono"><?= $h['last_success'] > 0 ? gp_e(gp_age($h['last_success'])) . ' ' . gp_e(gp_t('ago')) : '—' ?></td>
				<td class="gp-mono"><?= $h['next_expected'] > 0 ? gp_e(gmdate('H:i', $h['next_expected'])) . ' UTC' : '—' ?></td></tr>
			<?php endforeach; ?>
			</tbody></table></div>
		<p class="gp-help"><?= gp_e(gp_t('job_queue')) ?>: <span class="gp-mono"><?= gp_num((int)$queue['length']) ?></span><?= $queue['oldest_age'] !== null ? ' · ' . gp_e(gp_t('job_oldest')) . ' ' . gp_e(gp_age(time() - (int)$queue['oldest_age'])) : '' ?></p>
	</div>
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
	<?php if (!empty($storage) && is_array($storage)):
		$sw = $storage['warnings']; ?>
	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('ls_title')) ?>
			<span class="gp-badge <?= $sw ? 'gp-badge-warn' : 'gp-badge-on' ?>"><?= gp_e($sw ? gp_t('ls_attention') : gp_t('ls_ok')) ?></span>
		</div>
		<?php foreach ($sw as $w): ?>
		<p class="gp-note gp-note-strong" style="margin-bottom:.5rem"><?= gp_e(gp_t('ls_w_' . $w)) ?></p>
		<?php endforeach; ?>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('ls_total')) ?></span>
			<span class="gp-stat-val"><?= gp_e(gp_bytes($storage['total'])) ?>
				<?php if ($storage['max_mb'] > 0): ?> / <?= gp_e(gp_bytes($storage['max_mb'] * 1048576)) ?><?php endif; ?></span>
		</div>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('ls_today')) ?></span>
			<span class="gp-stat-val"><?= gp_e(gp_bytes($storage['today'])) ?></span>
		</div>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('ls_archives')) ?></span>
			<span class="gp-stat-val"><?= gp_e(gp_num($storage['archives'])) ?>
				<?php if ($storage['oldest'] !== ''): ?> · <?= gp_e(gp_t('ls_oldest')) ?> <?= gp_e(substr($storage['oldest'], 0, 4) . '-' . substr($storage['oldest'], 4, 2) . '-' . substr($storage['oldest'], 6, 2)) ?><?php endif; ?>
				· <?= gp_e(sprintf(gp_t('ls_kept'), gp_num($storage['retention_days']))) ?></span>
		</div>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('ls_free')) ?></span>
			<span class="gp-stat-val"><?= $storage['free'] === null ? gp_e(gp_t('unknown')) : gp_e(gp_bytes($storage['free'])) ?>
				<?php if ($storage['disk']): ?> / <?= gp_e(gp_bytes($storage['disk'])) ?><?php endif; ?>
				<?php if ($storage['min_free_mb'] > 0): ?> · <?= gp_e(sprintf(gp_t('ls_floor'), gp_bytes($storage['min_free_mb'] * 1048576))) ?><?php endif; ?></span>
		</div>
		<?php $lq = isset($jobs['logrotate']['result']['quota']) ? (string)$jobs['logrotate']['result']['quota'] : ''; if ($lq !== ''): ?>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('ls_quota')) ?></span>
			<span class="gp-stat-val gp-mono gp-ltr"><?= gp_e($lq) ?></span>
		</div>
		<?php endif; ?>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('ls_rotate')) ?></span>
			<span class="gp-stat-val"><?= $storage['rotate'] === null ? gp_e(gp_t('never'))
				: gp_e(gp_age((int)$storage['rotate']['ts'])) . ' ' . gp_e(gp_t('ago')) ?></span>
		</div>
		<?php if ($storage['skip_paths']): ?>
		<div class="gp-stat-row">
			<span class="gp-stat-key"><?= gp_e(gp_t('ls_skipped')) ?></span>
			<span class="gp-mono"><?= gp_e(implode('  ', $storage['skip_paths'])) ?></span>
		</div>
		<?php endif; ?>
		<p class="gp-help"><?= gp_e(gp_t('ls_help')) ?></p>
	</div>
	<?php endif; ?>
	</div>

	<?php /* system status and signals */ ?>
	
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
	<div class="gp-note gp-note-strong"><?= gp_e(gp_t('dash_degraded')) ?>: <?= gp_num((int)$traffic['degraded']) ?>
		(<?= gp_pct((int)$traffic['degraded'], (int)($traffic['requests'] ?: 1)) ?>)</div>
	<?php endif; ?>
</details>
