<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Dashboard v2 (layout spec: docs/15-DASHBOARD.md). One 12-column grid, equal-height cards, top to bottom:
//   1. status strip (+ collapsible alerts)   2. six KPI tiles   3. requests per hour   4. rollout readiness | funnel
//   5. top lists in tabs   6. system (compact)   7. more (collapsed)
// Heavy numbers come from analyzer/snapshot.json (the `dash` block is computed by the analyzer, never in this request); anything that
// decides an alert is read LIVE, because the snapshot job is one of the things that can die.
$s = is_array($snapshot) ? $snapshot : array();
$isum = isset($isum) ? $isum : array('total' => 0, 'enabled' => 0, 'by' => array());
$rules = isset($rules) && is_array($rules) ? $rules : array();
$geo = isset($geo) && is_array($geo) ? $geo : null;
$iplists = isset($iplists) && is_array($iplists) ? $iplists : array();
$traffic = isset($s['traffic']) && is_array($s['traffic']) ? $s['traffic'] : array();
$decisions = isset($s['decisions']) && is_array($s['decisions']) ? $s['decisions'] : array();
$coverage = isset($s['coverage']) && is_array($s['coverage']) ? $s['coverage'] : array();
$holdout = isset($s['holdout']) && is_array($s['holdout']) ? $s['holdout'] : array();
$kpi = isset($s['kpi']) && is_array($s['kpi']) ? $s['kpi'] : array();
$top_old = isset($s['top']) && is_array($s['top']) ? $s['top'] : array();
$dash = gp_dash_block($s);
$generated = isset($s['generated_at']) ? (float)$s['generated_at'] : 0;
$snapshot_stale = $generated > 0 && (time() - $generated) > 3600;
$alerts = isset($alerts) && is_array($alerts) ? $alerts : array();
$jobs = isset($jobs) && is_array($jobs) ? $jobs : array();
$cron = isset($cron) && is_array($cron) ? $cron : array('mode' => 'none', 'report' => null, 'age' => null);
$queue = isset($queue) && is_array($queue) ? $queue : array('length' => 0, 'oldest_age' => null, 'stuck' => false, 'redis' => false);
$kcur = isset($kpi['cur']) && is_array($kpi['cur']) ? $kpi['cur'] : array();
$kprev = isset($kpi['prev']) && is_array($kpi['prev']) ? $kpi['prev'] : array();
$sc = gp_dash_strip_counts($alerts, $jobs);
$pm = $protection;
$version = function_exists('gp_upd_version') ? gp_upd_version() : '';
$can_act = gp_acl_allows($role ?? 'admin', 'overrides', 'POST');
$stale_badge = $snapshot_stale ? ' <span class="gp-badge gp-badge-warn">' . gp_e(gp_t('dash_stale')) . '</span>' : '';
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('dash_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('dash_tz')) ?>: <span class="gp-mono"><?= gp_e(date('T P')) ?></span>
		<?php if (isset($s['tz']['offset'])): ?> / <?= gp_e(gp_t('dash_tz_analyzer')) ?>: <span class="gp-mono"><?= gp_e(($s['tz']['name'] ?? '') . ' ' . sprintf('%+03d:%02d', intdiv((int)$s['tz']['offset'], 3600), abs((int)$s['tz']['offset'] % 3600) / 60)) ?></span><?php endif; ?></p>
</div>

<div class="gp-dash">

<?php /* ------------------------------------------------------------ 1. status strip */ ?>
<section class="gp-dstrip gp-dspan-12" aria-label="<?= gp_e(gp_t('dash_strip')) ?>" id="dash-strip">
	<div class="gp-dchip" data-chip="mode">
		<span class="gp-dchip-k"><?= gp_e(gp_t('dash_protection')) ?></span>
		<span class="gp-dchip-v"><span class="gp-badge <?= $pm['mode'] === 'enforcing' ? 'gp-badge-on' : ($pm['mode'] === 'partial' ? 'gp-badge-warn' : 'gp-badge-off') ?>"><?= gp_e(gp_t('dash_mode_' . $pm['mode'])) ?></span></span>
		<span class="gp-dchip-s"><a href="index.php?r=rules"><?= gp_num($rsum['enabled']) ?> / <?= gp_num($rsum['total']) ?> <?= gp_e(gp_t('dash_rules_short')) ?></a>
			· <a href="index.php?r=iplists"><?= gp_num($isum['enabled']) ?> / <?= gp_num($isum['total']) ?> <?= gp_e(gp_t('dash_lists_short')) ?></a></span>
	</div>
	<div class="gp-dchip <?= $kill ? 'gp-dchip-stopped' : 'gp-dchip-armed' ?>" data-chip="kill" id="dash-kill">
		<span class="gp-dchip-k"><?= gp_e(gp_t('dash_killswitch')) ?></span>
		<span class="gp-dchip-v"><span class="gp-pulse <?= $kill ? 'gp-pulse-bad' : 'gp-pulse-ok' ?>"></span> <?= gp_e($kill ? gp_t('dash_kill_on') : gp_t('dash_kill_off')) ?></span>
		<?php if ($kill): ?>
		<form method="post" action="index.php?r=dashboard" class="gp-dchip-s">
			<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
			<input type="hidden" name="killswitch" value="start">
			<button type="submit" class="gp-btn gp-btn-sm gp-btn-primary"><?= gp_e(gp_t('dash_kill_start')) ?></button>
		</form>
		<?php elseif (!empty($kill_confirm)): /* the confirmation step: a plain page state (GET), no browser dialog */ ?>
		<form method="post" action="index.php?r=dashboard" class="gp-dchip-s gp-kill-confirm" role="alertdialog" aria-label="<?= gp_e(gp_t('dash_kill_ask')) ?>">
			<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
			<input type="hidden" name="killswitch" value="stop">
			<input type="hidden" name="confirm" value="1">
			<span class="gp-kill-ask"><b><?= gp_e(gp_t('dash_kill_ask')) ?></b> <?= gp_e(gp_t('dash_kill_ask_sub')) ?></span>
			<span class="gp-kill-btns"><button type="submit" class="gp-btn gp-btn-sm gp-btn-danger"><?= gp_e(gp_t('dash_kill_do')) ?></button>
				<a class="gp-btn gp-btn-sm gp-btn-ghost" href="index.php?r=dashboard#dash-kill"><?= gp_e(gp_t('cancel')) ?></a></span>
		</form>
		<?php else: ?>
		<span class="gp-dchip-s"><a class="gp-btn gp-btn-sm gp-btn-danger" href="index.php?r=dashboard&amp;kill_confirm=1#dash-kill"><?= gp_e(gp_t('dash_kill_stop')) ?></a></span>
		<?php endif; ?>
	</div>
	<div class="gp-dchip" data-chip="alerts">
		<span class="gp-dchip-k"><?= gp_e(gp_t('al_title')) ?></span>
		<span class="gp-dchip-v"><?php if (!$alerts): ?><span class="gp-badge gp-badge-on"><?= gp_e(gp_t('dash_none_open')) ?></span><?php else: ?>
			<?php if ($sc['critical']): ?><span class="gp-badge gp-badge-bad"><?= gp_num($sc['critical']) ?> <?= gp_e(gp_t('al_critical')) ?></span><?php endif; ?>
			<?php if ($sc['warning']): ?><span class="gp-badge gp-badge-warn"><?= gp_num($sc['warning']) ?> <?= gp_e(gp_t('al_warning')) ?></span><?php endif; ?><?php endif; ?></span>
		<?php if ($alerts): ?><span class="gp-dchip-s"><a href="#dash-alerts"><?= gp_e(gp_t('dash_show_alerts')) ?></a></span><?php endif; ?>
	</div>
	<div class="gp-dchip" data-chip="jobs">
		<span class="gp-dchip-k"><?= gp_e(gp_t('dash_jobs')) ?></span>
		<span class="gp-dchip-v"><span class="gp-badge <?= $sc['jobs_bad'] ? 'gp-badge-bad' : 'gp-badge-on' ?>"><?= gp_num($sc['jobs_ok']) ?> / <?= gp_num($sc['jobs_total']) ?> <?= gp_e(gp_t('dash_jobs_ok')) ?></span></span>
		<span class="gp-dchip-s"><a href="index.php?r=jobs"><?= gp_e(gp_t('al_open')) ?></a></span>
	</div>
	<div class="gp-dchip" data-chip="snapshot">
		<span class="gp-dchip-k"><?= gp_e(gp_t('dash_snapshot_age')) ?></span>
		<span class="gp-dchip-v"><?php if ($generated > 0): ?><?= gp_e(gp_age($generated)) ?> <?= gp_e(gp_t('ago')) ?><?= $stale_badge ?><?php else: ?><span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('dash_no_snapshot_short')) ?></span><?php endif; ?></span>
	</div>
	<div class="gp-dchip" data-chip="version">
		<span class="gp-dchip-k"><?= gp_e(gp_t('dash_version')) ?></span>
		<span class="gp-dchip-v gp-mono"><?= gp_e($version === '' ? '-' : $version) ?></span>
		<?php if (gp_acl_allows($role ?? 'admin', 'update', 'GET')): ?><span class="gp-dchip-s"><a href="index.php?r=update"><?= gp_e(gp_t('nav_update')) ?></a></span><?php endif; ?>
	</div>
	<?= gp_msg('killswitch') ?>
</section>

<?php if (!empty($ip_open)): ?><div class="gp-note gp-dspan-12"><?= gp_e(gp_t('dash_ip_open')) ?></div><?php endif; ?>

<?php /* alerts: the first critical one (else the first) is always shown; the rest sit in a collapsible list that opens by itself on wide screens */ ?>
<?php if ($alerts):
	$al_first = 0;
	foreach ($alerts as $i => $al0) { if ($al0['level'] === 'critical') { $al_first = $i; break; } }
	$al_role = isset($role) ? $role : 'admin';
	$al_row = function ($al) use ($al_role) { $crit = ($al['level'] === 'critical'); ob_start(); ?>
		<li class="gp-alert gp-alert-<?= $crit ? 'critical' : 'warning' ?>" data-alert="<?= gp_e($al['id']) ?>">
			<span class="gp-badge <?= $crit ? 'gp-badge-bad' : 'gp-badge-warn' ?>"><?= gp_e(gp_t($crit ? 'al_critical' : 'al_warning')) ?></span>
			<span class="gp-alert-text"><?= gp_e(gp_t($al['key'])) ?><?php if ($al['detail'] !== ''): ?>
				<span class="gp-mono gp-ltr"> — <?= gp_e($al['detail']) ?></span><?php endif; ?></span>
			<?php if ($al['link'] !== '' && gp_acl_allows($al_role, preg_split('/[&#]/', $al['link'])[0], 'GET')): ?><a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=<?= gp_e($al['link']) ?>"><?= gp_e(gp_t('al_open')) ?></a><?php endif; ?>
		</li>
	<?php return ob_get_clean(); };
	$al_summary = ($sc['critical'] ? gp_num($sc['critical']) . ' ' . gp_t('al_critical') : '') . ($sc['critical'] && $sc['warning'] ? ' · ' : '') . ($sc['warning'] ? gp_num($sc['warning']) . ' ' . gp_t('al_warning') : ''); ?>
<section class="gp-dcard gp-dcard-flat gp-dspan-12 gp-alerts" id="dash-alerts" aria-label="<?= gp_e(gp_t('al_title')) ?>" role="alert">
	<div class="gp-dcard-title"><?= gp_e(gp_t('al_title')) ?> <span class="gp-card-sub"><?= gp_num(count($alerts)) ?></span></div>
	<ul class="gp-alert-list" data-alerts-first="1"><?= $al_row($alerts[$al_first]) ?></ul>
	<?php if (count($alerts) > 1): ?>
	<details class="gp-alerts-more" data-open-wide="1">
		<summary><span class="gp-alerts-sum"><?= gp_e($al_summary) ?></span> <span class="gp-alerts-show">— <?= gp_e(sprintf(gp_t('dash_alerts_show'), gp_num(count($alerts) - 1))) ?></span><span class="gp-alerts-hide">— <?= gp_e(gp_t('dash_alerts_hide')) ?></span></summary>
		<ul class="gp-alert-list"><?php foreach ($alerts as $i => $al) { if ($i !== $al_first) { echo $al_row($al); } } ?></ul>
	</details>
	<?php endif; ?>
</section>
<?php endif; ?>

<?php if (!empty($cron_card)): ?>
<div class="gp-dcard gp-dspan-12" id="cron-setup">
	<div class="gp-dcard-title"><?= gp_e(gp_t('cron_title')) ?></div>
	<p class="gp-help"><?= gp_e(gp_t('cron_help')) ?></p>
	<?php if ($cron_lines): ?>
	<p class="gp-help"><?= gp_e(gp_t('cron_open')) ?> <code class="gp-mono">crontab -e</code></p>
	<pre class="gp-mono gp-ltr gp-pre"><?= gp_e(implode("\n", $cron_lines)) ?></pre>
	<?php else: ?>
	<p class="gp-note" role="status"><?= gp_e(gp_t('cron_card_nolines')) ?></p>
	<?php endif; ?>
	<p class="gp-help"><?= gp_e(gp_t('cron_source_' . $cron['mode'])) ?><?php if (in_array($cron['mode'], array('file', 'cache'), true) && $cron['age'] !== null): ?> (<?= gp_e(gp_age(time() - (int)$cron['age'])) ?> <?= gp_e(gp_t('ago')) ?>)<?php endif; ?></p>
</div>
<?php endif; ?>

<?php /* ------------------------------------------------------------ 2. KPI tiles */ ?>
<?php
$hours = isset($dash['hours']) ? $dash['hours'] : array();
$series = function ($f) use ($hours) { $o = array(); foreach ($hours as $b) { $o[] = is_callable($f) ? $f($b) : (int)($b[$f] ?? 0); } return $o; };
$tiles = array(
	'requests'   => array('dash_k_requests', 'neutral', $series('n')),
	'allowed'    => array('dash_k_allowed', 'ok', $series('a')),
	'challenged' => array('dash_k_challenged', 'warn', $series(function ($b) { return (int)($b['c'] ?? 0) + (int)($b['p'] ?? 0); })),
	'blocked'    => array('dash_k_blocked', 'bad', $series('b')),
	'limited'    => array('dash_k_limited', 'accent', $series('r')),
	'would_act'  => array('dash_k_would', 'neutral', $series('m')),
);
?>
<?php if (!$kcur): ?>
<div class="gp-dcard gp-dspan-12" id="dash-kpis">
	<div class="gp-dcard-title"><?= gp_e(gp_t('dash_24h')) ?></div>
	<p class="gp-note"><?= gp_e(gp_t('dash_k_none')) ?> <a href="index.php?r=jobs"><?= gp_e(gp_t('dash_fix_jobs')) ?></a></p>
</div>
<?php else: foreach ($tiles as $k => $td): $cv = $kcur[$k] ?? null; $pv = $kprev[$k] ?? null;
	$chg = gp_kpi_change($cv, $pv);
	$bad = in_array($k, array('blocked', 'limited'), true) && $chg !== '' && $chg[0] === '+'; ?>
<a class="gp-dcard gp-dtile gp-dspan-2" href="<?= gp_dash_tile_link($k) ?>" data-tile="<?= gp_e($k) ?>">
	<span class="gp-dtile-label"><span class="gp-dtile-name"><?= gp_e(gp_t($td[0])) ?></span><?= $k === 'would_act' ? gp_tip('dash_would') : '' ?></span>
	<span class="gp-dtile-value"><?= $cv === null ? '—' : gp_e(gp_num((int)$cv)) ?></span>
	<span class="gp-dtile-delta <?= $bad ? 'gp-text-bad' : '' ?>"><?= $chg === '' ? '' : gp_e($chg) . ' ' . gp_e(gp_t('dash_vs_prev')) ?></span>
	<?php if ($k === 'challenged'): $cs = $kcur['challenge_success'] ?? null; $cp = $kprev['challenge_success'] ?? null; ?>
	<span class="gp-dtile-extra"><?= gp_e(gp_t('dash_solve_rate')) ?>: <b><?= $cs === null ? '—' : gp_e(gp_num((float)$cs, 1)) . '%' ?></b><?= ($cs !== null && $cp !== null) ? ' (' . gp_e(sprintf('%+.1f pt', $cs - $cp)) . ')' : '' ?></span>
	<?php elseif ($k === 'would_act'): ?>
	<span class="gp-dtile-extra"><?= gp_e(gp_t('dash_would_sub')) ?></span>
	<?php else: ?>
	<span class="gp-dtile-extra"><?= gp_e(gp_t('dash_period_24h')) ?></span>
	<?php endif; ?>
	<?= gp_dash_spark($td[2], $td[1], gp_t($td[0])) ?>
</a>
<?php endforeach; endif; ?>

<?php /* ------------------------------------------------------------ 3. main chart */ ?>
<section class="gp-dcard gp-dspan-12" id="dash-main" aria-label="<?= gp_e(gp_t('dash_main_title')) ?>">
	<div class="gp-dcard-title"><?= gp_e(gp_t('dash_main_title')) ?><?= gp_tip('dash_chart') ?><?= $snapshot_stale ? $stale_badge : '' ?>
		<span class="gp-card-sub"><?= gp_e(sprintf(gp_t('dash_main_sub'), date('T P'))) ?></span></div>
	<?php if (!$dash): ?>
	<p class="gp-note"><?= gp_e(gp_t($generated > 0 ? 'dash_no_dash' : 'dash_no_snapshot')) ?> <a href="index.php?r=jobs"><?= gp_e(gp_t('dash_fix_jobs')) ?></a></p>
	<?php else:
		$days7 = isset($dash['days7']) && is_array($dash['days7']) ? $dash['days7'] : array();
		gp_tabs_begin('dmain', array('h24' => gp_t('dash_range_24h'), 'd7' => gp_t('dash_range_7d')));
		gp_tab_begin('dmain', 'h24', gp_t('dash_main_24h')); echo '<div class="gp-dchart-wrap">' . gp_dash_main_chart($hours, false, 'h24') . '</div>'; gp_tab_end();
		gp_tab_begin('dmain', 'd7', gp_t('dash_main_7d')); echo '<div class="gp-dchart-wrap">' . gp_dash_main_chart($days7, true, 'd7') . '</div>'; gp_tab_end();
		gp_tabs_end();
		echo gp_dash_legend();
	endif; ?>
</section>

<?php /* ------------------------------------------------------------ 4a. rollout readiness */ ?>
<?php
$rd = isset($dash['readiness']) && is_array($dash['readiness']) ? $dash['readiness'] : array('rules' => array(), 'lists' => array());
$rrows = array();
foreach ($rules as $r) {
	if (empty($r['enabled']) || ($r['mode'] ?? '') !== 'monitor') { continue; }
	$h = isset($rd['rules'][$r['id']]) && is_array($rd['rules'][$r['id']]) ? $rd['rules'][$r['id']] : array('h24' => 0, 'd7' => 0, 'ips' => 0, 'devs' => 0, 'tok' => 0);
	$rrows[] = array('kind' => 'rule', 'name' => $r['name'] !== '' ? $r['name'] : $r['id'], 'id' => $r['id'], 'h' => $h, 'link' => 'index.php?r=rules', 'logs' => 'index.php?r=logs&amp;reason=' . gp_u('SH_RULE:' . $r['id'] . ',RULE:' . $r['id']));
}
foreach ($iplists as $l) {
	if (empty($l['enabled']) || ($l['mode'] ?? '') !== 'monitor') { continue; }
	$h = isset($rd['lists'][$l['type'] . ':' . $l['id']]) && is_array($rd['lists'][$l['type'] . ':' . $l['id']]) ? $rd['lists'][$l['type'] . ':' . $l['id']] : array('h24' => 0, 'd7' => 0, 'ips' => 0, 'devs' => 0, 'tok' => 0);
	$rrows[] = array('kind' => 'list', 'name' => $l['name'] !== '' ? $l['name'] : $l['id'], 'id' => $l['id'], 'h' => $h, 'link' => 'index.php?r=iplists', 'type' => $l['type'],
		'logs' => 'index.php?r=logs&amp;ipln=' . gp_u($l['id']) . '&amp;ipl=' . gp_u($l['type']));
}
usort($rrows, function ($a, $b) { return $b['h']['d7'] <=> $a['h']['d7']; });
$rr_hit = array_values(array_filter($rrows, function ($r) { return (int)$r['h']['d7'] > 0; }));
$rr_quiet = array_values(array_filter($rrows, function ($r) { return (int)$r['h']['d7'] <= 0; }));
?>
<section class="gp-dcard gp-dspan-7" id="dash-ready" aria-label="<?= gp_e(gp_t('dash_ready_title')) ?>">
	<div class="gp-dcard-title"><?= gp_e(gp_t('dash_ready_title')) ?><?= gp_tip('dash_ready') ?><?= $snapshot_stale ? $stale_badge : '' ?>
		<span class="gp-card-sub"><?= gp_e(gp_t('dash_ready_sub')) ?></span></div>
	<?php if (!$rrows): ?>
	<p class="gp-note"><?= gp_e(gp_t('dash_ready_none')) ?> <a href="index.php?r=rules"><?= gp_e(gp_t('nav_rules')) ?></a> · <a href="index.php?r=iplists"><?= gp_e(gp_t('nav_iplists')) ?></a></p>
	<?php else: ?>
	<?php if ($rr_hit): ?>
	<div class="gp-table-wrap"><table class="gp-table gp-dtable gp-dready">
		<thead>
			<tr><th rowspan="2"><?= gp_e(gp_t('dash_rd_name')) ?></th><th colspan="2" class="gp-num gp-dgroup"><?= gp_e(gp_t('dash_rd_hits')) ?></th>
				<th rowspan="2" class="gp-num"><?= gp_e(gp_t('dash_rd_addr')) ?></th><th rowspan="2" class="gp-num"><?= gp_e(gp_t('dash_rd_tok')) ?></th><th rowspan="2"><?= gp_e(gp_t('dash_rd_ready')) ?></th></tr>
			<tr><th class="gp-num"><?= gp_e(gp_t('dash_rd_h24')) ?></th><th class="gp-num"><?= gp_e(gp_t('dash_rd_d7')) ?></th></tr>
		</thead>
		<tbody>
		<?php foreach ($rr_hit as $rw): $hint = gp_dash_ready_hint($rw['h'], $rw['kind'] === 'list' ? $rw['type'] : ''); ?>
		<tr data-ready="<?= gp_e($hint[0]) ?>">
			<td class="gp-dname"><a href="<?= $rw['logs'] ?>"><?= gp_e($rw['name']) ?></a>
				<span class="gp-badge gp-badge-off" data-type="<?= $rw['kind'] === 'rule' ? 'rule' : 'list-' . gp_e($rw['type']) ?>"><?= gp_e($rw['kind'] === 'rule' ? gp_t('dash_rd_t_rule') : gp_t('dash_rd_t_list_' . $rw['type'])) ?></span></td>
			<td class="gp-num"><?= gp_num((int)$rw['h']['h24']) ?></td><td class="gp-num"><?= gp_num((int)$rw['h']['d7']) ?></td>
			<td class="gp-num"><?= gp_num((int)$rw['h']['ips']) ?> / <?= gp_num((int)$rw['h']['devs']) ?></td>
			<td class="gp-num"><?= ((int)$rw['h']['d7'] > 0 && $hint[0] !== 'allow') ? gp_e(gp_num((float)$rw['h']['tok'], 1)) . '%' : '—' ?></td>
			<td><span class="gp-badge <?= gp_dash_ready_badge($hint[0]) ?>"><?= gp_e(gp_t($hint[1])) ?></span></td>
		</tr>
		<?php endforeach; ?>
		</tbody></table></div>
	<?php endif; ?>
	<?php if (!$rr_hit): ?><p class="gp-note"><?= gp_e(gp_t('dash_rd_nohits_all')) ?></p><?php endif; ?>
	<?php if ($rr_quiet): ?>
	<details class="gp-dquiet" id="dash-ready-quiet">
		<summary><?= gp_e(sprintf(gp_t(count($rr_quiet) === 1 ? 'dash_rd_quiet_one' : 'dash_rd_quiet'), gp_num(count($rr_quiet)))) ?> <span class="gp-dquiet-show">— <?= gp_e(gp_t('dash_rd_show')) ?></span><span class="gp-dquiet-hide">— <?= gp_e(gp_t('dash_rd_hide')) ?></span></summary>
		<ul class="gp-dquiet-list"><?php foreach ($rr_quiet as $rw): ?><li data-ready="none"><a href="<?= $rw['logs'] ?>"><?= gp_e($rw['name']) ?></a>
			<span class="gp-badge gp-badge-off" data-type="<?= $rw['kind'] === 'rule' ? 'rule' : 'list-' . gp_e($rw['type']) ?>"><?= gp_e($rw['kind'] === 'rule' ? gp_t('dash_rd_t_rule') : gp_t('dash_rd_t_list_' . $rw['type'])) ?></span></li><?php endforeach; ?></ul>
	</details>
	<?php endif; ?>
	<p class="gp-help"><?= gp_e(gp_t('dash_ready_help')) ?></p>
	<?php endif; ?>
</section>

<?php /* ------------------------------------------------------------ 4b. challenge and CAPTCHA funnel */ ?>
<?php $fn = isset($dash['funnel']) && is_array($dash['funnel']) ? $dash['funnel'] : array(); ?>
<section class="gp-dcard gp-dspan-5" id="dash-funnel" aria-label="<?= gp_e(gp_t('dash_funnel_title')) ?>">
	<div class="gp-dcard-title"><?= gp_e(gp_t('dash_funnel_title')) ?><?= gp_tip('dash_funnel') ?><?= $snapshot_stale ? $stale_badge : '' ?>
		<span class="gp-card-sub"><?= gp_e(gp_t('dash_period_24h')) ?></span></div>
	<?php $any = false; foreach (array('js', 'captcha') as $lv) { if (!empty($fn[$lv]['served'])) { $any = true; } } ?>
	<?php if (!$fn): ?>
		<p class="gp-note"><?= gp_e(gp_t($generated > 0 ? 'dash_no_dash' : 'dash_no_snapshot')) ?></p>
	<?php elseif (!$any): ?>
		<p class="gp-note"><?= gp_e(gp_t('dash_funnel_none')) ?> <a href="index.php?r=rules"><?= gp_e(gp_t('nav_rules')) ?></a></p>
	<?php else: foreach (array('js', 'captcha') as $lv): $f = $fn[$lv] ?? array(); $served = (int)($f['served'] ?? 0);
		if ($lv === 'captcha' && $served === 0) { echo '<p class="gp-help">' . gp_e(gp_t('dash_funnel_nocap')) . '</p>'; continue; } ?>
	<div class="gp-funnel" data-level="<?= $lv ?>">
		<div class="gp-funnel-h"><?= gp_e(gp_t('dash_lv_' . $lv)) ?><?php if ($lv === 'captcha' && isset($f['median_s']) && $f['median_s'] !== null): ?>
			<span class="gp-card-sub"><?= gp_e(gp_t('dash_c_median')) ?>: <?= gp_e(gp_num((float)$f['median_s'], 1)) ?> s</span><?php endif; ?></div>
		<?php foreach (array('served' => 'ok', 'solved' => 'info', 'passed' => 'ok') as $st => $color): $v = (int)($f[$st] ?? 0); $w = $served > 0 ? max($v > 0 ? 1.5 : 0, min(100, 100.0 * $v / $served)) : 0; ?>
		<div class="gp-funnel-row"><span class="gp-funnel-k"><?= gp_e(gp_t('dash_fn_' . $st)) ?></span>
			<span class="gp-funnel-bar"><span style="width:<?= number_format($w, 1, '.', '') ?>%;background:<?= gp_chart_color($color) ?>"></span></span>
			<span class="gp-funnel-v"><?= gp_num($v) ?><?php if ($st !== 'served' && $served > 0): ?> <small>(<?= gp_e(gp_num(100.0 * $v / $served, 0)) ?>%)</small><?php endif; ?></span></div>
		<?php endforeach; ?>
		<div class="gp-funnel-row"><span class="gp-funnel-k"><?= gp_e(gp_t('dash_fn_failed')) ?></span>
			<span class="gp-funnel-bar"><span style="width:<?= number_format($served > 0 ? max((int)($f['failed'] ?? 0) > 0 ? 1.5 : 0, min(100, 100.0 * (int)($f['failed'] ?? 0) / $served)) : 0, 1, '.', '') ?>%;background:<?= gp_chart_color('bad') ?>"></span></span>
			<span class="gp-funnel-v"><?= gp_num((int)($f['failed'] ?? 0)) ?></span></div>
	</div>
	<?php endforeach; endif; ?>
</section>

<?php /* ------------------------------------------------------------ 5. top lists in tabs */ ?>
<?php
$kinds = array('ips' => 'dash_tab_ips', 'devices' => 'dash_tab_devices', 'uas' => 'dash_tab_uas', 'paths' => 'dash_tab_paths', 'countries' => 'dash_tab_countries', 'asns' => 'dash_tab_asns');
$total_req = (int)($kcur['requests'] ?? 0);
$tl = isset($dash['top']) && is_array($dash['top']) ? $dash['top'] : array();
$tl_tabs = array();
foreach ($kinds as $k => $lab) { $tl_tabs[$k] = gp_t($lab); }
?>
<section class="gp-dcard gp-dspan-12" id="dash-top" aria-label="<?= gp_e(gp_t('dash_top')) ?>">
	<div class="gp-dcard-title"><?= gp_e(gp_t('dash_top')) ?><?= $snapshot_stale ? $stale_badge : '' ?> <span class="gp-card-sub"><?= gp_e(gp_t('dash_top_sub2')) ?></span></div>
	<?php if (!$dash): ?>
	<p class="gp-note"><?= gp_e(gp_t($generated > 0 ? 'dash_no_dash' : 'dash_no_snapshot')) ?> <a href="index.php?r=jobs"><?= gp_e(gp_t('dash_fix_jobs')) ?></a></p>
	<?php else: gp_tabs_begin('dtop', $tl_tabs);
		foreach ($kinds as $k => $lab):
			$rows = isset($tl[$k]) && is_array($tl[$k]) ? $tl[$k] : array();
			gp_tab_begin('dtop', $k, gp_t($lab)); ?>
		<?php if (!$rows): ?>
			<p class="gp-note"><?= in_array($k, array('countries', 'asns'), true) ? gp_dash_geo_empty_html($geo, $cfg) : gp_e(gp_t('dash_top_none')) ?></p>
		<?php else: ?>
		<div class="gp-table-wrap"><table class="gp-table gp-dtable" data-top="<?= gp_e($k) ?>">
			<thead><tr><th><?= gp_e(gp_t($lab)) ?></th><th class="gp-num"><?= gp_e(gp_t('dash_k_requests')) ?></th><th class="gp-num"><?= gp_e(gp_t('dash_share')) ?></th><th><?= gp_e(gp_t('dash_mix')) ?></th><th><?= gp_e(gp_t('dash_qa')) ?></th></tr></thead>
			<tbody>
			<?php foreach ($rows as $r): $key = (string)$r[0]; ?>
			<tr>
				<td class="gp-mono gp-ltr"><a class="gp-dtrunc" href="<?= gp_dash_top_link($k, $key) ?>"><?= gp_e($k === 'asns' ? 'AS' . $key : $key) ?></a></td>
				<td class="gp-num"><?= gp_num((int)$r[1]) ?></td>
				<td class="gp-num"><?= $total_req > 0 ? gp_e(gp_num(100.0 * (int)$r[1] / $total_req, 1)) . '%' : '—' ?></td>
				<td><?= gp_dash_mixbar($r) ?></td>
				<td class="gp-dqa">
					<?php if (in_array($k, array('ips', 'devices'), true)): ?>
						<a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=identity&amp;id=<?= gp_u($key) ?>"><?= gp_e(gp_t('dash_qa_identity')) ?></a>
						<?php if ($can_act): ?><details class="gp-qa"><summary class="gp-btn gp-btn-ghost gp-btn-sm"><?= gp_e(gp_t('dash_qa_actions')) ?></summary><?= gp_quick_actions_html($key, 'index.php?r=dashboard', $role ?? 'admin') ?></details><?php endif; ?>
					<?php else: ?>
						<a class="gp-btn gp-btn-ghost gp-btn-sm" href="<?= gp_dash_top_link($k, $key) ?>"><?= gp_e(gp_t('nav_logs')) ?></a>
						<a class="gp-btn gp-btn-ghost gp-btn-sm" href="<?= str_replace('r=logs', 'r=live', gp_dash_top_link($k, $key)) ?>&amp;minutes=60"><?= gp_e(gp_t('nav_live')) ?></a>
					<?php endif; ?>
				</td>
			</tr>
			<?php endforeach; ?>
			</tbody></table></div>
		<?php endif; ?>
	<?php gp_tab_end(); endforeach; gp_tabs_end(); endif; ?>
</section>

<?php /* ------------------------------------------------------------ 6. system (compact) */ ?>
<?php
$geo = isset($geo) && is_array($geo) ? $geo : null;
$feeds = isset($feeds) && is_array($feeds) ? $feeds : array('failing' => array(), 'held' => array(), 'scheduled' => 0);
$perms = isset($perms) && is_array($perms) ? $perms : null;
?>
<div class="gp-dsys-title gp-dspan-12"><?= gp_e(gp_t('dash_system')) ?></div>

<section class="gp-dcard gp-dspan-4" id="dash-sys-jobs">
	<div class="gp-dcard-title"><?= gp_e(gp_t('dash_jobs')) ?> <a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=jobs"><?= gp_e(gp_t('al_open')) ?></a></div>
	<?php foreach ($jobs as $jn => $h): ?>
	<div class="gp-stat-row"><span class="gp-stat-key gp-mono"><a href="index.php?r=jobs&amp;job=<?= gp_u($jn) ?>"><?= gp_e($jn) ?></a></span>
		<?php $jst = gp_dash_job_state($jn, $h, $cron); ?>
		<span class="gp-stat-val"><span class="gp-badge <?= $jst === 'unscheduled' ? 'gp-badge-off' : gp_job_badge($h['state']) ?>" data-job-state="<?= gp_e($jst) ?>"><?= gp_e(gp_t($jst === 'unscheduled' ? 'job_s_unscheduled' : 'job_s_' . $h['state'])) ?></span>
			<span class="gp-mono"><?= $h['last_success'] > 0 ? gp_e(gp_age($h['last_success'])) : '—' ?></span></span></div>
	<?php endforeach; ?>
	<p class="gp-help"><?= gp_e(gp_t('job_queue')) ?>: <span class="gp-mono"><?= gp_num((int)$queue['length']) ?></span><?= $queue['oldest_age'] !== null ? ' · ' . gp_e(gp_t('job_oldest')) . ' ' . gp_e(gp_age(time() - (int)$queue['oldest_age'])) : '' ?></p>
</section>

<section class="gp-dcard gp-dspan-4" id="dash-sys-redis">
	<div class="gp-dcard-title"><?= gp_e(gp_t('dash_status')) ?></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('dash_redis')) ?></span>
		<span class="gp-badge <?= $redis_up ? 'gp-badge-on' : 'gp-badge-bad' ?>"><?= gp_e($redis_up ? gp_t('dash_redis_up') : gp_t('dash_redis_down')) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('dash_redis_endpoint')) ?></span><span class="gp-stat-val gp-mono" dir="ltr"><?= gp_e($rinfo['endpoint']) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key">db / prefix / auth</span><span class="gp-stat-val gp-mono" dir="ltr"><?= gp_e($rinfo['db']) ?> / <?= gp_e($rinfo['prefix'] === '' ? '-' : $rinfo['prefix']) ?> / <?= gp_e($rinfo['auth'] ? 'on' : 'off') ?></span></div>
	<?php if (!empty($health['breaker'])): ?><div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('dash_breaker')) ?></span><span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('dash_breaker_open')) ?></span></div><?php endif; ?>
	<?php if (!empty($health['last_error'])): ?><div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('dash_last_error')) ?></span><span class="gp-stat-val gp-mono" dir="ltr"><?= gp_e($health['last_error']) ?></span></div><?php endif; ?>
	<?php foreach (array('block', 'challenge', 'ratelimit') as $k): $on = !empty($cfg['enforce'][$k]); ?>
	<div class="gp-stat-row"><span class="gp-stat-key gp-mono">enforce.<?= gp_e($k) ?></span><span class="gp-badge <?= $on ? 'gp-badge-on' : 'gp-badge-off' ?>"><?= gp_e($on ? gp_t('on') : gp_t('off')) ?></span></div>
	<?php endforeach; ?>
	<?php foreach (array('reputation', 'ml', 'clf') as $k): $on = !empty($cfg['signals'][$k]); ?>
	<div class="gp-stat-row"><span class="gp-stat-key gp-mono">signals.<?= gp_e($k) ?></span><span class="gp-badge <?= $on ? 'gp-badge-on' : 'gp-badge-off' ?>"><?= gp_e($on ? gp_t('on') : gp_t('off')) ?></span></div>
	<?php endforeach; ?>
</section>

<?php if (!empty($storage) && is_array($storage)): $sw = $storage['warnings']; ?>
<section class="gp-dcard gp-dspan-4" id="dash-sys-storage">
	<div class="gp-dcard-title"><?= gp_e(gp_t('ls_title')) ?> <span class="gp-badge <?= $sw ? 'gp-badge-warn' : 'gp-badge-on' ?>"><?= gp_e($sw ? gp_t('ls_attention') : gp_t('ls_ok')) ?></span></div>
	<?php foreach ($sw as $w): ?><p class="gp-note gp-note-strong"><?= gp_e(gp_t('ls_w_' . $w)) ?></p><?php endforeach; ?>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('ls_total')) ?></span><span class="gp-stat-val"><?= gp_e(gp_bytes($storage['total'])) ?><?php if ($storage['max_mb'] > 0): ?> / <?= gp_e(gp_bytes($storage['max_mb'] * 1048576)) ?><?php endif; ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('ls_today')) ?></span><span class="gp-stat-val"><?= gp_e(gp_bytes($storage['today'])) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('ls_archives')) ?></span><span class="gp-stat-val"><?= gp_e(gp_num($storage['archives'])) ?> · <?= gp_e(sprintf(gp_t('ls_kept'), gp_num($storage['retention_days']))) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('ls_free')) ?></span><span class="gp-stat-val"><?= $storage['free'] === null ? gp_e(gp_t('unknown')) : gp_e(gp_bytes($storage['free'])) ?><?php if ($storage['disk']): ?> / <?= gp_e(gp_bytes($storage['disk'])) ?><?php endif; ?></span></div>
	<?php $lq = isset($jobs['logrotate']['result']['quota']) ? (string)$jobs['logrotate']['result']['quota'] : ''; if ($lq !== ''): ?>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('ls_quota')) ?></span><span class="gp-stat-val gp-mono gp-ltr"><?= gp_e($lq) ?></span></div><?php endif; ?>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('ls_rotate')) ?></span><span class="gp-stat-val"><?= $storage['rotate'] === null ? gp_e(gp_t('never')) : gp_e(gp_age((int)$storage['rotate']['ts'])) . ' ' . gp_e(gp_t('ago')) ?></span></div>
	<?php if (!empty($pipeline) && is_array($pipeline)): $pv = (string)$pipeline['verdict']; ?>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('pipe_title')) ?></span><span class="gp-badge <?= $pv === 'ok' ? 'gp-badge-on' : 'gp-badge-bad' ?>"><?= gp_e(gp_t('pipe_' . $pv)) ?></span></div><?php endif; ?>
</section>
<?php endif; ?>

<section class="gp-dcard gp-dspan-4" id="clf-labels">
	<div class="gp-dcard-title"><?= gp_e(gp_t('dash_models')) ?> <a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=models#clf-labels"><?= gp_e(gp_t('nav_models')) ?></a></div>
	<div class="gp-card-title gp-dsub"><?= gp_e(gp_t('mdl_labels_title')) ?><?= gp_tip('mdl_labels') ?></div>
	<?= gp_clf_labels_html(isset($clf_labels) ? $clf_labels : null) ?>
	<?php $mdl = isset($s['models']) && is_array($s['models']) ? $s['models'] : array();
	foreach (array('ml', 'clf') as $mk): $live = isset($mdl[$mk]['live']) && is_array($mdl[$mk]['live']) ? $mdl[$mk]['live'] : null; ?>
	<div class="gp-stat-row"><span class="gp-stat-key gp-mono"><?= gp_e($mk) ?></span><span class="gp-stat-val"><?php if ($live && !empty($live['exists'])): ?>
		<span class="gp-badge <?= !empty($live['loadable']) && empty($live['stale']) ? 'gp-badge-on' : 'gp-badge-warn' ?>"><?= gp_e(gp_t(!empty($live['loadable']) ? (empty($live['stale']) ? 'dash_model_ok' : 'dash_model_stale') : 'dash_model_bad')) ?></span>
		<?php if (!empty($live['mtime'])): ?><span class="gp-mono"><?= gp_e(gp_age((float)$live['mtime'])) ?> <?= gp_e(gp_t('ago')) ?></span><?php endif; ?>
		<?php else: ?><span class="gp-badge gp-badge-off"><?= gp_e(gp_t('dash_model_none')) ?></span><?php endif; ?></span></div>
	<?php endforeach; ?>
</section>

<section class="gp-dcard gp-dspan-4" id="dash-sys-geo">
	<div class="gp-dcard-title"><?= gp_e(gp_t('dash_geo_feeds')) ?> <a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=geo"><?= gp_e(gp_t('nav_geo')) ?></a></div>
	<?php foreach (array('country' => 'dash_geo_country', 'asn' => 'dash_geo_asn') as $gk => $gl): $gi = $geo[$gk] ?? null; ?>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t($gl)) ?></span><span class="gp-stat-val"><?php if ($gi && !empty($gi['valid'])): ?>
		<span class="gp-badge <?= ($gi['age_days'] ?? 0) > 45 ? 'gp-badge-warn' : 'gp-badge-on' ?>"><?= gp_e(sprintf(gp_t('dash_geo_age'), gp_num((int)($gi['age_days'] ?? 0)))) ?></span>
		<?php else: ?><span class="gp-badge gp-badge-off"><?= gp_e(gp_t('dash_geo_none')) ?></span><?php endif; ?></span></div>
	<?php endforeach; ?>
	<?php if (!empty($geo_warn)): ?><p class="gp-note gp-note-strong"><?= gp_e(gp_t('dash_geo_fix')) ?></p><?php endif; ?>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('dash_feeds')) ?></span><span class="gp-stat-val"><?= gp_num((int)$feeds['scheduled']) ?> <?= gp_e(gp_t('dash_feeds_sched')) ?><?php if ($feeds['failing']): ?>
		<span class="gp-badge gp-badge-bad"><?= gp_num(count($feeds['failing'])) ?> <?= gp_e(gp_t('dash_feeds_failing')) ?></span><?php endif; ?></span></div>
</section>

<section class="gp-dcard gp-dspan-4" id="dash-sys-perms">
	<div class="gp-dcard-title"><?= gp_e(gp_t('dash_perms')) ?> <a class="gp-btn gp-btn-ghost gp-btn-sm" href="index.php?r=jobs#perms"><?= gp_e(gp_t('al_open')) ?></a></div>
	<?php if (!$perms): ?><p class="gp-help"><?= gp_e(gp_t('dash_perms_none')) ?></p><?php else: $pbad = count((array)$perms['unreadable']) + (int)$perms['writable_dirs'] + (int)$perms['writable_files'] + count((array)$perms['secret_readable']) + count((array)$perms['cron_not_exec']); ?>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('dash_perms_state')) ?></span><span class="gp-badge <?= $pbad ? 'gp-badge-warn' : 'gp-badge-on' ?>"><?= gp_e(gp_t($pbad ? 'dash_perms_attn' : 'dash_perms_ok')) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('dash_perms_scanned')) ?></span><span class="gp-stat-val"><?= gp_num((int)$perms['scanned']) ?> · <?= gp_e(gp_age((int)$perms['time'])) ?> <?= gp_e(gp_t('ago')) ?></span></div>
	<?php endif; ?>
</section>

<?php /* ------------------------------------------------------------ 7. more (collapsed) */ ?>
<details class="gp-more gp-details gp-dspan-12" id="dash-more">
	<summary><?= gp_e(gp_t('dash_more')) ?></summary>
	<div class="gp-dmore">
		<?php $bv = isset($s['bot_verify']) && is_array($s['bot_verify']) ? $s['bot_verify'] : array();
		if (!empty($bv['unknown'])): ?>
		<div class="gp-dcard gp-dspan-12"><span class="gp-badge gp-badge-warn"><?= gp_e(gp_t('dash_verify_unknown')) ?></span> <span class="gp-stat-val"><?= gp_num((int)$bv['unknown']) ?></span>
			<p class="gp-help"><?= gp_e(gp_t('dash_verify_unknown_help')) ?></p></div>
		<?php endif; ?>
		<div class="gp-dcard gp-dspan-6">
			<div class="gp-dcard-title"><?= gp_e(gp_t('dash_holdout_gap')) ?></div>
			<?php if (empty($holdout['enabled'])): ?><p class="gp-note"><?= gp_dash_holdout_empty_html($cfg) ?></p><?php else: ?>
			<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('logs_holdout')) ?></span><span class="gp-stat-val"><?= gp_num((float)($holdout['holdout_challenge_rate'] ?? 0), 1) ?>%</span></div>
			<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('dash_enforce')) ?></span><span class="gp-stat-val"><?= gp_num((float)($holdout['enforced_challenge_rate'] ?? 0), 1) ?>%</span></div>
			<?php endif; ?>
		</div>
		<div class="gp-dcard gp-dspan-6">
			<div class="gp-dcard-title"><?= gp_e(gp_t('dash_coverage')) ?></div>
			<p class="gp-help"><?= gp_e(gp_t('dash_coverage_sub')) ?></p>
			<?php foreach (array('rep', 'ml', 'clf') as $k): $pc = (float)($coverage[$k] ?? 0); ?>
			<div class="gp-dcov"><div class="gp-row-head" style="justify-content:space-between"><span class="gp-mono"><?= gp_e($k) ?></span><span class="gp-stat-val"><?= gp_num($pc, 1) ?>%</span></div>
				<div class="gp-bar-track"><div class="gp-bar-fill<?= $pc < 20 ? ' gp-bar-fill-warn' : '' ?>" style="width:<?= number_format(max(0, min(100, $pc)), 1, '.', '') ?>%"></div></div></div>
			<?php endforeach; ?>
		</div>
		<div class="gp-dcard gp-dspan-6">
			<div class="gp-dcard-title"><?= gp_e(gp_t('dash_chart_score')) ?></div>
			<?= gp_chart_histogram(isset($s['sc_hist']) && is_array($s['sc_hist']) ? $s['sc_hist'] : array(), isset($s['esc_hist']) && is_array($s['esc_hist']) ? $s['esc_hist'] : array(), gp_t('logs_sc'), gp_t('logs_esc')) ?>
		</div>
		<div class="gp-dcard gp-dspan-6">
			<div class="gp-dcard-title"><?= gp_e(gp_t('dash_chart_status')) ?></div>
			<?php $st_rows = isset($s['status']) && is_array($s['status']) ? $s['status'] : array();
			if ($st_rows): ?><?= gp_chart_bars($st_rows, array('color' => gp_chart_color('info'))) ?><?php else: ?><p class="gp-note"><?= gp_dash_status_empty_html($cfg) ?></p><?php endif; ?>
		</div>
		<div class="gp-dcard gp-dspan-6">
			<div class="gp-dcard-title"><?= gp_e(gp_t('dash_chart_reasons')) ?></div>
			<?= gp_chart_bars(isset($s['reasons']) && is_array($s['reasons']) ? $s['reasons'] : array(), array('color' => gp_chart_color('accent'), 'reasons' => true)) ?>
		</div>
		<div class="gp-dcard gp-dspan-6">
			<div class="gp-dcard-title"><?= gp_e(gp_t('dash_top_rules')) ?></div>
			<?php $rl = isset($top_old['rules']) && is_array($top_old['rules']) ? $top_old['rules'] : array();
			if (!$rl): ?><p class="gp-help"><?= gp_e(gp_t('dash_top_none')) ?></p><?php else: foreach ($rl as $r): ?>
			<div class="gp-stat-row"><a class="gp-stat-key gp-mono gp-ltr gp-truncate" href="index.php?r=logs&amp;reason=<?= gp_u('RULE:' . $r[0] . ',SH_RULE:' . $r[0]) ?>"><?= gp_reason_badge('RULE:' . (string)$r[0], false) ?></a><span class="gp-stat-val"><?= gp_e(gp_num((int)$r[1])) ?></span></div>
			<?php endforeach; endif; ?>
		</div>
		<?php if (!empty($traffic['degraded'])): ?>
		<div class="gp-note gp-note-strong gp-dspan-12"><?= gp_e(gp_t('dash_degraded')) ?>: <?= gp_num((int)$traffic['degraded']) ?> (<?= gp_pct((int)$traffic['degraded'], (int)($traffic['requests'] ?: 1)) ?>)</div>
		<?php endif; ?>
	</div>
</details>

</div>
