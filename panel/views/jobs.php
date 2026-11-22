<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Background jobs: health of every cron job (from the status the cron wrapper records on each run),
// the crontab check, the panel's job queue and the jobs started from the panel. The panel only ever writes a
// typed JSON envelope onto a Redis list; the Python worker calls the matching function in-process. Nothing
// here builds or runs a command line. Error text comes from log files that were redacted when written and is
// shown escaped.
$health = isset($health) && is_array($health) ? $health : array();
$detail = isset($detail) ? (string)$detail : '';
$cron = isset($cron) && is_array($cron) ? $cron : array('mode' => 'none', 'report' => null, 'age' => null);
$queue = isset($queue) && is_array($queue) ? $queue : array('length' => 0, 'oldest_age' => null, 'stuck' => false, 'redis' => false);
$cron_lines = isset($cron_lines) && is_array($cron_lines) ? $cron_lines : array();
?>
<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('job_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('job_needs_worker')) ?></p>
</div>

<?php if (!$redis_up): ?>
<div class="gp-note gp-note-strong"><?= gp_e(gp_t('job_needs_redis')) ?></div>
<?php endif; ?>
<?php if (!empty($queue['stuck'])): ?>
<div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('al_queue_stuck')) ?>: <?= gp_e((string)(int)floor($queue['oldest_age'] / 60)) ?> min</div>
<?php endif; ?>

<?php /* ---------------------------------------------------- detail of one job */ ?>
<?php if ($detail !== '' && isset($health[$detail])): $h = $health[$detail]; ?>
<div class="gp-card" id="job-detail">
	<div class="gp-card-title"><span class="gp-mono"><?= gp_e($detail) ?></span>
		<span class="gp-badge <?= gp_job_badge($h['state']) ?>"><?= gp_e(gp_t('job_s_' . $h['state'])) ?></span></div>
	<dl class="gp-props">
		<div class="gp-prop"><dt class="gp-prop-name"><?= gp_e(gp_t('job_c_success')) ?></dt><dd class="gp-prop-val"><?= $h['last_success'] > 0 ? gp_e(gmdate('Y-m-d H:i:s', $h['last_success'])) . ' UTC (' . gp_e(gp_age($h['last_success'])) . ' ' . gp_e(gp_t('ago')) . ')' : '—' ?></dd></div>
		<div class="gp-prop"><dt class="gp-prop-name"><?= gp_e(gp_t('job_c_failure')) ?></dt><dd class="gp-prop-val"><?= $h['last_failure'] > 0 ? gp_e(gmdate('Y-m-d H:i:s', $h['last_failure'])) . ' UTC (' . gp_e(gp_age($h['last_failure'])) . ' ' . gp_e(gp_t('ago')) . ')' : '—' ?></dd></div>
		<div class="gp-prop"><dt class="gp-prop-name"><?= gp_e(gp_t('job_c_next')) ?></dt><dd class="gp-prop-val"><?= $h['next_expected'] > 0 ? gp_e(gmdate('Y-m-d H:i', $h['next_expected'])) . ' UTC' : '—' ?></dd></div>
		<div class="gp-prop"><dt class="gp-prop-name"><?= gp_e(gp_t('job_c_runs')) ?></dt><dd class="gp-prop-val"><?= gp_e(gp_num($h['runs'])) ?> · <?= gp_e(gp_t('job_c_failures')) ?> <?= gp_e(gp_num($h['failures'])) ?> · <?= gp_e(gp_t('job_c_skipped')) ?> <?= gp_e(gp_num($h['skipped'])) ?> · <?= gp_e(gp_t('job_c_duration')) ?> <?= gp_e(gp_num($h['duration'])) ?> s · exit <?= gp_e((string)$h['last_exit']) ?></dd></div>
		<?php if ($h['skew']): ?><div class="gp-prop"><dt class="gp-prop-name"><?= gp_e(gp_t('job_skew')) ?></dt><dd class="gp-prop-val"><?= gp_e(gp_t('job_skew_text')) ?></dd></div><?php endif; ?>
	</dl>
	<?php foreach ($h['warnings'] as $w): ?><p class="gp-note gp-note-strong"><?= gp_e(gp_t('job_s_warning')) ?>: <?= gp_e($w) ?></p><?php endforeach; ?>
	<?php if (is_array($h['result'])): ?>
	<div class="gp-card-title" style="margin-top:.75rem"><?= gp_e(gp_t('job_result')) ?></div>
	<dl class="gp-props"><?php foreach ($h['result'] as $rk => $rv): ?>
		<div class="gp-prop"><dt class="gp-prop-name gp-mono"><?= gp_e((string)$rk) ?></dt><dd class="gp-prop-val"><?= gp_e(is_scalar($rv) ? (string)$rv : json_encode($rv)) ?></dd></div>
	<?php endforeach; ?></dl>
	<?php endif; ?>
	<?php if ($h['last_error'] !== ''): ?>
	<div class="gp-card-title" style="margin-top:.75rem"><?= gp_e(gp_t('job_last_error')) ?></div>
	<pre class="gp-mono gp-ltr gp-pre"><?= gp_e($h['last_error']) ?></pre>
	<?php endif; ?>
	<?php foreach ($errors as $eb): ?>
	<div class="gp-card-title" style="margin-top:.75rem"><?= gp_e(gp_t('job_captured')) ?></div>
	<pre class="gp-mono gp-ltr gp-pre"><?= gp_e($eb) ?></pre>
	<?php endforeach; ?>
	<?php if ($h['state'] === 'failing'): ?>
	<form method="post" action="index.php?r=jobs">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<button class="gp-btn gp-btn-ghost" type="submit" name="seen" value="<?= gp_e($detail) ?>"<?= $h['seen'] ? ' disabled' : '' ?>><?= gp_e(gp_t($h['seen'] ? 'job_seen_already' : 'job_mark_seen')) ?></button>
		<span class="gp-help"><?= gp_e(gp_t('job_seen_help')) ?></span>
	</form>
	<?php endif; ?>
	<?php if ($runs): ?>
	<div class="gp-card-title" style="margin-top:.75rem"><?= gp_e(gp_t('job_recent_runs')) ?></div>
	<div class="gp-table-wrap"><table class="gp-table">
		<thead><tr><th><?= gp_e(gp_t('job_c_when')) ?></th><th><?= gp_e(gp_t('job_c_state')) ?></th><th>exit</th><th><?= gp_e(gp_t('job_c_duration')) ?></th><th><?= gp_e(gp_t('job_c_error')) ?></th></tr></thead>
		<tbody><?php foreach ($runs as $r): ?>
		<tr><td class="gp-mono"><?= gp_e(gmdate('m-d H:i:s', (int)($r['end'] ?? 0))) ?></td><td><?= gp_e((string)($r['status'] ?? '')) ?></td><td class="gp-mono"><?= gp_e((string)($r['exit'] ?? '')) ?></td>
			<td class="gp-mono"><?= gp_e((string)($r['duration'] ?? '')) ?> s</td><td class="gp-mono gp-ltr"><?= gp_e((string)($r['error'] ?? '')) ?></td></tr>
		<?php endforeach; ?></tbody></table></div>
	<?php endif; ?>
</div>
<?php endif; ?>

<?php /* ---------------------------------------------------- health table */ ?>
<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('job_health')) ?></div>
	<div class="gp-table-wrap"><table class="gp-table">
		<thead><tr><th><?= gp_e(gp_t('job_c_job')) ?></th><th><?= gp_e(gp_t('job_c_state')) ?></th><th><?= gp_e(gp_t('job_c_success')) ?></th>
			<th><?= gp_e(gp_t('job_c_failure')) ?></th><th><?= gp_e(gp_t('job_c_next')) ?></th><th><?= gp_e(gp_t('job_c_error')) ?></th></tr></thead>
		<tbody>
		<?php foreach ($health as $jn => $h): ?>
		<tr>
			<td><a class="gp-mono" href="index.php?r=jobs&amp;job=<?= gp_u($jn) ?>#job-detail"><?= gp_e($jn) ?></a><br>
				<span class="gp-help"><?= gp_e(gp_t($h['required'] ? 'job_required' : 'job_recommended')) ?> · <?= gp_e(gp_t('job_every')) ?> <?= gp_e(gp_num((int)($h['interval'] / 60))) ?> min</span></td>
			<td><span class="gp-badge <?= gp_job_badge($h['state']) ?>"><?= gp_e(gp_t('job_s_' . $h['state'])) ?></span><?= $h['seen'] ? ' <span class="gp-help">' . gp_e(gp_t('job_seen')) . '</span>' : '' ?></td>
			<td class="gp-mono"><?= $h['last_success'] > 0 ? gp_e(gp_age($h['last_success'])) . ' ' . gp_e(gp_t('ago')) : '—' ?></td>
			<td class="gp-mono"><?= $h['last_failure'] > 0 ? gp_e(gp_age($h['last_failure'])) . ' ' . gp_e(gp_t('ago')) : '—' ?></td>
			<td class="gp-mono"><?= $h['next_expected'] > 0 ? gp_e(gmdate('m-d H:i', $h['next_expected'])) . ' UTC' : '—' ?></td>
			<td class="gp-mono gp-ltr"><?= gp_e(substr($h['first_line'], 0, 120)) ?></td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table></div>
	<p class="gp-help"><?= gp_e(gp_t('job_health_help')) ?></p>
</div>

<?php /* ---------------------------------------------------- crontab check */ ?>
<div class="gp-card" id="cron-check">
	<div class="gp-card-title"><?= gp_e(gp_t('cron_check_title')) ?>
		<form method="post" action="index.php?r=jobs#cron-check" style="display:inline">
			<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
			<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="cron_refresh" value="1"><?= gp_e(gp_t('cron_refresh_btn')) ?></button>
		</form></div>
	<?php if (!is_array($cron['report'])): ?>
	<p class="gp-note gp-note-strong"><?= gp_e(gp_t('cron_unreadable')) ?> <code class="gp-mono">scripts/cron-check.sh</code></p>
	<?php else: ?>
	<p class="gp-help"><?= gp_e(gp_t('cron_source_' . $cron['mode'])) ?><?= (in_array($cron['mode'], array('file', 'cache'), true) && $cron['age'] !== null) ? ' (' . gp_e(gp_age(time() - (int)$cron['age'])) . ' ' . gp_e(gp_t('ago')) . ')' : '' ?></p>
	<div class="gp-table-wrap"><table class="gp-table">
		<thead><tr><th><?= gp_e(gp_t('job_c_job')) ?></th><th><?= gp_e(gp_t('job_c_state')) ?></th><th><?= gp_e(gp_t('cron_c_schedule')) ?></th><th></th></tr></thead>
		<tbody><?php foreach ($cron['report']['jobs'] as $cj): ?>
		<tr><td class="gp-mono"><?= gp_e($cj['job']) ?></td>
			<td><span class="gp-badge <?= ($cj['severity'] ?? 'ok') === 'ok' ? 'gp-badge-on' : (($cj['severity'] ?? '') === 'critical' ? 'gp-badge-bad' : (($cj['severity'] ?? '') === 'warning' ? 'gp-badge-warn' : 'gp-badge-off')) ?>"><?= gp_e(gp_t('cron_s_' . $cj['state'])) ?></span></td>
			<td class="gp-mono gp-ltr"><?= gp_e((string)($cj['schedule'] ?? '')) ?></td><td class="gp-help"><?= gp_e((string)($cj['message'] ?? '')) ?></td></tr>
		<?php endforeach; ?></tbody></table></div>
	<?php $gpy = $cron['report']['gv_python']; ?>
	<p class="gp-help">GV_PYTHON: <?= !empty($gpy['set']) ? '<code class="gp-mono">' . gp_e($gpy['value']) . '</code> ' . gp_e(gp_t(!empty($gpy['ok']) ? 'cron_py_ok' : 'cron_py_bad')) : gp_e(gp_t('cron_py_unset')) ?></p>
	<?php endif; ?>
	<?php if ($cron_lines): ?>
	<p class="gp-help"><?= gp_e(gp_t('cron_add_lines')) ?> <code class="gp-mono">crontab -e</code></p>
	<pre class="gp-mono gp-ltr gp-pre"><?= gp_e(implode("\n", $cron_lines)) ?></pre>
	<?php endif; ?>
</div>

<?php /* ------------------------------------------------------------ file permissions */ ?>
<?php if (isset($perms) && is_array($perms)): $perm_bad = gp_perm_has_issues($perms); ?>
<div class="gp-card" id="perms">
	<div class="gp-card-title"><?= gp_e(gp_t('perm_title')) ?>
		<form method="post" action="index.php?r=jobs#perms" style="display:inline">
			<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
			<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="perm_refresh" value="1"><?= gp_e(gp_t('perm_rescan')) ?></button>
		</form></div>
	<p class="gp-help"><?= gp_e(gp_t('perm_help')) ?><?= gp_tip('perm_check') ?></p>
	<p class="gp-help"><?= gp_e(gp_t('perm_scanned')) ?>: <span class="gp-mono"><?= gp_num((int)$perms['scanned']) ?></span>
		(<?= gp_e(gp_age(max(0, time() - (int)$perms['time']))) ?> <?= gp_e(gp_t('ago')) ?>; <?= gp_e(gp_t('perm_cached')) ?>)</p>
	<?php if (!$perm_bad): ?>
	<p><span class="gp-badge gp-badge-on"><?= gp_e(gp_t('perm_ok')) ?></span></p>
	<?php else: ?>
	<?php if ($perms['secret_readable']): ?><div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('perm_secret')) ?>: <span class="gp-mono"><?= gp_e(implode(', ', $perms['secret_readable'])) ?></span></div><?php endif; ?>
	<?php if ($perms['cron_not_exec']): ?><div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('perm_cron')) ?>: <span class="gp-mono"><?= gp_e(implode(', ', $perms['cron_not_exec'])) ?></span></div><?php endif; ?>
	<?php if ($perms['writable_dirs'] + $perms['writable_files'] > 0): ?><div class="gp-note"><?= gp_e(gp_t('perm_writable')) ?>: <span class="gp-mono"><?= gp_num((int)$perms['writable_dirs']) ?> <?= gp_e(gp_t('perm_dirs')) ?>, <?= gp_num((int)$perms['writable_files']) ?> <?= gp_e(gp_t('perm_files')) ?></span>
		<pre class="gp-mono gp-ltr gp-pre"><?= gp_e(implode("\n", $perms['writable_sample'])) ?></pre></div><?php endif; ?>
	<p class="gp-help"><?= gp_e(gp_t('perm_fix')) ?></p>
	<pre class="gp-mono gp-ltr gp-pre"><?= gp_e(implode("\n", gp_perm_fix_commands($perms))) ?></pre>
	<?php if ($perms['truncated']): ?><p class="gp-help"><?= gp_e(gp_t('perm_truncated')) ?></p><?php endif; ?>
	<?php endif; ?>
</div>
<?php endif; ?>

<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('job_queue')) ?></div>
	<p class="gp-help"><?= gp_e(gp_t('job_queue_len')) ?>: <span class="gp-mono"><?= gp_num((int)$queue['length']) ?></span><?= $queue['oldest_age'] !== null ? ' · ' . gp_e(gp_t('job_oldest')) . ': ' . gp_e(gp_age(time() - (int)$queue['oldest_age'])) : '' ?></p>
</div>

<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('job_type')) ?></div>
	<form method="post" action="index.php?r=jobs">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<div class="gp-row-head">
			<?php foreach (array('verify', 'nightly', 'snapshot', 'geo_compile') as $type): ?>
			<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit"
				name="job" value="<?= gp_e($type) ?>"><?= gp_e($type) ?></button>
			<?php endforeach; ?>
		</div>
	</form>
</div>

<div class="gp-card">
	<div class="gp-card-title">
		<?= gp_e(gp_t('job_title')) ?>
		<span class="gp-card-sub"><?= gp_num(count($jobs)) ?></span>
	</div>
	<?php if (!$jobs): ?>
		<p class="gp-help"><?= gp_e(gp_t('no_results')) ?></p>
	<?php else: ?>
	<div class="gp-rows">
		<?php foreach ($jobs as $job):
			$status = (string)($job['status'] ?? 'queued');
			$badge = 'gp-badge-off';
			if ($status === 'done') { $badge = 'gp-badge-on'; }
			elseif ($status === 'failed') { $badge = 'gp-badge-bad'; }
			elseif ($status === 'running') { $badge = 'gp-badge-warn'; }
			$label = 'job_' . ($status === 'done' ? 'done' : $status); ?>
		<div class="gp-row">
			<div class="gp-row-head">
				<span class="gp-badge <?= $badge ?>"><?= gp_e(gp_t($label)) ?></span>
				<span class="gp-mono"><?= gp_e($job['type'] ?? '') ?></span>
				<span class="gp-mono gp-ltr"><?= gp_e($job['id'] ?? '') ?></span>
				<span class="gp-mono" style="margin-inline-start:auto">
					<?= gp_e(gp_num_raw(date('m-d H:i:s', (int)($job['requested_at'] ?? 0)))) ?></span>
			</div>
			<div class="gp-row-meta">
				<span><?= gp_e(gp_t('job_requested')) ?>: <?= gp_e($job['requested_by'] ?? '') ?></span>
				<?php if (isset($job['duration'])): ?>
				<span><?= gp_e(gp_t('job_duration')) ?>: <?= gp_num((float)$job['duration'], 1) ?>s</span>
				<?php endif; ?>
			</div>
			<?php if (!empty($job['output'])): ?>
			<div class="gp-detail">
				<pre class="gp-mono gp-ltr" style="white-space:pre-wrap;margin:0"><?= gp_e($job['output']) ?></pre>
			</div>
			<?php endif; ?>
		</div>
		<?php endforeach; ?>
	</div>
	<?php endif; ?>
</div>
