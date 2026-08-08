<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Analyzer jobs. The panel only ever writes a typed JSON envelope onto a Redis
// list; the Python worker calls the matching function in-process. Nothing here
// builds or runs a command line.
?>
<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('job_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('job_needs_worker')) ?></p>
</div>

<?php if (!$redis_up): ?>
<div class="gp-note gp-note-strong"><?= gp_e(gp_t('job_needs_redis')) ?></div>
<?php endif; ?>

<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('job_type')) ?></div>
	<form method="post" action="index.php?r=jobs">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<div class="gp-row-head">
			<?php foreach (array('verify', 'nightly', 'snapshot') as $type): ?>
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
