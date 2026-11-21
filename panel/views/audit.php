<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Audit trail: append-only, read-only. Every config change, override, job and
// login attempt lands here.
?>
<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('aud_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('aud_readonly')) ?></p>
</div>

<?= gp_filter_form_html('audit', array(
	'event' => array('aud_event', 'is', array('config', 'config_reset', 'killswitch', 'override_allow', 'override_deny', 'override_clear', 'job', 'login_ok', 'login_failed',
		'rule_create', 'rule_update', 'rule_delete', 'geo_upload', 'geo_rollback'), 'flt_event'),
	'actor' => array('aud_actor', 'is', array(), 'flt_actor'),
	'q' => array('search', 'has', array(), 'flt_q')), $filter) ?>

<div class="gp-card">
	<?php if (!$entries): ?>
		<p class="gp-help"><?= gp_e(gp_t('no_results')) ?></p>
	<?php else: ?>
	<div class="gp-rows">
		<?php foreach ($entries as $entry):
			$event = (string)($entry['event'] ?? '');
			$badge = 'gp-badge-off';
			if ($event === 'login_failed' || $event === 'login_locked') { $badge = 'gp-badge-bad'; }
			elseif ($event === 'login_ok') { $badge = 'gp-badge-on'; }
			elseif ($event === 'config' || $event === 'config_reset') { $badge = 'gp-badge-info'; }
			elseif ($event === 'killswitch') { $badge = 'gp-badge-warn'; } ?>
		<div class="gp-row">
			<div class="gp-row-head">
				<span class="gp-badge <?= $badge ?>"><?= gp_e($event) ?></span>
				<span class="gp-mono"><?= gp_e($entry['actor'] ?? '') ?></span>
				<span class="gp-mono gp-ltr"><?= gp_e($entry['ip'] ?? '') ?></span>
				<span class="gp-mono" style="margin-inline-start:auto">
					<?= gp_e(gp_num_raw(date('Y-m-d H:i:s', (int)($entry['ts'] ?? 0)))) ?></span>
			</div>
			<?php if (isset($entry['key'])): ?>
			<div class="gp-row-meta">
				<span class="gp-mono"><?= gp_e($entry['key']) ?></span>
				<?php if (array_key_exists('old', $entry)): ?>
				<span><?= gp_e(gp_t('aud_old')) ?>:
					<code class="gp-mono gp-ltr"><?= gp_e(json_encode($entry['old'], JSON_UNESCAPED_UNICODE)) ?></code></span>
				<?php endif; ?>
				<?php if (array_key_exists('new', $entry)): ?>
				<span><?= gp_e(gp_t('aud_new')) ?>:
					<code class="gp-mono gp-ltr"><?= gp_e(json_encode($entry['new'], JSON_UNESCAPED_UNICODE)) ?></code></span>
				<?php endif; ?>
			</div>
			<?php endif; ?>
		</div>
		<?php endforeach; ?>
	</div>
	<?php endif; ?>
</div>
