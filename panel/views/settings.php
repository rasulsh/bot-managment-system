<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Settings: every operational setting, grouped, over the overlay whitelist.
//
// Each field shows a label, the config key, what it does, and its allowed
// range. Out-of-range values are rejected by name, never clamped silently.
// After a rejected save the form shows what the operator typed, not the old
// value, so nothing has to be typed again.
$rules = gv_overlay_whitelist();
$errors = is_array($errors ?? null) ? $errors : array();
$pending = is_array($pending ?? null) ? $pending : array();

$groups = array(
	'enforce'  => array('set_group_enforce', '', array('enforce.block', 'enforce.challenge', 'enforce.ratelimit', 'challenge.gate_post')),
	'signals'  => array('set_group_signals', '', array('signals.reputation', 'signals.ml', 'signals.clf', 'hard_block_score', 'ml_weight', 'clf_weight')),
	'limits'   => array('set_group_limits', '', array('limits.window', 'limits.device', 'limits.ip_ua', 'limits.ip', 'limits.bot',
		'limits.mint', 'limits.device_hour', 'limits.device_day', 'limits.preview', 'limits.bot_unverified')),
	'tokens'   => array('set_group_tokens', '', array('challenge.pow_bits', 'token_ttl', 'nonce_ttl', 'challenge.bind_ip')),
	'strings'  => array('set_group_strings', 'set_group_strings_sub', array('strings.lang', 'strings.dir', 'strings.title', 'strings.sub',
		'strings.noscript', 'strings.failed', 'strings.nocookie', 'strings.retry')),
	'holdout'  => array('set_group_holdout', '', array('holdout_pct', 'capture_outcomes')),
	'paths'    => array('set_group_paths', '', array('exempt_paths', 'exempt_params', 'exempt_params_paths', 'honeypot_path')),
	'network'  => array('set_group_network', '', array('cdn_ranges')),
	'bots'     => array('set_group_bots', '', array('known_bots', 'preview_bots', 'bot_suffixes')),
	'logs'     => array('set_group_logs', 'set_group_logs_sub', array('log_skip_paths', 'log_retention_days', 'log_max_mb', 'log_min_free_mb')),
	'analyzer' => array('set_group_analyzer', 'set_group_analyzer_sub', array('analyzer.window_days', 'analyzer.session_gap_s',
		'analyzer.rep_ttl', 'analyzer.ml_ttl', 'analyzer.botv_ttl', 'analyzer.botbad_ttl', 'analyzer.dns_canary',
		'analyzer.ml_min_train', 'analyzer.contamination', 'analyzer.clf_min_positive', 'analyzer.clf_target_precision',
		'analyzer.report_days', 'analyzer.report_top_n', 'analyzer.challenge_success_target', 'analyzer.snapshot_days',
		'analyzer.job_ttl', 'analyzer.worker_max_jobs', 'analyzer.path_listing', 'analyzer.path_detail')),
);

// The value to show in a field: what was just typed (after a rejected save),
// otherwise the effective value ($cfg is gp_effective_config()).
$value_of = function ($key) use ($cfg, $pending, $errors) {
	if ($errors && array_key_exists($key, $pending)) { return $pending[$key]; }
	return gp_effective_value($cfg, $key);
};

$lbl = function ($key) {
	$k = 'lbl_' . str_replace('.', '_', $key);
	$t = gp_t($k);
	return $t === $k ? $key : $t;
};

// Render one field. The control follows the whitelist type.
$field = function ($key) use ($rules, $overlay, $errors, $value_of, $lbl) {
	$spec = $rules[$key];
	$type = $spec[0];
	$value = $value_of($key);
	$id = 'f-' . str_replace('.', '-', $key);
	$name = 'f[' . $key . ']';
	$err = isset($errors[$key]) ? gp_overlay_msg($errors[$key], $key) : '';
	$wide = in_array($type, array('paths', 'exactpaths', 'bots', 'cidrs4', 'regexes', 'params', 'suffixes', 'text'), true);
	?>
	<div class="gp-set<?= $wide ? ' gp-set-wide' : '' ?><?= $err !== '' ? ' gp-set-invalid' : '' ?>">
	<?php if ($type === 'bool'): ?>
		<label class="gp-check" for="<?= gp_e($id) ?>">
			<input type="hidden" name="present[<?= gp_e($key) ?>]" value="1">
			<input type="checkbox" id="<?= gp_e($id) ?>" name="<?= gp_e($name) ?>" value="1" <?= !empty($value) ? 'checked' : '' ?>>
			<span class="gp-set-label"><?= gp_e($lbl($key)) ?></span>
		</label>
	<?php else: ?>
		<label class="gp-set-label" for="<?= gp_e($id) ?>"><?= gp_e($lbl($key)) ?></label>
		<?php if ($type === 'int' || $type === 'float'): ?>
			<input class="gp-input" type="number" id="<?= gp_e($id) ?>" name="<?= gp_e($name) ?>"
				inputmode="<?= $type === 'int' ? 'numeric' : 'decimal' ?>"
				step="<?= $type === 'int' ? '1' : 'any' ?>"
				min="<?= gp_e((string)$spec[1]) ?>" max="<?= gp_e((string)$spec[2]) ?>"
				value="<?= gp_e(is_scalar($value) ? (string)$value : '') ?>">
		<?php elseif ($type === 'enum'): ?>
			<select class="gp-input" id="<?= gp_e($id) ?>" name="<?= gp_e($name) ?>">
				<?php foreach ($spec[1] as $opt): ?>
				<option value="<?= gp_e($opt) ?>" <?= $value === $opt ? 'selected' : '' ?>><?= gp_e($opt) ?></option>
				<?php endforeach; ?>
			</select>
		<?php elseif (in_array($type, array('paths', 'exactpaths', 'bots', 'cidrs4', 'regexes'), true)): ?>
			<textarea class="gp-textarea" id="<?= gp_e($id) ?>" name="<?= gp_e($name) ?>" rows="4"
				spellcheck="false"><?= gp_e(is_array($value) ? implode("\n", $value) : (string)$value) ?></textarea>
		<?php elseif ($type === 'params' || $type === 'suffixes'):
			$text = '';
			if (is_array($value)) {
				foreach ($value as $n => $list) { $text .= $n . ': ' . implode(', ', (array)$list) . "\n"; }
			} ?>
			<textarea class="gp-textarea" id="<?= gp_e($id) ?>" name="<?= gp_e($name) ?>" rows="4"
				spellcheck="false" placeholder="<?= $type === 'params' ? 'route: payment/, api/' : 'googlebot: .googlebot.com, .google.com' ?>"><?= gp_e(rtrim($text)) ?></textarea>
		<?php else: ?>
			<input class="gp-input" type="text" id="<?= gp_e($id) ?>" name="<?= gp_e($name) ?>"
				<?= $type === 'text' ? 'maxlength="' . (int)$spec[1] . '"' : '' ?>
				value="<?= gp_e(is_scalar($value) ? (string)$value : '') ?>"
				<?= ($key === 'strings.title' || $key === 'strings.sub' || $key === 'strings.noscript' || $key === 'strings.failed'
					|| $key === 'strings.retry' || $key === 'strings.nocookie') ? 'dir="auto"' : 'spellcheck="false"' ?>>
		<?php endif; ?>
	<?php endif; ?>
		<div class="gp-set-meta">
			<code class="gp-prop-key"><?= gp_e($key) ?></code>
			<?php if (array_key_exists($key, $overlay)): ?>
			<span class="gp-badge gp-badge-info"><?= gp_e(gp_t('set_overridden')) ?></span>
			<?php endif; ?>
			<?php if ($type === 'int' || $type === 'float'): ?>
			<span><?= gp_e(gp_t('set_range')) ?>: <?= gp_e((string)$spec[1]) ?>–<?= gp_e((string)$spec[2]) ?></span>
			<?php elseif (in_array($type, array('paths', 'exactpaths', 'bots', 'cidrs4', 'regexes'), true)): ?>
			<span><?= gp_e(gp_t('set_one_per_line')) ?></span>
			<?php elseif ($type === 'params' || $type === 'suffixes'): ?>
			<span><?= gp_e(gp_t('set_name_values')) ?></span>
			<?php endif; ?>
		</div>
		<span class="gp-help"><?= gp_e(gp_t('help_' . str_replace('.', '_', $key))) ?></span>
		<?php if ($err !== ''): ?><span class="gp-error" role="alert"><?= gp_e($err) ?></span><?php endif; ?>
	</div>
	<?php
};
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('set_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('set_no_ui')) ?>
		<a class="gp-link" href="index.php?r=config_file"><?= gp_e(gp_t('set_open_editor')) ?></a></p>
</div>

<nav class="gp-toc" aria-label="<?= gp_e(gp_t('set_contents')) ?>">
	<?php foreach ($groups as $gid => $g): ?>
	<a href="#set-<?= gp_e($gid) ?>"><?= gp_e(gp_t($g[0])) ?></a>
	<?php endforeach; ?>
	<a href="#set-file-only"><?= gp_e(gp_t('set_group_file_only')) ?></a>
</nav>

<?php if ($errors): ?>
<div class="gp-flash gp-flash-error" role="alert"><?= gp_e(gp_t('set_errors_below')) ?></div>
<?php endif; ?>

<?php if (!empty($diff) && !$errors): ?>
<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('set_pending')) ?></div>
	<div class="gp-table-wrap">
	<table class="gp-table">
		<thead><tr><th><?= gp_e(gp_t('aud_key')) ?></th>
			<th><?= gp_e(gp_t('aud_old')) ?></th>
			<th><?= gp_e(gp_t('aud_new')) ?></th></tr></thead>
		<tbody>
		<?php foreach ($diff as $change): ?>
		<tr>
			<td class="gp-mono"><?= gp_e($change['key']) ?></td>
			<td class="gp-mono"><?= gp_e(json_encode($change['old'], JSON_UNESCAPED_UNICODE)) ?></td>
			<td class="gp-mono"><?= gp_e(json_encode($change['new'], JSON_UNESCAPED_UNICODE)) ?></td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
</div>
<?php endif; ?>

<form method="post" action="index.php?r=settings" class="gp-form" novalidate>
	<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
	<input type="hidden" name="action" value="save">

	<?php foreach ($groups as $gid => $g): ?>
	<section class="gp-card" id="set-<?= gp_e($gid) ?>">
		<div class="gp-card-title"><?= gp_e(gp_t($g[0])) ?></div>
		<?php if ($g[1] !== ''): ?><p class="gp-help" style="margin-bottom:.75rem"><?= gp_e(gp_t($g[1])) ?></p><?php endif; ?>
		<div class="gp-set-grid">
			<?php foreach ($g[2] as $k) { if (isset($rules[$k])) { $field($k); } } ?>
		</div>
	</section>
	<?php endforeach; ?>

	<div class="gp-savebar">
		<button class="gp-btn gp-btn-primary" type="submit"><?= gp_e(gp_t('save')) ?></button>
		<span class="gp-help"><?= gp_e(gp_t('set_applies_guard')) ?></span>
	</div>
</form>

<section class="gp-card" id="set-file-only">
	<div class="gp-card-title"><?= gp_e(gp_t('set_group_file_only')) ?></div>
	<p class="gp-help" style="margin-bottom:.5rem"><?= gp_e(gp_t('set_file_only_sub')) ?></p>
	<?php
	$secret_state = function ($v, $placeholder) {
		if (!is_string($v) || $v === '' || $v === $placeholder) { return gp_t('set_placeholder'); }
		return gp_t('set_is_set');
	};
	$rinfo_fo = gp_redis_info();
	$file_only = array(
		array('secret', $secret_state($cfg['secret'] ?? '', 'CHANGE_ME')),
		array('holdout_salt', $secret_state($cfg['holdout_salt'] ?? '', 'CHANGE_ME_TOO')),
		array('challenge.trust_headers', !empty($cfg['challenge']['trust_headers']) ? gp_t('on') : gp_t('off')),
		array('challenge.test_key', (string)($cfg['challenge']['test_key'] ?? '') === '' ? gp_t('set_not_set') : gp_t('set_is_set')),
		array('redis', $rinfo_fo['endpoint'] . ' · db ' . $rinfo_fo['db'] . ' · auth ' . ($rinfo_fo['auth'] ? gp_t('on') : gp_t('off'))),
		array('redis.timeout / breaker_ttl', (string)($cfg['redis']['timeout'] ?? '') . ' s / ' . (string)($cfg['redis']['breaker_ttl'] ?? '') . ' s'),
		array('cookie_name', (string)($cfg['cookie_name'] ?? '')),
		array('log_dir', (string)($cfg['log_dir'] ?? '')),
		array('panel/panel.config.php', gp_t('set_is_set')),
	);
	?>
	<dl class="gp-props">
		<?php foreach ($file_only as $row): ?>
		<div class="gp-prop"><dt class="gp-prop-name"><code class="gp-prop-key"><?= gp_e($row[0]) ?></code></dt>
			<dd class="gp-prop-val"><span class="gp-prop-text"><?= gp_e($row[1]) ?></span></dd></div>
		<?php endforeach; ?>
	</dl>
</section>

<?php if ($overlay): ?>
<section class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('set_overridden')) ?></div>
	<div class="gp-rows">
		<?php foreach ($overlay as $key => $value): ?>
		<div class="gp-row">
			<div class="gp-row-head">
				<span class="gp-mono"><?= gp_e($key) ?></span>
				<code class="gp-mono gp-truncate" style="max-width:28rem"><?= gp_e(json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) ?></code>
				<form method="post" action="index.php?r=settings" style="display:inline;margin-inline-start:auto">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="action" value="reset">
					<input type="hidden" name="key" value="<?= gp_e($key) ?>">
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit"><?= gp_e(gp_t('set_reset')) ?></button>
				</form>
			</div>
		</div>
		<?php endforeach; ?>
	</div>
</section>
<?php endif; ?>
