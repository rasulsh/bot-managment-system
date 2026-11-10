<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Settings: grouped forms over the overlay whitelist.
//
// Every field carries a one-line explanation of what it does and what a bad
// value costs. Out-of-range values are rejected by name, never clamped
// silently, so a typo is reported rather than absorbed.
$rules = gv_overlay_whitelist();

// Render one boolean toggle.
function gp_field_bool($key, $cfg, $overlay, $errors) {
	$current = gp_effective_value($cfg, $key);
	$from_panel = array_key_exists($key, $overlay);
	?>
	<div class="gp-field">
		<label class="gp-check">
			<input type="hidden" name="present[<?= gp_e($key) ?>]" value="1">
			<input type="checkbox" name="f[<?= gp_e($key) ?>]" value="1"
				<?= !empty($current) ? 'checked' : '' ?>>
			<span class="gp-mono"><?= gp_e($key) ?></span>
			<?php if ($from_panel): ?>
			<span class="gp-badge gp-badge-info" style="margin-inline-start:auto">
				<?= gp_e(gp_t('set_overridden')) ?></span>
			<?php endif; ?>
		</label>
		<span class="gp-help"><?= gp_e(gp_t('help_' . str_replace('.', '_', $key))) ?></span>
		<?php gp_field_error($key, $errors); ?>
	</div>
	<?php
}

// Render one numeric field with its documented range.
function gp_field_num($key, $cfg, $overlay, $errors, $step = '1') {
	global $rules;
	$spec = isset($rules[$key]) ? $rules[$key] : array('int', 0, 0);
	$current = gp_effective_value($cfg, $key);
	$from_panel = array_key_exists($key, $overlay);
	?>
	<div class="gp-field">
		<span class="gp-label">
			<span class="gp-mono"><?= gp_e($key) ?></span>
			<?php if ($from_panel): ?>
			<span class="gp-badge gp-badge-info"><?= gp_e(gp_t('set_overridden')) ?></span>
			<?php endif; ?>
		</span>
		<input class="gp-input gp-ltr" type="number" inputmode="decimal" step="<?= gp_e($step) ?>"
			min="<?= gp_e((string)$spec[1]) ?>" max="<?= gp_e((string)$spec[2]) ?>"
			name="f[<?= gp_e($key) ?>]" value="<?= gp_e((string)$current) ?>">
		<span class="gp-help">
			<?= gp_e(gp_t('help_' . str_replace('.', '_', $key))) ?>
			· <?= gp_e(gp_t('set_range')) ?>: <?= gp_e((string)$spec[1]) ?>–<?= gp_e((string)$spec[2]) ?>
		</span>
		<?php gp_field_error($key, $errors); ?>
	</div>
	<?php
}

function gp_field_error($key, $errors) {
	if (!isset($errors[$key])) { return; }
	$map = array('out_of_range' => gp_t('err_range'), 'not_int' => gp_t('err_range'),
		'not_number' => gp_t('err_range'));
	echo '<span class="gp-error">'
		. gp_e(isset($map[$errors[$key]]) ? $map[$errors[$key]] : $errors[$key])
		. '</span>';
}

function gp_reset_button($key) {
	?>
	<form method="post" action="index.php?r=settings" style="display:inline">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<input type="hidden" name="action" value="reset">
		<input type="hidden" name="key" value="<?= gp_e($key) ?>">
		<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit">
			<?= gp_e(gp_t('set_reset')) ?></button>
	</form>
	<?php
}
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('set_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('set_no_ui')) ?></p>
</div>

<?php if (!empty($diff)): ?>
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
			<td class="gp-mono gp-ltr"><?= gp_e(json_encode($change['old'], JSON_UNESCAPED_UNICODE)) ?></td>
			<td class="gp-mono gp-ltr"><?= gp_e(json_encode($change['new'], JSON_UNESCAPED_UNICODE)) ?></td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
</div>
<?php endif; ?>

<form method="post" action="index.php?r=settings" class="gp-form">
	<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
	<input type="hidden" name="action" value="save">

	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('set_group_enforce')) ?></div>
		<div class="gp-grid-3">
			<?php foreach (array('enforce.block', 'enforce.challenge', 'enforce.ratelimit') as $k) {
				gp_field_bool($k, $cfg, $overlay, $errors);
			} ?>
		</div>
	</div>

	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('set_group_signals')) ?></div>
		<div class="gp-grid-3">
			<?php foreach (array('signals.reputation', 'signals.ml', 'signals.clf') as $k) {
				gp_field_bool($k, $cfg, $overlay, $errors);
			} ?>
		</div>
		<div class="gp-grid-3" style="margin-top:.75rem">
			<?php gp_field_num('hard_block_score', $cfg, $overlay, $errors); ?>
			<?php gp_field_num('ml_weight', $cfg, $overlay, $errors, '0.05'); ?>
			<?php gp_field_num('clf_weight', $cfg, $overlay, $errors, '0.05'); ?>
		</div>
	</div>

	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('set_group_limits')) ?></div>
		<div class="gp-grid-3">
			<?php foreach (array('limits.window', 'limits.device', 'limits.ip_ua',
				'limits.ip', 'limits.bot', 'limits.mint') as $k) {
				gp_field_num($k, $cfg, $overlay, $errors);
			} ?>
		</div>
	</div>

	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('set_group_challenge')) ?></div>
		<div class="gp-grid-3">
			<?php gp_field_num('challenge.pow_bits', $cfg, $overlay, $errors); ?>
		</div>
	</div>

	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('set_group_holdout')) ?></div>
		<div class="gp-grid-2">
			<?php gp_field_num('holdout_pct', $cfg, $overlay, $errors); ?>
			<?php gp_field_bool('capture_outcomes', $cfg, $overlay, $errors); ?>
		</div>
	</div>

	<div class="gp-card">
		<div class="gp-card-title"><?= gp_e(gp_t('set_group_paths')) ?></div>

		<label class="gp-field">
			<span class="gp-label gp-mono">exempt_paths</span>
			<textarea class="gp-textarea gp-ltr" name="f[exempt_paths]" rows="5"
				dir="ltr"><?= gp_e(implode("\n", (array)($cfg['exempt_paths'] ?? array()))) ?></textarea>
			<span class="gp-help"><?= gp_e(gp_t('help_exempt_paths')) ?></span>
			<?php gp_field_error('exempt_paths', $errors); ?>
		</label>

		<label class="gp-field">
			<span class="gp-label gp-mono">exempt_params</span>
			<?php
			$params_text = '';
			foreach ((array)($cfg['exempt_params'] ?? array()) as $name => $values) {
				$params_text .= $name . ': ' . implode(', ', (array)$values) . "\n";
			}
			?>
			<textarea class="gp-textarea gp-ltr" name="f[exempt_params]" rows="3"
				dir="ltr" placeholder="route: payment/, api/"><?= gp_e(trim($params_text)) ?></textarea>
			<span class="gp-help"><?= gp_e(gp_t('help_exempt_params')) ?></span>
			<?php gp_field_error('exempt_params', $errors); ?>
		</label>

		<label class="gp-field">
			<span class="gp-label gp-mono">known_bots</span>
			<textarea class="gp-textarea gp-ltr" name="f[known_bots]" rows="3"
				dir="ltr"><?= gp_e(implode("\n", (array)($cfg['known_bots'] ?? array()))) ?></textarea>
			<span class="gp-help"><?= gp_e(gp_t('help_known_bots')) ?></span>
			<?php gp_field_error('known_bots', $errors); ?>
		</label>

		<label class="gp-field">
			<span class="gp-label gp-mono">honeypot_path</span>
			<input class="gp-input gp-ltr" type="text" name="f[honeypot_path]"
				value="<?= gp_e((string)($cfg['honeypot_path'] ?? '')) ?>">
			<span class="gp-help"><?= gp_e(gp_t('help_honeypot_path')) ?></span>
			<?php gp_field_error('honeypot_path', $errors); ?>
		</label>
	</div>

	<button class="gp-btn gp-btn-primary gp-btn-block" type="submit">
		<?= gp_e(gp_t('save')) ?></button>
</form>

<?php if ($overlay): ?>
<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('set_overridden')) ?></div>
	<div class="gp-rows">
		<?php foreach ($overlay as $key => $value): ?>
		<div class="gp-row">
			<div class="gp-row-head">
				<span class="gp-mono"><?= gp_e($key) ?></span>
				<code class="gp-mono gp-ltr"><?= gp_e(json_encode($value, JSON_UNESCAPED_UNICODE)) ?></code>
				<span style="margin-inline-start:auto"><?php gp_reset_button($key); ?></span>
			</div>
		</div>
		<?php endforeach; ?>
	</div>
</div>
<?php endif; ?>
