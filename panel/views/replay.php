<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Interactive threshold replay, computed natively in PHP.
//
// The false-positive proxy is visually emphasised because it is the number that
// decides the change: every unit of it is a real customer who would newly be
// challenged or blocked.
$p = $params;
$r = is_array($result) ? $result : null;
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('rep_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('rep_intro')) ?></p>
</div>

<form method="get" action="index.php" class="gp-card gp-form">
	<input type="hidden" name="r" value="replay">
	<input type="hidden" name="run" value="1">

	<div class="gp-grid-2">
		<label class="gp-field">
			<span class="gp-label">
				hard_block_score — <output id="out-hbs" class="gp-stat-val"></output>
			</span>
			<input class="gp-range" type="range" name="hard_block_score" min="10" max="200"
				step="1" value="<?= gp_e((string)$p['hard_block_score']) ?>"
				data-output="out-hbs">
			<span class="gp-help"><?= gp_e(gp_t('help_hard_block_score')) ?></span>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('rep_window')) ?></span>
			<select class="gp-input" name="days">
				<?php foreach (array(1, 3, 7, 14) as $d): ?>
				<option value="<?= (int)$d ?>" <?= ((int)$p['days'] === $d) ? 'selected' : '' ?>>
					<?= gp_e(gp_plural($d, 'day')) ?></option>
				<?php endforeach; ?>
			</select>
		</label>
		<label class="gp-field">
			<span class="gp-label">
				ml_weight — <output id="out-mlw" class="gp-stat-val"></output>
			</span>
			<input class="gp-range" type="range" name="ml_weight" min="0" max="2" step="0.05"
				value="<?= gp_e((string)$p['ml_weight']) ?>" data-output="out-mlw">
		</label>
		<label class="gp-field">
			<span class="gp-label">
				clf_weight — <output id="out-clfw" class="gp-stat-val"></output>
			</span>
			<input class="gp-range" type="range" name="clf_weight" min="0" max="2" step="0.05"
				value="<?= gp_e((string)$p['clf_weight']) ?>" data-output="out-clfw">
		</label>
	</div>

	<div class="gp-grid-3">
		<?php foreach (array('reputation', 'ml', 'clf') as $signal): ?>
		<label class="gp-check">
			<input type="checkbox" name="signals_<?= gp_e($signal) ?>" value="1"
				<?= !empty($p['signals_' . $signal]) ? 'checked' : '' ?>>
			<span>signals.<?= gp_e($signal) ?></span>
		</label>
		<?php endforeach; ?>
	</div>

	<button class="gp-btn gp-btn-primary" type="submit"><?= gp_e(gp_t('rep_recompute')) ?></button>
</form>

<?php if ($r !== null): ?>

<?php if (!empty($r['capped'])): ?>
<div class="gp-note gp-note-strong"><?= gp_e(gp_t('logs_capped')) ?></div>
<?php endif; ?>

<div class="gp-card">
	<div class="gp-card-title">
		<?= gp_e(gp_t('rep_baseline')) ?> / <?= gp_e(gp_t('rep_candidate')) ?>
		<span class="gp-card-sub">
			<?= gp_num((int)$r['considered']) ?> ·
			<?= gp_e(gp_t('logs_scanned')) ?> <?= gp_num((int)$r['scanned_lines']) ?>
		</span>
	</div>
	<div class="gp-table-wrap">
	<table class="gp-table">
		<thead><tr>
			<th><?= gp_e(gp_t('logs_act')) ?></th>
			<th><?= gp_e(gp_t('rep_baseline')) ?></th>
			<th><?= gp_e(gp_t('rep_candidate')) ?></th>
			<th><?= gp_e(gp_t('rep_delta')) ?></th>
		</tr></thead>
		<tbody>
		<?php foreach (array('allow', 'challenge', '403', '429') as $action):
			$b = (int)($r['baseline'][$action] ?? 0);
			$c = (int)($r['candidate'][$action] ?? 0);
			$d = $c - $b; ?>
			<tr>
				<td class="gp-mono"><?= gp_e($action) ?></td>
				<td><?= gp_num($b) ?></td>
				<td><?= gp_num($c) ?></td>
				<td class="<?= $d > 0 ? 'gp-stat-val' : '' ?>">
					<?= $d === 0 ? '—' : ($d > 0 ? '+' : '−') . gp_num(abs($d)) ?>
				</td>
			</tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
</div>

<div class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('rep_movement')) ?></div>
	<?php if (empty($r['movement'])): ?>
		<p class="gp-help"><?= gp_e(gp_t('rep_no_movement')) ?></p>
	<?php else: ?>
		<?php echo gp_chart_bars($r['movement'], array('color' => gp_chart_color('info'))); ?>
	<?php endif; ?>
</div>

<div class="gp-grid-3">
	<div class="gp-card">
		<div class="gp-kpi-label"><?= gp_e(gp_t('rep_bot_rows')) ?></div>
		<div class="gp-kpi-value"><?= gp_num((int)$r['bot_newly']) ?></div>
		<div class="gp-kpi-hint">
			<?= gp_e(gp_t('rep_newly')) ?> · <?= gp_e(gp_t('rep_recall')) ?>
			(<?= gp_num((int)$r['bot_rows']) ?>)
		</div>
	</div>

	<!-- The number that decides the change. -->
	<div class="gp-card gp-card-danger">
		<div class="gp-kpi-label gp-text-bad" style="font-weight:700">
			<?= gp_e(gp_t('rep_human_rows')) ?>
		</div>
		<div class="gp-kpi-value gp-text-bad">
			<?= gp_num((int)$r['human_newly']) ?>
		</div>
		<div class="gp-kpi-hint gp-text-bad">
			<?= gp_e(gp_t('rep_decider')) ?>
			(<?= gp_num((int)$r['human_rows']) ?>)
		</div>
	</div>

	<div class="gp-card">
		<div class="gp-kpi-label"><?= gp_e(gp_t('rep_holdout_rows')) ?></div>
		<div class="gp-kpi-value"><?= gp_num((int)$r['holdout_newly']) ?></div>
		<div class="gp-kpi-hint">(<?= gp_num((int)$r['holdout_rows']) ?>)</div>
	</div>
</div>

<?php if ((int)$r['human_rows'] === 0): ?>
<div class="gp-note gp-note-strong"><?= gp_e(gp_t('rep_no_human')) ?></div>
<?php endif; ?>

<div class="gp-card">
	<form method="post" action="index.php?r=replay" class="gp-form"
		data-confirm="<?= gp_e(gp_t('rep_apply')) ?>?">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<?php foreach (array('hard_block_score', 'ml_weight', 'clf_weight', 'days') as $k): ?>
		<input type="hidden" name="<?= gp_e($k) ?>" value="<?= gp_e((string)$p[$k]) ?>">
		<?php endforeach; ?>
		<?php foreach (array('reputation', 'ml', 'clf') as $signal):
			if (!empty($p['signals_' . $signal])): ?>
		<input type="hidden" name="signals_<?= gp_e($signal) ?>" value="1">
		<?php endif; endforeach; ?>
		<div class="gp-row-head">
			<button class="gp-btn gp-btn-primary" type="submit" name="action" value="apply">
				<?= gp_e(gp_t('rep_apply')) ?></button>
			<button class="gp-btn gp-btn-ghost" type="submit" name="action" value="full">
				<?= gp_e(gp_t('rep_full')) ?></button>
		</div>
	</form>
	<?= gp_msg('replay-actions') ?>
</div>

<?php endif; ?>
