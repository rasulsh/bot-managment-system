<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Log explorer: the replacement for grep and jq.
//
// Everything rendered below - user agents, paths, query strings, referers -
// was written by the clients this system is fighting. Every single value goes
// through gp_e(). There is no field here that is "safe".
$f = is_array($filter) ? $filter : array();
function gp_logs_qs(array $filter, array $extra = array()) {
	$query = array_merge(array('r' => 'logs'), $filter, $extra);
	return 'index.php?' . http_build_query($query);
}
$act_options = array('', 'allow', 'challenge', '403', '429', 'exempt', 'allow_bot',
	'allow_override', '404_hp', 'token_issued', 'nonce_bad');
$reason_options = array('', 'UA_EMPTY', 'UA_SCRIPT', 'NO_AL', 'NO_SF', 'FEW_HDR',
	'HP_HIST', 'BOT_FAKE');
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('logs_title')) ?></h1>
	<p class="gp-page-sub gp-mono">
		<?= gp_e($meta['file']) ?> ·
		<?= gp_e(gp_t('logs_scanned')) ?>: <?= gp_num((int)$meta['scanned_lines']) ?>
	</p>
</div>

<form method="get" action="index.php" class="gp-card gp-form">
	<input type="hidden" name="r" value="logs">
	<div class="gp-filters">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_date')) ?></span>
			<select class="gp-input" name="date">
				<?php foreach ($dates as $d): ?>
				<option value="<?= gp_e($d) ?>" <?= (($f['date'] ?? '') === $d) ? 'selected' : '' ?>>
					<?= gp_e(gp_num_raw(substr($d, 0, 4) . '-' . substr($d, 4, 2) . '-' . substr($d, 6, 2))) ?>
				</option>
				<?php endforeach; ?>
			</select>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_act')) ?></span>
			<select class="gp-input" name="act">
				<?php foreach ($act_options as $opt): ?>
				<option value="<?= gp_e($opt) ?>" <?= (($f['act'] ?? '') === $opt) ? 'selected' : '' ?>>
					<?= $opt === '' ? gp_e(gp_t('none')) : gp_e($opt) ?></option>
				<?php endforeach; ?>
			</select>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_reason')) ?></span>
			<select class="gp-input" name="reason">
				<?php foreach ($reason_options as $opt): ?>
				<option value="<?= gp_e($opt) ?>" <?= (($f['reason'] ?? '') === $opt) ? 'selected' : '' ?>>
					<?= $opt === '' ? gp_e(gp_t('none')) : gp_e($opt) ?></option>
				<?php endforeach; ?>
			</select>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_status')) ?></span>
			<select class="gp-input" name="status">
				<?php foreach (array('', '2xx', '3xx', '404', '4xx', '5xx') as $opt): ?>
				<option value="<?= gp_e($opt) ?>" <?= (($f['status'] ?? '') === $opt) ? 'selected' : '' ?>>
					<?= $opt === '' ? gp_e(gp_t('none')) : gp_e($opt) ?></option>
				<?php endforeach; ?>
			</select>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_device')) ?></span>
			<input class="gp-input gp-ltr" type="text" name="dev" value="<?= gp_e($f['dev'] ?? '') ?>">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_ip')) ?></span>
			<input class="gp-input gp-ltr" type="text" name="ip" value="<?= gp_e($f['ip'] ?? '') ?>">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_path')) ?></span>
			<input class="gp-input gp-ltr" type="text" name="path" value="<?= gp_e($f['path'] ?? '') ?>">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_token')) ?></span>
			<select class="gp-input" name="tok">
				<?php foreach (array('', 'v', 'm', 'b') as $opt): ?>
				<option value="<?= gp_e($opt) ?>" <?= (($f['tok'] ?? '') === $opt) ? 'selected' : '' ?>>
					<?= $opt === '' ? gp_e(gp_t('none')) : gp_e($opt) ?></option>
				<?php endforeach; ?>
			</select>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_shadow')) ?></span>
			<select class="gp-input" name="sh">
				<option value=""><?= gp_e(gp_t('none')) ?></option>
				<option value="1" <?= (($f['sh'] ?? '') === 1) ? 'selected' : '' ?>><?= gp_e(gp_t('yes')) ?></option>
				<option value="0" <?= (isset($f['sh']) && $f['sh'] === 0) ? 'selected' : '' ?>><?= gp_e(gp_t('no')) ?></option>
			</select>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_holdout')) ?></span>
			<select class="gp-input" name="hold">
				<option value=""><?= gp_e(gp_t('none')) ?></option>
				<option value="1" <?= (($f['hold'] ?? '') === 1) ? 'selected' : '' ?>><?= gp_e(gp_t('yes')) ?></option>
				<option value="0" <?= (isset($f['hold']) && $f['hold'] === 0) ? 'selected' : '' ?>><?= gp_e(gp_t('no')) ?></option>
			</select>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_score_min')) ?></span>
			<input class="gp-input gp-ltr" type="number" name="sc_min" inputmode="numeric"
				value="<?= gp_e((string)($f['sc_min'] ?? '')) ?>">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_score_max')) ?></span>
			<input class="gp-input gp-ltr" type="number" name="sc_max" inputmode="numeric"
				value="<?= gp_e((string)($f['sc_max'] ?? '')) ?>">
		</label>
	</div>
	<div class="gp-row-head">
		<button class="gp-btn gp-btn-primary" type="submit"><?= gp_e(gp_t('filter')) ?></button>
		<a class="gp-btn gp-btn-ghost" href="index.php?r=logs"><?= gp_e(gp_t('reset')) ?></a>
		<a class="gp-btn gp-btn-ghost" href="<?= gp_e(gp_logs_qs($f, array('export' => 'csv'))) ?>">
			<?= gp_e(gp_t('logs_export')) ?></a>
	</div>
</form>

<?php if (!empty($meta['capped'])): ?>
<div class="gp-note gp-note-strong"><?= gp_e(gp_t('logs_capped')) ?></div>
<?php endif; ?>

<?php if (!$rows): ?>
<div class="gp-card"><p class="gp-help"><?= gp_e(gp_t('no_results')) ?></p></div>
<?php else: ?>
<div class="gp-rows">
	<?php foreach ($rows as $i => $row):
		$act = (string)($row['act'] ?? '');
		$badge = 'gp-badge-off';
		if ($act === 'allow' || $act === 'allow_bot' || $act === 'allow_override') { $badge = 'gp-badge-on'; }
		elseif ($act === '403' || $act === 'nonce_bad') { $badge = 'gp-badge-bad'; }
		elseif ($act === '429' || $act === 'challenge') { $badge = 'gp-badge-warn'; }
		$out = isset($row['_out']) && is_array($row['_out']) ? $row['_out'] : null;
		$detail_id = 'gp-d-' . (int)$i;
		$identity = (string)($row['dev'] ?? '') !== '' ? (string)$row['dev'] : (string)($row['ip'] ?? '');
	?>
	<article class="gp-row">
		<div class="gp-row-head">
			<span class="gp-badge <?= $badge ?>"><?= gp_e($act) ?></span>
			<?php if ((int)($row['sh'] ?? 0) === 1): ?>
				<span class="gp-badge gp-badge-info"><?= gp_e(gp_t('logs_shadow')) ?></span>
			<?php endif; ?>
			<?php if ((int)($row['hold'] ?? 0) === 1): ?>
				<span class="gp-badge gp-badge-info"><?= gp_e(gp_t('logs_holdout')) ?></span>
			<?php endif; ?>
			<?php if ((string)($row['ovr'] ?? '') !== ''): ?>
				<span class="gp-badge gp-badge-warn"><?= gp_e($row['ovr']) ?></span>
			<?php endif; ?>
			<?php if ($out !== null): ?>
				<span class="gp-badge gp-badge-off"><?= gp_e((string)($out['st'] ?? '')) ?></span>
			<?php endif; ?>
			<span class="gp-mono" style="margin-inline-start:auto">
				<?= gp_e(gp_num_raw(date('H:i:s', (int)($row['ts'] ?? 0)))) ?></span>
		</div>

		<div class="gp-row-main gp-mono gp-ltr gp-truncate"><?= gp_e($row['p'] ?? '') ?></div>

		<div class="gp-row-meta">
			<span class="gp-ltr"><?= gp_e($row['ip'] ?? '') ?></span>
			<span><?= gp_e(gp_t('logs_sc')) ?>: <?= gp_num((int)($row['sc'] ?? 0)) ?></span>
			<span><?= gp_e(gp_t('logs_esc')) ?>: <?= gp_num((int)($row['esc'] ?? 0)) ?></span>
			<?php foreach ((array)($row['rs'] ?? array()) as $reason): ?>
				<span class="gp-badge gp-badge-off"><?= gp_e($reason) ?></span>
			<?php endforeach; ?>
			<button class="gp-btn gp-btn-ghost gp-btn-sm" type="button"
				data-toggle="<?= gp_e($detail_id) ?>" aria-expanded="false">
				<?= gp_e(gp_t('logs_detail')) ?></button>
			<?php if ($identity !== ''): ?>
			<a class="gp-btn gp-btn-ghost gp-btn-sm"
				href="index.php?r=identity&amp;id=<?= gp_u($identity) ?>">
				<?= gp_e(gp_t('id_title')) ?></a>
			<?php endif; ?>
		</div>

		<div class="gp-detail" id="<?= gp_e($detail_id) ?>" hidden>
			<dl class="gp-dl">
				<?php
				$fields = array('rid' => 'rid', 'ts' => gp_t('logs_time'), 'ip' => gp_t('logs_ip'),
					'dev' => gp_t('logs_device'), 'm' => 'method', 'p' => gp_t('logs_path'),
					'q' => 'query', 'ua' => 'user agent', 'uah' => 'ua hash',
					'ref' => 'referer', 'tok' => gp_t('logs_token'), 'sf' => 'sec-fetch',
					'hc' => 'headers', 'nav' => 'nav', 'aj' => 'ajax',
					'sc' => gp_t('logs_sc'), 'esc' => gp_t('logs_esc'),
					'rep' => gp_t('id_reputation'), 'ml' => gp_t('id_ml'),
					'clf' => gp_t('id_clf'), 'botv' => gp_t('id_botv'),
					'bot' => 'bot', 'hp' => gp_t('id_honeypot'),
					'cd' => 'cd', 'ciu' => 'ciu', 'ci' => 'ci', 'rd' => 'redis down',
					'ms' => 'ms', 'v' => 'schema');
				foreach ($fields as $key => $label):
					if (!array_key_exists($key, $row)) { continue; }
					$value = $row[$key];
					if ($key === 'ts') { $value = gp_num_raw(date('Y-m-d H:i:s', (int)$value)); }
				?>
				<dt><?= gp_e($label) ?></dt>
				<dd class="gp-ltr"><?= gp_e(is_array($value) ? implode(' ', $value) : $value) ?></dd>
				<?php endforeach; ?>

				<?php if ($out !== null): ?>
				<dt><?= gp_e(gp_t('logs_outcome')) ?></dt>
				<dd class="gp-ltr">
					<?= gp_e(gp_t('logs_status')) ?>=<?= gp_e($out['st'] ?? '') ?>
					<?= gp_e(gp_t('logs_bytes')) ?>=<?= gp_e($out['by'] === null ? '-' : $out['by']) ?>
					<?= gp_e(gp_t('logs_duration')) ?>=<?= gp_e($out['dur'] === null ? '-' : $out['dur']) ?>
				</dd>
				<?php else: ?>
				<dt><?= gp_e(gp_t('logs_outcome')) ?></dt>
				<dd><?= gp_e(gp_t('logs_no_outcome')) ?></dd>
				<?php endif; ?>
			</dl>
		</div>
	</article>
	<?php endforeach; ?>
</div>

<?php if (!empty($meta['next_cursor'])): ?>
<div class="gp-row-head" style="justify-content:center">
	<a class="gp-btn gp-btn-ghost"
		href="<?= gp_e(gp_logs_qs($f, array('cursor' => (int)$meta['next_cursor']))) ?>">
		<?= gp_e(gp_t('logs_next')) ?></a>
</div>
<?php endif; ?>
<?php endif; ?>
