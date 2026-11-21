<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Log explorer: the replacement for grep and jq.
//
// Everything rendered below - user agents, paths, query strings, referers -
// was written by the clients this system is fighting. Every single value goes
// through gp_e(). There is no field here that is "safe".
$f = is_array($filter) ? $filter : array();
$act_options = array('', 'allow', 'challenge', '403', '429', 'exempt', 'allow_bot',
	'allow_preview', 'allow_override', '404_hp', 'token_issued', 'nonce_bad', 'nonce_replay', 'pow_bad',
	'mint_limited');
$reason_options = array('', 'UA_EMPTY', 'UA_SCRIPT', 'NO_AL', 'NO_SF', 'FEW_HDR',
	'HP_HIST', 'BOT_FAKE');
?>

<?php
$dash = '—';
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('logs_title')) ?></h1>
	<p class="gp-page-sub gp-latin">
		<bdi class="gp-mono"><?= gp_e($meta['file']) ?></bdi>
		<span class="gp-sep">·</span>
		<span><?= gp_e(gp_t('logs_scanned')) ?>: <?= gp_e(gp_latin((int)$meta['scanned_lines'])) ?></span>
		<span class="gp-sep">·</span>
		<span><?= gp_e(gp_t('logs_shown')) ?>: <?= gp_e(gp_latin(count($rows))) ?></span>
	</p>
</div>

<?php
// Every filter is a pair: an operator (is / is not, contains / does not contain) and
// a value. Choice fields take several values separated by commas (OR inside the
// field); fields are AND-ed. The operator travels as <key>_op=not.
$flt = array(
	'act'    => array('logs_act', 'is', $act_options),
	'ip'     => array('logs_ip', 'is', array()),
	'path'   => array('logs_path', 'has', array()),
	'ua'     => array('logs_ua', 'has', array()),
	'status' => array('logs_status', 'is', array('2xx', '3xx', '404', '4xx', '5xx')),
	'cc'     => array('geo_cc', 'is', array()),
	'asn'    => array('geo_asn', 'is', array()),
	'reason' => array('logs_reason', 'is', $reason_options),
	'botv'   => array('id_botv', 'is', array('ok', 'bad')),
	'dev'    => array('logs_device', 'is', array()),
	'tok'    => array('logs_token', 'is', array('v', 'm', 'b')),
	'sh'     => array('logs_shadow', 'is', array('1', '0')),
	'hold'   => array('logs_holdout', 'is', array('1', '0')),
);
$flt_field = function ($key) use ($flt, $f) {
	$d = $flt[$key];
	$v = isset($f[$key]) ? $f[$key] : null;
	$dl = array_values(array_filter($d[2], 'strlen'));
	if (!empty(gp_log_filter_spec()[$key][4])) { $dl[] = GP_FILTER_NONE; }      // (none) = empty value
	ob_start(); ?>
	<div class="gp-field">
		<label class="gp-label" for="flt-<?= gp_e($key) ?>"><?= gp_e(gp_t($d[0])) ?><?= gp_tip('flt_' . ($key === 'tok' || $key === 'dev' ? $key : $key)) ?></label>
		<div class="gp-fgroup">
			<?= gp_filter_op_select($key, $v, $d[1]) ?>
			<input class="gp-input gp-ltr" type="text" id="flt-<?= gp_e($key) ?>" name="<?= gp_e($key) ?>" value="<?= gp_e(gp_filter_text($v)) ?>"
				<?= $dl ? 'list="dl-' . gp_e($key) . '"' : '' ?> spellcheck="false" autocomplete="off"
				<?= $d[1] === 'is' ? 'placeholder="' . gp_e(gp_t('flt_hint_list')) . '"' : '' ?>>
			<?php if ($dl): ?><datalist id="dl-<?= gp_e($key) ?>"><?php foreach ($dl as $o): ?><option value="<?= gp_e($o) ?>"><?php endforeach; ?></datalist><?php endif; ?>
		</div>
	</div>
	<?php return ob_get_clean();
};
$chips = gp_filter_chips($f, array_map(function ($d) { return gp_t($d[0]); }, $flt),
	array_map(function ($d) { return $d[1] === 'has' ? 'text' : 'choice'; }, $flt),
	function ($q) { return 'index.php?' . http_build_query(array_merge(array('r' => 'logs'), $q)); });
?>
<form method="get" action="index.php" class="gp-card gp-form">
	<input type="hidden" name="r" value="logs">
	<div class="gp-filters gp-filters-3">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('logs_date')) ?><?= gp_tip('flt_date') ?></span>
			<select class="gp-input gp-ltr" name="date">
				<?php foreach ($dates as $d): ?>
				<option value="<?= gp_e($d) ?>" <?= (($f['date'] ?? '') === $d) ? 'selected' : '' ?>>
					<?= gp_e(substr($d, 0, 4) . '-' . substr($d, 4, 2) . '-' . substr($d, 6, 2)) ?>
				</option>
				<?php endforeach; ?>
			</select>
		</label>
		<?php foreach (array('act', 'ip', 'path', 'ua', 'status', 'cc') as $k) { echo $flt_field($k); } ?>
	</div>

	<?php
	$adv_open = false;
	foreach (array('reason', 'botv', 'dev', 'tok', 'sh', 'hold', 'asn', 'sc_min', 'sc_max') as $k) { if (isset($f[$k]) && $f[$k] !== '') { $adv_open = true; } }
	?>
	<details class="gp-more" <?= $adv_open ? 'open' : '' ?>>
		<summary><?= gp_e(gp_t('logs_more_filters')) ?></summary>
		<div class="gp-filters gp-filters-3">
			<?php foreach (array('reason', 'botv', 'dev', 'tok', 'sh', 'hold', 'asn') as $k) { echo $flt_field($k); } ?>
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('logs_score_min')) ?><?= gp_tip('flt_score') ?></span>
				<input class="gp-input gp-ltr" type="number" name="sc_min" inputmode="numeric" value="<?= gp_e((string)($f['sc_min'] ?? '')) ?>">
			</label>
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('logs_score_max')) ?></span>
				<input class="gp-input gp-ltr" type="number" name="sc_max" inputmode="numeric" value="<?= gp_e((string)($f['sc_max'] ?? '')) ?>">
			</label>
		</div>
	</details>

	<div class="gp-row-head">
		<button class="gp-btn gp-btn-primary" type="submit"><?= gp_e(gp_t('filter')) ?></button>
		<a class="gp-btn gp-btn-ghost" href="index.php?r=logs"><?= gp_e(gp_t('reset')) ?></a>
		<a class="gp-btn gp-btn-ghost" href="<?= gp_e(gp_logs_qs($f, array('export' => 'csv'))) ?>"
			title="<?= gp_e(gp_t('logs_export_hint')) ?>">
			<?= gp_e(gp_t('logs_export')) ?></a>
		<a class="gp-btn gp-btn-ghost" href="<?= gp_e(gp_logs_qs($f)) ?>" data-copy-link><?= gp_e(gp_t('logs_share')) ?></a>
	</div>
	<?= gp_filter_chips_html($chips) ?>
</form>

<?php if (!empty($meta['capped'])): ?>
<div class="gp-note gp-note-strong"><?= gp_e(gp_t('logs_capped')) ?></div>
<?php endif; ?>

<?php if (!$rows): ?>
<div class="gp-card"><p class="gp-help"><?= gp_e(gp_t('no_results')) ?></p>
	<?php if (!empty($pipeline) && is_array($pipeline) && $pipeline['verdict'] !== 'ok'): ?>
	<p class="gp-help"><span class="gp-badge gp-badge-bad"><?= gp_e(gp_t('pipe_' . $pipeline['verdict'])) ?></span></p>
	<?php endif; ?></div>
<?php else: ?>

<div class="gp-log-list gp-latin">
	<div class="gp-log-line gp-log-head" aria-hidden="true">
		<span><?= gp_e(gp_t('logs_time')) ?></span>
		<span><?= gp_e(gp_t('logs_act')) ?></span>
		<span><?= gp_e(gp_t('logs_request')) ?></span>
		<span><?= gp_e(gp_t('logs_ip')) ?></span>
		<span><?= gp_e(gp_t('logs_score')) ?></span>
		<span>HTTP</span>
		<span></span>
	</div>
	<?php foreach ($rows as $i => $row):
		$act = (string)($row['act'] ?? '');
		$badge = 'gp-badge-off';
		if ($act === 'allow' || $act === 'allow_bot' || $act === 'allow_preview' || $act === 'allow_override') { $badge = 'gp-badge-on'; }
		elseif ($act === '403' || $act === 'nonce_bad' || $act === 'nonce_replay' || $act === 'pow_bad') { $badge = 'gp-badge-bad'; }
		elseif ($act === '429' || $act === 'challenge' || $act === 'mint_limited') { $badge = 'gp-badge-warn'; }
		$out = isset($row['_out']) && is_array($row['_out']) ? $row['_out'] : null;
		$detail_id = 'gp-d-' . (int)$i;
		$identity = (string)($row['dev'] ?? '') !== '' ? (string)$row['dev'] : (string)($row['ip'] ?? '');
		$ts = (int)($row['ts'] ?? 0);
		$sc = (int)($row['sc'] ?? 0);
		$esc = (int)($row['esc'] ?? 0);
		$score_cls = $esc >= 60 ? 'gp-badge-bad' : ($esc >= 30 ? 'gp-badge-warn' : 'gp-badge-off');
		$reasons = array_values(array_filter((array)($row['rs'] ?? array()), 'is_string'));
	?>
	<article class="gp-log">
		<div class="gp-log-line">
			<time class="gp-log-time gp-ltr" datetime="<?= gp_e(gmdate('c', $ts)) ?>"
				title="<?= gp_e(date('Y-m-d H:i:s', $ts)) ?>"><?= gp_e(date('H:i:s', $ts)) ?></time>
			<div class="gp-log-acts">
				<span class="gp-badge <?= $badge ?> gp-ltr"><?= gp_e($act) ?></span>
				<?php if ((int)($row['sh'] ?? 0) === 1): ?>
					<span class="gp-badge gp-badge-info"><?= gp_e(gp_t('logs_shadow')) ?></span>
				<?php endif; ?>
				<?php if ((int)($row['hold'] ?? 0) === 1): ?>
					<span class="gp-badge gp-badge-info"><?= gp_e(gp_t('logs_holdout')) ?></span>
				<?php endif; ?>
				<?php if ((string)($row['ovr'] ?? '') !== ''): ?>
					<span class="gp-badge gp-badge-warn gp-ltr"><?= gp_e($row['ovr']) ?></span>
				<?php endif; ?>
			</div>
			<div class="gp-log-req gp-ltr">
				<span class="gp-log-method"><?= gp_e($row['m'] ?? '') ?></span>
				<span class="gp-log-path"><?= gp_e($row['p'] ?? '') ?></span>
			</div>
			<div class="gp-log-ip gp-ltr"><?= gp_e($row['ip'] ?? '') ?>
				<?php if ((string)($row['cc'] ?? '') !== ''): ?><span class="gp-badge gp-badge-off" title="<?= gp_e(gp_t('geo_cc')) ?>"><?= gp_e($row['cc']) ?></span><?php endif; ?></div>
			<div class="gp-log-score gp-ltr"
				title="<?= gp_e(gp_t('logs_sc')) ?> / <?= gp_e(gp_t('logs_esc')) ?>">
				<?php if ($sc !== $esc): ?><span class="gp-log-base"><?= gp_e(gp_latin($sc)) ?> →</span><?php endif; ?>
				<span class="gp-badge <?= $score_cls ?>"><?= gp_e(gp_latin($esc)) ?></span>
			</div>
			<div class="gp-log-status gp-ltr">
				<?php if ($out !== null && isset($out['st'])): ?>
					<span class="gp-badge <?= gp_log_status_badge($out['st']) ?>"><?= gp_e(gp_latin((int)$out['st'])) ?></span>
				<?php else: ?><span class="gp-log-none"><?= $dash ?></span><?php endif; ?>
			</div>
			<div class="gp-log-actions">
				<button class="gp-btn gp-btn-ghost gp-btn-sm" type="button"
					data-toggle="<?= gp_e($detail_id) ?>" aria-expanded="false" aria-controls="<?= gp_e($detail_id) ?>">
					<?= gp_e(gp_t('logs_detail')) ?></button>
				<?php if ($identity !== ''): ?>
				<a class="gp-btn gp-btn-ghost gp-btn-sm"
					href="index.php?r=identity&amp;id=<?= gp_u($identity) ?>">
					<?= gp_e(gp_t('id_title')) ?></a>
				<?php endif; ?>
				<?php if (isset($row['ua'])): ?>
				<a class="gp-btn gp-btn-ghost gp-btn-sm"
					href="index.php?r=rules&amp;new=1&amp;qua=<?= gp_u($row['ua']) ?>">
					<?= gp_e(gp_t('rules_quick_block')) ?></a>
				<?php endif; ?>
			</div>
		</div>
		<?php if ($reasons): ?>
		<div class="gp-log-reasons gp-ltr">
			<?php foreach ($reasons as $reason): ?>
				<span class="gp-badge gp-badge-off"><?= gp_e($reason) ?></span>
			<?php endforeach; ?>
		</div>
		<?php endif; ?>

		<div class="gp-log-detail" id="<?= gp_e($detail_id) ?>" hidden>
			<?php
			// Each section: title => list of log key => array(label, kind).
			// kinds: str (as is), int, float, bool, time, list, query. Only int and
			// float are formatted as numbers; ids such as rid stay strings even when
			// they happen to be digits. The raw log key is shown next to every label
			// so a value can be matched to the JSONL line (jq, grep) without guessing.
			$sections = array(
				array('logs_sec_request', 'gp-log-sec-wide', array(
					'ts'  => array(gp_t('logs_time'), 'time'),
					'm'   => array(gp_t('logs_method'), 'str'),
					'p'   => array(gp_t('logs_path'), 'str'),
					'q'   => array(gp_t('logs_query'), 'query'),
					'ua'  => array(gp_t('logs_ua'), 'str'),
					'ref' => array(gp_t('logs_referer'), 'str'),
					'sf'  => array(gp_t('logs_sec_fetch'), 'str'),
					'hc'  => array(gp_t('logs_headers'), 'int'),
					'nav' => array(gp_t('logs_nav'), 'bool'),
					'aj'  => array(gp_t('logs_ajax'), 'bool'),
					'uah' => array(gp_t('logs_uah'), 'str'),
				)),
				array('logs_sec_identity', '', array(
					'ip'   => array(gp_t('logs_ip'), 'str'),
					'dev'  => array(gp_t('logs_device'), 'str'),
					'tok'  => array(gp_t('logs_token'), 'str'),
					'bot'  => array(gp_t('logs_bot'), 'str'),
					'botv' => array(gp_t('id_botv'), 'str'),
					'hp'   => array(gp_t('id_honeypot'), 'bool'),
					'cc'   => array(gp_t('geo_cc'), 'str'),
					'asn'  => array(gp_t('geo_asn'), 'int'),
				)),
				array('logs_sec_score', '', array(
					'sc'  => array(gp_t('logs_sc'), 'int'),
					'esc' => array(gp_t('logs_esc'), 'int'),
					'rep' => array(gp_t('id_reputation'), 'int'),
					'ml'  => array(gp_t('id_ml'), 'int'),
					'clf' => array(gp_t('id_clf'), 'int'),
					'rs'  => array(gp_t('logs_reason'), 'list'),
				)),
				array('logs_sec_counters', '', array(
					'cd'  => array(gp_t('logs_c_cd'), 'int'),
					'cdh' => array(gp_t('logs_c_cdh'), 'int'),
					'cdd' => array(gp_t('logs_c_cdd'), 'int'),
					'ciu' => array(gp_t('logs_c_ciu'), 'int'),
					'ci'  => array(gp_t('logs_c_ci'), 'int'),
					'rd'  => array(gp_t('logs_c_rd'), 'bool'),
					'ms'  => array(gp_t('logs_c_ms'), 'float'),
					'v'   => array(gp_t('logs_c_v'), 'int'),
					'rid' => array(gp_t('logs_rid'), 'str'),
				)),
			);
			foreach ($sections as $sec):
				$present = array_intersect_key($sec[2], $row);
				if (!$present) { continue; } ?>
			<section class="gp-log-sec <?= $sec[1] ?>">
				<h3 class="gp-log-sec-title"><?= gp_e(gp_t($sec[0])) ?></h3>
				<dl class="gp-props">
				<?php foreach ($present as $key => $def):
					$value = $row[$key]; ?>
					<div class="gp-prop">
						<dt class="gp-prop-name"><?= gp_e($def[0]) ?>
							<code class="gp-prop-key" title="<?= gp_e(gp_t('logs_field_key')) ?>"><?= gp_e($key) ?></code></dt>
						<dd class="gp-prop-val">
						<?php switch ($def[1]):
							case 'bool': ?>
							<span class="gp-badge <?= ((int)$value) ? 'gp-badge-on' : 'gp-badge-off' ?>"><?= gp_e(((int)$value) ? gp_t('yes') : gp_t('no')) ?></span>
							<?php break;
							case 'list':
								$items = is_array($value) ? array_values(array_filter($value, 'is_string')) : array();
								if (!$items) { echo '<span class="gp-prop-empty">—</span>'; }
								foreach ($items as $item): ?>
							<span class="gp-badge gp-badge-off"><?= gp_e($item) ?></span>
								<?php endforeach;
								break;
							case 'query':
								echo gp_log_value(is_scalar($value) ? (string)$value : '');
								$pairs = is_scalar($value) ? gp_log_query_pairs((string)$value) : array();
								if ($pairs): ?>
							<table class="gp-params" aria-label="<?= gp_e(gp_t('logs_query_params')) ?>">
								<?php foreach ($pairs as $pair): ?>
								<tr><th scope="row"><?= gp_e($pair[0]) ?></th><td><?= gp_log_value($pair[1], 120) ?></td></tr>
								<?php endforeach; ?>
							</table>
								<?php endif;
								break;
							case 'time':  echo gp_log_value(date('Y-m-d H:i:s', (int)$value)); break;
							case 'int':   echo gp_log_value(gp_latin((int)$value)); break;
							case 'float': echo gp_log_value(gp_latin((float)$value, 2, true)); break;
							default:      echo gp_log_value(is_scalar($value) ? (string)$value : '');
						endswitch; ?>
						</dd>
					</div>
				<?php endforeach; ?>
				</dl>
			</section>
			<?php endforeach; ?>

			<section class="gp-log-sec">
				<h3 class="gp-log-sec-title"><?= gp_e(gp_t('logs_outcome')) ?></h3>
				<?php if ($out !== null): ?>
				<dl class="gp-props">
					<div class="gp-prop"><dt class="gp-prop-name"><?= gp_e(gp_t('logs_status')) ?> <code class="gp-prop-key">st</code></dt>
						<dd class="gp-prop-val"><?= gp_log_value(isset($out['st']) ? gp_latin((int)$out['st']) : '') ?></dd></div>
					<div class="gp-prop"><dt class="gp-prop-name"><?= gp_e(gp_t('logs_bytes')) ?> <code class="gp-prop-key">by</code></dt>
						<dd class="gp-prop-val"><?= gp_log_value(($out['by'] ?? null) === null ? '' : gp_latin((int)$out['by'])) ?></dd></div>
					<div class="gp-prop"><dt class="gp-prop-name"><?= gp_e(gp_t('logs_duration')) ?> (ms) <code class="gp-prop-key">dur</code></dt>
						<dd class="gp-prop-val"><?= gp_log_value(($out['dur'] ?? null) === null ? '' : gp_latin((float)$out['dur'], 2, true)) ?></dd></div>
				</dl>
				<?php else: ?>
				<p class="gp-help"><?= gp_e(gp_t('logs_no_outcome')) ?></p>
				<?php endif; ?>
			</section>
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
