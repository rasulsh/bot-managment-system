<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Update: upload a GitHub ZIP, review the plan, apply with the password, roll back.
// Variables: env, version, plan (staged plan or null), history, res, ts, m (manifest summary), token (shown once), cron_lines, web_url.
$mb = function ($n) { return gp_bytes((int)$n); };
$warn_ids = isset($plan['warnings']) ? $plan['warnings'] : array();
$need_confirm = $plan ? array_values(array_intersect(array('downgrade', 'same_version', 'git_present'), $warn_ids)) : array();
$ftime = function ($t) { return $t > 0 ? date('Y-m-d H:i', (int)$t) : ''; };
$install_dir = dirname(__DIR__, 2);
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('upd_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('upd_sub')) ?></p>
</div>

<?php if ($res === 'ok' && $m): ?>
<section class="gp-card" id="update-result" tabindex="-1">
	<div class="gp-flash gp-flash-ok" role="status"><?= gp_e(sprintf(gp_t('upd_done'), (string)($m['to'] ?? ''))) ?></div>
	<?php if ($token !== ''): ?>
	<div class="gp-note gp-note-strong">
		<strong><?= gp_e(gp_t('upd_token_title')) ?></strong>
		<p><code class="gp-mono"><?= gp_e($token) ?></code></p>
		<p class="gp-help"><?= gp_e(gp_t('upd_token_help')) ?></p>
		<p class="gp-help"><?= gp_e(gp_t('upd_token_cli')) ?> <code class="gp-mono">php <?= gp_e($install_dir) ?>/updates/rollback.php</code></p>
		<p class="gp-help"><?= gp_e(gp_t('upd_token_web')) ?> <code class="gp-mono"><?= gp_e($web_url) ?>?token=<?= gp_e($token) ?></code></p>
	</div>
	<?php endif; ?>
	<?php if (!empty($m['requirements_changed'])): ?>
	<div class="gp-note">
		<?= gp_e(empty($m['pip_error']) ? gp_t('upd_pip_queued') : gp_t('upd_pip_failed') . ': ' . (string)$m['pip_error']) ?>
		<p class="gp-help"><?= gp_e(gp_t('upd_pip_ssh')) ?> <code class="gp-mono">$GV_PYTHON -m pip install -r <?= gp_e($install_dir) ?>/analyzer/requirements.txt</code></p>
	</div>
	<?php endif; ?>
	<?php if (!empty($m['cron_scripts_changed']) || $cron_lines): ?>
	<div class="gp-note">
		<?= gp_e(gp_t($cron_lines ? 'upd_cron_missing' : 'upd_cron_changed')) ?>
		<?php if ($cron_lines): ?><pre class="gp-mono gp-ltr gp-pre"><?= gp_e(implode("\n", $cron_lines)) ?></pre><?php endif; ?>
	</div>
	<?php endif; ?>
	<?php if (!empty($m['modes_fixed']) && ($m['modes_fixed']['files'] + $m['modes_fixed']['dirs']) > 0): ?>
	<div class="gp-note"><?= gp_e(sprintf(gp_t('upd_modes_fixed'), (int)$m['modes_fixed']['files'], (int)$m['modes_fixed']['dirs'])) ?></div>
	<?php endif; ?>
	<?php if (isset($perms) && is_array($perms) && gp_perm_has_issues($perms)): ?>
	<div class="gp-note gp-note-strong" role="alert">
		<?= gp_e(gp_t('upd_perm_found')) ?>
		<pre class="gp-mono gp-ltr gp-pre"><?= gp_e(implode("\n", gp_perm_fix_commands($perms))) ?></pre>
		<p class="gp-help"><a href="index.php?r=jobs#perms"><?= gp_e(gp_t('perm_title')) ?></a></p>
	</div>
	<?php endif; ?>
	<?php if (!empty($m['changelog'])): ?>
	<h2 class="gp-card-title"><?= gp_e(gp_t('upd_changelog')) ?></h2>
	<?php foreach ($m['changelog'] as $c): ?>
		<h3 class="gp-card-sub"><?= gp_e((string)$c['version']) ?></h3><pre class="gp-mono gp-ltr gp-pre"><?= gp_e((string)$c['text']) ?></pre>
	<?php endforeach; ?>
	<?php endif; ?>
	<p class="gp-help"><?= gp_e(gp_t('upd_notes_link')) ?> <code class="gp-mono">docs/10-UPGRADE-NOTES.md</code></p>
</section>
<?php elseif ($res === 'rolled' || $res === 'rollback_failed'): ?>
<section class="gp-card" id="update-result" tabindex="-1">
	<div class="gp-flash gp-flash-error" role="alert"><?= gp_e(gp_t($res === 'rolled' ? 'upd_auto_rolled' : 'upd_auto_failed')) ?></div>
	<?php if ($m && !empty($m['verify_failed'])): ?><pre class="gp-mono gp-ltr gp-pre"><?= gp_e((string)$m['verify_failed']) ?></pre><?php endif; ?>
	<?php if ($res === 'rollback_failed'): ?><p class="gp-help"><code class="gp-mono">php <?= gp_e($install_dir) ?>/updates/rollback.php</code></p><?php endif; ?>
</section>
<?php endif; ?>

<?php foreach ($history as $h): if ($h['status'] === 'applied' || $h['status'] === 'applying'): ?>
<div class="gp-flash gp-flash-error" role="alert">
	<?= gp_e(sprintf(gp_t('upd_unverified'), $h['stamp'])) ?>
	<a class="gp-btn gp-btn-ghost" href="recover.php?a=verify&amp;ts=<?= gp_e(rawurlencode($h['stamp'])) ?>&amp;k=<?= gp_e(rawurlencode($h['verify_key'])) ?>"><?= gp_e(gp_t('upd_verify_now')) ?></a>
</div>
<?php endif; break; endforeach; ?>

<section class="gp-card">
	<h2 class="gp-card-title"><?= gp_e(gp_t('upd_installed')) ?></h2>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('upd_version')) ?></span>
		<span class="gp-stat-val gp-mono"><?= gp_e($version !== '' ? $version : gp_t('unknown')) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('upd_reader')) ?><?= gp_tip('upd_reader') ?></span>
		<span class="gp-stat-val"><?= gp_e($env['backend'] === 'ziparchive' ? 'ZipArchive' : ($env['backend'] === 'pure' ? gp_t('upd_reader_pure') : gp_t('upd_reader_none'))) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('upd_writable')) ?><?= gp_tip('upd_writable') ?></span>
		<span class="gp-badge <?= ($env['writable'] && $env['updates_writable']) ? 'gp-badge-on' : 'gp-badge-bad' ?>"><?= gp_e(gp_t(($env['writable'] && $env['updates_writable']) ? 'yes' : 'no')) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('upd_free')) ?></span>
		<span class="gp-stat-val"><?= $env['free'] === null ? gp_e(gp_t('unknown')) : gp_e($mb($env['free'])) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('upd_opcache')) ?></span>
		<span class="gp-stat-val"><?= gp_e(gp_t($env['opcache'] ? 'yes' : 'no')) ?></span></div>
	<?php if ($env['git']): ?><div class="gp-note gp-note-strong"><?= gp_e(gp_t('upd_git_note')) ?></div><?php endif; ?>
</section>

<?php if ($plan): ?>
<section class="gp-card" id="update-plan">
	<h2 class="gp-card-title"><?= gp_e(gp_t('upd_review')) ?></h2>
	<p><span class="gp-mono"><?= gp_e($plan['from'] !== '' ? $plan['from'] : gp_t('unknown')) ?></span> &rarr; <strong class="gp-mono"><?= gp_e($plan['to']) ?></strong>
		<span class="gp-help">(<?= gp_e($plan['zip_name']) ?>)</span></p>
	<?php foreach ($warn_ids as $w): ?>
	<div class="gp-flash gp-flash-warn" role="status"><?= gp_e(gp_t('upd_warn_' . $w)) ?></div>
	<?php endforeach; ?>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('upd_n_add')) ?></span><span class="gp-stat-val"><?= gp_num(count($plan['add'])) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('upd_n_change')) ?></span><span class="gp-stat-val"><?= gp_num(count($plan['change'])) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('upd_n_remove')) ?></span><span class="gp-stat-val"><?= gp_num(count($plan['remove'])) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('upd_n_same')) ?></span><span class="gp-stat-val"><?= gp_num((int)$plan['unchanged']) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('upd_n_protected')) ?><?= gp_tip('upd_protected') ?></span><span class="gp-stat-val"><?= gp_num(count($plan['protected_skipped'])) ?></span></div>
	<?php foreach (array('add' => 'upd_n_add', 'change' => 'upd_n_change', 'remove' => 'upd_n_remove', 'protected_skipped' => 'upd_n_protected') as $k => $lbl): if (!$plan[$k]) { continue; } ?>
	<details><summary><?= gp_e(gp_t($lbl)) ?></summary><pre class="gp-mono gp-ltr gp-pre"><?= gp_e(implode("\n", $plan[$k])) ?></pre></details>
	<?php endforeach; ?>
	<?php if ($plan['changelog']): ?>
	<h3 class="gp-card-title"><?= gp_e(gp_t('upd_changelog')) ?></h3>
	<?php foreach ($plan['changelog'] as $c): ?><h4 class="gp-card-sub"><?= gp_e($c['version']) ?></h4><pre class="gp-mono gp-ltr gp-pre"><?= gp_e($c['text']) ?></pre><?php endforeach; ?>
	<?php endif; ?>

	<form method="post" action="index.php?r=update" class="gp-form" id="update-apply">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<input type="hidden" name="plan" value="<?= gp_e($plan['id']) ?>">
		<?php foreach ($need_confirm as $w): ?>
		<label class="gp-check"><input type="checkbox" name="confirm[<?= gp_e($w) ?>]" value="1" required> <?= gp_e(gp_t('upd_confirm_' . $w)) ?></label>
		<?php endforeach; ?>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('upd_password')) ?><?= gp_tip('upd_password') ?></span>
			<input class="gp-input" type="password" name="password" autocomplete="current-password" required dir="ltr">
		</label>
		<p class="gp-help"><?= gp_e(gp_t('upd_apply_help')) ?></p>
		<div style="display:flex;gap:.5rem;flex-wrap:wrap">
			<button class="gp-btn gp-btn-primary" type="submit" name="do" value="apply"><?= gp_e(gp_t('upd_apply')) ?></button>
			<button class="gp-btn gp-btn-ghost" type="submit" name="do" value="discard" formnovalidate><?= gp_e(gp_t('upd_discard')) ?></button>
		</div>
	</form>
</section>
<?php endif; ?>

<section class="gp-card" id="update-upload">
	<h2 class="gp-card-title"><?= gp_e(gp_t('upd_upload_title')) ?></h2>
	<form method="post" action="index.php?r=update" enctype="multipart/form-data" class="gp-form">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('upd_file')) ?><?= gp_tip('upd_file') ?></span>
			<input class="gp-input" type="file" name="zip" accept=".zip,application/zip" required>
			<span class="gp-help"><?= gp_e(gp_t('upd_file_help')) ?> <?= gp_e(gp_t('upd_limit')) ?>: <?= gp_e($mb($env['limit'])) ?>.</span>
		</label>
		<?php if (!$env['uploads']): ?><div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('upd_uploads_off')) ?></div><?php endif; ?>
		<?php if ($env['backend'] === ''): ?><div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('upd_err_nozip')) ?></div><?php endif; ?>
		<button class="gp-btn gp-btn-primary" type="submit" name="do" value="upload"><?= gp_e(gp_t('upd_upload_btn')) ?></button>
	</form>
</section>

<section class="gp-card" id="update-history">
	<h2 class="gp-card-title"><?= gp_e(gp_t('upd_history')) ?></h2>
	<?php if (!$history): ?><p class="gp-help"><?= gp_e(gp_t('upd_history_none')) ?></p><?php else: ?>
	<div class="gp-table-wrap"><table class="gp-table">
		<thead><tr><th><?= gp_e(gp_t('upd_h_when')) ?></th><th><?= gp_e(gp_t('upd_h_change')) ?></th><th><?= gp_e(gp_t('upd_h_status')) ?></th><th><?= gp_e(gp_t('upd_h_by')) ?></th><th></th></tr></thead>
		<tbody>
		<?php foreach ($history as $h): ?>
		<tr>
			<td class="gp-mono"><?= gp_e($ftime($h['created'])) ?></td>
			<td class="gp-mono"><?= gp_e(($h['from'] !== '' ? $h['from'] : '?') . ' → ' . $h['to']) ?> <span class="gp-help">(<?= gp_num($h['files']) ?>)</span></td>
			<td><span class="gp-badge <?= $h['status'] === 'ok' ? 'gp-badge-on' : ($h['status'] === 'rolled_back' ? 'gp-badge-off' : 'gp-badge-bad') ?>"><?= gp_e(gp_t('upd_st_' . $h['status']) === 'upd_st_' . $h['status'] ? $h['status'] : gp_t('upd_st_' . $h['status'])) ?></span></td>
			<td><?= gp_e($h['actor']) ?></td>
			<td>
				<?php if ($h['status'] !== 'rolled_back'): ?>
				<form method="post" action="index.php?r=update" data-confirm="<?= gp_e(gp_t('upd_rb_confirm')) ?>" style="display:inline">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="stamp" value="<?= gp_e($h['stamp']) ?>">
					<button class="gp-btn gp-btn-danger" type="submit" name="do" value="rollback"><?= gp_e(gp_t('upd_rollback')) ?></button>
				</form>
				<?php endif; ?>
			</td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table></div>
	<p class="gp-help"><?= gp_e(gp_t('upd_rb_help')) ?> <code class="gp-mono">php <?= gp_e($install_dir) ?>/updates/rollback.php</code></p>
	<?php endif; ?>
</section>
