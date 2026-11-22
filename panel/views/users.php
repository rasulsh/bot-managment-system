<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Users (admin only): list with include / exclude filters, create, role, enable / disable, reset password, delete.
// Variables: users (filtered rows, no password hashes), all_count, filter, state, me (the signed-in user name).
$fmt = function ($t) { return $t > 0 ? date('Y-m-d H:i', (int)$t) : ''; };
$roles = gp_users_roles();
$admins = 0;
foreach ($users as $u) { if ($u['role'] === 'admin' && $u['enabled']) { $admins++; } }
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('usr_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('usr_sub')) ?></p>
</div>
<?php if (!empty($state['readonly'])): ?><div class="gp-note gp-note-strong" role="alert"><?= gp_e(gp_t('usr_err_readonly')) ?></div><?php endif; ?>

<?= gp_filter_form_html('users', array(
	'role' => array('usr_role', 'is', $roles, 'flt_usr_role'),
	'enabled' => array('usr_enabled', 'is', array('yes', 'no'), 'flt_usr_enabled'),
	'q' => array('usr_username', 'has', array(), 'flt_usr_q')), $filter) ?>

<section class="gp-card" id="users-list">
	<h2 class="gp-card-title"><?= gp_e(gp_t('usr_list')) ?> <span class="gp-card-sub"><?= gp_num(count($users)) ?> / <?= gp_num($all_count) ?></span></h2>
	<?php if (!$users): ?><p class="gp-help"><?= gp_e(gp_t('no_results')) ?></p><?php else: ?>
	<div class="gp-table-wrap"><table class="gp-table">
		<thead><tr><th><?= gp_e(gp_t('usr_username')) ?></th><th><?= gp_e(gp_t('usr_role')) ?></th><th><?= gp_e(gp_t('usr_enabled')) ?></th>
			<th><?= gp_e(gp_t('usr_created')) ?></th><th><?= gp_e(gp_t('usr_last_login')) ?></th><th><?= gp_e(gp_t('usr_actions')) ?><?= gp_tip('usr_actions') ?></th></tr></thead>
		<tbody>
		<?php foreach ($users as $u): $self = ($u['username'] === $me); ?>
		<tr>
			<td class="gp-mono"><?= gp_e($u['username']) ?><?= $self ? ' <span class="gp-badge gp-badge-info">' . gp_e(gp_t('usr_you')) . '</span>' : '' ?></td>
			<td><?= gp_e(gp_users_role_label($u['role'])) ?></td>
			<td><span class="gp-badge <?= $u['enabled'] ? 'gp-badge-on' : 'gp-badge-off' ?>"><?= gp_e(gp_t($u['enabled'] ? 'yes' : 'no')) ?></span></td>
			<td class="gp-mono"><?= gp_e($fmt($u['created_at'])) ?><br><span class="gp-help"><?= gp_e($u['created_by']) ?></span></td>
			<td class="gp-mono"><?= gp_e($fmt($u['last_login_at'])) ?><?= $u['last_login_ip'] !== '' ? '<br><span class="gp-help gp-ltr">' . gp_e($u['last_login_ip']) . '</span>' : '' ?></td>
			<td>
				<form method="post" action="index.php?r=users" style="display:flex;gap:.4rem;flex-wrap:wrap;align-items:center">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="username" value="<?= gp_e($u['username']) ?>">
					<select class="gp-input" name="role" aria-label="<?= gp_e(gp_t('usr_role')) ?>"<?= $self ? ' disabled' : '' ?>>
						<?php foreach ($roles as $r): ?><option value="<?= gp_e($r) ?>"<?= $r === $u['role'] ? ' selected' : '' ?>><?= gp_e(gp_users_role_label($r)) ?></option><?php endforeach; ?>
					</select>
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="do" value="role"<?= $self ? ' disabled title="' . gp_e(gp_t('usr_err_self')) . '"' : '' ?>><?= gp_e(gp_t('usr_set_role')) ?></button>
					<?php if ($u['enabled']): ?>
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="do" value="disable"<?= $self ? ' disabled title="' . gp_e(gp_t('usr_err_self')) . '"' : '' ?>><?= gp_e(gp_t('usr_disable')) ?></button>
					<?php else: ?>
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="do" value="enable"><?= gp_e(gp_t('usr_enable')) ?></button>
					<?php endif; ?>
				</form>
				<form method="post" action="index.php?r=users" style="display:flex;gap:.4rem;flex-wrap:wrap;align-items:center;margin-top:.4rem">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="username" value="<?= gp_e($u['username']) ?>">
					<input class="gp-input" type="password" name="password" autocomplete="new-password" minlength="<?= (int)GP_USERS_MIN_PASSWORD ?>" placeholder="<?= gp_e(gp_t('usr_new_password')) ?>" aria-label="<?= gp_e(gp_t('usr_new_password')) ?>" dir="ltr">
					<button class="gp-btn gp-btn-ghost gp-btn-sm" type="submit" name="do" value="reset"><?= gp_e(gp_t('usr_reset')) ?></button>
				</form>
				<form method="post" action="index.php?r=users" data-confirm="<?= gp_e(sprintf(gp_t('usr_delete_confirm'), $u['username'])) ?>" style="margin-top:.4rem">
					<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
					<input type="hidden" name="username" value="<?= gp_e($u['username']) ?>">
					<button class="gp-btn gp-btn-danger gp-btn-sm" type="submit" name="do" value="delete"<?= $self ? ' disabled title="' . gp_e(gp_t('usr_err_self')) . '"' : '' ?>><?= gp_e(gp_t('usr_delete')) ?></button>
				</form>
			</td>
		</tr>
		<?php endforeach; ?>
		</tbody>
	</table></div>
	<?php endif; ?>
	<p class="gp-help"><?= gp_e(gp_t('usr_rules_help')) ?></p>
</section>

<section class="gp-card" id="users-create">
	<h2 class="gp-card-title"><?= gp_e(gp_t('usr_create')) ?></h2>
	<form method="post" action="index.php?r=users" class="gp-form">
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('usr_username')) ?><?= gp_tip('usr_username') ?></span>
			<input class="gp-input" type="text" name="username" pattern="[A-Za-z0-9._-]{3,32}" required autocomplete="off" spellcheck="false" dir="ltr">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('usr_role')) ?><?= gp_tip('usr_role') ?></span>
			<select class="gp-input" name="role">
				<?php foreach (array('operator', 'demo', 'admin') as $r): ?><option value="<?= gp_e($r) ?>"><?= gp_e(gp_users_role_label($r)) ?></option><?php endforeach; ?>
			</select>
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('usr_password')) ?><?= gp_tip('usr_password') ?></span>
			<input class="gp-input" type="password" name="password" autocomplete="new-password" minlength="<?= (int)GP_USERS_MIN_PASSWORD ?>" required dir="ltr">
		</label>
		<button class="gp-btn gp-btn-primary" type="submit" name="do" value="create"><?= gp_e(gp_t('usr_create_btn')) ?></button>
	</form>
</section>
