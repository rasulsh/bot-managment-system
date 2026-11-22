<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// My account (any role): the role and the last sign-in, and the form to change your OWN password (current one required).
// Variable: me (the signed-in user's record, no hash).
$when = $me['last_login_at'] > 0 ? date('Y-m-d H:i', (int)$me['last_login_at']) : '';
?>
<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('acc_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('acc_sub')) ?></p>
</div>

<section class="gp-card">
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('usr_username')) ?></span><span class="gp-stat-val gp-mono"><?= gp_e($me['username']) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('usr_role')) ?></span><span class="gp-stat-val"><?= gp_e(gp_users_role_label($me['role'])) ?></span></div>
	<div class="gp-stat-row"><span class="gp-stat-key"><?= gp_e(gp_t('usr_last_login')) ?></span><span class="gp-stat-val gp-mono"><?= gp_e($when) ?></span></div>
</section>

<section class="gp-card" id="account-password">
	<h2 class="gp-card-title"><?= gp_e(gp_t('acc_password')) ?></h2>
	<form method="post" action="index.php?r=account" class="gp-form" data-allow>
		<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('acc_current')) ?><?= gp_tip('acc_current') ?></span>
			<input class="gp-input" type="password" name="current" autocomplete="current-password" required dir="ltr">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('acc_new')) ?><?= gp_tip('acc_new') ?></span>
			<input class="gp-input" type="password" name="new" autocomplete="new-password" minlength="<?= (int)GP_USERS_MIN_PASSWORD ?>" required dir="ltr">
		</label>
		<label class="gp-field">
			<span class="gp-label"><?= gp_e(gp_t('acc_repeat')) ?></span>
			<input class="gp-input" type="password" name="repeat" autocomplete="new-password" minlength="<?= (int)GP_USERS_MIN_PASSWORD ?>" required dir="ltr">
		</label>
		<p class="gp-help"><?= gp_e(gp_t('acc_help')) ?></p>
		<button class="gp-btn gp-btn-primary" type="submit" name="do" value="password"><?= gp_e(gp_t('acc_change')) ?></button>
	</form>
</section>
