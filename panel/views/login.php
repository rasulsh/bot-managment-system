<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; } ?>
<div class="gp-login">
	<div class="gp-login-card">
		<div class="gp-login-brand">
			<span class="gp-brand-mark" aria-hidden="true">&#9679;</span>
			<strong><?= gp_e(gp_t('app_name')) ?></strong>
			<small><?= gp_e(gp_t('app_sub')) ?></small>
		</div>

		<form method="post" action="index.php?r=login" class="gp-form">
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('login_user')) ?></span>
				<input class="gp-input" type="text" name="username" autocomplete="username"
					required autofocus dir="ltr">
			</label>
			<label class="gp-field">
				<span class="gp-label"><?= gp_e(gp_t('login_pass')) ?></span>
				<input class="gp-input" type="password" name="password"
					autocomplete="current-password" required dir="ltr">
			</label>
			<button class="gp-btn gp-btn-primary gp-btn-block" type="submit">
				<?= gp_e(gp_t('login_submit')) ?>
			</button>
		</form>
	</div>
</div>
