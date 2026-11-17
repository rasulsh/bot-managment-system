<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; } ?>
<div class="gp-theme" role="group" aria-label="<?= gp_e(gp_t('theme_label')) ?>">
	<button type="button" class="gp-theme-btn" data-theme-set="light" aria-pressed="false"><?= gp_e(gp_t('theme_light')) ?></button>
	<button type="button" class="gp-theme-btn" data-theme-set="dark" aria-pressed="false"><?= gp_e(gp_t('theme_dark')) ?></button>
	<button type="button" class="gp-theme-btn" data-theme-set="system" aria-pressed="true"><?= gp_e(gp_t('theme_system')) ?></button>
</div>
