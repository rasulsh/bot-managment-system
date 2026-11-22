<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; } ?>
<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('forbidden_title')) ?></h1>
	<p class="gp-page-sub"><?= gp_e(gp_t('forbidden_text')) ?></p>
	<p><a class="gp-btn gp-btn-ghost" href="index.php?r=dashboard"><?= gp_e(gp_t('nav_dashboard')) ?></a></p>
</div>
