<?php if (!defined('GP_BOOT')) { http_response_code(404); exit; }
// Overlay file editor: guard/config.local.json as text, with JSON syntax
// highlighting, a live syntax check in the browser and the authoritative check
// on the server (gp_overlay_file_check()). The browser part is a progressive
// enhancement: without JavaScript it is a plain textarea and the server still
// refuses anything invalid.
$check = is_array($check ?? null) ? $check : null;
$rules = gv_overlay_whitelist();
?>

<div>
	<h1 class="gp-page-title"><?= gp_e(gp_t('cf_title')) ?></h1>
	<p class="gp-page-sub"><code class="gp-mono"><?= gp_e($path) ?></code></p>
</div>

<p class="gp-note"><?= gp_e(gp_t('cf_intro')) ?></p>

<?php if ($from_backup !== ''): ?>
<div class="gp-flash gp-flash-warn" role="status"><?= gp_e(sprintf(gp_t('cf_from_backup'), $from_backup)) ?></div>
<?php endif; ?>

<?php if ($check !== null && !$check['ok'] && $check['errors']): ?>
<div class="gp-card gp-card-danger" role="alert">
	<div class="gp-card-title"><?= gp_e(gp_t('cf_errors')) ?></div>
	<ul class="gp-errlist">
		<?php foreach ($check['errors'] as $e): ?>
		<li>
			<a href="#" data-goto-line="<?= (int)$e['line'] ?>" class="gp-mono"><?= gp_e(gp_t('cf_line')) ?> <?= gp_e(gp_latin($e['line'])) ?>, <?= gp_e(gp_t('cf_col')) ?> <?= gp_e(gp_latin($e['column'])) ?></a>
			<?php if ($e['key'] !== ''): ?><code class="gp-prop-key"><?= gp_e($e['key']) ?></code><?php endif; ?>
			<span><?= gp_e($e['message']) ?></span>
		</li>
		<?php endforeach; ?>
	</ul>
</div>
<?php endif; ?>

<form method="post" action="index.php?r=config_file" class="gp-card gp-form" data-confirm="<?= gp_e(gp_t('cf_confirm')) ?>">
	<input type="hidden" name="csrf" value="<?= gp_e(gp_csrf_token()) ?>">
	<input type="hidden" name="action" value="save_file">
	<input type="hidden" name="base_hash" value="<?= gp_e($base_hash) ?>">
	<div class="gp-editor" data-editor>
		<pre class="gp-editor-hl" aria-hidden="true"><code data-editor-hl></code></pre>
		<textarea class="gp-editor-input" name="content" rows="22" spellcheck="false" autocomplete="off"
			autocapitalize="off" wrap="off" aria-label="config.local.json" data-editor-input><?= gp_e($text) ?></textarea>
	</div>
	<p class="gp-help" data-editor-status aria-live="polite"></p>
	<div class="gp-row-head">
		<button class="gp-btn gp-btn-primary" type="submit"><?= gp_e(gp_t('cf_save')) ?></button>
		<a class="gp-btn gp-btn-ghost" href="index.php?r=config_file"><?= gp_e(gp_t('cf_reload')) ?></a>
	</div>
	<?= gp_msg('config-file') ?>
</form>

<details class="gp-card">
	<summary class="gp-card-title" style="cursor:pointer;margin:0"><?= gp_e(gp_t('cf_keys_help')) ?></summary>
	<div class="gp-table-wrap" style="margin-top:.75rem">
	<table class="gp-table">
		<thead><tr><th><?= gp_e(gp_t('aud_key')) ?></th><th><?= gp_e(gp_t('set_range')) ?></th></tr></thead>
		<tbody>
		<?php foreach ($rules as $key => $spec):
			$desc = $spec[0];
			if ($spec[0] === 'int' || $spec[0] === 'float') { $desc .= ' ' . $spec[1] . '–' . $spec[2]; }
			elseif ($spec[0] === 'enum') { $desc .= ': ' . implode(' | ', $spec[1]); }
			elseif ($spec[0] === 'text') { $desc .= ', max ' . $spec[1]; } ?>
		<tr><td class="gp-mono"><?= gp_e($key) ?></td><td class="gp-mono"><?= gp_e($desc) ?></td></tr>
		<?php endforeach; ?>
		</tbody>
	</table>
	</div>
</details>

<section class="gp-card">
	<div class="gp-card-title"><?= gp_e(gp_t('cf_backups')) ?></div>
	<p class="gp-help" style="margin-bottom:.5rem"><?= gp_e(gp_t('cf_backups_sub')) ?></p>
	<?php if (!$backups): ?>
	<p class="gp-help"><?= gp_e(gp_t('cf_no_backups')) ?></p>
	<?php else: ?>
	<div class="gp-rows">
		<?php foreach ($backups as $b): ?>
		<div class="gp-row gp-row-head">
			<span class="gp-mono"><?= gp_e(gp_datetime($b['time'])) ?></span>
			<span class="gp-mono gp-help"><?= gp_e($b['name']) ?> · <?= gp_e(gp_num($b['size'])) ?> B</span>
			<a class="gp-btn gp-btn-ghost gp-btn-sm" style="margin-inline-start:auto"
				href="index.php?r=config_file&amp;backup=<?= gp_u($b['name']) ?>"><?= gp_e(gp_t('cf_open')) ?></a>
		</div>
		<?php endforeach; ?>
	</div>
	<?php endif; ?>
</section>

<script>
// JSON editor: a transparent textarea over a highlighted <pre>. No library, no
// network, works under the panel's CSP. The textarea stays the form field.
(function () {
	'use strict';
	var box = document.querySelector('[data-editor]');
	if (!box) { return; }
	var input = box.querySelector('[data-editor-input]');
	var out = box.querySelector('[data-editor-hl]');
	var status = document.querySelector('[data-editor-status]');
	var okText = <?= gp_json(gp_t('cf_live_ok')) ?>;
	var badText = <?= gp_json(gp_t('cf_live_bad')) ?>;
	var lineText = <?= gp_json(gp_t('cf_line')) ?>;
	box.classList.add('gp-editor-on');
	var esc = function (s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); };
	var token = /("(?:[^"\\\n]|\\.)*")(\s*:)?|(-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b)|\b(true|false|null)\b|([{}\[\],:])/g;
	var paint = function () {
		var text = input.value;
		var html = '', last = 0, m;
		token.lastIndex = 0;
		while ((m = token.exec(text)) !== null) {
			html += esc(text.slice(last, m.index));
			if (m[1] !== undefined) {
				html += '<span class="' + (m[2] ? 'gp-j-key' : 'gp-j-str') + '">' + esc(m[1]) + '</span>' + (m[2] ? esc(m[2]) : '');
			} else if (m[3] !== undefined) {
				html += '<span class="gp-j-num">' + esc(m[3]) + '</span>';
			} else if (m[4] !== undefined) {
				html += '<span class="gp-j-lit">' + esc(m[4]) + '</span>';
			} else {
				html += '<span class="gp-j-pun">' + esc(m[5]) + '</span>';
			}
			last = token.lastIndex;
		}
		out.innerHTML = html + esc(text.slice(last)) + '\n';
		try {
			var v = JSON.parse(text);
			if (v === null || typeof v !== 'object' || Array.isArray(v)) { throw new Error('not an object'); }
			status.textContent = okText;
			status.className = 'gp-help gp-editor-ok';
		} catch (e) {
			var msg = String(e.message || e);
			var pos = /position (\d+)/.exec(msg);
			if (pos) {
				var before = text.slice(0, +pos[1]);
				msg += ' (' + lineText + ' ' + (before.split('\n').length) + ')';
			}
			status.textContent = badText + ': ' + msg;
			status.className = 'gp-help gp-error';
		}
	};
	var sync = function () { out.parentNode.scrollTop = input.scrollTop; out.parentNode.scrollLeft = input.scrollLeft; };
	input.addEventListener('input', function () { paint(); sync(); });
	input.addEventListener('scroll', sync);
	input.addEventListener('keydown', function (e) {
		if (e.key !== 'Tab' || e.shiftKey || e.ctrlKey || e.metaKey || e.altKey) { return; }
		e.preventDefault();
		var s = input.selectionStart, t = input.selectionEnd;
		input.value = input.value.slice(0, s) + '    ' + input.value.slice(t);
		input.selectionStart = input.selectionEnd = s + 4;
		paint();
	});
	document.querySelectorAll('[data-goto-line]').forEach(function (a) {
		a.addEventListener('click', function (e) {
			e.preventDefault();
			var n = parseInt(a.getAttribute('data-goto-line'), 10) || 1;
			var lines = input.value.split('\n');
			var start = 0;
			for (var i = 0; i < n - 1 && i < lines.length; i++) { start += lines[i].length + 1; }
			input.focus();
			input.selectionStart = start;
			input.selectionEnd = start + (lines[n - 1] || '').length;
			var lh = parseFloat(getComputedStyle(input).lineHeight) || 18;
			input.scrollTop = Math.max(0, (n - 3) * lh);
			sync();
		});
	});
	paint();
})();
</script>
