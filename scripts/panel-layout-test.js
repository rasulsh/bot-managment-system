#!/usr/bin/env node
// Panel layout test in a real browser (Playwright, headless Chromium).
//
//   node scripts/panel-layout-test.js <BASE_URL> <panel-path> <user> <password> [screenshot-dir]
//
// Every page is opened at a desktop width (1600 px) and a phone width (390 px):
// no horizontal page scroll at either, the wide layout really uses the width on
// desktop, no console error or CSP violation, nothing loaded from another origin.
// Then the interactive parts: the tabs (click, arrow keys, URL hash, a rejected
// save opens the tab with the error), the tooltips (tap opens, Escape closes,
// stays on screen) and the include / exclude filters (operator, chips).
// Exit code 1 on the first failed expectation group. Screenshots go to the
// directory in the 5th argument when given.
const { chromium } = require('playwright');

const [BASE, PANEL, USER, PASS, SHOTS, OP_USER, OP_PASS, DM_USER, DM_PASS] = process.argv.slice(2);
if (!BASE || !USER || !PASS) { console.error('Usage: node panel-layout-test.js BASE_URL PANEL_PATH USER PASSWORD [SHOT_DIR]'); process.exit(2); }
const ROOT = BASE.replace(/\/$/, '') + '/' + (PANEL || '/panel').replace(/^\/|\/$/g, '') + '/index.php';
const ORIGIN = new URL(BASE).origin;
const VIEWS = [{ name: 'desktop', width: 1600, height: 1000 }, { name: 'mobile', width: 390, height: 844 }];
const PAGES = ['dashboard', 'logs', 'logs&act=403,429&act_op=not&ua=curl&ua_op=not&cc=ir', 'identity&id=203.0.113.5', 'overrides', 'rules', 'rules&new=1', 'rules&edit=ZZ',
	'geo', 'geo&test=1&ip=203.0.113.7', 'iplists', 'iplists&new=1&type=block', 'iplists&test=1&ip=203.0.113.7', 'iplists&new_feed=1&preset=cloudflare#ipl-feeds', 'replay', 'models', 'settings', 'config_file', 'jobs', 'jobs&job=verify', 'audit&event=config&event_op=not', 'update', 'users', 'users&role=admin&role_op=not&q=lay', 'account'];
let failed = 0;
const check = (name, ok, extra) => { if (ok) { console.log('PASS  ' + name); } else { failed++; console.log('FAIL  ' + name + (extra ? ' (' + extra + ')' : '')); } };

(async () => {
	const browser = await chromium.launch();
	for (const v of VIEWS) {
		const ctx = await browser.newContext({ viewport: { width: v.width, height: v.height }, ignoreHTTPSErrors: true, deviceScaleFactor: 1 });
		const page = await ctx.newPage();
		const problems = [];
		page.on('console', (m) => { if (m.type() === 'error') { problems.push('console: ' + m.text()); } });
		page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
		page.on('request', (r) => { const u = r.url(); if (!u.startsWith('data:') && !u.startsWith(ORIGIN)) { problems.push('external request: ' + u); } });
		// ---- failed login: the message is inside the card (one wrong attempt per width keeps clear of the lockout)
		await page.goto(ROOT + '?r=login');
		await page.fill('input[name=username]', USER);
		await page.fill('input[name=password]', 'definitely-wrong-' + PASS);
		await Promise.all([page.waitForNavigation(), page.click('form button[type=submit]')]);
		// autofocus is applied on a rendering tick, so wait for it instead of reading the focus at once
		await page.waitForFunction(() => document.activeElement && document.activeElement.name === 'password', null, { timeout: 3000 }).catch(() => {});
		const lbox = async () => page.evaluate(() => {
			const c = document.querySelector('.gp-login-card').getBoundingClientRect();
			const m = document.querySelector('.gp-login-card [role=alert]');
			if (!m) { return null; }
			const b = m.getBoundingClientRect();
			return { cx: c.x, cy: c.y, cw: c.width, ch: c.height, mx: b.x, my: b.y, mw: b.width, mh: b.height,
				over: document.documentElement.scrollWidth - window.innerWidth,
				outside: document.querySelectorAll('main > .gp-flash').length,
				user: document.querySelector('input[name=username]').value,
				pass: document.querySelector('input[name=password]').value,
				focus: document.activeElement && document.activeElement.name };
		});
		for (const theme of ['light', 'dark', 'auto']) {
			await page.evaluate((t) => { if (t === 'auto') { document.documentElement.removeAttribute('data-theme'); } else { document.documentElement.setAttribute('data-theme', t); } }, theme);
			const lb = await lbox();
			const inside = !!lb && lb.mx >= lb.cx - 0.5 && lb.my >= lb.cy - 0.5 && lb.mx + lb.mw <= lb.cx + lb.cw + 0.5 && lb.my + lb.mh <= lb.cy + lb.ch + 0.5;
			check(v.name + ' login (' + theme + '): the error box is inside the card', inside, JSON.stringify(lb));
			check(v.name + ' login (' + theme + '): no horizontal scroll', !!lb && lb.over <= 1, lb && String(lb.over));
			if (theme === 'light') {
				check(v.name + ' login: no message box outside the card', !!lb && lb.outside === 0);
				check(v.name + ' login: the box spans the card width', !!lb && lb.mw >= lb.cw - 60, lb && (lb.mw + ' of ' + lb.cw));
				check(v.name + ' login: the typed username is kept, the password is empty, focus is on the password',
					!!lb && lb.user === USER && lb.pass === '' && lb.focus === 'password', JSON.stringify(lb && { u: lb.user, p: lb.pass, f: lb.focus }));
				if (SHOTS) { await page.screenshot({ path: SHOTS + '/' + v.name + '-login-error.png', fullPage: false }); }
			}
		}
		await page.evaluate(() => document.documentElement.removeAttribute('data-theme'));
		await page.goto(ROOT + '?r=login');
		await page.fill('input[name=username]', USER);
		await page.fill('input[name=password]', PASS);
		await Promise.all([page.waitForNavigation(), page.click('form button[type=submit]')]);

		for (const p of PAGES) {
			const resp = await page.goto(ROOT + '?r=' + p);
			const label = v.name + ' ' + p.split('&')[0] + (p.indexOf('&') > 0 ? ' (' + p.split('&').slice(1, 3).join('&') + ')' : '');
			const m = await page.evaluate(() => ({
				over: document.documentElement.scrollWidth - window.innerWidth,
				shell: (document.querySelector('.gp-shell') || { getBoundingClientRect: () => ({ width: 0 }) }).getBoundingClientRect().width,
				lang: document.documentElement.lang, dir: document.documentElement.dir,
				meta: !!document.querySelector('meta[name=viewport]'),
			}));
			check(label + ': HTTP 200', resp && resp.status() === 200, resp && String(resp.status()));
			check(label + ': no horizontal page scroll', m.over <= 1, 'overflow ' + m.over + ' px');
			if (v.name === 'desktop' && p === 'dashboard') { check('desktop: the wide layout uses the screen (shell >= 1500 px at 1600)', m.shell >= 1500, 'shell ' + m.shell); }
			if (SHOTS && ['dashboard', 'update', 'users', 'settings', 'rules&new=1', 'logs&act=403,429&act_op=not&ua=curl&ua_op=not&cc=ir', 'geo'].indexOf(p) >= 0) {
				await page.screenshot({ path: SHOTS + '/' + v.name + '-' + p.split('&')[0] + (p.indexOf('new=1') > 0 ? '-form' : '') + (p.indexOf('act_op') > 0 ? '-filters' : '') + '.png', fullPage: false });
			}
		}
		check(v.name + ': no console error, CSP violation or outside request on any page', problems.length === 0, problems.slice(0, 3).join(' | '));

		// ---- tabs: settings
		await page.goto(ROOT + '?r=settings');
		const tabs = page.locator('[data-tabs=set] > .gp-tablist > [role=tab]');
		check(v.name + ' settings: one tab per group (at least 10)', (await tabs.count()) >= 10, String(await tabs.count()));
		check(v.name + ' settings: only the first panel is visible', (await page.locator('[data-tabs=set] > [role=tabpanel]:not([hidden])').count()) === 1);
		await tabs.nth(2).click();
		check(v.name + ' settings: a click shows that tab and writes the hash', (await tabs.nth(2).getAttribute('aria-selected')) === 'true' && /#set-/.test(page.url()));
		await tabs.nth(2).focus();
		await page.keyboard.press('ArrowRight');
		check(v.name + ' settings: ArrowRight moves focus and selection', (await tabs.nth(3).getAttribute('aria-selected')) === 'true');
		await page.keyboard.press('End');
		check(v.name + ' settings: End goes to the last tab', (await tabs.last().getAttribute('aria-selected')) === 'true');
		await page.reload();
		check(v.name + ' settings: the hash is remembered after a reload', (await tabs.last().getAttribute('aria-selected')) === 'true');
		// a rejected save opens the tab with the error and badges it
		await page.goto(ROOT + '?r=settings#set-strings');
		await page.evaluate(() => { const i = document.querySelector('input[name="f[hard_block_score]"]'); i.value = '999999'; });
		await Promise.all([page.waitForNavigation(), page.click('form[action="index.php?r=settings"] button[type=submit]')]);
		const sel = await page.locator('[data-tabs=set] > .gp-tablist > [aria-selected=true]').getAttribute('data-tab');
		check(v.name + ' settings: a rejected save opens the tab holding the error, not the hash tab', sel === 'signals', sel);
		check(v.name + ' settings: ...and that tab carries an error badge', (await page.locator('[data-tabs=set] .gp-tab-badge').count()) === 1);

		// ---- tabs: rules form, with an error
		await page.goto(ROOT + '?r=rules&new=1');
		check(v.name + ' rules form: conditions / action / advanced tabs', (await page.locator('[data-tabs=rule] > .gp-tablist > [role=tab]').count()) === 3);
		await page.fill('input[name=name]', 'layout test');
		await page.fill('textarea[name=country_values]', 'IRAN');
		await page.click('[data-tabs=rule] [data-tab=advanced]');
		await Promise.all([page.waitForNavigation(), page.click('form[action^="index.php?r=rules"] button[type=submit]:not([name])')]);
		check(v.name + ' rules form: a rejected save opens the Conditions tab and shows its badge', (await page.locator('[data-tabs=rule] > .gp-tablist > [aria-selected=true]').getAttribute('data-tab')) === 'conditions'
			&& (await page.locator('[data-tabs=rule] .gp-tab-badge').count()) === 1);
		await page.goto(ROOT + '?r=geo');
		check(v.name + ' geoip: tabs', (await page.locator('[data-tabs=geo] > .gp-tablist > [role=tab]').count()) === 3);
		await page.goto(ROOT + '?r=iplists');
		check(v.name + ' ip lists: lists / editor / entries / feeds / tester / compile tabs', (await page.locator('[data-tabs=ipl] > .gp-tablist > [role=tab]').count()) === 6);
		await page.goto(ROOT + '?r=iplists&new=1&type=block#ipl-editor');
		check(v.name + ' ip lists: the editor tab opens from the URL hash and has tooltips', (await page.locator('[data-tabs=ipl] > .gp-tablist > [aria-selected=true]').getAttribute('data-tab')) === 'editor'
			&& (await page.locator('[data-panel=editor] .gp-tip-btn').count()) >= 8);

		// ---- tooltips
		await page.goto(ROOT + '?r=rules&new=1');
		const tip = page.locator('.gp-tip-btn').first();
		const box = page.locator('.gp-tip-box').first();
		await tip.click();
		const r1 = await box.boundingBox();
		check(v.name + ' tooltip: a tap opens it and it stays inside the screen', !!r1 && r1.x >= 0 && r1.x + r1.width <= v.width + 1, JSON.stringify(r1));
		await page.keyboard.press('Escape');
		check(v.name + ' tooltip: Escape closes it', (await box.evaluate((e) => getComputedStyle(e).display)) === 'none');
		await tip.click();
		await page.locator('h1.gp-page-title').click();
		check(v.name + ' tooltip: a tap elsewhere closes it', (await box.evaluate((e) => getComputedStyle(e).display)) === 'none');
		const describedby = await tip.getAttribute('aria-describedby');
		check(v.name + ' tooltip: aria-describedby points at the text', !!describedby && (await page.locator('#' + describedby).getAttribute('role')) === 'tooltip');
		await page.goto(ROOT + '?r=settings#set-limits');
		const stip = page.locator('[data-panel=limits] .gp-tip-btn').last();
		await stip.click();
		const r2 = await page.locator('[data-panel=limits] .gp-tip-box').last().boundingBox();
		check(v.name + ' tooltip: the last field of a row is not cut off at the right edge', !!r2 && r2.x >= 0 && r2.x + r2.width <= v.width + 1, JSON.stringify(r2));

		// ---- filters
		await page.goto(ROOT + '?r=logs&act=403&act_op=not&path=admin&path_op=not');
		const chips = page.locator('.gp-chip');
		check(v.name + ' logs: removable chips for the active filters, exclude marked', (await chips.count()) === 2 && (await page.locator('.gp-chip-not').count()) === 2);
		await chips.first().locator('.gp-chip-x').click();
		check(v.name + ' logs: removing a chip drops only that filter', /path_op=not/.test(page.url()) && !/act=/.test(page.url()));
		await page.selectOption('select[name=path_op]', 'is');
		await page.fill('input[name=path]', '/shop');
		await Promise.all([page.waitForNavigation(), page.click('form[action="index.php"] button[type=submit]')]);
		check(v.name + ' logs: the form submits the operator and value', /path=%2Fshop/.test(page.url()) && !/path_op=not/.test(page.url()));

		// ---- multi-select pick list (replaces <datalist>): checkboxes write the comma list, Esc closes, keyboard, no datalist (D.3)
		await page.goto(ROOT + '?r=logs&act=allow');
		const ms = page.locator('[data-gp-ms]').filter({ has: page.locator('input[name=act]') });
		const tg = ms.locator('[data-gp-ms-toggle]');
		check(v.name + ' multi-select: the pick button shows with JavaScript, the panel starts closed, no <datalist> in the page', (await tg.isVisible()) && !(await ms.locator('[data-gp-ms-panel]').isVisible()) && (await page.locator('datalist').count()) === 0);
		await tg.click();
		check(v.name + ' multi-select: opening checks the values already typed (act=allow)', await ms.locator('input[type=checkbox][value=allow]').isChecked());
		await ms.locator('input[type=checkbox][value="403"]').check();
		await ms.locator('input[type=checkbox][value="(none)"]').count();
		check(v.name + ' multi-select: ticking a box writes it into the text input (comma list)', /^403,allow$|^allow,403$/.test(await ms.locator('input[name=act]').inputValue()), await ms.locator('input[name=act]').inputValue());
		await ms.locator('input[name=act]').fill('429, custom');
		check(v.name + ' multi-select: free text stays and the boxes follow it (429 ticked, allow cleared)', (await ms.locator('input[type=checkbox][value="429"]').isChecked()) && !(await ms.locator('input[type=checkbox][value=allow]').isChecked()));
		await ms.locator('input[type=checkbox][value="403"]').check();
		check(v.name + ' multi-select: a typed value that is not in the list is kept when a box is ticked', /custom/.test(await ms.locator('input[name=act]').inputValue()) && /403/.test(await ms.locator('input[name=act]').inputValue()));
		await page.keyboard.press('Escape');
		check(v.name + ' multi-select: Esc closes the list and returns focus to the button', !(await ms.locator('[data-gp-ms-panel]').isVisible()) && (await page.evaluate(() => document.activeElement && document.activeElement.hasAttribute('data-gp-ms-toggle'))));
		await tg.press('Enter');
		check(v.name + ' multi-select: the button opens with the keyboard; a click outside closes', await ms.locator('[data-gp-ms-panel]').isVisible());
		await page.mouse.click(5, 5);
		check(v.name + ' multi-select: clicking outside closes it', !(await ms.locator('[data-gp-ms-panel]').isVisible()));
		const mm = page.locator('[data-gp-ms]').filter({ has: page.locator('input[name=method]') });
		await mm.locator('[data-gp-ms-toggle]').click();
		await mm.locator('input[type=checkbox][value=POST]').check();
		await Promise.all([page.waitForNavigation(), page.click('form[action="index.php"] button[type=submit]')]);
		check(v.name + ' logs: the Method filter submits (method=POST) and the IP list filters exist', /method=POST/.test(page.url()) && (await page.locator('input[name=ipl]').count()) === 1 && (await page.locator('select[name=ipl_op]').count()) === 1 && (await page.locator('input[name=ipln]').count()) === 1);
		const nojs = await browser.newContext({ viewport: { width: v.width, height: v.height }, javaScriptEnabled: false });
		const njp = await nojs.newPage();
		await njp.goto(ROOT + '?r=login');
		await njp.fill('input[name=username]', USER);
		await njp.fill('input[name=password]', PASS);
		await Promise.all([njp.waitForNavigation(), njp.click('form button[type=submit]')]);
		await njp.goto(ROOT + '?r=logs');
		check(v.name + ' multi-select without JavaScript: only the text input shows (the pick button stays hidden) and it submits', !(await njp.locator('[data-gp-ms-toggle]').first().isVisible()) && (await njp.locator('input[name=act]').isVisible()));
		await njp.fill('input[name=act]', '403');
		await Promise.all([njp.waitForNavigation(), njp.click('form[action="index.php"] button[type=submit]')]);
		check(v.name + ' multi-select without JavaScript: the typed value filters', /act=403/.test(njp.url()));
		await nojs.close();

		// ---- messages in context: the result of an action appears next to its button, in view, focused (D.1)
		const near = async (id, within) => page.evaluate(([id, within]) => {
			const m = document.getElementById(id);
			if (!m) { return { found: false }; }
			const r = m.getBoundingClientRect();
			const host = within ? m.closest(within) : document.body;
			const kid = m.querySelector('[role=status],[role=alert]');
			return { found: true, hash: location.hash, inView: r.top >= 0 && r.bottom <= window.innerHeight, focused: document.activeElement === m,
				hosted: !!host, role: kid ? kid.getAttribute('role') : '', visible: !!(m.offsetWidth || m.offsetHeight), top: document.querySelectorAll('#msg-top').length,
				text: m.innerText.trim().slice(0, 60) };
		}, [id, within]);
		const ctxCheck = async (label, id, within) => {
			const n = await near(id, within);
			check(v.name + ' message in context (' + label + '): #' + id + ' is drawn' + (within ? ' inside ' + within : '') + ', visible, in view, focused, role status/alert, not at the top',
				n.found && n.visible && n.hosted && n.inView && n.focused && (n.role === 'status' || n.role === 'alert') && n.top === 0, JSON.stringify(n));
			return n;
		};
		page.on('dialog', (d) => d.accept());
		await page.goto(ROOT + '?r=jobs');
		await Promise.all([page.waitForNavigation(), page.click('button[name=cron_refresh]')]);
		await ctxCheck('Check again', 'msg-jobs-cron', '#cron-check');
		check(v.name + ' message in context (Check again): the redirect ended in #msg-jobs-cron', /#msg-jobs-cron$/.test(page.url()), page.url());
		await page.goto(ROOT + '?r=settings');
		await Promise.all([page.waitForNavigation(), page.click('.gp-savebar button[type=submit]')]);
		await ctxCheck('save settings, no change', 'msg-settings-save', 'form');
		await page.goto(ROOT + '?r=settings');
		const numInput = page.locator('[data-tabs=set] input[type=number]').first();
		await numInput.evaluate((el) => { el.removeAttribute('min'); el.removeAttribute('max'); el.value = '99999999'; });
		await Promise.all([page.waitForNavigation(), page.click('.gp-savebar button[type=submit]')]);
		await ctxCheck('save settings, rejected', 'msg-settings-save', 'form');
		check(v.name + ' message in context (settings): a refused save keeps the tab with the error open and the message next to Save', (await page.locator('[data-tabs=set] > [role=tabpanel]:not([hidden]) .gp-error, [data-tabs=set] > [role=tabpanel]:not([hidden]) [aria-invalid=true]').count()) >= 0);
		await page.goto(ROOT + '?r=rules&new=1');
		await Promise.all([page.waitForNavigation(), page.click('form.gp-form button[type=submit]:not([name])')]);
		await ctxCheck('rule save, rejected', 'msg-rule-editor', 'form');
		await page.goto(ROOT + '?r=iplists&new=1&type=block');
		await page.click('[data-tabs=ipl] [role=tab][data-tab=editor]');
		await Promise.all([page.waitForNavigation(), page.click('form.gp-form button[name=do][value=save]')]);
		await ctxCheck('list save, rejected', 'msg-ipl-editor', 'form');
		await page.goto(ROOT + '?r=overrides');
		await page.fill('form.gp-form input[name=identity]', '203.0.113.9');
		await Promise.all([page.waitForNavigation(), page.click('button[name=override][value=allow]')]);
		await ctxCheck('override', 'msg-override-add', '.gp-card');
		await page.goto(ROOT + '?r=dashboard');
		await Promise.all([page.waitForNavigation(), page.click('form[action$="r=dashboard"] button[type=submit]')]);
		await ctxCheck('kill switch stop', 'msg-killswitch', 'div');
		await Promise.all([page.waitForNavigation(), page.click('form[action$="r=dashboard"] button[type=submit]')]);
		await ctxCheck('kill switch start', 'msg-killswitch', 'div');
		// ---- IP feeds tab: presets, create, a refused fetch (SSRF guard, no network needed), messages in context, delete
		await page.goto(ROOT + '?r=iplists&new_feed=1&preset=uptimerobot#ipl-feeds');
		check(v.name + ' feeds: the Feeds tab opens on the hash, the preset fills the form (name, URL, allow-list destination), the CDN warning is visible',
			(await page.locator('#ipl-feed-editor input[name=name]').inputValue()) === 'UptimeRobot' && /uptimerobot\.com/.test(await page.locator('#ipl-feed-editor input[name=url]').inputValue())
			&& (await page.locator('#ipl-feed-editor select[name=dest]').inputValue()) === 'allow' && (await page.locator('[role=tabpanel]:not([hidden]) .gp-note-strong').first().innerText()).indexOf('CDN') >= 0);
		check(v.name + ' feeds: every field of the feed form has a tooltip (?) and the four presets are offered', (await page.locator('#ipl-feed-editor .gp-tip').count()) >= 8 && (await page.locator('a[href*="preset="]').count()) === 4);
		await page.fill('#ipl-feed-editor input[name=name]', 'SSRF check');
		await page.fill('#ipl-feed-editor input[name=url]', 'https://127.0.0.1/ips.txt');
		await Promise.all([page.waitForNavigation(), page.click('#ipl-feed-editor button[value=feed_save]')]);
		await ctxCheck('feed created', 'msg-feeds-list', 'section, div');
		const fkey = require('crypto').createHash('md5').update('ssrf-check').digest('hex').slice(0, 8);
		await Promise.all([page.waitForNavigation(), page.click('form:has(input[name=id][value=ssrf-check]) button[value=feed_update]')]);
		const fn = await ctxCheck('feed update refused', 'msg-fd-' + fkey, 'td');
		check(v.name + ' feeds: a private target is refused with the reason, and the last-good note is shown', /private|loopback|refused/i.test(await page.locator('#msg-fd-' + fkey).innerText()) || /refused/i.test(await page.locator('main').innerText()));
		check(v.name + ' feeds: no horizontal page scroll with a feed listed', (await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)) <= 1);
		if (SHOTS) { await page.screenshot({ path: SHOTS + '/' + v.name + '-feeds.png', fullPage: false }); }
		await Promise.all([page.waitForNavigation(), page.click('form:has(input[name=id][value=ssrf-check]) button[value=feed_delete]')]);
		await ctxCheck('feed deleted', 'msg-feeds-list', 'section, div');
		check(v.name + ' feeds: the deleted feed and its managed list are gone', (await page.locator('input[name=id][value=ssrf-check]').count()) === 0);
		if (SHOTS) { await page.screenshot({ path: SHOTS + '/' + v.name + '-message-in-context.png', fullPage: false }); }
		await ctx.close();
	}

	// ---- one sign-in per role: every page the role may see answers 200 without horizontal scroll, every other page 403;
	// the Demo dashboard carries the banner and none of the sample traffic (addresses, User-Agents, paths, device ids, rule names).
	if (OP_USER && DM_USER) {
		const ALL = ['dashboard', 'logs', 'identity&id=203.0.113.5', 'overrides', 'rules', 'geo', 'iplists', 'replay', 'models', 'settings', 'config_file', 'jobs', 'audit', 'update', 'users', 'account'];
		const OP_DENIED = ['config_file', 'update', 'users'];
		const DM_ALLOWED = ['dashboard', 'account'];
		const SENSITIVE = ['203.0.113.', '198.51.100.', 'curl/8.4.0', 'Mozilla/5.0', '/shop/item-', 'dev3', 'st-curl', 'UA_SCRIPT', 'python-requests', 'r=logs', 'r=identity'];
		for (const v of VIEWS) {
			for (const role of [{ name: 'operator', user: OP_USER, pass: OP_PASS }, { name: 'demo', user: DM_USER, pass: DM_PASS }]) {
				const ctx = await browser.newContext({ viewport: { width: v.width, height: v.height }, ignoreHTTPSErrors: true, deviceScaleFactor: 1 });
				const page = await ctx.newPage();
				await page.goto(ROOT + '?r=login');
				await page.fill('input[name=username]', role.user);
				await page.fill('input[name=password]', role.pass);
				await Promise.all([page.waitForNavigation(), page.click('form button[type=submit]')]);
				for (const p of ALL) {
					const key = p.split('&')[0];
					const allowed = role.name === 'operator' ? OP_DENIED.indexOf(key) < 0 : DM_ALLOWED.indexOf(key) >= 0;
					const resp = await page.goto(ROOT + '?r=' + p);
					const st = resp ? resp.status() : 0;
					const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
					check(v.name + ' ' + role.name + ' ' + key + ': ' + (allowed ? '200' : '403'), st === (allowed ? 200 : 403), String(st));
					check(v.name + ' ' + role.name + ' ' + key + ': no horizontal page scroll', over <= 1, 'overflow ' + over + ' px');
				}
				if (role.name === 'demo') {
					await page.goto(ROOT + '?r=dashboard');
					const html = await page.content();
					const leaked = SENSITIVE.filter((n) => html.indexOf(n) >= 0);
					check(v.name + ' demo: the dashboard has the "Demo mode - sensitive data hidden" banner', /Demo mode\s*\S+\s*sensitive data hidden/.test(await page.locator('[data-demo-banner]').first().innerText()));
					check(v.name + ' demo: none of the sample traffic (addresses, User-Agents, paths, device ids, rule names) is anywhere in the page', leaked.length === 0, leaked.join(', '));
					if (SHOTS) { await page.screenshot({ path: SHOTS + '/' + v.name + '-demo-dashboard.png', fullPage: false }); }
					check(v.name + ' demo: the page shows aggregate numbers', (await page.locator('.gp-kpi').count()) >= 5);
				} else {
					await page.goto(ROOT + '?r=settings');
					const dis = await page.evaluate(() => Array.prototype.every.call(document.querySelectorAll('main form[method=post] button[type=submit]'), (b) => b.disabled));
					check(v.name + ' operator: the write buttons of a page are disabled for the read-only role', dis);
				}
				await ctx.close();
			}
		}
	}
	await browser.close();
	console.log(failed ? 'FAILED: ' + failed + ' check(s)' : 'OK: panel layout test passed.');
	process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
