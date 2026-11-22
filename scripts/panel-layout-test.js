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

const [BASE, PANEL, USER, PASS, SHOTS] = process.argv.slice(2);
if (!BASE || !USER || !PASS) { console.error('Usage: node panel-layout-test.js BASE_URL PANEL_PATH USER PASSWORD [SHOT_DIR]'); process.exit(2); }
const ROOT = BASE.replace(/\/$/, '') + '/' + (PANEL || '/panel').replace(/^\/|\/$/g, '') + '/index.php';
const ORIGIN = new URL(BASE).origin;
const VIEWS = [{ name: 'desktop', width: 1600, height: 1000 }, { name: 'mobile', width: 390, height: 844 }];
const PAGES = ['dashboard', 'logs', 'logs&act=403,429&act_op=not&ua=curl&ua_op=not&cc=ir', 'identity&id=203.0.113.5', 'overrides', 'rules', 'rules&new=1', 'rules&edit=ZZ',
	'geo', 'geo&test=1&ip=203.0.113.7', 'iplists', 'iplists&new=1&type=block', 'iplists&test=1&ip=203.0.113.7', 'replay', 'models', 'settings', 'config_file', 'jobs', 'jobs&job=verify', 'audit&event=config&event_op=not', 'update'];
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
			if (SHOTS && ['dashboard', 'update', 'settings', 'rules&new=1', 'logs&act=403,429&act_op=not&ua=curl&ua_op=not&cc=ir', 'geo'].indexOf(p) >= 0) {
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
		check(v.name + ' ip lists: lists / editor / entries / tester / compile tabs', (await page.locator('[data-tabs=ipl] > .gp-tablist > [role=tab]').count()) === 5);
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
		await ctx.close();
	}
	await browser.close();
	console.log(failed ? 'FAILED: ' + failed + ' check(s)' : 'OK: panel layout test passed.');
	process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
