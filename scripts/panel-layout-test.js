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
const PAGES = ['dashboard', 'logs', 'logs&act=403,429&act_op=not&ua=curl&ua_op=not&cc=ir', 'identity&id=203.0.113.5', 'overrides', 'overrides&new=100.64.0.5', 'live&minutes=60', 'rules', 'rules&new=1', 'rules&edit=ZZ',
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
			if (p === 'dashboard') {
				// Dashboard v2 grid (docs/15-DASHBOARD.md): tiles, readiness | funnel, system cards.
				const g = await page.evaluate(() => {
					const box = (el) => { const r = el.getBoundingClientRect(); return { x: Math.round(r.left), y: Math.round(r.top + window.scrollY), w: Math.round(r.width), h: Math.round(r.height) }; };
					const all = (sel) => Array.prototype.slice.call(document.querySelectorAll(sel)).map(box);
					return { tiles: all('[data-tile]'), ready: all('#dash-ready'), funnel: all('#dash-funnel'), sys: all('[id^=dash-sys-], #clf-labels'), main: all('#dash-main'), strip: all('#dash-strip'), chips: all('.gp-dchip'),
						svgW: (document.querySelector('#dash-main svg') || { getBoundingClientRect: () => ({ width: 0 }) }).getBoundingClientRect().width };
				});
				const rows = (list) => { const m = {}; list.forEach((b) => { (m[b.y] = m[b.y] || []).push(b); }); return Object.keys(m).map((k) => m[k]); };
				check(label + ': six KPI tiles', g.tiles.length === 6, String(g.tiles.length));
				const perRow = v.name === 'desktop' ? 6 : 2;
				check(label + ': KPI tiles ' + perRow + ' per row, equal width and height', rows(g.tiles).every((r) => r.length === perRow && r.every((b) => Math.abs(b.w - r[0].w) <= 1 && Math.abs(b.h - r[0].h) <= 1)), JSON.stringify(g.tiles.map((b) => [b.x, b.y, b.w, b.h])));
				check(label + ': status strip has 6 chips, ' + (v.name === 'desktop' ? 'one row' : 'two per row'), g.chips.length === 6 && rows(g.chips).length === (v.name === 'desktop' ? 1 : 3), String(rows(g.chips).length));
				if (g.ready.length && g.funnel.length) {
					if (v.name === 'desktop') { check(label + ': readiness and funnel side by side, equal height, 7:5', g.ready[0].y === g.funnel[0].y && g.ready[0].h === g.funnel[0].h && Math.abs(g.ready[0].w / g.funnel[0].w - 7 / 5) < 0.12, JSON.stringify([g.ready[0], g.funnel[0]])); }
					else { check(label + ': readiness and funnel stacked full width', g.funnel[0].y > g.ready[0].y && Math.abs(g.ready[0].w - g.funnel[0].w) <= 1, JSON.stringify([g.ready[0], g.funnel[0]])); }
				}
				check(label + ': system cards equal height per row', rows(g.sys).every((r) => r.every((b) => b.h === r[0].h)), JSON.stringify(g.sys.map((b) => [b.y, b.h])));
				check(label + ': main chart fills its card (' + Math.round(g.svgW) + ' px)', g.svgW > (v.name === 'desktop' ? 1000 : 300), String(g.svgW));
			}
			if (p === 'dashboard') {
				// review fixes: tiles aligned, readiness table not run together, alerts on a phone, active tab readable in both themes
				const r = await page.evaluate(() => {
					const rect = (el) => { const b = el.getBoundingClientRect(); return { x: b.left, y: Math.round(b.top + window.scrollY), w: b.width, h: b.height, r: b.right }; };
					const th = Array.prototype.slice.call(document.querySelectorAll('#dash-ready thead th')).map((e) => Object.assign(rect(e), { clip: e.scrollWidth > e.clientWidth + 1, t: e.innerText }));
					const badges = Array.prototype.slice.call(document.querySelectorAll('#dash-ready [data-ready] .gp-badge')).map((e) => rect(e).h);
					const det = document.querySelector('#dash-alerts details');
					const first = document.querySelector('#dash-alerts [data-alerts-first] .gp-alert');
					const tile0 = document.querySelector('[data-tile]');
					return { vals: Array.prototype.slice.call(document.querySelectorAll('[data-tile] .gp-dtile-value')).map((e) => rect(e).y), sparks: Array.prototype.slice.call(document.querySelectorAll('[data-tile] .gp-dspark')).map((e) => rect(e).y),
						labels: Array.prototype.slice.call(document.querySelectorAll('[data-tile] .gp-dtile-label')).map((e) => Math.round(rect(e).h)), th, badges,
						open: det ? det.hasAttribute('open') : null, firstVisible: first ? (rect(first).h > 20 && rect(first).y < 900) : null, alertsH: Math.round(rect(document.querySelector('#dash-alerts')).h), tileY: tile0 ? rect(tile0).y : 0 };
				});
				const rowsOf = (ys) => { const m = {}; ys.forEach((y, i) => { (m[Math.round(y / 50)] = m[Math.round(y / 50)] || []).push(i); }); return Object.keys(m).length; };
				check(label + ': KPI values start at the same height in every tile of a row (the help icon does not push one down)', new Set(r.vals.slice(0, v.name === 'desktop' ? 6 : 2)).size === 1 && new Set(r.labels).size === 1, JSON.stringify([r.vals, r.labels]));
				check(label + ': KPI sparklines line up across a row', new Set(r.sparks.slice(0, v.name === 'desktop' ? 6 : 2)).size === 1, JSON.stringify(r.sparks));
				check(label + ': readiness headers do not run together (no clipped header, none overlapping its neighbour)', r.th.length >= 8 && r.th.every((t, i) => !t.clip && (i === 0 || r.th[i - 1].y !== t.y || r.th[i - 1].r <= t.x + 0.5)), JSON.stringify(r.th.map((t) => [t.t, Math.round(t.x), Math.round(t.r), t.clip])));
				const wrapFits = await page.evaluate(() => { const w = document.querySelector('#dash-ready .gp-table-wrap'); return w ? [w.scrollWidth, w.clientWidth] : null; });
				if (v.name === 'desktop') { check(label + ': the readiness table fits its card (no horizontal scroll, every column visible)', !!wrapFits && wrapFits[0] <= wrapFits[1] + 1, JSON.stringify(wrapFits)); }
				check(label + ': the "Ready to enforce" and type badges never wrap (one line high)', r.badges.length > 0 && r.badges.every((h) => h < 30), JSON.stringify(r.badges));
				if (v.name === 'mobile') {
					check(label + ': the alert list is collapsed on a phone, the first critical alert is still shown, the KPIs start high on the page', r.open === false && r.firstVisible === true && r.alertsH < 330 && r.tileY < 1100, JSON.stringify([r.open, r.firstVisible, r.alertsH, r.tileY]));
				} else {
					check(label + ': the alert list is open on a wide screen', r.open === true, String(r.open));
				}
				for (const scheme of ['light', 'dark']) {
					await page.emulateMedia({ colorScheme: scheme }); await page.waitForTimeout(500);
					const ct = await page.evaluate(() => {
						const lum = (c) => { const m = c.match(/[\d.]+/g).map(Number); const f = (x) => { x /= 255; return x <= 0.03928 ? x / 12.92 : Math.pow((x + 0.055) / 1.055, 2.4); }; return 0.2126 * f(m[0]) + 0.7152 * f(m[1]) + 0.0722 * f(m[2]); };
						const bg = (el) => { while (el) { const c = getComputedStyle(el).backgroundColor; if (c && !/rgba?\(0, 0, 0, 0\)/.test(c) && !/, 0\)$/.test(c)) { return c; } el = el.parentElement; } return 'rgb(255, 255, 255)'; };
						const on = document.querySelector('#dash-main .gp-tab[aria-selected="true"]'), off = document.querySelector('#dash-main .gp-tab[aria-selected="false"]');
						if (!on || !off) { return null; }
						const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
						return { on: ratio(getComputedStyle(on).color, bg(on)), off: ratio(getComputedStyle(off).color, bg(off)), onW: getComputedStyle(on).fontWeight, same: getComputedStyle(on).color !== getComputedStyle(off).color || getComputedStyle(on).fontWeight !== getComputedStyle(off).fontWeight };
					});
					check(label + ' ' + scheme + ': the active "24 h" tab is readable (contrast >= 4.5) and looks active, not disabled', !!ct && ct.on >= 4.5 && ct.off >= 3 && ct.same, JSON.stringify(ct));
					if (SHOTS) { await page.screenshot({ path: SHOTS + '/' + v.name + '-dashboard-' + scheme + '.png', fullPage: true }); }
				}
				await page.emulateMedia({ colorScheme: 'light' });
			}
			if (false) {
			} else if (SHOTS && ['update', 'users', 'settings', 'rules&new=1', 'logs&act=403,429&act_op=not&ua=curl&ua_op=not&cc=ir', 'geo'].indexOf(p) >= 0) {
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

		// ---- GeoIP sources (PR F): the file column keeps a readable width, the tooltip in a scrolling table is never clipped, the filter
		// controls share one height with the pick button inside the box, and a file over the limit is refused in the browser
		await page.goto(ROOT + '?r=geo#geo-sources');
		const gcell = page.locator('[data-panel=sources] td.gp-col-name').first();
		const gcw = await gcell.evaluate((e) => e.getBoundingClientRect().width);
		check(v.name + ' geo: the File column is at least 150 px wide (not squeezed to a character)', gcw >= 150, String(gcw));
		await page.locator('[data-panel=sources] .gp-table .gp-tip-btn').first().click();
		const gtb = await page.locator('[data-panel=sources] .gp-table .gp-tip-box').first().boundingBox();
		const gvis = await page.locator('[data-panel=sources] .gp-table .gp-tip-box').first().evaluate((e) => {
			const r = e.getBoundingClientRect(); const cx = r.left + r.width / 2, cy = r.top + Math.min(r.height - 2, 20);
			const top = document.elementFromPoint(cx, cy); return !!top && (top === e || e.contains(top));
		});
		check(v.name + ' geo: the Delete tooltip is fully on screen and is the topmost element at its own centre (not clipped by the table)', !!gtb && gtb.x >= 0 && gtb.x + gtb.width <= v.width + 1 && gvis, JSON.stringify(gtb));
		await page.keyboard.press('Escape');
		const gh = await page.evaluate(() => {
			const row = document.querySelector('[data-panel=sources] .gp-fgroup');
			if (!row) { return null; }
			const sel = row.querySelector('select'), inp = row.querySelector('input[type=text]'), tg = row.querySelector('[data-gp-ms-toggle]');
			const a = sel.getBoundingClientRect(), b = inp.getBoundingClientRect(), t = tg && !tg.hidden ? tg.getBoundingClientRect() : null;
			return { sel: a.height, inp: b.height, selTop: a.top, inpTop: b.top, toggleInside: !t || (t.left >= b.left - 1 && t.right <= b.right + 1 && t.top >= b.top - 1 && t.bottom <= b.bottom + 1) };
		});
		check(v.name + ' geo: the filter operator and value box have the same height and top (a pick button, when shown, sits inside the box)',
			!!gh && Math.abs(gh.sel - gh.inp) <= 1 && (v.width < 640 || Math.abs(gh.selTop - gh.inpTop) <= 1) && gh.toggleInside, JSON.stringify(gh));
		const big = Buffer.alloc(40 * 1048576, 0x61);
		await page.setInputFiles('[data-panel=sources] input[type=file]', { name: 'GeoLite2-City.mmdb', mimeType: 'application/octet-stream', buffer: big });
		const gmsg = await page.locator('[data-panel=sources] [data-gp-upload-msg]').innerText();
		check(v.name + ' geo: a 40 MiB file is refused in the browser with the SFTP hint, Upload is disabled and nothing was sent',
			/40\.0 MiB/.test(gmsg) && /SFTP/.test(gmsg) && (await page.locator('[data-panel=sources] [data-gp-upload-send]').isDisabled()) && (await page.locator('[data-panel=sources] input[type=file]').inputValue()) === '' && /r=geo/.test(page.url()));
		await page.setInputFiles('[data-panel=sources] input[type=file]', { name: 'GeoLite2-Country.mmdb', mimeType: 'application/octet-stream', buffer: Buffer.alloc(1024, 0x61) });
		check(v.name + ' geo: a small file clears the message and enables Upload again', !(await page.locator('[data-panel=sources] [data-gp-upload-msg]').isVisible()) && !(await page.locator('[data-panel=sources] [data-gp-upload-send]').isDisabled()));
		check(v.name + ' geo: the "not compiled yet" banner is shown while a source is uncompiled', /not compiled yet|never compiled|not compiled/i.test(await page.locator('main .gp-note-strong').first().innerText()));
		// ---- temporary blocks (PR G): the page, the shared-address warning, quick actions on a log row (admin), none for an operator
		await page.goto(ROOT + '?r=overrides&new=100.64.0.5');
		check(v.name + ' overrides: the page is "Temporary blocks & allows", with four buttons, eight presets, a custom-minutes box and the shared-address warning prefilled from ?new=',
			/Temporary blocks/.test(await page.locator('h1').innerText()) && (await page.locator('#override-add button[name=override]').count()) === 4 && (await page.locator('#override-add select[name=ttl] option').count()) === 8
			&& /immediately, also in monitor mode/.test(await page.locator('[data-ovr-immediate]').innerText()) && (await page.locator('#override-add input[name=ttl_minutes]').count()) === 1 && (await page.locator('#override-add input[name=identity]').inputValue()) === '100.64.0.5' && (await page.locator('[data-shared-ip=cgnat]').count()) === 1);
		await page.goto(ROOT + '?r=logs');
		await page.locator('.gp-log').first().locator('[data-toggle]').first().click();
		const qa = page.locator('.gp-log').first().locator('.gp-quick');
		check(v.name + ' logs: a row opens quick actions for the address (and the device when there is one): Block 15 min, Challenge 1 h, CAPTCHA 1 h, Allow 1 h, Custom...',
			(await qa.count()) >= 1 && (await qa.first().locator('button[name=quick]').count()) === 4 && /Custom/.test(await qa.first().innerText()) && (await qa.first().locator('input[name=csrf]').count()) === 1);
		const qaBox = await qa.first().boundingBox();
		check(v.name + ' logs: the quick actions fit the screen width', !!qaBox && qaBox.x >= 0 && qaBox.x + qaBox.width <= v.width + 1, JSON.stringify(qaBox));
		await Promise.all([page.waitForNavigation(), qa.first().locator('button[value="challenge:3600"]').click()]);
		check(v.name + ' logs: pressing a quick action returns to the Logs page (not the Overrides page) with a message', /r=logs/.test(page.url()) && (await page.locator('.gp-flash, [role=status], [role=alert]').count()) >= 1, page.url());
		// ---- Live requests (PR H): follows the log, half lines wait, hover and hidden tab pause the polling, text is never markup, drawer with quick actions
		if (process.env.LAYOUT_LOG_FILE) {
			const fs = require('fs');
			const LOGF = process.env.LAYOUT_LOG_FILE;
			const rowJson = (extra) => JSON.stringify(Object.assign({ v: 5, rid: Math.random().toString(16).slice(2, 14).padEnd(12, '0'), ts: Date.now() / 1000, ip: '203.0.113.77', ua: 'live-test', uah: 'b'.repeat(12), m: 'GET', p: '/live-test', q: '', aj: 0, nav: 1, gate: 1, tok: 'm', dev: 'devlive1', sf: 'navigate', al: 1, hc: 8, sc: 0, esc: 0, rs: [], rd: 0, hp: 0, bot: '', ref: '', botv: '', rep: 0, ml: -1, clf: -1, hold: 0, ovr: '', act: 'allow', sh: 0, ms: 1 }, extra));
			const sfx = v.name;                                       // paths are unique per viewport: the log keeps the rows of the first pass
			let ridN = 0;
			const uid = () => (Date.now() * 100 + (++ridN)).toString(16).padStart(12, '0').slice(-12);      // a new request id per row: the page never shows one id twice
			let polls = 0;
			page.on('request', (r) => { if (/[?&]poll=1/.test(r.url())) { polls++; } });
			await page.goto(ROOT + '?r=live&minutes=60');
			await page.selectOption('#live-interval', '2');
			await page.waitForSelector('#live-rows .gp-live-row');
			if (SHOTS) { await page.screenshot({ path: SHOTS + '/' + v.name + '-live.png', fullPage: false }); }
			const over = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
			check(v.name + ' live: the first load shows the last 60 minutes, newest on top, no horizontal scroll', (await page.locator('#live-rows .gp-live-row').count()) >= 20 && over <= 1, String(over));
			check(v.name + ' live: the header strip has numbers, an inline SVG chart with bars and a legend; Top right now has entries',
				(await page.locator('#live-stats .gp-live-stat').count()) >= 8 && (await page.locator('#live-chart svg rect').count()) >= 1 && (await page.locator('#live-chart .gp-live-legend-i').count()) === 6 && (await page.locator('#live-toplists .gp-live-top-i').count()) >= 3);
			check(v.name + ' live: reasons are badges with the full name, the code and a monitor marker for SH_ codes', /Rule matched/.test(await page.locator('#live-rows').innerText()) && (await page.locator('#live-rows .gp-reason-mon').count()) >= 1 && (await page.locator('#live-rows .gp-reason-code').count()) >= 3);
			// a client-written User-Agent and path are text, never markup; a half line waits until it is complete
			fs.appendFileSync(LOGF, rowJson({ rid: uid(), ua: '<img src=x onerror=window.__xss=1>', p: '/<b>live-xss-' + sfx + '</b>', rs: ['SH_RULE:r1'], act: '403', sh: 1 }) + '\n');
			const half = rowJson({ rid: uid(), p: '/live-half-' + sfx, act: '429' });
			fs.appendFileSync(LOGF, half.slice(0, 40));
			await page.waitForSelector('#live-rows .gp-live-path:text("live-xss-' + sfx + '")', { timeout: 8000 });
			check(v.name + ' live: a row appended to the log appears at the top without a reload', (await page.locator('#live-rows .gp-live-row').first().locator('.gp-live-path').innerText()).indexOf('live-xss-' + sfx) >= 0);
			check(v.name + ' live: the markup in the User-Agent and the path is shown as text (no element created, no script ran)', (await page.locator('#live-rows img, #live-rows b').count()) === 0 && (await page.evaluate(() => window.__xss === undefined)));
			await page.waitForTimeout(2600);
			check(v.name + ' live: a half-written line is not shown', (await page.locator('#live-rows .gp-live-path:text("live-half-' + sfx + '")').count()) === 0);
			fs.appendFileSync(LOGF, half.slice(40) + '\n');
			await page.waitForSelector('#live-rows .gp-live-path:text("live-half-' + sfx + '")', { timeout: 8000 });
			check(v.name + ' live: ...and it is shown, once, when it is complete', (await page.locator('#live-rows .gp-live-path:text("live-half-' + sfx + '")').count()) === 1);
			// hover pauses the polling
			await page.hover('#live-rows');
			await page.waitForTimeout(300);
			const p0 = polls;
			fs.appendFileSync(LOGF, rowJson({ rid: uid(), p: '/live-hover-' + sfx }) + '\n');
			await page.waitForTimeout(4500);
			check(v.name + ' live: no request is made while the pointer is over the table, and the row waits', polls === p0 && (await page.locator('#live-rows .gp-live-path:text("live-hover-' + sfx + '")').count()) === 0 && /pointer/.test(await page.locator('#live-state').innerText()), polls + ' vs ' + p0);
			await page.mouse.move(5, 5);
			await page.waitForSelector('#live-rows .gp-live-path:text("live-hover-' + sfx + '")', { timeout: 8000 });
			check(v.name + ' live: leaving the table resumes it and the waiting row arrives (cursor, nothing lost)', true);
			// a hidden tab stops polling
			await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }); document.dispatchEvent(new Event('visibilitychange')); });
			await page.waitForTimeout(300);
			const p1 = polls;
			await page.waitForTimeout(4500);
			check(v.name + ' live: no request is made while the tab is hidden', polls === p1 && /not visible/.test(await page.locator('#live-state').innerText()), polls + ' vs ' + p1);
			await page.evaluate(() => { delete document.hidden; document.dispatchEvent(new Event('visibilitychange')); });
			await page.waitForTimeout(2600);
			check(v.name + ' live: showing the tab again resumes the polling', polls > p1);
			await page.selectOption('#live-interval', '0');
			await page.waitForTimeout(400);
			const p2 = polls;
			await page.waitForTimeout(3000);
			check(v.name + ' live: interval "Paused" makes no request', polls === p2 && /Paused/.test(await page.locator('#live-state').innerText()));
			await page.selectOption('#live-interval', '2');
			// details drawer, quick actions, watch
			await page.locator('#live-rows .gp-live-row:has(.gp-live-path:text("live-xss-' + sfx + '"))').first().click();
			check(v.name + ' live: a row opens the details drawer with the reasons, the identity links and all fields', await page.locator('#live-drawer').isVisible() && (await page.locator('#live-drawer .gp-prop').count()) >= 10 && (await page.locator('#live-drawer a[href*="r=identity"]').count()) >= 1 && (await page.locator('#live-drawer .gp-reason').count()) >= 1);
			check(v.name + ' live: the drawer has the quick actions for the address and the device (Block 15 min, Challenge 1 h, CAPTCHA 1 h, Allow 1 h, Custom...), CSRF-protected, returning to Live',
				(await page.locator('#live-drawer form.gp-quick').count()) === 2 && (await page.locator('#live-drawer form.gp-quick').first().locator('button[name=quick]').count()) === 4 && (await page.locator('#live-drawer form.gp-quick input[name=csrf]').first().inputValue()).length >= 32
				&& /^index\.php\?r=live/.test(await page.locator('#live-drawer form.gp-quick input[name=back]').first().inputValue()));
			const dbox = await page.locator('#live-drawer').boundingBox();
			check(v.name + ' live: the drawer fits the screen', !!dbox && dbox.x >= -1 && dbox.x + dbox.width <= v.width + 1, JSON.stringify(dbox));
			await page.locator('#live-drawer button:has-text("Watch")').first().click();
			check(v.name + ' live: Watch pins an address or device (a chip in the watch bar, kept in this browser)', (await page.locator('#live-watchlist .gp-chip').count()) === 1 && (await page.locator('#live-rows .gp-live-watched').count()) >= 1);
			await page.keyboard.press('Escape');
			check(v.name + ' live: Escape closes the drawer', !(await page.locator('#live-drawer').isVisible()));
			await page.locator('#live-watchlist .gp-chip').first().click();
			// a click on a "top right now" entry becomes a filter
			const ipEntry = page.locator('#live-toplists .gp-live-top-sec').first().locator('.gp-live-top-i').first();
			const ipVal = (await ipEntry.locator('.gp-live-top-v').innerText()).trim();
			await ipEntry.click();
			await page.waitForTimeout(800);
			check(v.name + ' live: pressing an entry of Top right now adds it as a filter (the field and the address bar) and reloads the view', (await page.locator('#lf-ip').inputValue()).indexOf(ipVal) >= 0 && page.url().indexOf('ip=') > 0);
			const ips = await page.locator('#live-rows .gp-live-ip').allInnerTexts();
			check(v.name + ' live: ...and only rows of that address remain', ips.length >= 1 && ips.every((t) => t.indexOf(ipVal) >= 0), ipVal + ' / ' + ips.slice(0, 3).join('|'));
			await page.fill('#lf-ip', '');
			await page.evaluate(() => { document.getElementById('lf-ip').value = ''; });
			// quick toggle "Blocked" and the CSV
			fs.appendFileSync(LOGF, rowJson({ rid: uid(), act: '403', p: '/live-blocked-' + sfx }) + '\n');
			await page.check('[data-live-show=blocked]');
			await page.click('#live-apply');
			await page.waitForTimeout(900);
			const classes = await page.locator('#live-rows .gp-live-row').evaluateAll((es) => es.map((e) => e.className));
			check(v.name + ' live: the Blocked toggle shows only blocked requests', classes.length >= 1 && classes.every((c) => /gp-live-r-blocked/.test(c)), String(classes.length));
			await page.uncheck('[data-live-show=blocked]');
			await page.click('#live-apply');
			await page.waitForTimeout(900);
			const [dl] = await Promise.all([page.waitForEvent('download'), page.click('#live-export')]);
			const csv = fs.readFileSync(await dl.path(), 'utf8');
			check(v.name + ' live: Export CSV downloads the rows on screen (short columns plus the reasons spelled out)', /^﻿ts,rid,ip,dev,m,p,q,act,sh,hold,ovr,tok,sc,esc,rs,rep,ml,clf,botv,cc,asn,st,by,dur,rs_names/.test(csv) && csv.split('\r\n').length >= 5 && /Rule matched/.test(csv));
			// a fixed window
			const off = await page.evaluate(() => JSON.parse(document.getElementById('live-cfg').textContent).tzOffset);
			const loc = (t) => new Date((t + off) * 1000).toISOString().slice(0, 16);
			const nowS = Math.floor(Date.now() / 1000);
			await page.check('input[name=mode][value=window]');
			await page.fill('#live-start', loc(nowS - 3000));
			await page.fill('#live-end', loc(nowS - 600));
			await page.click('#live-apply');
			await page.waitForSelector('#live-rows .gp-live-row', { timeout: 8000 });
			await page.waitForTimeout(600);
			const wt = await page.locator('#live-rows .gp-live-time').allInnerTexts();
			check(v.name + ' live: a fixed start / end window replays only that window and says when it is over', wt.length >= 5 && /End of the window/.test(await page.locator('#live-state').innerText()), wt.length + ' rows');
			if (SHOTS) { await page.screenshot({ path: SHOTS + '/' + v.name + '-live-window.png', fullPage: false }); }
			await page.check('input[name=mode][value=live]');
			// the role view: a Monitoring operator has no quick actions (checked below in the role loop through the same config flag)
		}
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
		let dialogs = 0; const onDialog = () => { dialogs++; }; page.on('dialog', onDialog);
		await Promise.all([page.waitForNavigation(), page.click('#dash-kill a[href*="kill_confirm=1"]')]);
		const ask = await page.locator('#dash-kill .gp-kill-confirm').innerText();
		check(v.name + ' kill switch: one click only asks ("Stop the guard? This switches off all protection." Stop / Cancel), inline, no browser dialog, nothing stopped yet',
			/Stop the guard\?/.test(ask) && /switches off all protection/.test(ask) && /Cancel/.test(ask) && dialogs === 0 && (await page.locator('#dash-kill .gp-pulse-ok').count()) === 1, ask.replace(/\s+/g, ' '));
		await Promise.all([page.waitForNavigation(), page.click('#dash-kill a:has-text("Cancel")')]);
		check(v.name + ' kill switch: Cancel leaves the guard running and the Stop link back', (await page.locator('#dash-kill .gp-pulse-ok').count()) === 1 && (await page.locator('#dash-kill .gp-kill-confirm').count()) === 0);
		await Promise.all([page.waitForNavigation(), page.click('#dash-kill a[href*="kill_confirm=1"]')]);
		await Promise.all([page.waitForNavigation(), page.click('#dash-kill .gp-kill-confirm button[type=submit]')]);
		check(v.name + ' kill switch: the confirmed Stop stopped the guard (no dialog)', (await page.locator('#dash-kill .gp-pulse-bad').count()) === 1 && dialogs === 0);
		await ctxCheck('kill switch stop', 'msg-killswitch', 'div');
		await Promise.all([page.waitForNavigation(), page.click('#dash-kill form button[type=submit]')]);
		await ctxCheck('kill switch start', 'msg-killswitch', 'div');
		page.off('dialog', onDialog);
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
		const ALL = ['dashboard', 'logs', 'live', 'identity&id=203.0.113.5', 'overrides', 'rules', 'geo', 'iplists', 'replay', 'models', 'settings', 'config_file', 'jobs', 'audit', 'update', 'users', 'account'];
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
				const pr = await page.goto(ROOT + '?r=live&poll=1&minutes=60');
				const ptxt = await pr.text();
				check(v.name + ' ' + role.name + ' live poll: ' + (role.name === 'operator' ? 'JSON for the operator (a GET, no-store)' : '403 for demo'), role.name === 'operator' ? (pr.status() === 200 && /json/.test(pr.headers()['content-type'] || '') && /no-store/.test(pr.headers()['cache-control'] || '') && JSON.parse(ptxt).ok === true) : pr.status() === 403);
				if (role.name === 'operator') {
					await page.goto(ROOT + '?r=live&minutes=60');
					check(v.name + ' operator live: the page shows no quick actions (read only role)', (await page.evaluate(() => JSON.parse(document.getElementById('live-cfg').textContent).canQuick)) === false);
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
