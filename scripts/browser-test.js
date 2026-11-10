#!/usr/bin/env node
// Real-browser test of the JavaScript challenge (Playwright).
//
//   node scripts/browser-test.js [chromium|firefox|webkit]
//
// Needs `playwright` resolvable (CI installs it) and the PHP built-in server.
// It starts the dev router on a free port (roomier rate limits than
// config.dev.php), plus a self-signed https reverse proxy in front of it, then
// checks, with JavaScript and cookies on:
//   * the challenge is passed on http:// and on https://,
//   * a rejected handshake retries automatically at most twice and then shows
//     the localized failure message with a working manual retry link,
//   * median solve time at the default difficulty, and raw hash rate.
// Exit code 1 on any failed check.
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const https = require('https');

const browserName = process.argv[2] || 'chromium';
const pw = require('playwright');
const repo = path.resolve(__dirname, '..');
let failed = 0;
const check = (name, cond, extra) => {
  console.log((cond ? 'PASS  ' : 'FAIL  ') + name + (extra ? ' (' + extra + ')' : ''));
  if (!cond) failed++;
};

async function main() {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gv-browser-'));
  const cfgPath = path.join(tmp, 'config.php');
  fs.writeFileSync(cfgPath, `<?php if (!defined('GV_BOOT')) { exit; }
$c = require '${repo}/scripts/config.dev.php';
$c['limits'] = array('window' => 60, 'device' => 100000, 'ip_ua' => 100000, 'ip' => 100000, 'bot' => 100000, 'mint' => 100000);
$c['holdout_pct'] = 0;
$c['capture_outcomes'] = false;
$c['log_dir'] = '${tmp}/logs';
return $c;`);
  const port = 18000 + Math.floor(Math.random() * 1000);
  const php = spawn('php', ['-S', '127.0.0.1:' + port, path.join(repo, 'scripts', 'dev-router.php')],
    { env: Object.assign({}, process.env, { GV_DEV_CONFIG: cfgPath }), stdio: 'ignore' });
  await new Promise(r => setTimeout(r, 800));

  // https reverse proxy with a throwaway certificate
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
    '-keyout', path.join(tmp, 'k.pem'), '-out', path.join(tmp, 'c.pem')], { stdio: 'ignore' });
  const proxy = https.createServer({ key: fs.readFileSync(path.join(tmp, 'k.pem')), cert: fs.readFileSync(path.join(tmp, 'c.pem')) },
    (req, res) => {
      const up = http.request({ host: '127.0.0.1', port, path: req.url, method: req.method,
        headers: Object.assign({}, req.headers, { 'x-forwarded-proto': 'https' }) }, ur => {
        res.writeHead(ur.statusCode, ur.headers); ur.pipe(res);
      });
      req.pipe(up);
    });
  await new Promise(r => proxy.listen(0, '127.0.0.1', r));
  const sport = proxy.address().port;

  const browser = await pw[browserName].launch();
  try {
    for (const [label, base] of [['http', 'http://127.0.0.1:' + port], ['https', 'https://127.0.0.1:' + sport]]) {
      const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
      const page = await ctx.newPage();
      const t0 = Date.now();
      await page.goto(base + '/?run=1', { waitUntil: 'load' });
      await page.waitForFunction(() => document.body && document.body.textContent.indexOf('OK') !== -1, null, { timeout: 20000 });
      check(`${browserName} passes the challenge on ${label}:// with JS and cookies on`, true, (Date.now() - t0) + ' ms');
      const cookies = await ctx.cookies();
      check(`${label}: the _gv token cookie is set` + (label === 'https' ? ' with Secure' : ''),
        cookies.some(c => c.name === '_gv' && (label === 'http' || c.secure)));
      await ctx.close();
    }

    // Failure path: every handshake is refused -> two automatic retries, then the message.
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    let posts = 0;
    await page.route('**/*', route => {
      if (route.request().method() === 'POST') { posts++; return route.fulfill({ status: 403, body: '' }); }
      return route.continue();
    });
    await page.goto('http://127.0.0.1:' + port + '/?run=fail');
    await page.waitForSelector('#gv-fail:not([hidden])', { timeout: 20000 });
    check('a refused handshake is retried automatically at most twice, then the message shows', posts === 3, posts + ' POSTs');
    check('the failure message and retry link are visible', await page.isVisible('#gv-retry'));
    const before = posts;
    await page.unroute('**/*');
    await page.click('#gv-retry');
    await page.waitForFunction(() => document.body.textContent.indexOf('OK') !== -1, null, { timeout: 20000 });
    check('the manual retry link starts a fresh challenge that succeeds', posts === before);
    await ctx.close();

    // Solve time at the default difficulty, and raw hashes per second.
    const times = [];
    let rate = 0;
    for (let i = 0; i < 12; i++) {
      const c2 = await browser.newContext();
      const p2 = await c2.newPage();
      if (process.env.GV_CPU_THROTTLE && browserName === 'chromium') {
        // Emulate a slower CPU (CDP): e.g. GV_CPU_THROTTLE=6 approximates a low-end phone.
        const cdp = await c2.newCDPSession(p2);
        await cdp.send('Emulation.setCPUThrottlingRate', { rate: Number(process.env.GV_CPU_THROTTLE) });
      }
      let tChallenge = 0, tDone = 0;
      p2.on('response', r => {
        if (r.request().method() === 'GET' && r.status() === 503) tChallenge = Date.now();
        if (r.request().method() === 'POST' && r.status() === 204) tDone = Date.now();
      });
      await p2.goto('http://127.0.0.1:' + port + '/?perf=' + i);
      await p2.waitForFunction(() => document.body.textContent.indexOf('OK') !== -1, null, { timeout: 20000 });
      if (tChallenge && tDone) times.push(tDone - tChallenge);
      if (i === 0) {
        // hash rate of the very same solver
        const c3 = await browser.newContext();
        const p3 = await c3.newPage();
        await p3.route('**/*', route => route.request().method() === 'POST' ? route.abort() : route.continue());
        await p3.goto('http://127.0.0.1:' + port + '/?rate=1');
        rate = await p3.evaluate(() => {
          const src = document.scripts[document.scripts.length - 1].textContent;
          const body = src.replace(/^\s*\(function \(\) \{/, '').replace(/\}\)\(\);\s*$/, '')
            .replace(/setTimeout\(function \(\) \{ if \(B > 0\)[\s\S]*$/, '');
          const f = new Function('document', 'window', 'sessionStorage', 'location', 'fetch', 'setTimeout',
            body + '; var t = performance.now(), n = 300000; for (var c = 0; c < n; c++) { test(c); } return n / ((performance.now() - t) / 1000);');
          return f({ getElementById: () => ({}) }, window, window.sessionStorage, location, fetch, setTimeout);
        });
        await c3.close();
      }
      await c2.close();
    }
    times.sort((a, b) => a - b);
    const median = times[Math.floor(times.length / 2)];
    console.log(`INFO  ${browserName}: median solve ${median} ms over ${times.length} runs (min ${times[0]}, max ${times[times.length - 1]}); ~${Math.round(rate)} hashes/s`);
    check('median solve time at the default difficulty is under 2 s on this machine', median < 2000, median + ' ms');
  } finally {
    await browser.close();
    proxy.close();
    php.kill();
  }
  process.exit(failed ? 1 : 0);
}
main().catch(e => { console.error(e); process.exit(1); });
