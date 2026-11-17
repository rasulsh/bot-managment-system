# Testing the challenge page by hand

The challenge page is shown to a visitor without a valid token, but only when `enforce.challenge` is on. In monitor mode nobody sees it, so you cannot just wait for it. The test switch shows the real page to **your browser only**.

## What it does

- Off by default (`challenge.test_key` is empty).
- With a key set, opening `https://YOUR-SITE/?gv_test=KEY` sets a signed cookie (10 minutes) and redirects to the same URL without the key.
- While that cookie is valid, **every GET from that browser** gets the real challenge page, even if it already holds a valid token and even in monitor mode.
- It goes through the normal flow: nonce, proof of work, token cookie, the same refusals. Solving it clears the switch and you are let in.
- Nobody else is affected. No path, IP or rule is exempted or relaxed. A wrong key does nothing. The cookie is HMAC-signed with `secret`, so it cannot be forged. It is ignored while `secret` is still `CHANGE_ME`.
- Each shown page is logged as `challenge` with the reason `TEST`.

## Manual procedure

1. Server, create a key: `openssl rand -hex 16`
2. Server, edit `guard/config.php` and set inside the `challenge` array: `'test_key' => 'THE_KEY',`
3. Browser, open a private window and go to `https://YOUR-SITE/?gv_test=THE_KEY`
4. You see the challenge page (HTTP 503) and it solves itself in about a second, then the site loads. That is the full flow.
5. To test again, repeat step 3.
6. When done, set `'test_key' => '',` again. Pending cookies stop working at once.

## Wrong answer and expiry

These cannot be done by hand from the page, so they are tested by `scripts/e2e-challenge.sh` (needs `php`, `curl`, `redis-server`):

```
bash scripts/e2e-challenge.sh
```

It checks: page shown, correct proof gives 204 and access, wrong proof 403, garbage nonce 403, nonce older than `nonce_ttl` 403, replay 403, other visitors unaffected, wrong or forged or expired switch ignored, switch off while the key is empty, monitor mode (tester sees the page, others never do), and the `TEST` log rows.
