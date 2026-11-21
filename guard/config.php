<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// Bot Guard configuration.
// Copy this file per deployment and point GV_CONFIG at it, or edit it in place.
// While 'secret' equals CHANGE_ME every enforce toggle is forced to false
// (monitor only), so an unconfigured install can never affect a live site.
return array(
	'secret'           => 'CHANGE_ME',        // per deployment: openssl rand -hex 32
	'cookie_name'      => '_gv',
	'token_ttl'        => 604800,             // 7 days
	'nonce_ttl'        => 120,                // seconds
	'enforce'          => array(              // all false = monitor mode
		'block'     => false,                 // stage 1
		'challenge' => false,                 // stage 2
		'ratelimit' => false,                 // stage 3
	),
	'signals'          => array(              // all false = shadow only
		'reputation' => false,                // add gv:rep:{dev} to the score
		'ml'         => false,                // add the gv:ml:{dev} anomaly level
		'clf'        => false,                // add the gv:clf:{dev} classifier level
	),
	'ml_weight'        => 0.4,                // ml level 0..100 -> score contribution
	'clf_weight'       => 0.5,                // clf level 0..100 -> score contribution
	'holdout_pct'      => 0,                  // percent of identities measured but never
	                                          // enforced against. 0 = off. Values above 5
	                                          // are clamped: a measurement sample, not a bypass.
	'holdout_salt'     => 'CHANGE_ME_TOO',    // any stable string; changing it reshuffles
	                                          // who is in the holdout, so change it rarely
	'capture_outcomes' => false,              // Phase 4. Off by default: this is the only
	                                          // guard code that runs after the application,
	                                          // so it is opt-in like every other new behaviour.
	                                          // Adds a second tiny JSONL line per allowed
	                                          // request, correlated by rid.
	'bot_suffixes'     => array(              // consumed by the Python verifier;
	                                          // documented here for one source of truth.
	                                          // Keep in sync with analyzer/config.py.
		'googlebot'             => array('.googlebot.com', '.google.com'),
		'adsbot-google'         => array('.googlebot.com', '.google.com'),
		'mediapartners-google'  => array('.googlebot.com', '.google.com'),
		'google-inspectiontool' => array('.googlebot.com', '.google.com'),
		'storebot-google'       => array('.googlebot.com', '.google.com'),
		'googleother'           => array('.googlebot.com', '.google.com'),
		'bingbot'               => array('.search.msn.com'),
		'adidxbot'              => array('.search.msn.com'),
		'bingpreview'           => array('.search.msn.com'),
	),
	'hard_block_score' => 60,
	'limits'           => array(              // fixed window, per 'window' seconds
		'window' => 300,
		'device' => 150,
		'ip_ua'  => 400,
		'ip'     => 1200,                     // deliberately generous: CGNAT reality
		'bot'    => 600,
		'mint'   => 300,                      // tokens minted per IP per window (see challenge).
		                                      // Generous on purpose: a carrier address is shared
		                                      // by many new visitors, and anyone on it could
		                                      // otherwise use the budget up and lock them out
		'device_hour' => 400,                 // requests per device token per hour and per
		'device_day'  => 1500,                // day (fixed windows). These catch the scraper
		                                      // that paces itself under 'device' and keeps
		                                      // changing address. Exempt your admin path first.
		'preview'     => 20,                  // requests per preview_bots name per window,
		                                      // site-wide (not per IP)
		'bot_unverified' => 300,              // requests per known_bots name per window, site-wide,
		                                      // from addresses the verifier has not confirmed yet.
		                                      // Needs `analyzer-cron.sh verify` running, or real
		                                      // crawlers stay inside this budget for ever
	),
	'challenge'        => array(
		'pow_bits' => 16,                     // proof-of-work difficulty, 0-24; 0 disables
		                                      // (~65k SHA-256 attempts at 16, well under a
		                                      // second in a current browser)
		'bind_ip'  => true,                   // tie a nonce to the IP it was issued to; set
		                                      // false on networks that rotate IPs mid-page-load
		'gate_post' => false,                 // false: a token-less POST is served and logged as a
		                                      // shadow challenge (act=challenge, sh=1, m=POST).
		                                      // true: it is challenged like a GET. Most shops
		                                      // render a product page for a POST too, so leave it
		                                      // off only until the shadow rows show which POST
		                                      // endpoints (gateway callbacks) still need exempting
		'trust_headers' => false,             // false: every GET needs a token. true: only a
		                                      // GET that asks for HTML does (the old rule; any
		                                      // client that omits Accept: text/html walks past)
		'test_key' => '',                     // operator test switch, off while empty. With a key
		                                      // set, opening /?gv_test=KEY shows the real challenge
		                                      // page to THAT browser only (10 minutes, or until it
		                                      // is solved). Use a long random value; see docs
	),
	'honeypot_path'    => '/old-archive',     // change per site; must 404 today
	'exempt_paths'     => array(),            // URI prefixes, e.g. '/wp-cron.php', '/wp-json/'
	'exempt_params'    => array(),            // param => array of value prefixes,
	                                          // e.g. 'route' => array('payment/', 'api/')
	'exempt_params_paths' => array('/', '/index.php'),  // exempt_params only count on these exact
	                                          // paths (the front controller). On an SEO URL
	                                          // the parameter is just something the client added
	'known_bots'       => array(              // lowercase UA substrings. Each one needs a
	                                          // bot_suffixes entry: the pass is revoked for
	                                          // an address that fails reverse-DNS verification
		'googlebot', 'adsbot-google', 'mediapartners-google', 'google-inspectiontool',
		'storebot-google', 'googleother', 'bingbot', 'adidxbot', 'bingpreview',
	),
	'preview_bots'     => array(              // link-preview fetchers, lowercase UA substrings.
	                                          // Nothing verifies them, so all addresses of one
	                                          // name share limits.preview; over it they are
	                                          // treated like any other client
		'telegrambot', 'whatsapp', 'facebookexternalhit', 'twitterbot', 'linkedinbot',
	),
	'cdn_ranges'       => array(),            // v4 CIDRs; XFF trusted only when
	                                          // REMOTE_ADDR is inside one of these
	'redis'            => array(              // shared by the guard, the panel AND the analyzer
		'host'        => '127.0.0.1',
		'port'        => 6379,
		'socket'      => '',                  // unix socket path; when set, host/port are ignored
		'username'    => '',                  // optional (Redis 6+ ACL); empty = default user
		'password'    => '',                  // optional; empty = no AUTH is sent
		'db'          => 0,                   // optional; 0 = no SELECT is sent
		'prefix'      => '',                  // optional key namespace, e.g. 'shop1:'
		'timeout'     => 0.05,                // seconds, per read in the request path
		'breaker_ttl' => 5,                   // seconds to skip Redis after a failure; 0 = off
	),
	'log_dir'          => dirname(__DIR__) . '/logs',
	'strings'          => array(              // user-facing, operator-localizable
		'lang'     => 'fa',
		'dir'      => 'rtl',
		'title'    => 'لطفاً چند لحظه صبر کنید…',
		'sub'      => 'در حال بررسی مرورگر شما هستیم.',
		'noscript' => 'برای ادامه، لطفاً JavaScript و Cookie مرورگر را فعال کنید.',
		'failed'   => 'بررسی مرورگر شما انجام نشد.',
		'retry'    => 'تلاش دوباره',
		'nocookie' => 'مرورگر شما کوکی را نگه نمی‌دارد. لطفاً کوکی‌ها را برای این سایت فعال کنید و دوباره تلاش کنید.',
		'cap_title' => 'لطفاً تأیید کنید که ربات نیستید',
		'cap_sub'  => 'نویسه‌هایی را که در تصویر می‌بینید وارد کنید.',
		'cap_label' => 'نویسه‌ها',
		'cap_submit' => 'ادامه',
		'cap_new'  => 'تصویر جدید',
		'cap_wrong' => 'درست نیست. لطفاً دوباره تلاش کنید.',
		'cap_failed' => 'بررسی انجام نشد. لطفاً تصویر جدید بگیرید.',
		'cap_expired' => 'تصویر منقضی شده است. لطفاً تصویر جدید بگیرید.',
	),
);
