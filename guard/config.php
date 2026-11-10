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
		'googlebot' => array('.googlebot.com', '.google.com'),
		'bingbot'   => array('.search.msn.com'),
	),
	'hard_block_score' => 60,
	'limits'           => array(              // fixed window, per 'window' seconds
		'window' => 300,
		'device' => 150,
		'ip_ua'  => 400,
		'ip'     => 1200,                     // deliberately generous: CGNAT reality
		'bot'    => 600,
	),
	'honeypot_path'    => '/old-archive',     // change per site; must 404 today
	'exempt_paths'     => array(),            // URI prefixes, e.g. '/wp-cron.php', '/wp-json/'
	'exempt_params'    => array(),            // param => array of value prefixes,
	                                          // e.g. 'route' => array('payment/', 'api/')
	'known_bots'       => array('googlebot', 'bingbot'),  // lowercase UA substrings
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
	),
);
