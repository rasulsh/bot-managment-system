<?php
if (!defined('GV_BOOT')) { http_response_code(404); exit; }

// TEST-ONLY configuration for the local dev router. Never deploy this file:
// the secret is public, every enforce toggle is on, and the limits are tiny
// so the rate-limit case trips within a few dozen requests.
return array(
	'secret'           => 'dev-only-secret',
	'cookie_name'      => '_gv',
	'token_ttl'        => 604800,
	'nonce_ttl'        => 120,
	'enforce'          => array(
		'block'     => true,
		'challenge' => true,
		'ratelimit' => true,
	),
	'signals'          => array(              // ON here so the matrix can exercise them
		'reputation' => true,
		'ml'         => true,
		'clf'        => true,
	),
	'ml_weight'        => 0.4,
	'clf_weight'       => 0.5,
	// The matrix drives a single client, so it cannot rely on chance to land
	// inside a 5% holdout: scripts/holdout-probe.php asks the guard which
	// device id is a member and mints a token for it. This salt is chosen so
	// that 127.0.0.1 itself is NOT a member - otherwise every token-less case
	// in the matrix would be held out and nothing would ever be enforced.
	'holdout_pct'      => 5,
	'holdout_salt'     => 'gv-dev-1',
	// ON here so the matrix can prove outcome lines appear. The byte-identity
	// test flips this via GV_CAPTURE to compare the same pages both ways.
	'capture_outcomes' => (getenv('GV_CAPTURE') !== '0'),
	'bot_suffixes'     => array(
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
	'limits'           => array(
		'window' => 60,
		'device' => 10,
		'ip_ua'  => 15,
		'ip'     => 25,
		'bot'    => 10,
		'mint'   => 60,
		'device_hour' => 40,
		'device_day'  => 60,
		'preview'     => 3,
		'bot_unverified' => 50,
	),
	'challenge'        => array('pow_bits' => 16, 'bind_ip' => true),
	'honeypot_path'    => '/old-archive',
	'exempt_paths'     => array('/exempt-me'),
	'exempt_params'    => array('route' => array('payment/')),
	'known_bots'       => array('googlebot', 'adsbot-google', 'bingbot'),
	'preview_bots'     => array('telegrambot', 'whatsapp'),
	'cdn_ranges'       => array(),
	'redis'            => array('host' => '127.0.0.1', 'port' => 6379,
	                            'timeout' => 0.05),
	'log_dir'          => sys_get_temp_dir() . '/gv-logs',
	'strings'          => array(
		'lang'     => 'en',
		'dir'      => 'ltr',
		'title'    => 'Please wait a moment...',
		'sub'      => 'We are checking your browser.',
		'noscript' => 'Please enable JavaScript and cookies to continue.',
		'failed'   => 'We could not verify your browser.',
		'retry'    => 'Try again',
		'nocookie' => 'Your browser is not keeping cookies. Please enable cookies for this site and try again.',
	),
);
