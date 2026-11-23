<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Access control: ONE permission map, checked by the router before any handler runs, for GET and POST.
// Server-side and deny by default: a route that is not in the map, and a POST action that is not listed for its route,
// need the admin role. Hiding a button is never the protection.
//
// Roles (lowest to highest): demo < operator < admin.
//   demo      the aggregate dashboard (a separate, data-minimised view), "My account", logout. Nothing else.
//   operator  (UI label: Monitoring operator) every report and page an admin sees EXCEPT the raw Config file, the Update page and
//             user management. It changes NOTHING: no POST of any kind except logging out and changing its OWN password.
//   admin     everything.
//
// Map shape: route => array('GET' => minimum role, 'POST' => minimum role, or array('*' => role, '<action>' => role)).
// The POST action of a request is gp_acl_action(). Decision table (also in README Part 2 and docs/09):
//
//   route        GET       POST
//   dashboard    demo      admin   (kill switch)            demo gets the aggregate view model, nothing else
//   account      demo      demo: do=password (own password) other actions admin
//   logout       demo      demo
//   logs         operator  admin   (CSV export and share links are GETs: operator yes, demo no because demo cannot open Logs)
//   live         operator  admin   (the page and its JSON poll are GETs that only read the log; the quick actions POST to overrides)
//   identity     operator  admin   (quick block, mark seen)
//   overrides    operator  admin
//   rules        operator  admin   (the impact / test boxes are GET reads and stay open to the operator)
//   geo          operator  admin   (the lookup test is a GET read: operator yes; upload, compile, rollback: admin)
//   iplists      operator  admin   (the lookup test and the list export are GET reads: operator yes)
//   replay       operator  admin   (running a replay is a POST: admin)
//   models       operator  admin
//   settings     operator  admin
//   captcha_preview operator admin (the sample image of the CAPTCHA settings: a GET that renders what is typed, saves nothing)
//   jobs         operator  admin   (check again, mark seen, start a job)
//   audit        operator  admin
//   config_file  admin     admin   (raw overlay editor)
//   update       admin     admin
//   users        admin     admin
//
// Anything else: admin.

function gp_acl_roles() { return array('demo' => 1, 'operator' => 2, 'admin' => 3); }

function gp_acl_map() {
	return array(
		'dashboard'   => array('GET' => 'demo',     'POST' => 'admin'),
		'account'     => array('GET' => 'demo',     'POST' => array('*' => 'admin', 'password' => 'demo')),
		'logout'      => array('GET' => 'demo',     'POST' => 'demo'),
		'logs'        => array('GET' => 'operator', 'POST' => 'admin'),
		'live'        => array('GET' => 'operator', 'POST' => 'admin'),
		'identity'    => array('GET' => 'operator', 'POST' => 'admin'),
		'overrides'   => array('GET' => 'operator', 'POST' => 'admin'),
		'rules'       => array('GET' => 'operator', 'POST' => 'admin'),
		'geo'         => array('GET' => 'operator', 'POST' => 'admin'),
		'iplists'     => array('GET' => 'operator', 'POST' => 'admin'),
		'replay'      => array('GET' => 'operator', 'POST' => 'admin'),
		'models'      => array('GET' => 'operator', 'POST' => 'admin'),
		'settings'    => array('GET' => 'operator', 'POST' => 'admin'),
		'captcha_preview' => array('GET' => 'operator', 'POST' => 'admin'),
		'jobs'        => array('GET' => 'operator', 'POST' => 'admin'),
		'audit'       => array('GET' => 'operator', 'POST' => 'admin'),
		'config_file' => array('GET' => 'admin',    'POST' => 'admin'),
		'update'      => array('GET' => 'admin',    'POST' => 'admin'),
		'users'       => array('GET' => 'admin',    'POST' => 'admin'),
	);
}

// The POST action of a request: only the "account" page has actions with their own rule; for every other route all POST
// actions share one rule, so the action does not matter.
function gp_acl_action($route, array $post) {
	return $route === 'account' ? (is_string($post['do'] ?? null) ? $post['do'] : '') : '';
}

// The minimum role for (route, method, action). Unknown route, unknown method or unlisted action: admin.
function gp_acl_required($route, $method, $action = '') {
	$map = gp_acl_map();
	$method = strtoupper((string)$method) === 'POST' ? 'POST' : 'GET';
	if (!isset($map[$route]) || !isset($map[$route][$method])) { return 'admin'; }
	$rule = $map[$route][$method];
	if (is_string($rule)) { return $rule; }
	if ($action !== '' && isset($rule[$action])) { return $rule[$action]; }
	return isset($rule['*']) ? $rule['*'] : 'admin';
}

function gp_acl_allows($role, $route, $method, $action = '') {
	$ranks = gp_acl_roles();
	if (!isset($ranks[$role])) { return false; }                       // logged out, or an unknown role
	return $ranks[$role] >= $ranks[gp_acl_required($route, $method, $action)];
}

// Routes a role may open with GET (the navigation).
function gp_acl_nav($role) {
	$out = array();
	foreach (array_keys(gp_acl_map()) as $route) {
		if ($route !== 'logout' && gp_acl_allows($role, $route, 'GET')) { $out[] = $route; }
	}
	return $out;
}
