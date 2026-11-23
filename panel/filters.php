<?php
if (!defined('GP_BOOT')) { http_response_code(404); exit; }

// Include / exclude filters, shared by every list in the panel.
//
// One field = one value list and one operator:
//   choice  is / is not, several values (comma list, OR inside the field)
//   ident   is / is not, several values; an address also matches a CIDR value
//   text    contains / does not contain (one value, case-insensitive)
//   num     a plain whole number (ranges such as sc_min / sc_max keep no operator)
// Fields are AND-ed. Query string: the field keeps its name (`act=403,429`) and
// an operator adds `<key>_op=not`; absent = include, so every older link works.
//
// Everything here is pure: the parser reads an array, the matcher reads a value,
// nothing touches a file or the request.

// The token that means "this field is absent or empty on the row". Only meaningful on
// optional fields (see gp_filter_test).
define('GP_FILTER_NONE', '(none)');
define('GP_FILTER_MAX_VALUES', 8);
define('GP_FILTER_MAX_LEN', 200);

// Parse $get against $spec (key => type, or key => array(type, 'ci' => true)).
// Returns key => array('v' => string[], 'not' => bool) for the operator types and
// key => int for 'num'. Empty fields are dropped.
function gp_filter_parse(array $get, array $spec) {
	$out = array();
	foreach ($spec as $key => $def) {
		$type = is_array($def) ? $def[0] : $def;
		$ci = is_array($def) && !empty($def['ci']);
		$raw = (isset($get[$key]) && is_scalar($get[$key])) ? trim((string)$get[$key]) : '';
		if ($raw === '') { continue; }
		if ($type === 'num') { $out[$key] = (int)$raw; continue; }
		if ($type === 'text') {
			$vals = array(substr($raw, 0, GP_FILTER_MAX_LEN));
		} else {
			$vals = array();
			foreach (explode(',', substr($raw, 0, 1000)) as $p) {
				$p = trim($p);
				if ($p === '') { continue; }
				$p = substr($p, 0, GP_FILTER_MAX_LEN);
				if (strtolower($p) === GP_FILTER_NONE) { $p = GP_FILTER_NONE; }
				elseif ($ci) { $p = strtoupper($p); }
				if (!in_array($p, $vals, true)) { $vals[] = $p; }
				if (count($vals) >= GP_FILTER_MAX_VALUES) { break; }
			}
		}
		if (!$vals) { continue; }
		$out[$key] = array('v' => $vals, 'not' => (isset($get[$key . '_op']) && $get[$key . '_op'] === 'not'));
	}
	return $out;
}

// A filter value in either shape: the parsed array above, or a bare scalar (the
// form older callers pass, e.g. array('ip' => '1.2.3.4')) which means "is".
// Returns array('v' => ..., 'not' => bool) or null when there is nothing to test.
function gp_filter_def($f) {
	if (is_array($f) && isset($f['v']) && is_array($f['v'])) { return $f['v'] ? $f : null; }
	if (is_scalar($f) && (string)$f !== '') { return array('v' => array((string)$f), 'not' => false); }
	return null;
}

// Whether an address lies in an IPv4 or IPv6 CIDR (a bare address = itself).
function gp_filter_in_cidr($ip, $cidr) {
	$ip = (string)$ip;
	$cidr = (string)$cidr;
	$slash = strpos($cidr, '/');
	$net = $slash === false ? $cidr : substr($cidr, 0, $slash);
	$a = @inet_pton($ip);
	$b = @inet_pton($net);
	if ($a === false || $b === false || strlen($a) !== strlen($b)) { return false; }
	$max = strlen($a) * 8;
	if ($slash === false) { return $a === $b; }
	$tail = substr($cidr, $slash + 1);
	if ($tail === '' || !ctype_digit($tail) || (int)$tail > $max) { return false; }
	$bits = (int)$tail;
	$full = intdiv($bits, 8);
	if (substr($a, 0, $full) !== substr($b, 0, $full)) { return false; }
	$rest = $bits % 8;
	if ($rest === 0) { return true; }
	$mask = (0xFF << (8 - $rest)) & 0xFF;
	return ((ord($a[$full]) & $mask) === (ord($b[$full]) & $mask));
}

// Test one value (or a list of values, e.g. the reasons of a row) against a filter
// value. $type: choice | ident | text. Include = any value matches; not = none does.
//
// Two kinds of field, by what an empty value MEANS:
//  * $optional = true: empty means NOT KNOWN (country and ASN when no lookup ran or
//    nothing was found, the outcome status when it was not captured, the bot verdict
//    when no bot was claimed). Like the rule engine's unknown country, a row WITHOUT a
//    value matches neither "is" nor "is not".
//  * $optional = false: empty is a KNOWN value (no reasons, no device id = a token-less
//    client, no override, a rule with no country condition). It is simply not equal to
//    any real value, so "is not X" includes it, as usual.
// On both kinds the value (none) means "empty": "is (none)" lists those rows, "is not
// (none)" lists the rows that have a value, and (none) can sit in a comma list next to
// real values.
function gp_filter_test($type, $f, $actual, $ci = false, $optional = false) {
	$def = gp_filter_def($f);
	if ($def === null) { return true; }
	$actual = is_array($actual) ? array_map('strval', array_values($actual)) : array((string)$actual);
	$want_none = in_array(GP_FILTER_NONE, $def['v'], true);
	if ($optional) {
		$actual = array_values(array_filter($actual, function ($a) { return $a !== ''; }));
		if (!$actual) { return $want_none && empty($def['not']); }
	} elseif (!$actual) {
		$actual = array('');                       // known-empty: a value that equals nothing real
	}
	$hit = false;
	foreach ($def['v'] as $want) {
		if ($want === GP_FILTER_NONE && $type !== 'text') {
			if (!$optional) { foreach ($actual as $a) { if ($a === '') { $hit = true; break 2; } } }
			continue;
		}
		foreach ($actual as $a) {
			if ($type === 'text') { $m = ($want === '' || stripos($a, $want) !== false); }
			elseif ($type === 'ident' && $a !== '' && strpbrk($want, '/') !== false) { $m = gp_filter_in_cidr($a, $want); }
			else { $m = $ci ? (strcasecmp($a, $want) === 0) : ($a === $want); }
			if ($m) { $hit = true; break 2; }
		}
	}
	return !empty($def['not']) ? !$hit : $hit;
}

// The query-string pairs of a parsed (or mixed) filter set: values joined by commas,
// plus <key>_op=not. Scalars pass through, so a filter carrying the date or a score
// range survives a page change. Pure.
function gp_filter_qs(array $filter) {
	$q = array();
	foreach ($filter as $key => $f) {
		if (is_array($f) && isset($f['v'])) {
			$q[$key] = implode(',', $f['v']);
			if (!empty($f['not'])) { $q[$key . '_op'] = 'not'; }
		} elseif (is_scalar($f)) {
			$q[$key] = $f;
		}
	}
	return $q;
}

// Removable chips for the active operator filters. $labels: key => label.
// $url: callable(array $query_without_this_field) => href. Returns a list of
// array(key, label, not, text, href). Pure apart from $url.
function gp_filter_chips(array $filter, array $labels, array $kinds, callable $url) {
	$out = array();
	foreach ($filter as $key => $f) {
		if (!isset($labels[$key]) || !is_array($f) || !isset($f['v'])) { continue; }
		$rest = $filter;
		unset($rest[$key]);
		$out[] = array('key' => $key, 'label' => $labels[$key], 'not' => !empty($f['not']),
			'kind' => isset($kinds[$key]) ? $kinds[$key] : 'choice', 'text' => implode(', ', $f['v']), 'href' => $url(gp_filter_qs($rest)));
	}
	return $out;
}

// The operator select next to a field. $kind 'is' (is / is not) or 'has' (contains /
// does not contain). The select has the field's own name plus "_op".
function gp_filter_op_select($key, $f, $kind) {
	$not = is_array($f) && !empty($f['not']);
	$yes = gp_t($kind === 'has' ? 'flt_contains' : 'flt_is');
	$no = gp_t($kind === 'has' ? 'flt_not_contains' : 'flt_is_not');
	return '<select class="gp-input gp-op" name="' . gp_e($key) . '_op" aria-label="' . gp_e(gp_t('flt_operator')) . '">'
		. '<option value="is">' . gp_e($yes) . '</option>'
		. '<option value="not"' . ($not ? ' selected' : '') . '>' . gp_e($no) . '</option></select>';
}

// The text to show in a field's input: its values, comma separated.
function gp_filter_text($f) {
	return (is_array($f) && isset($f['v'])) ? implode(',', $f['v']) : (is_scalar($f) ? (string)$f : '');
}

// The chip row above a table (empty when no operator filter is active).
function gp_filter_chips_html(array $chips) {
	if (!$chips) { return ''; }
	$h = '<ul class="gp-chips" aria-label="' . gp_e(gp_t('flt_active')) . '">';
	foreach ($chips as $c) {
		$op = gp_t($c['kind'] === 'text' ? ($c['not'] ? 'flt_not_contains' : 'flt_contains') : ($c['not'] ? 'flt_is_not' : 'flt_is'));
		$h .= '<li class="gp-chip' . ($c['not'] ? ' gp-chip-not' : '') . '"><span class="gp-chip-k">' . gp_e($c['label']) . '</span> '
			. '<span class="gp-chip-op">' . gp_e($op) . '</span> <span class="gp-chip-v gp-ltr">' . gp_e($c['text']) . '</span>'
			. '<a class="gp-chip-x" href="' . gp_e($c['href']) . '" aria-label="' . gp_e(gp_t('flt_remove') . ': ' . $c['label']) . '">&times;</a></li>';
	}
	return $h . '</ul>';
}

// A choice field with a pick list: the plain text input (comma list, free text allowed) plus, when JavaScript runs, a
// button that opens a checkbox list of the usual values. The input is what the form submits and what works without
// JavaScript; the checkboxes carry no name. Replaces the browser datalist, which is not a multi-select and looks different in every
// browser. $options: values offered (include GP_FILTER_NONE where the field offers "(none)"). $attr: extra input attributes
// (already escaped), e.g. a placeholder.
// Whether a pick list is value => label (true) or a plain list of values (false).
function gp_is_labelled(array $options) { return $options && array_keys($options) !== range(0, count($options) - 1); }

function gp_multi_input($id, $name, $value, array $options, $attr = '') {
	$h = '<div class="gp-ms" data-gp-ms>'
		. '<input class="gp-input gp-ltr" type="text" id="' . gp_e($id) . '" name="' . gp_e($name) . '" value="' . gp_e($value) . '" spellcheck="false" autocomplete="off"' . ($attr !== '' ? ' ' . $attr : '') . '>';
	if ($options) {
		$h .= '<button type="button" class="gp-ms-toggle" data-gp-ms-toggle hidden aria-haspopup="true" aria-expanded="false" aria-controls="' . gp_e($id) . '-ms" aria-label="' . gp_e(gp_t('flt_pick')) . '" title="' . gp_e(gp_t('flt_pick')) . '">&#9662;</button>'
			. '<div class="gp-ms-panel" id="' . gp_e($id) . '-ms" role="group" aria-label="' . gp_e(gp_t('flt_pick')) . '" data-gp-ms-panel hidden>';
		// A list of values, or value => label: the box submits the VALUE; the label is what the operator reads (reason codes).
		$labelled = gp_is_labelled($options);
		foreach ($options as $k => $o) {
			$v = $labelled ? (string)$k : (string)$o;
			$h .= '<label class="gp-ms-opt"><input type="checkbox" value="' . gp_e($v) . '"> <span class="gp-ltr">'
				. ($labelled ? gp_e($o) . ' <code class="gp-reason-code">' . gp_e($v) . '</code>' : gp_e($o)) . '</span></label>';
		}
		$h .= '</div>';
	}
	return $h . '</div>';
}

// A complete filter form for a list page: one row per field (operator + value), a
// Filter / Reset pair, and the removable chips. $fields: key => array(label key,
// 'is' | 'has', datalist values, tooltip key). $hidden: extra GET parameters to keep
// (the route, an identity). Used by Overrides, Audit and Identity.
function gp_filter_form_html($route, array $fields, array $filter, array $hidden = array()) {
	$chips = gp_filter_chips($filter, array_map(function ($d) { return gp_t($d[0]); }, $fields),
		array_map(function ($d) { return $d[1] === 'has' ? 'text' : 'choice'; }, $fields),
		function ($q) use ($route, $hidden) { return 'index.php?' . http_build_query(array_merge(array('r' => $route), $hidden, $q)); });
	$h = '<form method="get" action="index.php" class="gp-card gp-form"><input type="hidden" name="r" value="' . gp_e($route) . '">';
	foreach ($hidden as $k => $v) { $h .= '<input type="hidden" name="' . gp_e($k) . '" value="' . gp_e($v) . '">'; }
	$h .= '<div class="gp-filters">';
	foreach ($fields as $key => $d) {
		$v = isset($filter[$key]) ? $filter[$key] : null;
		$h .= '<div class="gp-field"><label class="gp-label" for="f-' . gp_e($route . '-' . $key) . '">' . gp_e(gp_t($d[0])) . (isset($d[3]) ? gp_tip($d[3]) : '') . '</label>'
			. '<div class="gp-fgroup">' . gp_filter_op_select($key, $v, $d[1])
			. gp_multi_input('f-' . $route . '-' . $key, $key, gp_filter_text($v), $d[2]);
		$h .= '</div></div>';
	}
	$h .= '</div><div class="gp-row-head"><button class="gp-btn gp-btn-primary" type="submit">' . gp_e(gp_t('filter')) . '</button>'
		. '<a class="gp-btn gp-btn-ghost" href="index.php?' . gp_e(http_build_query(array_merge(array('r' => $route), $hidden))) . '">' . gp_e(gp_t('reset')) . '</a></div>'
		. gp_filter_chips_html($chips) . '</form>';
	return $h;
}
