/* Tailwind configuration for the admin panel.
 *
 * Used only at build time, on a machine with npm. The panel serves the built
 * app.css and never needs Node, npm or any network access at runtime.
 *
 *   npx tailwindcss@3 -c panel/assets/tailwind.config.js \
 *     -i panel/assets/app.src.css -o panel/assets/app.css --minify
 */
module.exports = {
	/* Only the PHP. app.src.css used to be listed here so its component
	 * selectors survived purging - but the scanner also reads every argument
	 * of every @apply in that file as a used class, and emitted ~180
	 * standalone utility rules the markup never references. The components now
	 * live outside @layer components (see app.src.css), so they are never
	 * purged and this file no longer has to be scanned.
	 *
	 * The glob stays panel-wide: data.php generates the inline SVG charts and
	 * carries class names of its own, so narrowing it to views/ would silently
	 * drop .gp-chart, .gp-legend and friends. */
	content: [
		'./panel/**/*.php',
	],
	/* No dark: variants are used. Both themes come from the CSS variables in
	 * app.src.css, so a component is written once and works in either theme. */
	darkMode: 'media',
	theme: {
		extend: {
			/* Semantic colours, each backed by a CSS variable ("R G B"). */
			colors: (function () {
				var v = function (name) { return 'rgb(var(--gp-' + name + ') / <alpha-value>)'; };
				var out = {};
				['page', 'surface', 'sunken', 'line', 'field', 'ink', 'muted', 'subtle',
				 'accent', 'brand', 'danger'].forEach(function (n) { out[n] = v(n); });
				out['brand-hover'] = v('brand-hover');
				out['on-brand'] = v('on-brand');
				out['danger-hover'] = v('danger-hover');
				out['on-danger'] = v('on-danger');
				['ok', 'warn', 'bad', 'info'].forEach(function (k) {
					out[k + '-bg'] = v(k + '-bg');
					out[k + '-fg'] = v(k + '-fg');
					out[k + '-line'] = v(k + '-line');
				});
				['ok', 'info', 'warn', 'bad', 'accent', 'neutral'].forEach(function (k) {
					out['chart-' + k] = v('chart-' + k);
				});
				return out;
			})(),
			fontFamily: {
				sans: ['system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'Vazirmatn', 'Tahoma', 'sans-serif'],
			},
		},
	},
	corePlugins: {
		// The panel uses logical properties throughout, so the directional
		// float/clear utilities are dead weight.
		float: false,
		clear: false,
		// Nothing in the panel transforms, filters or animates an element -
		// the one animation is a hand-written @keyframes, and the one
		// transition is on width. Each enabled plugin also contributes its
		// --tw-* defaults to the two blocks every element and every ::backdrop
		// carry, so switching them off is worth more than the utilities alone.
		translate: false, rotate: false, skew: false, scale: false,
		transformOrigin: false, animation: false,
		blur: false, brightness: false, contrast: false, dropShadow: false,
		grayscale: false, hueRotate: false, invert: false, saturate: false,
		sepia: false,
		// backdrop-blur is used by the sticky top bar; the rest are not.
		backdropBrightness: false, backdropContrast: false,
		backdropGrayscale: false, backdropHueRotate: false,
		backdropInvert: false, backdropOpacity: false, backdropSaturate: false,
		backdropSepia: false,
		// border-collapse IS used by .gp-table; the other table utilities and
		// every list, object-fit, scroll-snap and blend utility are not.
		tableLayout: false, borderSpacing: false, captionSide: false,
		divideWidth: false, divideColor: false, divideStyle: false,
		divideOpacity: false,
		listStyleType: false, listStyleImage: false, listStylePosition: false,
		objectFit: false, objectPosition: false, aspectRatio: false,
		scrollBehavior: false, scrollMargin: false, scrollPadding: false,
		scrollSnapAlign: false, scrollSnapStop: false, scrollSnapType: false,
		mixBlendMode: false, backgroundBlendMode: false, isolation: false,
		columns: false, breakAfter: false, breakBefore: false,
		breakInside: false, boxDecorationBreak: false,
		placeholderColor: false, placeholderOpacity: false, caretColor: false,
		touchAction: false, userSelect: false, willChange: false,
		resize: false, hyphens: false,
		backgroundAttachment: false, backgroundOrigin: false,
		// tabular-nums is set as plain CSS in the base layer, not a utility.
		fontVariantNumeric: false,
	},
	plugins: [],
};
