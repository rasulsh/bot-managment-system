/* Tailwind configuration for the admin panel.
 *
 * Used only at build time, on a machine with npm. The panel serves the built
 * app.css and never needs Node, npm or any network access at runtime.
 *
 *   npx tailwindcss@3 -c panel/assets/tailwind.config.js \
 *     -i panel/assets/app.src.css -o panel/assets/app.css --minify
 */
module.exports = {
	content: [
		'./panel/**/*.php',
		'./panel/assets/app.src.css',
	],
	darkMode: 'media',
	theme: {
		extend: {
			fontFamily: {
				sans: ['Vazirmatn', 'system-ui', '-apple-system', 'Segoe UI', 'Tahoma', 'sans-serif'],
			},
		},
	},
	corePlugins: {
		// The panel is RTL and uses logical properties throughout, so the
		// directional float/clear utilities are dead weight.
		float: false,
		clear: false,
	},
	plugins: [],
};
