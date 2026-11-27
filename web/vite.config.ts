import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				// Force runes mode for the project, except for libraries. Can be removed in svelte 6.
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},

			// Static single-page app, embedded in the Go binary (see server/internal/web).
			// The Go server serves 200.html for every app route.
			adapter: adapter({ fallback: '200.html' }),

			// Emitted as a <meta> CSP with hashes for SvelteKit's inline bootstrap
			// script. The Go server adds frame-ancestors/base-uri/object-src as a header.
			csp: {
				mode: 'hash',
				directives: {
					'default-src': ['self'],
					'script-src': ['self'],
					'style-src': ['self'],
					'img-src': ['self', 'data:', 'blob:'],
					'connect-src': ['self'],
					'font-src': ['self'],
					'form-action': ['self']
				}
			}
		})
	],
	server: {
		// `npm run dev` proxies API calls to a local `kumokeep serve`.
		proxy: {
			'/api': 'http://127.0.0.1:8080'
		}
	}
});
