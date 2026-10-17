import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Browser, Page } from 'playwright';
import { repo } from './common';

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function chunkPath(source: string): string {
	const manifest: unknown = JSON.parse(
		readFileSync(join(repo, 'frontend/.svelte-kit/output/client/.vite/manifest.json'), 'utf8')
	);
	assert.ok(isRecord(manifest));
	const chunk = manifest[source];
	assert.ok(isRecord(chunk) && typeof chunk.file === 'string', `Missing chunk for ${source}`);
	return chunk.file;
}

type LoadCase = {
	label: string;
	source: string;
	path: string;
	ready: (page: Page) => Promise<void>;
};

const cases: LoadCase[] = [
	{
		label: 'grid view',
		source: 'src/lib/components/FileGrid.svelte',
		path: '/browse?path=perf&view=grid',
		ready: (page) => page.locator('[data-file-item="true"]').first().waitFor()
	},
	{
		label: 'wallpaper settings',
		source: 'src/lib/components/settings/wallpaper/WallpaperSettings.svelte',
		path: '/settings',
		ready: (page) => page.getByRole('button', { name: 'Choose Wallpaper', exact: true }).waitFor()
	},
	{
		label: 'shared links',
		source: 'src/lib/components/settings/ShareLinksSettings.svelte',
		path: '/settings',
		ready: (page) => page.getByText('No shared links.', { exact: true }).waitFor()
	}
];

export async function verifyLazyLoadErrors(
	browser: Browser,
	url: string,
	credentials: { username: string; password: string }
) {
	for (const test of cases) {
		const context = await browser.newContext();
		try {
			const login = await context.request.post(`${url}/api/v1/auth/login`, { data: credentials });
			assert.equal(login.ok(), true);
			const blockedPath = `**/${chunkPath(test.source)}`;
			let blockedRequests = 0;
			await context.route(blockedPath, (route) => {
				blockedRequests++;
				return route.abort('failed');
			});
			const page = await context.newPage();
			const errors: string[] = [];
			page.on('pageerror', (error) => errors.push(error.message));
			await page.goto(`${url}${test.path}`);
			const alert = page
				.getByRole('alert')
				.filter({ hasText: `Could not load the ${test.label}.` });
			await alert.waitFor({ timeout: 5000 });
			assert.ok(blockedRequests > 0, `${test.label}: the component request must be blocked`);
			await context.unroute(blockedPath);
			await alert.getByRole('button', { name: 'Reload', exact: true }).click();
			await test.ready(page);
			assert.equal(page.url(), `${url}${test.path}`, 'reload preserves the current location');
			assert.equal(await alert.count(), 0, 'successful recovery removes the error');
			assert.deepEqual(errors, [], 'component failures are handled without uncaught errors');
		} finally {
			await context.close();
		}
	}
	console.log(
		'PASS: failed grid, wallpaper and shared-link chunks show errors and recover on reload'
	);
}
