import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { chromium, type Page, type Route } from 'playwright';
import { type Subprocess } from 'bun';
import { createFixture } from '../../scripts/auth-smoke/fixtures';
import {
	buildBinary,
	reservePort,
	startServer,
	killAndWait
} from '../../scripts/auth-smoke/process';
import { clearCredentials } from '../../scripts/auth-smoke/credentials';

type Client = Pick<
	typeof import('../src/lib/api/client'),
	'refreshSession' | 'getAccessToken' | 'logoutSession'
>;
const repo = resolve(import.meta.dir, '../..');
const root = mkdtempSync(join(tmpdir(), 'boxbox-session-browser-'));
const processes: Subprocess[] = [];
const browser = await chromium.launch({ headless: true });
const moduleUrl = '/auth-test-client.js';

async function refresh(page: Page) {
	return page.evaluate(async (url) => {
		const client: Client = await import(url);
		await client.refreshSession();
		return Boolean(client.getAccessToken());
	}, moduleUrl);
}

try {
	const port = await reservePort();
	const fixture = await createFixture(root, port);
	const binary = await buildBinary(root, join(repo, 'backend'), processes);
	await startServer(
		binary,
		fixture.configPath,
		join(repo, 'backend'),
		port,
		processes,
		'browser auth'
	);
	const bundle = await Bun.build({
		entrypoints: [join(repo, 'frontend/src/lib/api/client.ts')],
		target: 'browser'
	});
	assert.ok(bundle.success, 'API client bundle must compile');
	const source = await bundle.outputs[0].text();
	const context = await browser.newContext();
	await context.route('**' + moduleUrl, (route) =>
		route.fulfill({ contentType: 'text/javascript', body: source })
	);
	const first = await context.newPage();
	const second = await context.newPage();
	await Promise.all([
		first.goto(fixture.baseUrl + '/health'),
		second.goto(fixture.baseUrl + '/health')
	]);
	const login = await context.request.post(fixture.baseUrl + '/api/v1/auth/login', {
		data: { username: 'auth-smoke-user', password: fixture.password }
	});
	assert.equal(login.status(), 200);
	assert.equal(await refresh(first), true);
	assert.equal(await refresh(second), true);

	// Both requests leave with the same cookie; deliver the stale rejection after the new cookie.
	const waiting: Route[] = [];
	const statuses: number[] = [];
	await context.route('**/api/v1/auth/refresh', async (route) => {
		waiting.push(route);
		if (waiting.length !== 2) return;
		const replies = await Promise.all(
			waiting.map(async (held) => ({ held, response: await held.fetch() }))
		);
		replies.sort((a, b) => a.response.status() - b.response.status());
		await context.unroute('**/api/v1/auth/refresh');
		for (const { held, response } of replies) {
			statuses.push(response.status());
			if (response.status() === 409) assert.equal(response.headers()['set-cookie'], undefined);
			await held.fulfill({ response });
		}
	});
	assert.deepEqual(await Promise.all([refresh(first), refresh(second)]), [true, true]);
	assert.deepEqual(statuses, [200, 409]);
	assert.ok((await context.cookies()).some((cookie) => cookie.name === 'boxbox_refresh'));
	assert.equal(await refresh(first), true);
	assert.equal(await refresh(second), true);
	await first.evaluate(async (url) => {
		const client: Client = await import(url);
		await client.logoutSession();
	}, moduleUrl);
	await assert.rejects(refresh(second));
	assert.equal(
		await second.evaluate(async (url) => {
			const client: Client = await import(url);
			return Boolean(client.getAccessToken());
		}, moduleUrl),
		false
	);
	console.log(
		'PASS: overlapping refreshes preserve the shared cookie and both tabs; logout still ends the session.'
	);
} finally {
	await browser.close();
	await Promise.all(processes.map(killAndWait));
	clearCredentials();
	rmSync(root, { recursive: true, force: true });
}
