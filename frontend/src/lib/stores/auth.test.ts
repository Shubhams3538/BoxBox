import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import { AuthRefreshEvent, clearTokens, getAccessToken, setAccessToken } from '$lib/api/client';
import { authStore } from './auth.svelte';
import { settingsStore } from './settings.svelte';

function installBrowser(origin: string) {
	const previousWindow = globalThis.window;
	const previousDocument = globalThis.document;
	const previousLocalStorage = globalThis.localStorage;
	const previousSettings = settingsStore.current;
	const values = new Map<string, string>();
	let resolvePreferenceWrite: (() => void) | undefined;
	const preferenceWrite = new Promise<void>((resolve) => {
		resolvePreferenceWrite = resolve;
	});
	const activeWindow = Object.assign(new EventTarget(), { location: { origin } });
	activeWindow.addEventListener(AuthRefreshEvent.eventName, (event) => {
		if (!(event instanceof AuthRefreshEvent)) return;
		if (event.result.kind === 'succeeded') {
			authStore.handleRefreshSuccess();
		} else {
			authStore.handleRefreshFailure(event.result.error, 'refresh');
		}
	});
	const activeStorage = {
		getItem(key: string) {
			return values.get(key) ?? null;
		},
		setItem(key: string, value: string) {
			values.set(key, value);
			resolvePreferenceWrite?.();
		},
		removeItem(key: string) {
			values.delete(key);
		}
	};
	Object.assign(globalThis, {
		window: activeWindow,
		localStorage: activeStorage,
		document: {
			querySelector() {
				return null;
			}
		}
	});
	return {
		previousWindow,
		previousDocument,
		previousLocalStorage,
		preferenceWrite,
		restoreSettings() {
			settingsStore.set(previousSettings);
		}
	};
}

describe('auth store persistence behavior', () => {
	test('transient logout failure stays signed in and a retry succeeds', async () => {
		let logoutCalls = 0;
		const server = Bun.serve({
			port: 0,
			fetch(request) {
				if (new URL(request.url).pathname === '/api/v1/auth/logout') {
					logoutCalls += 1;
					if (logoutCalls === 1) {
						return Response.json(
							{ error: 'Storage unavailable', code: 'INTERNAL_ERROR' },
							{ status: 500 }
						);
					}
					return Response.json({ message: 'Logged out' });
				}
				return Response.json({ error: 'Not found', code: 'NOT_FOUND' }, { status: 404 });
			}
		});
		const { previousWindow, previousDocument, previousLocalStorage } = installBrowser(
			server.url.origin
		);
		clearTokens();
		setAccessToken('active-token');
		authStore.isAuthenticated = true;
		authStore.isDevelopment = false;

		try {
			assert.equal(await authStore.logout(), false);
			assert.equal(authStore.isAuthenticated, true);
			assert.equal(getAccessToken(), 'active-token');
			assert.equal(authStore.authAlert?.kind, 'transient');

			assert.equal(await authStore.logout(), true);
			assert.equal(authStore.isAuthenticated, false);
			assert.equal(getAccessToken(), null);
			assert.equal(authStore.authAlert, null);
			assert.equal(logoutCalls, 2);
		} finally {
			if (authStore.isAuthenticated) await authStore.logout();
			authStore.clearAuthAlert();
			clearTokens();
			Object.assign(globalThis, {
				window: previousWindow,
				localStorage: previousLocalStorage,
				document: previousDocument
			});
			server.stop(true);
		}
	});

	test('terminal recovery logout signs out but keeps a visible warning', async () => {
		const server = Bun.serve({
			port: 0,
			fetch(request) {
				if (new URL(request.url).pathname === '/api/v1/auth/logout') {
					return Response.json(
						{ error: 'Sign in required', code: 'SESSION_RECOVERY_REQUIRED' },
						{ status: 401 }
					);
				}
				return Response.json({ error: 'Not found', code: 'NOT_FOUND' }, { status: 404 });
			}
		});
		const { previousWindow, previousDocument, previousLocalStorage } = installBrowser(
			server.url.origin
		);
		clearTokens();
		setAccessToken('active-token');
		authStore.isAuthenticated = true;
		authStore.isDevelopment = false;

		try {
			assert.equal(await authStore.logout(), true);
			assert.equal(authStore.isAuthenticated, false);
			assert.equal(getAccessToken(), null);
			assert.equal(authStore.authAlert?.kind, 'terminal');
		} finally {
			authStore.clearAuthAlert();
			clearTokens();
			Object.assign(globalThis, {
				window: previousWindow,
				localStorage: previousLocalStorage,
				document: previousDocument
			});
			server.stop(true);
		}
	});

	test('successful login clears the terminal recovery warning', async () => {
		let logoutCalls = 0;
		const server = Bun.serve({
			port: 0,
			fetch(request) {
				const { pathname } = new URL(request.url);
				if (pathname === '/api/v1/auth/logout') {
					logoutCalls += 1;
					if (logoutCalls === 1) {
						return Response.json(
							{ error: 'Sign in required', code: 'SESSION_RECOVERY_REQUIRED' },
							{ status: 401 }
						);
					}
					return Response.json({ message: 'Logged out' });
				}
				if (pathname === '/api/v1/auth/login') {
					return Response.json({
						accessToken: 'new-session-token',
						expiresAt: '2030-01-01T00:00:00Z'
					});
				}
				if (pathname === '/api/v1/settings/drive-names') {
					return Response.json({ mappings: [] });
				}
				return Response.json({ error: 'Not found', code: 'NOT_FOUND' }, { status: 404 });
			}
		});
		const {
			previousWindow,
			previousDocument,
			previousLocalStorage,
			preferenceWrite,
			restoreSettings
		} = installBrowser(server.url.origin);
		clearTokens();
		setAccessToken('active-token');
		authStore.isAuthenticated = true;
		authStore.isDevelopment = false;

		try {
			assert.equal(await authStore.logout(), true);
			assert.equal(authStore.authAlert?.kind, 'terminal');

			assert.equal(await authStore.login('alice', 'password'), true);
			assert.equal(authStore.isAuthenticated, true);
			assert.equal(authStore.authAlert, null);
			assert.equal(getAccessToken(), 'new-session-token');
			await preferenceWrite;
		} finally {
			if (authStore.isAuthenticated) {
				await preferenceWrite;
				await authStore.logout();
			}
			restoreSettings();
			authStore.clearAuthAlert();
			clearTokens();
			Object.assign(globalThis, {
				window: previousWindow,
				localStorage: previousLocalStorage,
				document: previousDocument
			});
			server.stop(true);
		}
	});

	test('allowlist login failure stays signed out and a retry succeeds', async () => {
		let loginCalls = 0;
		const server = Bun.serve({
			port: 0,
			fetch(request) {
				const { pathname } = new URL(request.url);
				if (pathname === '/api/v1/auth/login') {
					loginCalls += 1;
					if (loginCalls === 1) {
						return Response.json(
							{ error: 'Login denied by allowlist', code: 'INTERNAL_ERROR' },
							{ status: 500 }
						);
					}
					return Response.json({
						accessToken: 'allowed-session-token',
						expiresAt: '2030-01-01T00:00:00Z'
					});
				}
				if (pathname === '/api/v1/settings/drive-names') {
					return Response.json({ mappings: [] });
				}
				if (pathname === '/api/v1/auth/logout') {
					return Response.json({ message: 'Logged out' });
				}
				return Response.json({ error: 'Not found', code: 'NOT_FOUND' }, { status: 404 });
			}
		});
		const {
			previousWindow,
			previousDocument,
			previousLocalStorage,
			preferenceWrite,
			restoreSettings
		} = installBrowser(server.url.origin);
		clearTokens();
		authStore.isAuthenticated = false;
		authStore.isDevelopment = false;
		authStore.clearAuthAlert();

		try {
			assert.equal(await authStore.login('alice', 'password'), false);
			assert.equal(authStore.isAuthenticated, false);
			assert.equal(getAccessToken(), null);
			assert.ok(authStore.error);

			assert.equal(await authStore.login('alice', 'password'), true);
			assert.equal(authStore.isAuthenticated, true);
			assert.equal(getAccessToken(), 'allowed-session-token');
			assert.equal(authStore.error, null);
			assert.equal(loginCalls, 2);
			await preferenceWrite;
		} finally {
			if (authStore.isAuthenticated) {
				await preferenceWrite;
				await authStore.logout();
			}
			restoreSettings();
			authStore.clearAuthAlert();
			clearTokens();
			Object.assign(globalThis, {
				window: previousWindow,
				localStorage: previousLocalStorage,
				document: previousDocument
			});
			server.stop(true);
		}
	});

	test('anonymous startup 401 does not show an expired-session warning', async () => {
		const server = Bun.serve({
			port: 0,
			fetch(request) {
				if (new URL(request.url).pathname === '/api/v1/auth/refresh') {
					return Response.json({ error: 'Unauthorized', code: 'UNAUTHORIZED' }, { status: 401 });
				}
				return Response.json({ error: 'Not found', code: 'NOT_FOUND' }, { status: 404 });
			}
		});
		const { previousWindow, previousDocument, previousLocalStorage } = installBrowser(
			server.url.origin
		);
		clearTokens();
		setAccessToken('temporary-token');
		clearTokens();
		authStore.clearAuthAlert();
		authStore.isAuthenticated = false;
		authStore.isDevelopment = false;

		try {
			await authStore.initialize();
			assert.equal(authStore.isAuthenticated, false);
			assert.equal(getAccessToken(), null);
			assert.equal(authStore.authAlert, null);
		} finally {
			authStore.clearAuthAlert();
			clearTokens();
			Object.assign(globalThis, {
				window: previousWindow,
				localStorage: previousLocalStorage,
				document: previousDocument
			});
			server.stop(true);
		}
	});

	test('startup recovery-required 401 keeps a visible terminal warning', async () => {
		const server = Bun.serve({
			port: 0,
			fetch(request) {
				if (new URL(request.url).pathname === '/api/v1/auth/refresh') {
					return Response.json(
						{ error: 'Sign in required', code: 'SESSION_RECOVERY_REQUIRED' },
						{ status: 401 }
					);
				}
				return Response.json({ error: 'Not found', code: 'NOT_FOUND' }, { status: 404 });
			}
		});
		const { previousWindow, previousDocument, previousLocalStorage } = installBrowser(
			server.url.origin
		);
		clearTokens();
		setAccessToken('temporary-token');
		clearTokens();
		authStore.clearAuthAlert();
		authStore.isAuthenticated = false;
		authStore.isDevelopment = false;

		try {
			await authStore.initialize();
			assert.equal(authStore.isAuthenticated, false);
			assert.equal(getAccessToken(), null);
			assert.equal(authStore.authAlert?.kind, 'terminal');
		} finally {
			authStore.clearAuthAlert();
			clearTokens();
			Object.assign(globalThis, {
				window: previousWindow,
				localStorage: previousLocalStorage,
				document: previousDocument
			});
			server.stop(true);
		}
	});

	test('startup storage failure remains recoverable and reports a transient alert', async () => {
		let refreshCalls = 0;
		const server = Bun.serve({
			fetch(request) {
				const { pathname } = new URL(request.url);
				if (pathname === '/api/v1/auth/refresh') {
					refreshCalls += 1;
					if (refreshCalls === 1) {
						return Response.json(
							{ error: 'Storage unavailable', code: 'INTERNAL_ERROR' },
							{ status: 500 }
						);
					}
					return Response.json({
						accessToken: 'restored-token',
						expiresAt: '2030-01-01T00:00:00Z'
					});
				}
				if (pathname === '/api/v1/auth/logout') {
					return Response.json({ message: 'Logged out' });
				}
				if (pathname === '/api/v1/settings/drive-names') {
					return Response.json({ mappings: [] });
				}
				return Response.json({ error: 'Not found', code: 'NOT_FOUND' }, { status: 404 });
			},
			port: 0
		});
		const {
			previousWindow,
			previousDocument,
			previousLocalStorage,
			preferenceWrite,
			restoreSettings
		} = installBrowser(server.url.origin);
		clearTokens();
		setAccessToken('temporary-token');
		clearTokens();
		authStore.isAuthenticated = false;
		authStore.isDevelopment = false;

		try {
			await authStore.initialize();
			assert.equal(authStore.isAuthenticated, false);
			assert.equal(getAccessToken(), null);
			assert.equal(authStore.authAlert?.kind, 'transient');

			await authStore.initialize();
			assert.equal(refreshCalls, 2);
			assert.equal(authStore.isAuthenticated, true);
			assert.equal(getAccessToken(), 'restored-token');
			await preferenceWrite;
			assert.equal(authStore.authAlert, null);
		} finally {
			if (authStore.isAuthenticated) {
				await preferenceWrite;
				await authStore.logout();
			}
			restoreSettings();
			authStore.clearAuthAlert();
			clearTokens();
			Object.assign(globalThis, {
				window: previousWindow,
				localStorage: previousLocalStorage,
				document: previousDocument
			});
			server.stop(true);
		}
	});
});
