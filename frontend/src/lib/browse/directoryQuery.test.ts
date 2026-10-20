import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { QueryClient, QueryObserver } from '@tanstack/svelte-query';
import { CONFIG } from '#lib/config.js';
import type { EarlyStartSource } from '#lib/api/earlyStart.js';
import type { FileList } from '#lib/api/files.js';
import { directoryQueryOptions } from './directoryQuery';

const realFetch = globalThis.fetch;
const realWindow = globalThis.window;
const options = { sortBy: 'name', sortDir: 'asc' } as const;
let listRequests = 0;
let names: string[] = [];

beforeEach(() => {
	listRequests = 0;
	names = ['a.txt'];
	Object.assign(globalThis, {
		// The API client builds its URLs from the page origin.
		window: { location: { origin: 'http://localhost' } },
		fetch: async () => {
			listRequests++;
			const items = names.map((name) => ({ name, path: `media/${name}`, isDir: false }));
			return Response.json({ path: 'media', items });
		}
	});
});

afterEach(() => Object.assign(globalThis, { fetch: realFetch, window: realWindow }));

const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

describe('open folder freshness', () => {
	test('a hover prefetch fills the cache once, however often the pointer returns', async () => {
		const queryClient = new QueryClient();
		const prefetch = () =>
			queryClient.prefetchQuery({
				...directoryQueryOptions('media', options),
				staleTime: CONFIG.query.prefetchStaleTimeMs
			});
		await prefetch();
		await prefetch();
		assert.equal(listRequests, 1);
	});

	test('opening a prefetched folder shows its listing at once, then confirms it with the server', async () => {
		const queryClient = new QueryClient();
		await queryClient.prefetchQuery({
			...directoryQueryOptions('media', options),
			staleTime: CONFIG.query.prefetchStaleTimeMs
		});
		names = ['a.txt', 'added-outside.txt']; // a change made after the prefetch

		const observer = new QueryObserver(queryClient, directoryQueryOptions('media', options));
		const unsubscribe = observer.subscribe(() => {});
		const atOnce = observer.getCurrentResult().data?.items.map((item) => item.name);
		assert.deepEqual(atOnce, ['a.txt'], 'the cached listing must not wait for the network');

		await settle();
		assert.equal(listRequests, 2, 'opening the folder must always ask the server');
		const confirmed = observer.getCurrentResult().data?.items.map((item) => item.name);
		assert.deepEqual(confirmed, ['a.txt', 'added-outside.txt']);
		unsubscribe();
	});
});

describe('early listing from the shell', () => {
	const listing = (name: string): FileList => ({
		path: 'media',
		items: [
			{
				name,
				path: `media/${name}`,
				isDir: false,
				size: 1,
				modTime: '',
				permissions: '',
				mimeType: ''
			}
		]
	});
	const source = (early: FileList | null): EarlyStartSource => ({
		takeSession: async () => null,
		takeDirectory: async () => early
	});

	beforeEach(() => {
		Object.assign(globalThis, {
			fetch: async () => {
				listRequests++;
				return Response.json(listing(`network-${listRequests}.txt`));
			}
		});
	});

	test('uses the matching early listing without making its own request', async () => {
		const queryClient = new QueryClient();
		const data = await queryClient.fetchQuery(
			directoryQueryOptions('media', options, source(listing('early.txt')))
		);
		assert.equal(data.items[0].name, 'early.txt');
		assert.equal(listRequests, 0);
	});

	test('falls back to the network when the shell has nothing usable', async () => {
		const queryClient = new QueryClient();
		const data = await queryClient.fetchQuery(
			directoryQueryOptions('media', options, source(null))
		);
		assert.equal(data.items[0].name, 'network-1.txt');
		assert.equal(listRequests, 1);
	});
});
