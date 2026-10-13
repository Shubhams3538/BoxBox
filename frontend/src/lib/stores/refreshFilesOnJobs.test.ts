import assert from 'node:assert/strict';
import { afterEach, beforeEach, describe, test } from 'node:test';
import { QueryClient } from '@tanstack/svelte-query';
import type { Job, JobState } from '$lib/api/jobs';
import { fileQueryKeys } from './files';
import { jobsStore } from './jobs.svelte';
import { refreshFilesWhenJobsFinish } from './refreshFilesOnJobs';

function job(state: JobState): Job {
	return {
		id: 'job-1',
		type: 'delete',
		state,
		progress: 0,
		sourcePath: 'media/old',
		createdAt: '2026-01-01T00:00:00Z'
	};
}

const listKey = fileQueryKeys.list('media', { pageSize: 50, sortBy: 'name', sortDir: 'asc' });
const statsKey = [...fileQueryKeys.roots(), 'stats'];

const realFetch = globalThis.fetch;
const realWindow = globalThis.window;

/** The server's job list, as `loadJobs` will see it. */
function serveJobs(...jobs: Job[]) {
	Object.assign(globalThis, {
		// The API client builds its URLs from the page origin.
		window: { location: { origin: 'http://localhost' } },
		fetch: async () => Response.json({ jobs })
	});
}

/** Hold a captured HTTP snapshot until after live updates have arrived. */
function holdJobs(...jobs: Job[]) {
	let release!: (response: Response) => void;
	const response = new Promise<Response>((resolve) => (release = resolve));
	let started!: () => void;
	const requested = new Promise<void>((resolve) => (started = resolve));
	serveJobs();
	Object.assign(globalThis, {
		fetch: async () => {
			started();
			return response;
		}
	});
	return { requested, respond: () => release(Response.json({ jobs })) };
}

beforeEach(() => serveJobs());

afterEach(() => {
	Object.assign(globalThis, { fetch: realFetch, window: realWindow });
	jobsStore.onFinished = undefined;
	jobsStore.reset();
});

describe('jobsStore.onFinished', () => {
	test('fires once when a running job ends, not for progress', () => {
		let calls = 0;
		jobsStore.onFinished = () => calls++;
		jobsStore.upsertJob(job('running'));

		jobsStore.updateFromWebSocket({ jobId: 'job-1', state: 'running', progress: 40 });
		assert.equal(calls, 0);

		jobsStore.updateFromWebSocket({ jobId: 'job-1', state: 'completed', progress: 100 });
		jobsStore.updateFromWebSocket({ jobId: 'job-1', state: 'completed', progress: 100 });
		assert.equal(calls, 1);
	});

	test('fires for failed and cancelled jobs, which may have changed files', () => {
		let calls = 0;
		jobsStore.onFinished = () => calls++;
		for (const state of ['failed', 'cancelled'] as const) {
			jobsStore.upsertJob(job('pending'));
			jobsStore.updateFromWebSocket({ jobId: 'job-1', state, progress: 10 });
		}
		assert.equal(calls, 2);
	});

	test('ignores updates for unknown jobs', () => {
		let calls = 0;
		jobsStore.onFinished = () => calls++;
		jobsStore.updateFromWebSocket({ jobId: 'other', state: 'completed', progress: 100 });
		assert.equal(calls, 0);
	});
});

describe('jobsStore.loadJobs', () => {
	for (const state of ['completed', 'failed', 'cancelled'] as const) {
		test(`preserves a live ${state} update over an older running snapshot`, async () => {
			let calls = 0;
			jobsStore.onFinished = () => calls++;
			jobsStore.upsertJob(job('running'));
			const held = holdJobs(job('running'));
			const loading = jobsStore.loadJobs();
			await held.requested;

			jobsStore.updateFromWebSocket({ jobId: 'job-1', state, progress: 100 });
			const completed = jobsStore.jobs.get('job-1');
			held.respond();
			await loading;

			assert.equal(jobsStore.jobs.get('job-1'), completed);
			assert.equal(jobsStore.active.length, 0);
			assert.equal(calls, 1, 'completion must not be reported twice');
			assert.equal(jobsStore.isLoading, false);
		});
	}

	test('preserves live progress and jobs created while the list request waits', async () => {
		jobsStore.upsertJob(job('running'));
		const held = holdJobs(job('running'), { ...job('completed'), id: 'server-job' });
		const loading = jobsStore.loadJobs();
		await held.requested;
		jobsStore.updateFromWebSocket({ jobId: 'job-1', state: 'running', progress: 75 });
		jobsStore.upsertJob({ ...job('pending'), id: 'new-job' });
		held.respond();
		await loading;

		assert.equal(jobsStore.jobs.get('job-1')?.progress, 75);
		assert.equal(jobsStore.jobs.get('new-job')?.state, 'pending');
		assert.equal(jobsStore.jobs.get('server-job')?.state, 'completed');
	});

	test('preserves an updated job even when the HTTP snapshot omits it', async () => {
		jobsStore.upsertJob(job('running'));
		const held = holdJobs();
		const loading = jobsStore.loadJobs();
		await held.requested;
		jobsStore.updateFromWebSocket({ jobId: 'job-1', state: 'completed', progress: 100 });
		held.respond();
		await loading;

		assert.equal(jobsStore.jobs.get('job-1')?.state, 'completed');
	});

	test('a superseded request cannot overwrite the newer list', async () => {
		const held = holdJobs(job('running'));
		const loading = jobsStore.loadJobs();
		await held.requested;
		serveJobs(job('completed'));
		await jobsStore.loadJobs();
		held.respond();
		await loading;

		assert.equal(jobsStore.jobs.get('job-1')?.state, 'completed');
	});

	test('reset invalidates a pending request without disturbing a new load', async () => {
		const old = holdJobs(job('running'));
		const oldLoading = jobsStore.loadJobs();
		await old.requested;
		jobsStore.reset();
		const next = holdJobs({ ...job('pending'), id: 'new-session-job' });
		const nextLoading = jobsStore.loadJobs();
		await next.requested;
		old.respond();
		await oldLoading;
		assert.equal(jobsStore.jobs.size, 0);
		assert.equal(jobsStore.isLoading, true, 'old request must not finish the new load');
		next.respond();
		await nextLoading;
		assert.deepEqual([...jobsStore.jobs.keys()], ['new-session-job']);
		assert.equal(jobsStore.isLoading, false);
	});

	test('fires when a job we saw running has ended on the server, as after a reconnect', async () => {
		let calls = 0;
		jobsStore.onFinished = () => calls++;
		jobsStore.upsertJob(job('running'));

		serveJobs(job('completed'));
		await jobsStore.loadJobs();

		assert.equal(calls, 1);
		assert.equal(jobsStore.jobs.get('job-1')?.state, 'completed');
	});

	test('stays quiet when the job is still running, was already finished, or is new', async () => {
		let calls = 0;
		jobsStore.onFinished = () => calls++;
		jobsStore.upsertJob(job('running'));
		jobsStore.upsertJob({ ...job('completed'), id: 'job-2' });

		serveJobs(
			job('running'),
			{ ...job('completed'), id: 'job-2' },
			{ ...job('completed'), id: 'job-3' }
		);
		await jobsStore.loadJobs();

		assert.equal(calls, 0);
	});

	test('the first load, with nothing known yet, fires nothing', async () => {
		let calls = 0;
		jobsStore.onFinished = () => calls++;
		serveJobs(job('completed'));
		await jobsStore.loadJobs();
		assert.equal(calls, 0);
	});
});

describe('refreshFilesWhenJobsFinish', () => {
	test('marks cached listings and drive stats stale when a job ends, not before', () => {
		const queryClient = new QueryClient();
		queryClient.setQueryData(listKey, { pages: [], pageParams: [] });
		queryClient.setQueryData(statsKey, { drives: [] });
		refreshFilesWhenJobsFinish(queryClient);
		jobsStore.upsertJob(job('running'));

		jobsStore.updateFromWebSocket({ jobId: 'job-1', state: 'running', progress: 50 });
		assert.equal(queryClient.getQueryState(listKey)?.isInvalidated, false);

		jobsStore.updateFromWebSocket({ jobId: 'job-1', state: 'completed', progress: 100 });
		assert.equal(queryClient.getQueryState(listKey)?.isInvalidated, true);
		assert.equal(queryClient.getQueryState(statsKey)?.isInvalidated, true);
	});
});
