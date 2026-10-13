/**
 * Background jobs the current user has started
 */

import { SvelteMap } from 'svelte/reactivity';
import { listJobs, isJobActive, isJobTerminal, type Job, type JobUpdate } from '$lib/api/jobs';

function newestFirst(left: Job, right: Job): number {
	return new Date(right.createdAt).getTime() - new Date(left.createdAt).getTime();
}

class JobsStore {
	jobs = new SvelteMap<string, Job>();
	/** Called when a pending or running job ends, however it ends: it may have changed files. */
	onFinished?: () => void;
	isLoading = $state(false);
	error = $state<string | null>(null);
	/** Invalidates overlapping loads and responses from a previous session. */
	private loadVersion = 0;

	/** Pending and running jobs, newest first */
	active = $derived(Array.from(this.jobs.values()).filter(isJobActive).sort(newestFirst));

	async loadJobs(): Promise<void> {
		const version = ++this.loadVersion;
		const atRequest = new Map(this.jobs);
		this.isLoading = true;
		this.error = null;
		try {
			const response = await listJobs();
			if (version !== this.loadVersion) return;

			// Live updates and newly created jobs are newer than the HTTP snapshot.
			// Both writers replace Job objects, so identity tells us which changed.
			const liveUpdates = Array.from(this.jobs).filter(([id, job]) => job !== atRequest.get(id));
			const wasActive = this.active;
			this.jobs.clear();
			for (const job of response.jobs) this.jobs.set(job.id, job);
			for (const [id, job] of liveUpdates) this.jobs.set(id, job);
			// Only notify for transitions this reload discovers, not ones the socket already reported.
			if (wasActive.some((job) => !isJobActive(this.jobs.get(job.id) ?? job))) this.onFinished?.();
		} catch (err) {
			if (version === this.loadVersion) {
				this.error = err instanceof Error ? err.message : 'Failed to load jobs';
			}
		} finally {
			if (version === this.loadVersion) this.isLoading = false;
		}
	}

	upsertJob(job: Job): void {
		this.jobs.set(job.id, job);
	}

	updateFromWebSocket(update: JobUpdate): void {
		const existing = this.jobs.get(update.jobId);
		if (!existing) return;

		const job: Job = {
			...existing,
			state: update.state,
			progress: update.progress,
			error: update.error
		};
		if (isJobTerminal(job) && !job.completedAt) {
			job.completedAt = new Date().toISOString();
		}
		this.jobs.set(update.jobId, job);
		if (isJobActive(existing) && isJobTerminal(job)) this.onFinished?.();
	}

	reset(): void {
		this.loadVersion++;
		this.jobs.clear();
		this.isLoading = false;
		this.error = null;
	}
}

export const jobsStore = new JobsStore();
