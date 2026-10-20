import { queryOptions } from '@tanstack/svelte-query';
import { earlyStart, type EarlyStartSource } from '#lib/api/earlyStart.js';
import { directoryUrl, listDirectory, type ListOptions } from '#lib/api/files.js';
import { fileQueryKeys } from '#lib/stores/files.js';

/** One definition for the folder query, shared by the open folder and hover prefetch. */
export function directoryQueryOptions(
	path: string,
	options: ListOptions,
	source: EarlyStartSource = earlyStart
) {
	return queryOptions({
		queryKey: fileQueryKeys.list(path, options),
		queryFn: async ({ signal }) => {
			// The shell may already have fetched this listing while the app downloaded.
			const early = await source.takeDirectory(directoryUrl(path, options));
			return early ?? listDirectory(path, options, signal);
		},
		// The cached listing shows at once, but the server always confirms it.
		staleTime: 0
	});
}
