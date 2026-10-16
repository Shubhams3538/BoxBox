<script lang="ts">
	/**
	 * Main page - redirects to browse
	 */
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';
	import { Spinner } from '#lib/components/ui/index.js';

	onMount(() => {
		goto('/browse', { replace: true });
	});
</script>

<div class="flex min-h-screen items-center justify-center bg-surface-primary">
	<div class="flex flex-col items-center gap-4 text-text-secondary">
		<Spinner />
		<p>Redirecting to file browser...</p>
	</div>
</div>
