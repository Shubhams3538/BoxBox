<script lang="ts">
	/**
	 * FileGrid component - icon/thumbnail grid for browsing folders
	 */

	import type { FileInfo } from '#lib/api/files.js';
	import { getThumbnailUrl } from '#lib/api/files.js';
	import { formatFileSize, formatFileDate } from '#lib/utils/format.js';
	import { getFileTypeDescription, getFileIcon, getPreviewType } from '#lib/utils/fileTypes.js';
	import { SvelteSet } from 'svelte/reactivity';
	import { untrack } from 'svelte';
	import { Spinner } from '#lib/components/ui/index.js';
	import LoadError from '#lib/components/LoadError.svelte';
	import { FolderOpen } from 'lucide-svelte';
	import { CONFIG } from '#lib/config.js';
	import { createDelayedFlag } from '#lib/utils/delayedFlag.svelte.js';
	import { createFixedRowWindow } from '#lib/utils/fixedRowWindow.svelte.js';

	let {
		items = [],
		viewKey,
		emptyMessage = 'This folder is empty',
		selectedPaths = new SvelteSet<string>(),
		isLoading = false,
		compactMode = false,
		cutPaths = new SvelteSet<string>(),
		favoritePaths = new SvelteSet<string>(),
		canPaste = false,
		canCreate = false,
		showFileExtensions = true,
		previewOnSingleClick = false,
		onItemClick,
		onFolderHover,
		onSelectionChange,
		onContextMenuAction
	}: {
		items?: FileInfo[];
		viewKey: string;
		emptyMessage?: string;
		selectedPaths?: Set<string>;
		isLoading?: boolean;
		compactMode?: boolean;
		cutPaths?: Set<string>;
		favoritePaths?: Set<string>;
		canPaste?: boolean;
		canCreate?: boolean;
		showFileExtensions?: boolean;
		previewOnSingleClick?: boolean;
		onItemClick?: (item: FileInfo) => void;
		/** Path of the folder under the pointer, or null once it leaves */
		onFolderHover?: (path: string | null) => void;
		onSelectionChange?: (paths: Set<string>) => void;
		onContextMenuAction?: (action: string, items: FileInfo[]) => void;
	} = $props();

	const showSpinner = createDelayedFlag(() => isLoading, CONFIG.ui.spinnerDelayMs);
	let gridElement = $state<HTMLDivElement | null>(null);
	let activeItemPath = $state<string | null>(null);
	const activeItemIndex = $derived.by(() =>
		activeItemPath === null ? -1 : items.findIndex((item) => item.path === activeItemPath)
	);
	const activeItem = $derived(activeItemIndex < 0 ? null : (items[activeItemIndex] ?? null));
	const rowWindow = createFixedRowWindow({
		items: () => items,
		itemKey: (item) => item.path,
		viewKey: () => viewKey,
		isReady: () => !isLoading,
		rowHeight: () => (compactMode ? 124 : 148),
		itemOffset: () => (compactMode ? 8 : 12),
		contentEndPadding: () => (compactMode ? 8 : 12),
		columnsForWidth: (width) => {
			const tileWidth = compactMode ? 96 : 112;
			const gap = compactMode ? 8 : 12;
			const padding = compactMode ? 16 : 24;
			return Math.max(1, Math.floor((width - padding + gap) / (tileWidth + gap)));
		}
	});
	const attachRowWindow = rowWindow.attach;
	$effect(() => {
		const path = activeItemPath;
		if (path === null || items.some((item) => item.path === path)) return;
		untrack(() => {
			activeItemPath = null;
		});
	});

	let contextMenu = $state<{ x: number; y: number; items: FileInfo[] } | null>(null);
	let thumbnailErrors = new SvelteSet<string>();

	function handleItemClick(item: FileInfo, event: MouseEvent) {
		activeItemPath = item.path;
		gridElement?.focus({ preventScroll: true });
		if (event.ctrlKey || event.metaKey) {
			const newSelection = new SvelteSet<string>(selectedPaths);
			if (newSelection.has(item.path)) {
				newSelection.delete(item.path);
			} else {
				newSelection.add(item.path);
			}
			onSelectionChange?.(newSelection);
		} else if (event.shiftKey && selectedPaths.size > 0) {
			const newSelection = new SvelteSet<string>(selectedPaths);
			newSelection.add(item.path);
			onSelectionChange?.(newSelection);
		} else {
			const newSelection = new SvelteSet<string>([item.path]);
			onSelectionChange?.(newSelection);
		}

		if (item.isDir && !event.ctrlKey && !event.metaKey && !event.shiftKey) {
			onItemClick?.(item);
			return;
		}

		if (
			previewOnSingleClick &&
			!item.isDir &&
			!event.ctrlKey &&
			!event.metaKey &&
			!event.shiftKey
		) {
			onItemClick?.(item);
		}
	}

	function handleOpen(item: FileInfo) {
		if (previewOnSingleClick && !item.isDir) return;
		onItemClick?.(item);
	}

	function handleGridFocus() {
		if (items.length === 0 || activeItemPath !== null) return;
		const firstVisible = Math.min(
			items.length - 1,
			rowWindow.firstVisibleRow * rowWindow.columnCount
		);
		activeItemPath = items[firstVisible]?.path ?? null;
	}

	function handleViewportScroll() {
		rowWindow.onScroll();
	}

	function getKeyboardTargetItems(): FileInfo[] {
		if (selectedPaths.size > 0) {
			return items.filter((item) => selectedPaths.has(item.path));
		}
		return activeItem ? [activeItem] : [];
	}

	function handleKeyboardContextMenu() {
		if (!gridElement) return;
		const targetItems = getKeyboardTargetItems();
		if (targetItems.length === 0) return;

		const activeRow = Math.floor(activeItemIndex / rowWindow.columnCount);
		const activeIsVisible =
			activeItemIndex >= 0 &&
			activeRow >= rowWindow.firstVisibleRow &&
			activeRow < rowWindow.lastVisibleRow;
		const activeCell = activeIsVisible
			? gridElement.querySelector<HTMLElement>(`#file-grid-cell-${activeItemIndex}`)
			: null;
		const bounds =
			activeCell?.getBoundingClientRect() ??
			gridElement.parentElement?.getBoundingClientRect() ??
			gridElement.getBoundingClientRect();
		contextMenu = {
			x: Math.min(Math.max(0, bounds.left), Math.max(0, window.innerWidth - 1)),
			y: Math.min(Math.max(0, bounds.top), Math.max(0, window.innerHeight - 1)),
			items: targetItems
		};
	}

	function handleGridKeyDown(event: KeyboardEvent) {
		if (event.key === 'ContextMenu' || (event.key === 'F10' && event.shiftKey)) {
			event.preventDefault();
			handleKeyboardContextMenu();
			return;
		}
		if (items.length === 0) return;

		const columns = rowWindow.columnCount;
		const currentIndex = Math.min(
			items.length - 1,
			Math.max(0, activeItemIndex >= 0 ? activeItemIndex : rowWindow.firstVisibleRow * columns)
		);
		const rowStart = Math.floor(currentIndex / columns) * columns;
		const rowEnd = Math.min(items.length - 1, rowStart + columns - 1);
		let nextIndex: number;

		switch (event.key) {
			case 'ArrowLeft':
				nextIndex = Math.max(0, currentIndex - 1);
				break;
			case 'ArrowRight':
				nextIndex = Math.min(items.length - 1, currentIndex + 1);
				break;
			case 'ArrowUp':
				nextIndex = Math.max(0, currentIndex - columns);
				break;
			case 'ArrowDown':
				nextIndex = Math.min(items.length - 1, currentIndex + columns);
				break;
			case 'PageUp':
				nextIndex = Math.max(0, currentIndex - rowWindow.visibleRowCount * columns);
				break;
			case 'PageDown':
				nextIndex = Math.min(items.length - 1, currentIndex + rowWindow.visibleRowCount * columns);
				break;
			case 'Home':
				nextIndex = event.ctrlKey || event.metaKey ? 0 : rowStart;
				break;
			case 'End':
				nextIndex = event.ctrlKey || event.metaKey ? items.length - 1 : rowEnd;
				break;
			default: {
				const item = items[currentIndex];
				if (!item) return;
				if (event.key === 'Enter' || event.key === ' ') {
					event.preventDefault();
					onItemClick?.(item);
					return;
				}

				let action: 'delete' | 'rename' | 'copy' | 'cut' | 'paste' | null = null;
				if (event.key === 'Delete') action = 'delete';
				else if (event.key === 'F2') action = 'rename';
				else if ((event.key === 'c' || event.key === 'C') && (event.ctrlKey || event.metaKey)) {
					action = 'copy';
				} else if ((event.key === 'x' || event.key === 'X') && (event.ctrlKey || event.metaKey)) {
					action = 'cut';
				} else if ((event.key === 'v' || event.key === 'V') && (event.ctrlKey || event.metaKey)) {
					action = 'paste';
				}
				if (!action) return;

				const targetItems = getKeyboardTargetItems();
				if (targetItems.length === 0) return;
				event.preventDefault();
				onContextMenuAction?.(action, targetItems);
				return;
			}
		}

		event.preventDefault();
		activeItemPath = items[nextIndex]?.path ?? null;
		rowWindow.scrollToItem(nextIndex);
	}

	function handleContextMenu(item: FileInfo, event: MouseEvent) {
		activeItemPath = item.path;
		gridElement?.focus({ preventScroll: true });
		event.preventDefault();

		if (!selectedPaths.has(item.path)) {
			const newSelection = new SvelteSet<string>([item.path]);
			onSelectionChange?.(newSelection);
		}

		const selectedItems = items.filter((i) => selectedPaths.has(i.path) || i.path === item.path);

		contextMenu = {
			x: event.clientX,
			y: event.clientY,
			items: selectedItems.length > 0 ? selectedItems : [item]
		};
	}

	function handleBackgroundContextMenu(event: MouseEvent) {
		const target = event.target instanceof HTMLElement ? event.target : null;
		if (target?.closest('[data-file-item="true"]')) return;

		event.preventDefault();
		onSelectionChange?.(new SvelteSet<string>());
		contextMenu = {
			x: event.clientX,
			y: event.clientY,
			items: []
		};
	}

	function handleContextMenuClose() {
		contextMenu = null;
	}

	function handleContextMenuSelect(action: string) {
		if (contextMenu && onContextMenuAction) {
			onContextMenuAction(action, contextMenu.items);
		}
		contextMenu = null;
	}

	function handleThumbnailError(path: string) {
		thumbnailErrors.add(path);
	}

	function isSelected(path: string): boolean {
		return selectedPaths.has(path);
	}

	function isCut(path: string): boolean {
		return cutPaths.has(path);
	}

	function getDisplayName(item: FileInfo): string {
		if (showFileExtensions || item.isDir) return item.name;

		const dotIndex = item.name.lastIndexOf('.');
		return dotIndex > 0 ? item.name.slice(0, dotIndex) : item.name;
	}

	const tileClass =
		'group flex min-w-0 cursor-default flex-col rounded border border-transparent bg-transparent p-2 text-left outline-none transition-colors duration-100 hover:bg-surface-secondary focus:border-border-focus focus:bg-surface-secondary';
	const selectedClass = 'border-accent/70 bg-selection hover:bg-selection-hover';
	const thumbnailClass =
		'flex shrink-0 items-center justify-center overflow-hidden rounded border border-border-primary bg-surface-primary';
</script>

<!-- svelte-ignore a11y_no_static_element_interactions -->
<div
	class="relative h-full w-full overflow-auto bg-surface-primary [overflow-anchor:none]"
	use:attachRowWindow
	onscroll={handleViewportScroll}
	oncontextmenu={handleBackgroundContextMenu}
>
	{#if showSpinner.value}
		<div class="absolute inset-0 z-10 flex items-center justify-center bg-surface-primary/80">
			<Spinner />
		</div>
	{/if}

	{#if items.length === 0 && !isLoading}
		<div class="flex h-full flex-col items-center justify-center gap-2 text-text-muted">
			<FolderOpen size={32} class="opacity-50" />
			<span class="text-[13px]">{emptyMessage}</span>
		</div>
	{:else}
		<div
			bind:this={gridElement}
			class={compactMode ? 'flex flex-col p-2' : 'flex flex-col p-3'}
			role="grid"
			tabindex="0"
			aria-busy={isLoading}
			aria-multiselectable="true"
			aria-rowcount={rowWindow.rowCount}
			aria-colcount={rowWindow.columnCount}
			aria-activedescendant={activeItemIndex >= 0 &&
			activeItemIndex >= rowWindow.itemStart &&
			activeItemIndex < rowWindow.itemEnd &&
			activeItemIndex < items.length
				? `file-grid-cell-${activeItemIndex}`
				: undefined}
			onfocusin={handleGridFocus}
			onkeydown={handleGridKeyDown}
		>
			{#if rowWindow.beforeSize > 0}
				<div
					aria-hidden="true"
					role="presentation"
					class="shrink-0"
					style={`height: ${rowWindow.beforeSize}px`}
				></div>
			{/if}
			{#each rowWindow.visibleRows as rowIndex (rowIndex)}
				{@const firstItemIndex = rowIndex * rowWindow.columnCount}
				{@const rowItems = items.slice(
					firstItemIndex,
					Math.min(items.length, firstItemIndex + rowWindow.columnCount)
				)}
				<div
					class={compactMode
						? 'grid h-[124px] grid-flow-row gap-x-2'
						: 'grid h-[148px] grid-flow-row gap-x-3'}
					style={`grid-template-columns: repeat(${rowWindow.columnCount}, ${compactMode ? 96 : 112}px)`}
					role="row"
					aria-rowindex={rowIndex + 1}
				>
					{#each rowItems as item, columnOffset (item.path)}
						{@const itemIndex = firstItemIndex + columnOffset}
						{@const IconComponent = getFileIcon(item.name, item.isDir)}
						{@const displayName = getDisplayName(item)}
						{@const typeDescription = item.isDir ? 'Folder' : getFileTypeDescription(item.name)}
						{@const sizeDescription = item.isDir ? '' : formatFileSize(item.size)}
						{@const modifiedDescription = formatFileDate(item.modTime)}
						{@const showThumbnail =
							!item.isDir &&
							getPreviewType(item.name) === 'image' &&
							!thumbnailErrors.has(item.path)}
						{@const detailText = item.isDir ? 'Folder' : sizeDescription}
						<button
							type="button"
							id={`file-grid-cell-${itemIndex}`}
							class="{tileClass} {activeItemIndex === itemIndex
								? 'bg-surface-secondary'
								: ''} {isSelected(item.path) ? selectedClass : ''} {isCut(item.path)
								? 'opacity-50'
								: ''}"
							style={`height: ${compactMode ? 116 : 136}px`}
							role="gridcell"
							tabindex="-1"
							aria-colindex={columnOffset + 1}
							aria-selected={isSelected(item.path)}
							title={`${item.name}\n${typeDescription}${sizeDescription ? ` - ${sizeDescription}` : ''}\nModified ${modifiedDescription}`}
							onclick={(e) => handleItemClick(item, e)}
							onpointerenter={() => item.isDir && onFolderHover?.(item.path)}
							onpointerleave={() => onFolderHover?.(null)}
							ondblclick={() => handleOpen(item)}
							oncontextmenu={(e) => handleContextMenu(item, e)}
							data-file-item="true"
						>
							<div class="{thumbnailClass} {compactMode ? 'h-11' : 'h-16'}">
								{#if showThumbnail}
									<img
										src={getThumbnailUrl(
											item.path,
											compactMode ? 192 : 224,
											compactMode ? 96 : 144
										)}
										alt=""
										loading="lazy"
										class="h-full w-full object-cover"
										onerror={() => handleThumbnailError(item.path)}
									/>
								{:else}
									<span
										class="flex h-full w-full items-center justify-center {item.isDir
											? 'text-folder'
											: 'text-text-secondary'}"
									>
										<IconComponent size={compactMode ? 24 : 30} strokeWidth={1.7} />
									</span>
								{/if}
							</div>

							<div class="mt-1.5 min-w-0 overflow-hidden">
								<div class="file-grid-name text-center text-[13px] leading-4 text-text-primary">
									<span class={item.isDir ? 'text-folder' : ''}>{displayName}</span>
								</div>
								<div
									class="mt-0.5 truncate text-center text-[11px] leading-3.5 text-text-muted"
									title={typeDescription}
								>
									{detailText}
								</div>
							</div>
						</button>
					{/each}
				</div>
			{/each}
			{#if rowWindow.afterSize > 0}
				<div
					aria-hidden="true"
					role="presentation"
					class="shrink-0"
					style={`height: ${rowWindow.afterSize}px`}
				></div>
			{/if}
		</div>
	{/if}
</div>

{#if contextMenu}
	{#await import('./FileContextMenu.svelte') then { default: FileContextMenu }}
		<FileContextMenu
			items={contextMenu.items}
			{canPaste}
			{favoritePaths}
			{canCreate}
			x={contextMenu.x}
			y={contextMenu.y}
			onSelect={handleContextMenuSelect}
			onClose={handleContextMenuClose}
		/>
	{:catch}
		<LoadError label="file context menu" onClose={handleContextMenuClose} />
	{/await}
{/if}

<style>
	.file-grid-name {
		display: -webkit-box;
		overflow: hidden;
		-webkit-box-orient: vertical;
		-webkit-line-clamp: 2;
		line-clamp: 2;
		word-break: break-word;
	}
</style>
