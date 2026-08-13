// Shared construction logic for chat-mode providers (createChatProvider +
// createMlsChatProvider). Extracted to avoid duplication of CTR allocator
// validation, durable replay guard construction, and replay window management.

import { RandomCtrAllocator, MonotonicIdbCtrAllocator, type CtrAllocator } from './ctr-allocator.ts';
import { SlidingReplayWindow } from './replay.ts';
import { DurableReplayGuard } from './durable-replay.ts';
import { getOrCreateNested } from '../internal/collections.ts';

/** Maximum number of rooms tracked in replay windows (prevents unbounded growth). */
export const MAX_REPLAY_ROOMS = 1024;

/** Common options for replay/CTR construction (shared subset of both providers). */
export interface ReplayCtrOptions {
	ctrStrategy?: 'random-64' | 'monotonic-idb';
	ctrKeyspace?: string;
	replayWindow?: number;
	durableReplay?: boolean;
	durableReplayNamespace?: string;
	durableReplayWindow?: number;
}

export interface ReplayCtrState {
	allocator: CtrAllocator;
	replayWindow: number;
	durable: DurableReplayGuard | null;
	/** Per-(roomId, senderUid) replay windows. */
	replayWindows: Map<string, Map<string, SlidingReplayWindow>>;
}

/**
 * Validate options and construct the CTR allocator + durable replay guard.
 * Shared by createChatProvider and createMlsChatProvider.
 */
export function createReplayCtrState(
	opts: ReplayCtrOptions,
	providerName: string,
): ReplayCtrState {
	const replayWindow = opts.replayWindow ?? 1024;
	const ctrStrategy = opts.ctrStrategy ?? 'random-64';

	if (ctrStrategy === 'monotonic-idb' && !opts.ctrKeyspace) {
		throw new Error(`${providerName}: ctrKeyspace is required when ctrStrategy is monotonic-idb`);
	}

	if (opts.durableReplay === true && !opts.durableReplayNamespace) {
		throw new Error(`${providerName}: durableReplayNamespace is required when durableReplay is true`);
	}
	const durableReplayEnabled = opts.durableReplay !== false && !!opts.durableReplayNamespace;
	const durableReplayWindow = opts.durableReplayWindow ?? replayWindow;
	if (durableReplayEnabled && durableReplayWindow > replayWindow) {
		throw new Error(
			`${providerName}: durableReplayWindow (${durableReplayWindow}) must be <= replayWindow (${replayWindow})`,
		);
	}

	const allocator: CtrAllocator =
		ctrStrategy === 'monotonic-idb'
			? new MonotonicIdbCtrAllocator(opts.ctrKeyspace!, { allowSingleTab: true })
			: new RandomCtrAllocator();

	const durable = durableReplayEnabled
		? new DurableReplayGuard({
				namespace: opts.durableReplayNamespace!,
				window: durableReplayWindow,
			})
		: null;

	const replayWindows = new Map<string, Map<string, SlidingReplayWindow>>();

	return { allocator, replayWindow, durable, replayWindows };
}

/** Evict oldest replay rooms when the cap is exceeded. */
export function evictOldReplayRooms(replayWindows: Map<string, Map<string, SlidingReplayWindow>>): void {
	while (replayWindows.size > MAX_REPLAY_ROOMS) {
		const oldest = replayWindows.keys().next().value;
		if (oldest === undefined) break;
		replayWindows.delete(oldest);
	}
}

/** Get or create a replay window for (roomId, senderUid). */
export function getReplayWindow(
	replayWindows: Map<string, Map<string, SlidingReplayWindow>>,
	roomId: string,
	senderUid: string,
	windowSize: number,
): SlidingReplayWindow {
	const isNew = !replayWindows.has(roomId);
	const w = getOrCreateNested(
		replayWindows, roomId, senderUid,
		() => new SlidingReplayWindow(windowSize),
	);
	if (isNew) evictOldReplayRooms(replayWindows);
	return w;
}

/** Composite key for the durable guard — chat uses (roomId, senderUid). */
export function durableKey(roomId: string, senderUid: string): string {
	return `${roomId}|${senderUid}`;
}
