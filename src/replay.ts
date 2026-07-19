// Anti-replay sliding window for media SFrame frames (RFC 9605 §9.3, issue #10).
//
// Tracks recently seen CTR values per (epoch, peerIndex). The media-frame CTR
// is a bigint (from parseHeader). A bounded-set + FIFO queue is used — the same
// approach as src/chat/replay.ts SlidingReplayWindow — which is correct for both
// monotonic and non-monotonic CTR strategies. The media CTR is monotonic per
// sender-per-epoch (worker-frame.ts:88-89), so an HWM variant would be more
// efficient, but the bounded set is the safe, simple, correct default.
//
// Lifecycle (enforced by decodeFrame / drainPreEpochQueue):
//   1. check(ctr)  — BEFORE AEAD. Returns false if the CTR is in the recent set
//                    (replay). The caller emits decrypt_failure{reason:'replay'}
//                    + queue_drop{reason:'replay'} and throws ReplayError.
//   2. accept(ctr) — AFTER a successful AEAD decrypt. Records the CTR as seen.
//                    A replayed frame that failed check() is never accepted.
//   3. clear()     — on epoch rotation (wipeEpoch deletes the whole window).
//
// Window size 0 disables protection (check always returns true, accept is a
// no-op) — debug/tests only.

/**
 * Sliding replay window for media frames — tracks a bounded set of recently
 * seen bigint CTR values. `check()` returns false if the CTR has been seen
 * (replay). `accept()` records a CTR. `clear()` resets all state.
 *
 * NOT thread-safe; synchronous (no async state).
 */
export class MediaReplayWindow {
	/** Ordered record of CTR values (insertion order = eviction order). */
	private readonly seen: Set<bigint>;
	/** FIFO queue for eviction when window is full. */
	private readonly queue: bigint[];
	private readonly windowSize: number;

	constructor(windowSize: number) {
		this.windowSize = windowSize;
		this.seen = new Set();
		this.queue = [];
	}

	/**
	 * Check if a CTR value would be accepted.
	 * Returns `true` if the CTR has NOT been seen (accept ok).
	 * Returns `false` if the CTR IS in the recent set (replay detected).
	 * Window size 0 always returns `true`.
	 */
	check(ctr: bigint): boolean {
		if (this.windowSize === 0) return true;
		return !this.seen.has(ctr);
	}

	/**
	 * Record a CTR as seen. Evicts the oldest entry if the window is full.
	 * Must be called after a successful AEAD decrypt (after check passed).
	 * Window size 0 is a no-op.
	 */
	accept(ctr: bigint): void {
		if (this.windowSize === 0) return;
		if (this.seen.has(ctr)) return;
		// Evict oldest if at capacity
		if (this.queue.length >= this.windowSize) {
			const oldest = this.queue.shift();
			if (oldest !== undefined) this.seen.delete(oldest);
		}
		this.seen.add(ctr);
		this.queue.push(ctr);
	}

	/**
	 * Reset all replay state (called on epoch rotation / window-size change).
	 */
	clear(): void {
		this.seen.clear();
		this.queue.length = 0;
	}
}
