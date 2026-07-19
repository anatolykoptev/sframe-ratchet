// Sliding-window replay protection for chat-mode SFrame frames.
// Tracks recently seen CTR values per (roomId, senderUid) pair.
//
// Under random-64 strategy: only bounded-set semantics (no HWM check),
// because random CTRs are non-monotonic. See design §B.4.
//
// Window size 0 disables protection (debug/tests only).

/**
 * Sliding replay window — tracks a bounded set of recently seen bigint CTR
 * values. `check()` returns false if the CTR has been seen (replay).
 * `accept()` records a CTR. `clear()` resets all state.
 *
 * NOT thread-safe; synchronous (no async state).
 */
export class SlidingReplayWindow {
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
	 * Must be called after a successful unseal (after check passed).
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
	 * Reset all replay state (called on key rotation).
	 */
	clear(): void {
		this.seen.clear();
		this.queue.length = 0;
	}
}
