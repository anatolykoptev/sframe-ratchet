// Durable, cross-reload anti-replay for the SFrame chat provider and media
// frame path.
//
// ## Why (CWE-294 replay)
// `SlidingReplayWindow` (`src/internal/replay.ts`) is an in-memory bounded
// `Set` wiped on page reload. `MonotonicIdbCtrAllocator` persists the SENDER's
// CTR allocator — NOT the RECEIVER's replay defense. So after a reload a
// malicious / compromised app-server (or SFU) can re-serve an OLD authentic
// sealed frame under a fresh msg_id and it verifies (the ciphertext is
// genuinely authentic, just old), rendering a stale message as new.
//
// ## What
// This guard persists the set of already-accepted per-(namespace, key) CTRs
// to IndexedDB so the replay defense survives a reload. The CTR is read from
// the RFC 9605 §4.3 header via the library's own `parseHeader` — the header
// is the AEAD AAD, so the CTR is authenticated (an attacker cannot alter it
// without failing AEAD). The guard mirrors `SlidingReplayWindow`'s bounded-set
// semantics exactly, just durable.
//
// ## Availability
// Feature-detected. Durable persistence requires BOTH IndexedDB AND the Web
// Locks API: when either is unavailable (SSR / Node without a polyfill /
// private-mode quirks / legacy Safari <15.4 with no Web Locks) the guard
// degrades to a no-op with a one-time warning, and `SlidingReplayWindow`
// remains the only (session-scoped) defense — the guard never throws at
// construct and never breaks such a runtime. A `window` of 0 disables the
// durable window (mirrors `SlidingReplayWindow`'s `replayWindow: 0` debug
// switch).
//
// ## Concurrency
// Same-realm writes are serialized by a promise chain; CROSS-tab writes are
// serialized by the Web Locks API (the same `navigator.locks` pattern
// `MonotonicIdbCtrAllocator` uses), and each persist is a read-merge-write so
// a second tab's accepted CTRs are merged, not clobbered. When the Web Locks
// API is absent the read-merge-write cannot be serialized cross-tab (two tabs
// could interleave and silently drop a CTR), so durable persistence is gated
// OFF entirely (via `available`) rather than run an unlocked RMW — an honest
// "no durable claim without Web Locks" posture. The reachable persist path
// therefore ALWAYS holds the lock.
//
// ## Opt-in (architecture-council nit #5)
// Default is OFF. Callers must explicitly set `durableReplay: true` AND supply
// a `namespace` to isolate independent deployments sharing the same origin.
// Default-on would silently open an IDB database and risk false-rejections
// between unrelated apps that both omit the namespace.
//
// ## Check ordering (architecture-council nit #1)
// The CALLER runs the in-memory `SlidingReplayWindow.check()` FIRST (cheap,
// synchronous) and only calls `DurableReplayGuard.check()` if the in-memory
// check passes. This avoids the expensive IDB read on the common replay path.

const KEY_PREFIX = 'sframe-replay';
const DEFAULT_WINDOW = 1024;
const IDB_VERSION = 1;
const STORE_NAME = 'replay';

/**
 * Upper bound on the number of per-(namespace, key) `MemWindow` entries
 * retained in the in-memory `mem` cache. One entry is created per distinct
 * (namespace, key) on first hydrate and never released otherwise, so a
 * long-lived always-open consumer that sees many distinct keys would grow
 * `mem` without bound (slow memory leak). When the cache exceeds this cap the
 * OLDEST evictable entry (insertion-order FIFO) is dropped; the DURABLE
 * IndexedDB store is the source of truth, so an evicted pair simply
 * re-hydrates from IDB on its next use — correctness is preserved (no false
 * replay-accept/reject), only an in-memory read is forgone.
 */
const REPLAY_MEM_CACHE_CAP = 256;

/** Persisted shape for one (namespace, key) replay window. `seen` is oldest-first. */
interface PersistedWindow {
	v: 1;
	/** Accepted CTRs as decimal strings, oldest-first, bounded to the window size. */
	seen: string[];
}

/** In-memory mirror of a persisted window: a Set for O(1) checks + an order queue for eviction. */
interface MemWindow {
	set: Set<string>;
	order: string[];
}

/** Detect a usable IndexedDB without throwing under SSR / Node. */
function idbAvailable(): boolean {
	try {
		return typeof indexedDB !== 'undefined' && indexedDB !== null;
	} catch {
		return false;
	}
}

/**
 * Detect a USABLE Web Locks API (cross-tab mutual exclusion), mirroring
 * `MonotonicIdbCtrAllocator`'s availability check. Probes
 * `navigator.locks.request` as a function — a partial polyfill exposing
 * `navigator.locks` without `.request` must NOT pass (persistMerged calls
 * `.request` directly with no fallback).
 */
function locksAvailable(): boolean {
	try {
		return typeof navigator !== 'undefined' && typeof navigator.locks?.request === 'function';
	} catch {
		return false;
	}
}

/** Dedup keeping the LAST occurrence of each value, preserving that last-occurrence order. */
function dedupKeepLast(arr: readonly string[]): string[] {
	const seen = new Set<string>();
	const out: string[] = [];
	for (let i = arr.length - 1; i >= 0; i--) {
		const v = arr[i];
		if (v === undefined || seen.has(v)) continue;
		seen.add(v);
		out.push(v);
	}
	out.reverse();
	return out;
}

/**
 * Resolve the effective window size: `undefined` → default; `0` → disabled
 * (matches `SlidingReplayWindow`'s `replayWindow: 0`); a negative (invalid)
 * value → the secure default, not disabled.
 */
function resolveWindow(window: number | undefined): number {
	if (window === undefined || window < 0) return DEFAULT_WINDOW;
	return Math.trunc(window);
}

/** Open (or create) the IDB database for a given namespace. Mirrors ctr-allocator.ts. */
function openDb(namespace: string): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(`${KEY_PREFIX}/${namespace}`, IDB_VERSION);
		req.onupgradeneeded = () => {
			const db = req.result;
			if (!db.objectStoreNames.contains(STORE_NAME)) {
				db.createObjectStore(STORE_NAME);
			}
		};
		req.onsuccess = () => resolve(req.result);
		req.onerror = () => reject(req.error);
	});
}

export interface DurableReplayGuardOptions {
	/** Namespace isolating independent key-spaces in the shared IDB store. */
	namespace: string;
	/**
	 * Max distinct recent CTRs tracked per (namespace, key). Default 1024
	 * (matches `SlidingReplayWindow`). `0` disables the durable window
	 * (mirrors `SlidingReplayWindow`'s `replayWindow: 0`); a negative value is
	 * treated as invalid and falls back to the default (it does NOT disable).
	 */
	window?: number;
	/** Suppress the one-time no-IDB / no-WebLocks warning. */
	warnIfUnavailable?: boolean;
	/**
	 * Throw at construction when IndexedDB or Web Locks is unavailable, instead
	 * of silently degrading to in-memory-only protection (issue #43). Default
	 * `false` — the guard logs a warning and continues with `available=false`.
	 * Set to `true` for production deployments where cross-reload replay
	 * protection is a hard requirement.
	 */
	requireAvailable?: boolean;
}

/**
 * Durable receiver-side replay window. One instance per provider (chat) or
 * per worker (media); state is scoped per (namespace, key) so no cross-room /
 * cross-key-space replay-window confusion.
 *
 * The caller MUST pass a per-tenant `namespace` to isolate independent
 * deployments sharing the same origin. Two deployments sharing the same
 * namespace with a colliding key would share a window and could false-reject
 * each other.
 *
 * ## Check / accept ordering (architecture-council nit #1)
 * The CALLER is responsible for running the in-memory `SlidingReplayWindow`
 * check FIRST (cheap, synchronous) and only calling `check()` here if the
 * in-memory check passes. `accept()` MUST be called only AFTER a successful
 * AEAD verify, so a forged frame with a novel CTR cannot poison the window.
 */
export class DurableReplayGuard {
	/** True when IndexedDB is present; when false every method is a safe no-op. */
	readonly available: boolean;

	private readonly namespace: string;
	private readonly window: number;
	private readonly mem = new Map<string, MemWindow>();
	private readonly hydrating = new Map<string, Promise<MemWindow>>();
	/**
	 * Per-key count of in-flight persists. A key with a queued/running persist
	 * has an accepted CTR that is NOT yet in the durable store, so evicting it
	 * from `mem` and then re-hydrating from IDB would read a STALE window and
	 * false-ACCEPT that very CTR as new. `trimMemCache` therefore never
	 * evicts a key present here. A counter (not a Set) because two overlapping
	 * unseals of one key can schedule two persists concurrently.
	 */
	private readonly persisting = new Map<string, number>();
	/** Serializes persist writes so interleaved snapshots cannot clobber each other. */
	private persistTail: Promise<void> = Promise.resolve();
	private warnedPersistFail = false;
	private warnedReadFail = false;
	private dbPromise: Promise<IDBDatabase> | null = null;

	constructor(opts: DurableReplayGuardOptions) {
		if (!opts.namespace) {
			throw new Error('DurableReplayGuard: namespace is required');
		}
		this.namespace = opts.namespace;
		this.window = resolveWindow(opts.window);
		// Durable persistence requires BOTH IndexedDB (to store) AND the Web
		// Locks API (to serialize the cross-tab read-merge-write). On a legacy
		// engine with IDB but no Web Locks (Safari <15.4) the RMW would run
		// UNLOCKED and two tabs could interleave and silently drop a CTR (later
		// replayable). Gate durable persistence OFF when either capability is
		// absent; the in-memory window still defends within a session (only
		// cross-reload protection is lost). Both capabilities are static per
		// engine, so sampling them once at construct is sound.
		const hasIdb = idbAvailable();
		const hasLocks = locksAvailable();
		this.available = hasIdb && hasLocks;
		// Issue #43: throw when explicitly required and unavailable, instead of
		// silently degrading to in-memory-only protection.
		if (!this.available && opts.requireAvailable) {
			const missing = !hasIdb ? 'IndexedDB' : 'Web Locks API';
			throw new Error(
				`DurableReplayGuard: ${missing} is unavailable — durable cross-reload replay ` +
				'protection cannot be constructed. Set `requireAvailable: false` to allow ' +
				'silent degradation to in-memory-only protection (CWE-294 risk).',
			);
		}
		if (opts.warnIfUnavailable !== false) {
			if (!hasIdb) {
				console.warn(
					'[sframe-ratchet] IndexedDB unavailable — durable cross-reload replay ' +
						'protection is disabled (CWE-294); falling back to the in-memory replay ' +
						'window (session-scoped only).',
				);
			} else if (!hasLocks) {
				console.warn(
					'[sframe-ratchet] Web Locks API unavailable (legacy engine, e.g. Safari <15.4) ' +
						'— durable cross-reload replay protection is disabled: the persist ' +
						'read-merge-write cannot be serialized cross-tab, so falling back to the ' +
						'in-memory replay window (session-scoped only). Single-tab durable ' +
						'protection is forgone in exchange for an honest, uniform "no durable ' +
						'claim without Web Locks" posture.',
				);
			}
		}
	}

	private db(): Promise<IDBDatabase> {
		if (!this.dbPromise) {
			this.dbPromise = openDb(this.namespace);
		}
		return this.dbPromise;
	}

	private storeKey(key: string): string {
		return `${KEY_PREFIX}|${this.namespace}|${key}`;
	}

	/** Read a persisted window from IDB. */
	private idbRead(db: IDBDatabase, fullKey: string): Promise<PersistedWindow | undefined> {
		return new Promise((resolve, reject) => {
			const tx = db.transaction(STORE_NAME, 'readonly');
			const req = tx.objectStore(STORE_NAME).get(fullKey);
			req.onsuccess = () => resolve(req.result as PersistedWindow | undefined);
			req.onerror = () => reject(req.error);
		});
	}

	/** Write a persisted window to IDB. */
	private idbWrite(db: IDBDatabase, fullKey: string, value: PersistedWindow): Promise<void> {
		return new Promise((resolve, reject) => {
			const tx = db.transaction(STORE_NAME, 'readwrite');
			const req = tx.objectStore(STORE_NAME).put(value, fullKey);
			req.onsuccess = () => resolve();
			req.onerror = () => reject(req.error);
		});
	}

	/** Delete a persisted window from IDB. */
	private idbDeleteKey(db: IDBDatabase, fullKey: string): Promise<void> {
		return new Promise((resolve, reject) => {
			const tx = db.transaction(STORE_NAME, 'readwrite');
			const req = tx.objectStore(STORE_NAME).delete(fullKey);
			req.onsuccess = () => resolve();
			req.onerror = () => reject(req.error);
		});
	}

	/** Load (once) the persisted window for a key into the in-memory mirror. */
	private hydrate(key: string): Promise<MemWindow> {
		const fullKey = this.storeKey(key);
		const cached = this.mem.get(fullKey);
		if (cached) return Promise.resolve(cached);
		const inflight = this.hydrating.get(fullKey);
		if (inflight) return inflight;

		const p = (async (): Promise<MemWindow> => {
			let order: string[] = [];
			try {
				const db = await this.db();
				const persisted = await this.idbRead(db, fullKey);
				if (persisted && persisted.v === 1 && Array.isArray(persisted.seen)) {
					order = persisted.seen.slice(-this.window);
				}
			} catch (err: unknown) {
				// IndexedDB is present but the read threw (private-mode /
				// partitioned / quota-broken storage): we start with an EMPTY
				// window, so a frame accepted in a prior session would not be
				// caught. Surface that once rather than silently claiming
				// protection.
				if (!this.warnedReadFail) {
					this.warnedReadFail = true;
					console.warn(
						'[sframe-ratchet] could not read the persisted replay window ' +
							'(CWE-294); cross-reload replay protection is unavailable this session:',
						err,
					);
				}
			}
			const win: MemWindow = { set: new Set(order), order };
			this.mem.set(fullKey, win);
			this.hydrating.delete(fullKey);
			// Bound the in-memory cache. Runs after the insert so the freshest
			// read (this `key`) is protected; evicts the oldest safe entry
			// (never mid-hydration nor an entry with an in-flight persist). The
			// durable store is authoritative, so an evicted pair re-hydrates
			// correctly on next use.
			this.trimMemCache(fullKey);
			return win;
		})();
		this.hydrating.set(fullKey, p);
		return p;
	}

	/**
	 * True if this (key, ctr) has NOT been accepted before — i.e. it is safe
	 * to proceed with AEAD verification. A false result means the CTR was
	 * already seen (replay). No-op (returns true) when unavailable or disabled.
	 *
	 * The caller MUST run the in-memory `SlidingReplayWindow.check()` FIRST
	 * and only call this when the in-memory check passes.
	 */
	async check(key: string, ctr: bigint): Promise<boolean> {
		if (!this.available || this.window === 0) return true;
		const win = await this.hydrate(key);
		return !win.set.has(ctr.toString());
	}

	/**
	 * Record an AEAD-authentic CTR as accepted and persist it (write-through).
	 * MUST be called only AFTER a successful unseal, so a forged frame with a
	 * novel CTR cannot poison the window. No-op when unavailable or disabled.
	 */
	async accept(key: string, ctr: bigint): Promise<void> {
		if (!this.available || this.window === 0) return;
		const fullKey = this.storeKey(key);
		const win = await this.hydrate(key);
		const ctrStr = ctr.toString();
		if (win.set.has(ctrStr)) return;

		// Mark this key as having an in-flight mutation+persist BEFORE mutating
		// `win`, so a concurrent hydrate-triggered `trimMemCache` cannot evict
		// it mid-persist (which would let a fresh hydrate re-read stale IDB and
		// false-accept this very CTR). Cleared once the persist settles.
		this.persisting.set(fullKey, (this.persisting.get(fullKey) ?? 0) + 1);

		win.set.add(ctrStr);
		win.order.push(ctrStr);
		this.trim(win);

		// Serialize same-realm writes via the chain; serialize cross-tab writes
		// via Web Locks inside persistMerged. Non-fatal on failure (the
		// in-memory window still defends this session).
		this.persistTail = this.persistTail
			.catch(() => undefined)
			.then(() => this.persistMerged(fullKey, win))
			.catch((err: unknown) => this.warnPersistFail(err))
			.then(() => this.releasePersisting(fullKey));
		await this.persistTail;
	}

	/**
	 * Clear the durable replay window for a key (used on key rotation).
	 * Deletes the IDB entry, evicts from the in-memory cache, and clears any
	 * in-flight persist count for the key. No-op when unavailable or disabled,
	 * or when the key was never hydrated.
	 *
	 * Architecture-council nit #2: chat `rotate(roomId)` and media
	 * `wipeEpoch(epoch)` both need a matching durable clear so stale CTRs from
	 * a rotated key do not false-reject fresh frames under the new key.
	 */
	async clear(key: string): Promise<void> {
		if (!this.available || this.window === 0) return;
		const fullKey = this.storeKey(key);
		// Best-effort IDB delete; a failure leaves a stale entry that will be
		// re-merged on next hydrate — harmless because the caller also clears
		// the in-memory window, so the only risk is a stale CTR surviving in
		// IDB that the new key never queries (different key shape after
		// rotation). Swallow the error to mirror the graceful-degradation
		// posture of the rest of the guard.
		try {
			const db = await this.db();
			await this.idbDeleteKey(db, fullKey);
		} catch {
			// Stale IDB entry left behind — see comment above.
		}
		this.mem.delete(fullKey);
		this.hydrating.delete(fullKey);
		this.persisting.delete(fullKey);
	}

	/**
	 * Decrement the in-flight-persist count for a key, deleting it at zero.
	 * Uses `?? 0` (not `?? 1`) so a `clear()` that deleted the entry mid-flight
	 * does not underflow: `clear` removes the counter, then a stale release
	 * reads 0, computes -1, and deletes (no-op on an already-deleted key) —
	 * the counter never goes negative and never gets stuck.
	 */
	private releasePersisting(key: string): void {
		const next = (this.persisting.get(key) ?? 0) - 1;
		if (next <= 0) this.persisting.delete(key);
		else this.persisting.set(key, next);
	}

	/**
	 * Keep the in-memory `mem` cache bounded by REPLAY_MEM_CACHE_CAP, evicting
	 * the OLDEST evictable entry (insertion-order FIFO). The durable IDB store
	 * is authoritative, so an evicted entry re-hydrates on next use with no
	 * correctness loss.
	 *
	 * Never evicts:
	 *   - `justHydratedKey` — the freshest read that just triggered this call;
	 *   - a key still in `hydrating` — its mem entry is mid-load;
	 *   - a key in `persisting` — it holds an accepted CTR not yet durably
	 *     written; evicting it then re-hydrating from IDB would read a stale
	 *     window and false-accept that CTR (replay).
	 *
	 * If every over-cap entry is protected the loop stops (temporarily over
	 * cap); it self-heals once the in-flight persists settle and `persisting`
	 * drains.
	 */
	private trimMemCache(justHydratedKey: string): void {
		while (this.mem.size > REPLAY_MEM_CACHE_CAP) {
			let evicted = false;
			// Map iteration is insertion-order → the first eligible key is the oldest.
			for (const key of this.mem.keys()) {
				if (key === justHydratedKey) continue;
				if (this.hydrating.has(key)) continue;
				if (this.persisting.has(key)) continue;
				this.mem.delete(key);
				evicted = true;
				break;
			}
			if (!evicted) break;
		}
	}

	/** Drop oldest CTRs until the in-memory window is within bound. */
	private trim(win: MemWindow): void {
		while (win.order.length > this.window) {
			const evicted = win.order.shift();
			if (evicted !== undefined) win.set.delete(evicted);
		}
	}

	/**
	 * Read-merge-write the persisted window under a cross-tab exclusive lock
	 * (when available): union the persisted CTRs (possibly from another tab)
	 * with this tab's in-memory window, dedup, bound, persist, and reflect the
	 * union back into the in-memory mirror so this tab immediately rejects a
	 * CTR another tab already accepted.
	 */
	private async persistMerged(fullKey: string, win: MemWindow): Promise<void> {
		// Reached only when `available` is true, which requires the Web Locks
		// API (see the constructor). So the read-merge-write ALWAYS runs under
		// a cross-tab exclusive lock — there is no unlocked fallback (an
		// unlocked RMW could silently drop a CTR).
		const write = async (): Promise<void> => {
			const db = await this.db();
			let persistedSeen: string[] = [];
			try {
				const cur = await this.idbRead(db, fullKey);
				if (cur && cur.v === 1 && Array.isArray(cur.seen)) persistedSeen = cur.seen;
			} catch {
				// Read failed inside the RMW — fall back to this tab's in-memory view only.
			}
			const merged = dedupKeepLast(persistedSeen.concat(win.order)).slice(-this.window);
			win.order = merged;
			win.set = new Set(merged);
			const payload: PersistedWindow = { v: 1, seen: merged };
			await this.idbWrite(db, fullKey, payload);
		};

		await navigator.locks.request(`${KEY_PREFIX}-lock|${fullKey}`, { mode: 'exclusive' }, write);
	}

	private warnPersistFail(err: unknown): void {
		if (!this.warnedPersistFail) {
			this.warnedPersistFail = true;
			console.warn(
				'[sframe-ratchet] failed to persist replay window (CWE-294); cross-reload ' +
					'replay protection may be degraded:',
				err,
			);
		}
	}
}
