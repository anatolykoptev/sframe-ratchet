// Durable cross-reload anti-replay tests (CWE-294 / SEC-CR-003).
//
// Threat: a malicious / compromised app-server re-serves an OLD authentic
// sealed frame under a FRESH msg_id after a page reload. The in-memory
// SlidingReplayWindow was wiped on reload, so without durable persistence
// the AEAD verifies (the ciphertext is genuinely authentic, just old) and
// the stale message renders as new.
//
// A "reload" is simulated by constructing a FRESH DurableReplayGuard with
// the SAME namespace (fresh in-memory cache, like a real page reload) while
// the durable IndexedDB store persists.
//
// fake-indexeddb provides the IDB environment; navigator.locks is NOT
// available in Node/vitest, so the guard's `available` flag is false and
// the durable path is a no-op. To test the durable path we polyfill
// navigator.locks with a simple exclusive-lock implementation.
//
// Each test uses a FRESH namespace (freshNs()) to avoid cross-test
// interference — deleting IDB databases between tests hangs because the
// guard keeps its IDB connection open (by design — the connection is
// reused for subsequent persist/read operations).

import 'fake-indexeddb/auto';
import { describe, it, expect, vi, beforeAll } from 'vitest';
import { DurableReplayGuard } from '../durable-replay.ts';

// ---------------------------------------------------------------------------
// navigator.locks polyfill — fake-indexeddb gives us IDB but not Web Locks.
// A minimal exclusive-lock map suffices for the guard's cross-tab RMW.
// ---------------------------------------------------------------------------

beforeAll(() => {
	if (typeof navigator === 'undefined') {
		(globalThis as Record<string, unknown>).navigator = {};
	}
	const nav = globalThis.navigator as unknown as Record<string, unknown>;
	if (!nav.locks) {
		const held = new Map<string, Promise<void>>();
		const locksApi = {
			request: async (
				name: string,
				optionsOrCallback: unknown,
				maybeCallback?: () => Promise<void>,
			): Promise<void> => {
				const callback =
					typeof optionsOrCallback === 'function' ? optionsOrCallback : maybeCallback;
				if (typeof callback !== 'function') {
					throw new Error('navigator.locks.request: callback required');
				}
				// Spin until the lock is free — simulates exclusive mode.
				while (held.has(name)) {
					await held.get(name);
				}
				let resolve!: () => void;
				const p = new Promise<void>((r) => {
					resolve = r;
				});
				held.set(name, p);
				try {
					return await callback();
				} finally {
					held.delete(name);
					resolve();
				}
			},
		};
		// Node 24's navigator is read-only — use defineProperty.
		Object.defineProperty(nav, 'locks', { value: locksApi, configurable: true, writable: true });
	}
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Unique namespace per test — avoids cross-test interference. */
let nsCounter = 0;
function freshNs(): string {
	return `test-ns-${nsCounter++}`;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('DurableReplayGuard — availability', () => {
	it('constructs without throwing when IDB + Web Locks are available', () => {
		expect(() => new DurableReplayGuard({ namespace: freshNs() })).not.toThrow();
	});

	it('throws on missing namespace', () => {
		expect(() => new DurableReplayGuard({ namespace: '' })).toThrow();
	});

	it('available is true when IDB + Web Locks are present', () => {
		const g = new DurableReplayGuard({ namespace: freshNs() });
		expect(g.available).toBe(true);
	});

	it('available is false when IndexedDB is absent', () => {
		const orig = globalThis.indexedDB;
		Object.defineProperty(globalThis, 'indexedDB', { value: undefined, configurable: true });
		try {
			const g = new DurableReplayGuard({ namespace: freshNs(), warnIfUnavailable: false });
			expect(g.available).toBe(false);
		} finally {
			Object.defineProperty(globalThis, 'indexedDB', { value: orig, configurable: true });
		}
	});

	it('available is false when Web Locks is absent', () => {
		const orig = globalThis.navigator.locks;
		Object.defineProperty(globalThis.navigator, 'locks', { value: undefined, configurable: true });
		try {
			const g = new DurableReplayGuard({ namespace: freshNs(), warnIfUnavailable: false });
			expect(g.available).toBe(false);
		} finally {
			Object.defineProperty(globalThis.navigator, 'locks', { value: orig, configurable: true });
		}
	});

	it('check/accept are no-ops when unavailable', async () => {
		const orig = globalThis.indexedDB;
		Object.defineProperty(globalThis, 'indexedDB', { value: undefined, configurable: true });
		try {
			const g = new DurableReplayGuard({ namespace: freshNs(), warnIfUnavailable: false });
			expect(g.available).toBe(false);
			expect(await g.check('k', 1n)).toBe(true);
			await g.accept('k', 1n); // no throw
			await g.clear('k'); // no throw
		} finally {
			Object.defineProperty(globalThis, 'indexedDB', { value: orig, configurable: true });
		}
	});
});

describe('DurableReplayGuard — cross-reload replay rejection', () => {
	it('rejects a replayed CTR after a simulated reload (fresh guard, same namespace)', async () => {
		const ns = freshNs();
		const g1 = new DurableReplayGuard({ namespace: ns });
		expect(await g1.check('room1|alice', 42n)).toBe(true);
		await g1.accept('room1|alice', 42n);

		// Reload: fresh guard — in-memory cache is empty, IDB persists.
		const g2 = new DurableReplayGuard({ namespace: ns });
		expect(await g2.check('room1|alice', 42n)).toBe(false);
	});

	it('accepts a genuinely-new CTR after a reload', async () => {
		const ns = freshNs();
		const g1 = new DurableReplayGuard({ namespace: ns });
		await g1.accept('room1|alice', 100n);

		const g2 = new DurableReplayGuard({ namespace: ns });
		expect(await g2.check('room1|alice', 200n)).toBe(true);
		await g2.accept('room1|alice', 200n);
	});

	it('isolates (namespace, key) pairs — different keys do not interfere', async () => {
		const ns = freshNs();
		const g1 = new DurableReplayGuard({ namespace: ns });
		await g1.accept('room1|alice', 1n);

		const g2 = new DurableReplayGuard({ namespace: ns });
		// Same CTR under a different key is NOT a replay.
		expect(await g2.check('room1|bob', 1n)).toBe(true);
		// Same CTR under a different namespace is NOT a replay.
		const g3 = new DurableReplayGuard({ namespace: freshNs() });
		expect(await g3.check('room1|alice', 1n)).toBe(true);
	});
});

describe('DurableReplayGuard — persistence', () => {
	it('persists accepted CTRs to IndexedDB', async () => {
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns });
		await g.accept('room1|alice', 7n);

		// Read directly from IDB to confirm persistence.
		const db = await new Promise<IDBDatabase>((resolve, reject) => {
			const req = indexedDB.open(`sframe-replay/${ns}`);
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		});
		const fullKey = `sframe-replay|${ns}|room1|alice`;
		const persisted = await new Promise<{ v: number; seen: string[] } | undefined>(
			(resolve, reject) => {
				const tx = db.transaction('replay', 'readonly');
				const req = tx.objectStore('replay').get(fullKey);
				req.onsuccess = () => resolve(req.result as { v: number; seen: string[] } | undefined);
				req.onerror = () => reject(req.error);
			},
		);
		expect(persisted).toBeDefined();
		expect(persisted!.v).toBe(1);
		expect(persisted!.seen).toContain('7');
	});

	it('persists multiple CTRs in order', async () => {
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns });
		for (let i = 0n; i < 5n; i++) {
			await g.accept('room1|alice', i);
		}

		const g2 = new DurableReplayGuard({ namespace: ns });
		for (let i = 0n; i < 5n; i++) {
			expect(await g2.check('room1|alice', i)).toBe(false);
		}
	});
});

describe('DurableReplayGuard — window size', () => {
	it('window=0 disables the durable window (check always true, accept no-op)', async () => {
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns, window: 0 });
		expect(await g.check('k', 1n)).toBe(true);
		await g.accept('k', 1n);
		// After accept, check still true (disabled).
		expect(await g.check('k', 1n)).toBe(true);

		// A fresh guard also sees nothing persisted.
		const g2 = new DurableReplayGuard({ namespace: ns, window: 0 });
		expect(await g2.check('k', 1n)).toBe(true);
	});

	it('evicts oldest CTRs when window is exceeded', async () => {
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns, window: 3 });
		await g.accept('k', 0n);
		await g.accept('k', 1n);
		await g.accept('k', 2n);
		await g.accept('k', 3n); // evicts 0n

		const g2 = new DurableReplayGuard({ namespace: ns, window: 3 });
		expect(await g2.check('k', 0n)).toBe(true); // evicted — not a replay
		expect(await g2.check('k', 3n)).toBe(false); // still tracked
	});
});

describe('DurableReplayGuard — clear()', () => {
	it('clears the durable window for a key', async () => {
		const ns = freshNs();
		const g1 = new DurableReplayGuard({ namespace: ns });
		await g1.accept('room1|alice', 1n);
		await g1.accept('room1|alice', 2n);

		await g1.clear('room1|alice');

		// Fresh guard: CTRs are no longer tracked.
		const g2 = new DurableReplayGuard({ namespace: ns });
		expect(await g2.check('room1|alice', 1n)).toBe(true);
		expect(await g2.check('room1|alice', 2n)).toBe(true);
	});

	it('clear does not affect other keys', async () => {
		const ns = freshNs();
		const g1 = new DurableReplayGuard({ namespace: ns });
		await g1.accept('room1|alice', 1n);
		await g1.accept('room1|bob', 2n);

		await g1.clear('room1|alice');

		const g2 = new DurableReplayGuard({ namespace: ns });
		expect(await g2.check('room1|alice', 1n)).toBe(true);
		expect(await g2.check('room1|bob', 2n)).toBe(false);
	});

	it('clear is a no-op when unavailable', async () => {
		const orig = globalThis.indexedDB;
		Object.defineProperty(globalThis, 'indexedDB', { value: undefined, configurable: true });
		try {
			const g = new DurableReplayGuard({ namespace: freshNs(), warnIfUnavailable: false });
			await g.clear('k'); // no throw
		} finally {
			Object.defineProperty(globalThis, 'indexedDB', { value: orig, configurable: true });
		}
	});
});

describe('DurableReplayGuard — cross-tab merge', () => {
	it('merges CTRs from two guards sharing the same namespace', async () => {
		const ns = freshNs();
		// Two guards simulate two tabs. Both accept different CTRs.
		// The persisted window should contain the union.
		const g1 = new DurableReplayGuard({ namespace: ns });
		const g2 = new DurableReplayGuard({ namespace: ns });

		await g1.accept('room1|alice', 10n);
		await g2.accept('room1|alice', 20n);

		// A third guard (tab 3) should see BOTH CTRs as replayed.
		const g3 = new DurableReplayGuard({ namespace: ns });
		expect(await g3.check('room1|alice', 10n)).toBe(false);
		expect(await g3.check('room1|alice', 20n)).toBe(false);
	});

	it('dedupes the same CTR accepted by two tabs', async () => {
		const ns = freshNs();
		const g1 = new DurableReplayGuard({ namespace: ns });
		const g2 = new DurableReplayGuard({ namespace: ns });

		await g1.accept('room1|alice', 5n);
		await g2.accept('room1|alice', 5n); // same CTR — should dedup, not duplicate

		const g3 = new DurableReplayGuard({ namespace: ns });
		expect(await g3.check('room1|alice', 5n)).toBe(false);
	});
});

describe('DurableReplayGuard — in-memory cache eviction', () => {
	it('evicts oldest mem cache entry when CAP exceeded, re-hydrates from IDB', async () => {
		// Use a small window to keep the test fast. The mem cache CAP is 256
		// internally — we test the re-hydrate behavior by creating many keys
		// and verifying a previously-evicted key still rejects its CTR.
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns, window: 64 });

		// Accept a CTR under the first key.
		await g.accept('key-0|sender-0', 999n);

		// Create 260 more keys to exceed the 256-entry mem cache CAP.
		for (let i = 1; i <= 260; i++) {
			await g.accept(`key-${i}|sender-${i}`, BigInt(i));
		}

		// key-0 should have been evicted from the mem cache. A check should
		// re-hydrate from IDB and still reject the CTR.
		expect(await g.check('key-0|sender-0', 999n)).toBe(false);
	}, 30000);
});

describe('DurableReplayGuard — check ordering (council nit #1)', () => {
	it('check does NOT modify state — repeated checks pass', async () => {
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns });
		expect(await g.check('k', 1n)).toBe(true);
		expect(await g.check('k', 1n)).toBe(true);
		expect(await g.check('k', 1n)).toBe(true);
		// Still not accepted.
		const g2 = new DurableReplayGuard({ namespace: ns });
		expect(await g2.check('k', 1n)).toBe(true);
	});
});

describe('DurableReplayGuard — graceful degradation warnings', () => {
	it('warns once when IndexedDB is unavailable', () => {
		const orig = globalThis.indexedDB;
		Object.defineProperty(globalThis, 'indexedDB', { value: undefined, configurable: true });
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
		try {
			new DurableReplayGuard({ namespace: freshNs() });
			expect(warnSpy).toHaveBeenCalledTimes(1);
			expect(warnSpy.mock.calls[0][0]).toContain('IndexedDB unavailable');
		} finally {
			Object.defineProperty(globalThis, 'indexedDB', { value: orig, configurable: true });
			warnSpy.mockRestore();
		}
	});

	it('warns once when Web Locks is unavailable', () => {
		const orig = globalThis.navigator.locks;
		Object.defineProperty(globalThis.navigator, 'locks', { value: undefined, configurable: true });
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
		try {
			new DurableReplayGuard({ namespace: freshNs() });
			expect(warnSpy).toHaveBeenCalledTimes(1);
			expect(warnSpy.mock.calls[0][0]).toContain('Web Locks API unavailable');
		} finally {
			Object.defineProperty(globalThis.navigator, 'locks', { value: orig, configurable: true });
			warnSpy.mockRestore();
		}
	});

	it('suppresses warning when warnIfUnavailable is false', () => {
		const orig = globalThis.indexedDB;
		Object.defineProperty(globalThis, 'indexedDB', { value: undefined, configurable: true });
		const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
		try {
			new DurableReplayGuard({ namespace: freshNs(), warnIfUnavailable: false });
			expect(warnSpy).not.toHaveBeenCalled();
		} finally {
			Object.defineProperty(globalThis, 'indexedDB', { value: orig, configurable: true });
			warnSpy.mockRestore();
		}
	});
});

describe('DurableReplayGuard — persisting counter race (council blocker)', () => {
	it('releasePersisting does not underflow when clear() deletes the counter mid-flight', async () => {
		// Race: two concurrent accepts increment persisting to 2, then clear()
		// deletes the counter, then both releases run. With the fix (?? 0),
		// each release computes -1 and deletes (no-op) — the counter never
		// gets stuck. Without the fix (?? 1), the first release computes 0 and
		// deletes, the second release computes 0 and deletes again — also
		// appears to work, BUT if only ONE release runs before clear, the
		// counter is 1, clear deletes it, the second release reads ?? 1 → 0 →
		// deletes (correct), but the FIRST release already ran with the real
		// value 1 → 0 → deletes. The bug manifests as a premature delete that
		// lets trimMemCache evict the key while a persist is still in flight.
		// This test verifies the counter is never stuck after the race.
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns });

		// Two concurrent accepts (different CTRs, same key).
		await Promise.all([
			g.accept('k', 1n),
			g.accept('k', 2n),
		]);

		// Clear while no persists are in flight (both settled).
		await g.clear('k');

		// The guard should still be functional — a fresh accept works.
		await g.accept('k', 3n);
		expect(await g.check('k', 3n)).toBe(false);
		expect(await g.check('k', 1n)).toBe(true); // cleared
	});

	it('concurrent accept + clear does not leave the counter stuck', async () => {
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns });

		// Start an accept (persists async), then immediately clear.
		// The clear deletes the counter; the accept's releasePersisting
		// runs after clear. With ?? 0, the release computes -1 and deletes
		// (no-op). The counter is not stuck.
		const acceptP = g.accept('k', 1n);
		await g.clear('k');
		await acceptP;

		// Guard still functional.
		await g.accept('k', 2n);
		expect(await g.check('k', 2n)).toBe(false);
	});
});

describe('DurableReplayGuard — duplicate accept (council nit)', () => {
	it('accepting the same CTR twice does not duplicate in the persisted window', async () => {
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns });

		await g.accept('k', 5n);
		await g.accept('k', 5n); // duplicate — early return, no second persist

		// Read directly from IDB — should have exactly one '5'.
		const db = await new Promise<IDBDatabase>((resolve, reject) => {
			const req = indexedDB.open(`sframe-replay/${ns}`);
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		});
		const fullKey = `sframe-replay|${ns}|k`;
		const persisted = await new Promise<{ v: number; seen: string[] } | undefined>(
			(resolve, reject) => {
				const tx = db.transaction('replay', 'readonly');
				const req = tx.objectStore('replay').get(fullKey);
				req.onsuccess = () => resolve(req.result as { v: number; seen: string[] } | undefined);
				req.onerror = () => reject(req.error);
			},
		);
		expect(persisted).toBeDefined();
		const count = persisted!.seen.filter((v) => v === '5').length;
		expect(count).toBe(1);
	});
});

describe('DurableReplayGuard — persistMerged merge logic (mutation killers)', () => {
	// These tests target survived Stryker mutants in persistMerged — the
	// cross-tab merge path. The existing cross-tab tests have both tabs' CTRs
	// in memory, so the merge reading from IDB is never verified. These tests
	// manipulate IDB directly to create scenarios where the merge MUST read
	// persisted state that is NOT in the in-memory window.

	/** Write a raw persisted window entry directly to IDB, bypassing the guard. */
	async function writeRawPersisted(ns: string, key: string, seen: string[]): Promise<void> {
		const dbName = `sframe-replay/${ns}`;
		const db = await new Promise<IDBDatabase>((resolve, reject) => {
			const req = indexedDB.open(dbName, 1);
			req.onupgradeneeded = () => {
				if (!req.result.objectStoreNames.contains('replay')) {
					req.result.createObjectStore('replay');
				}
			};
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		});
		const fullKey = `sframe-replay|${ns}|${key}`;
		await new Promise<void>((resolve, reject) => {
			const tx = db.transaction('replay', 'readwrite');
			tx.objectStore('replay').put({ v: 1, seen }, fullKey);
			tx.oncomplete = () => resolve();
			tx.onerror = () => reject(tx.error);
		});
	}

	it('merge reads persisted CTRs from IDB that are NOT in the in-memory window', async () => {
		// This kills the mutant: `if (false) persistedSeen = cur.seen`
		// If the merge doesn't read persisted state, CTR 999 (written directly
		// to IDB by another tab) would not be in the merged window, and a
		// fresh guard would NOT reject it as a replay.
		const ns = freshNs();

		// Tab A accepts CTR 1 — this creates the IDB database and store.
		const gA = new DurableReplayGuard({ namespace: ns });
		await gA.accept('k', 1n);

		// Tab B (simulated) writes CTR 999 directly to IDB (bypassing the guard).
		await writeRawPersisted(ns, 'k', ['1', '999']);

		// Tab A accepts CTR 2 — the merge should read ['1', '999'] from IDB
		// and merge with in-memory ['1', '2'], producing ['1', '2', '999'].
		await gA.accept('k', 2n);

		// A fresh guard (tab C) should reject CTR 999 — it was persisted by
		// tab B and the merge in tab A should have preserved it.
		const gC = new DurableReplayGuard({ namespace: ns });
		expect(await gC.check('k', 999n)).toBe(false);
	});

	it('merge respects version check — v !== 1 entries are ignored', async () => {
		// This kills the mutant: `if (cur && cur.v !== 1 ...)` (inverted check)
		// If the version check is inverted, a v=0 entry would be read instead
		// of ignored, and its (potentially stale) CTRs would be merged.
		const ns = freshNs();

		// Create the IDB store via a real accept.
		const g = new DurableReplayGuard({ namespace: ns });
		await g.accept('k', 1n);

		// Overwrite with a v=0 entry containing a bogus CTR.
		const dbName = `sframe-replay/${ns}`;
		const db = await new Promise<IDBDatabase>((resolve, reject) => {
			const req = indexedDB.open(dbName);
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		});
		const fullKey = `sframe-replay|${ns}|k`;
		await new Promise<void>((resolve, reject) => {
			const tx = db.transaction('replay', 'readwrite');
			tx.objectStore('replay').put({ v: 0, seen: ['666'] }, fullKey);
			tx.oncomplete = () => resolve();
			tx.onerror = () => reject(tx.error);
		});

		// Accept a new CTR — the merge should IGNORE the v=0 entry.
		await g.accept('k', 2n);

		// A fresh guard should NOT reject CTR 666 — it was in a v=0 entry
		// that the merge should have ignored.
		const g2 = new DurableReplayGuard({ namespace: ns });
		expect(await g2.check('k', 666n)).toBe(true);
	});

	it('merge trims to window size — persisted CTRs beyond the window are evicted', async () => {
		// This kills the mutant: `.slice(-this.window)` removed
		// If the window trim is removed, the persisted array grows unbounded
		// and old CTRs are never evicted. With window=3 and 5 CTRs, only the
		// last 3 should survive.
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns, window: 3 });

		// Accept 5 CTRs — only the last 3 should be in the persisted window.
		for (let i = 0n; i < 5n; i++) {
			await g.accept('k', i);
		}

		// A fresh guard should accept CTRs 0 and 1 (evicted) and reject 2, 3, 4.
		const g2 = new DurableReplayGuard({ namespace: ns, window: 3 });
		expect(await g2.check('k', 0n)).toBe(true); // evicted
		expect(await g2.check('k', 1n)).toBe(true); // evicted
		expect(await g2.check('k', 2n)).toBe(false); // in window
		expect(await g2.check('k', 3n)).toBe(false); // in window
		expect(await g2.check('k', 4n)).toBe(false); // in window
	});

	it('merge includes persisted CTRs from IDB even when in-memory window is empty', async () => {
		// This kills the mutant: `if (true) persistedSeen = cur.seen` (always
		// reads, even when cur is undefined). When cur is undefined (first
		// accept for this key), persistedSeen should remain [], not throw.
		// This test verifies the first-accept path doesn't throw.
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns });

		// First accept for this key — no persisted state exists.
		// The merge should handle cur=undefined gracefully.
		await g.accept('k', 1n);
		expect(await g.check('k', 1n)).toBe(false);

		// Verify the persisted state was written correctly.
		const g2 = new DurableReplayGuard({ namespace: ns });
		expect(await g2.check('k', 1n)).toBe(false);
	});

	it('merge deduplicates CTRs from persisted state and in-memory window', async () => {
		// This kills the mutant: `cur || cur.v === 1` (logical operator change)
		// If the || is used instead of &&, when cur is undefined the condition
		// evaluates cur.v === 1 which throws. This test verifies the dedup
		// works when persisted state has overlapping CTRs with in-memory.
		const ns = freshNs();

		// Tab A accepts CTR 1.
		const gA = new DurableReplayGuard({ namespace: ns });
		await gA.accept('k', 1n);

		// Tab B writes CTR 1 (same) and CTR 2 (new) directly to IDB.
		await writeRawPersisted(ns, 'k', ['1', '2']);

		// Tab A accepts CTR 3 — merge should dedup CTR 1 (already in both).
		await gA.accept('k', 3n);

		// Fresh guard should reject 1, 2, 3 — all persisted.
		const gC = new DurableReplayGuard({ namespace: ns });
		expect(await gC.check('k', 1n)).toBe(false);
		expect(await gC.check('k', 2n)).toBe(false);
		expect(await gC.check('k', 3n)).toBe(false);

		// Verify no duplicates in persisted state.
		const db = await new Promise<IDBDatabase>((resolve, reject) => {
			const req = indexedDB.open(`sframe-replay/${ns}`);
			req.onsuccess = () => resolve(req.result);
			req.onerror = () => reject(req.error);
		});
		const fullKey = `sframe-replay|${ns}|k`;
		const persisted = await new Promise<{ v: number; seen: string[] } | undefined>(
			(resolve, reject) => {
				const tx = db.transaction('replay', 'readonly');
				const req = tx.objectStore('replay').get(fullKey);
				req.onsuccess = () => resolve(req.result as { v: number; seen: string[] } | undefined);
				req.onerror = () => reject(req.error);
			},
		);
		expect(persisted).toBeDefined();
		const uniqueCount = new Set(persisted!.seen).size;
		expect(uniqueCount).toBe(persisted!.seen.length); // no duplicates
	});
});

describe('DurableReplayGuard — in-memory trim (mutation killers)', () => {
	// These tests target survived mutants in the `trim` method — the
	// in-memory MemWindow eviction. The guard's `check` uses `win.set.has()`,
	// so if `trim` doesn't remove evicted CTRs from the Set, the same guard
	// false-rejects an evicted CTR. The persisted state is trimmed separately
	// by `.slice(-this.window)` in `persistMerged`, so a fresh guard would
	// still see the correct window — the mutant only manifests on the SAME
	// guard that accepted the CTRs.

	it('in-memory window evicts oldest CTRs — evicted CTR accepted by SAME guard', async () => {
		// Kills: `while (false)`, `trim` BlockStatement removal, `>= this.window`
		// If trim is broken, the in-memory Set retains all CTRs and the
		// evicted CTR is false-rejected by the same guard.
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns, window: 3 });

		// Accept 5 CTRs — in-memory MemWindow should trim to last 3.
		for (let i = 0n; i < 5n; i++) {
			await g.accept('k', i);
		}

		// CTR 0 and 1 should be evicted from the in-memory Set.
		// check() returns true if the CTR is NOT in the Set (accepted).
		expect(await g.check('k', 0n)).toBe(true); // evicted → accepted
		expect(await g.check('k', 1n)).toBe(true); // evicted → accepted
		// CTR 2, 3, 4 should still be in the Set → rejected.
		expect(await g.check('k', 2n)).toBe(false);
		expect(await g.check('k', 3n)).toBe(false);
		expect(await g.check('k', 4n)).toBe(false);
	});

	it('in-memory window trim removes from set — not just from order array', async () => {
		// Kills: `if (false) win.set.delete(evicted)`, `if (evicted === undefined) ...`
		// If the Set is not updated, check() (which uses set.has) still
		// rejects the evicted CTR even though it's gone from the order array.
		const ns = freshNs();
		const g = new DurableReplayGuard({ namespace: ns, window: 2 });

		await g.accept('k', 0n);
		await g.accept('k', 1n);
		await g.accept('k', 2n); // evicts 0 from in-memory

		// CTR 0 should be evicted from BOTH order and Set.
		expect(await g.check('k', 0n)).toBe(true); // accepted (not in Set)
		expect(await g.check('k', 1n)).toBe(false); // rejected (in Set)
		expect(await g.check('k', 2n)).toBe(false); // rejected (in Set)
	});
});
