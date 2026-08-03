// CTR allocator strategies for chat-mode SFrame.
//
// RandomCtrAllocator  — default, 64 random bits per frame.
//   Birthday bound: ~2^32 messages per (roomId, senderUid) before collision
//   risk becomes non-negligible. Key rotation cadence must be tuned accordingly.
//
// MonotonicIdbCtrAllocator — opt-in, requires ctrKeyspace.
//   IDB-backed atomic counter per (keyspace, roomId, senderUid).
//   Multi-tab safety via navigator.locks when available.
//   Graceful single-tab fallback in Node.js (test env, no navigator.locks).
//
// See design doc §B.2.

export interface CtrAllocator {
	/** Return the next CTR value for (roomId, senderUid). */
	next(roomId: string, senderUid: string): Promise<bigint>;
}

// ---------------------------------------------------------------------------
// RandomCtrAllocator
// ---------------------------------------------------------------------------

/**
 * Random 64-bit CTR allocator. Stateless — no IDB, no navigator.
 *
 * @remarks Birthday bound: expect first collision after ~2^32 messages per
 * (roomId, senderUid) under the same HKDF-derived key. Rotate the base key
 * (via SDK) to reset the CTR space. A one-time console.warn fires at 75% of
 * the birthday bound (~3.2 billion frames per (roomId, senderUid)) to alert
 * operators before the risk becomes non-negligible (issue #44).
 */
export class RandomCtrAllocator implements CtrAllocator {
	/** Per-(roomId, senderUid) frame counter for birthday-bound warning. */
	private readonly counts = new Map<string, number>();
	private warned = false;
	private static readonly BIRTHDAY_WARN_THRESHOLD = 2n ** 32n * 3n / 4n; // ~3.2B

	async next(roomId: string, senderUid: string): Promise<bigint> {
		// getRandomValues fills a BigUint64Array with uniform 64-bit unsigned values.
		const buf = new BigUint64Array(1);
		crypto.getRandomValues(buf);
		// Issue #44: track frame count per (roomId, senderUid) and warn once
		// when approaching the birthday bound (~2^32 messages).
		if (!this.warned) {
			const key = `${roomId}|${senderUid}`;
			const count = (this.counts.get(key) ?? 0) + 1;
			this.counts.set(key, count);
			if (BigInt(count) > RandomCtrAllocator.BIRTHDAY_WARN_THRESHOLD) {
				this.warned = true;
				console.warn(
					'[sframe-ratchet] Random CTR birthday bound approaching for ' +
					`(${roomId}, ${senderUid}): ${count} frames sent under the same key. ` +
					'Rotate the base key to reset the CTR space (issue #44).',
				);
			}
		}
		return buf[0];
	}
}

// ---------------------------------------------------------------------------
// MonotonicIdbCtrAllocator
// ---------------------------------------------------------------------------

const IDB_VERSION = 1;
const STORE_NAME = 'ctr';

/** Open (or create) the IDB database for a given keyspace. */
function openDb(keyspace: string): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(`sframe-chat/${keyspace}`, IDB_VERSION);
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

/** Read current counter value for a key; returns 0n if not found. */
function idbGet(store: IDBObjectStore, key: string): Promise<bigint> {
	return new Promise((resolve, reject) => {
		const req = store.get(key);
		req.onsuccess = () => resolve(req.result != null ? BigInt(req.result) : 0n);
		req.onerror = () => reject(req.error);
	});
}

/** Write a counter value. */
function idbPut(store: IDBObjectStore, key: string, value: bigint): Promise<void> {
	return new Promise((resolve, reject) => {
		// Store as string to avoid IDB bigint serialization issues in older runtimes.
		const req = store.put(value.toString(), key);
		req.onsuccess = () => resolve();
		req.onerror = () => reject(req.error);
	});
}

/** Atomic read-increment-write in a readwrite transaction. */
async function atomicIncrement(db: IDBDatabase, idbKey: string): Promise<bigint> {
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readwrite');
		const store = tx.objectStore(STORE_NAME);
		let currentValue = 0n;

		const getReq = store.get(idbKey);
		getReq.onsuccess = () => {
			currentValue = getReq.result != null ? BigInt(getReq.result) : 0n;
			const nextValue = currentValue + 1n;
			const putReq = store.put(nextValue.toString(), idbKey);
			putReq.onsuccess = () => resolve(currentValue);
			putReq.onerror = () => reject(putReq.error);
		};
		getReq.onerror = () => reject(getReq.error);
		tx.onerror = () => reject(tx.error);
	});
}

/**
 * IDB-backed monotonic CTR allocator.
 *
 * Requires `ctrKeyspace` — isolates counter stores per deployment/session.
 * Multi-tab safety via `navigator.locks.request` (exclusive lock per key).
 * Falls back to single-tab IDB-only mode when `navigator.locks` is unavailable
 * (Node.js test environment, old browsers).
 *
 * @warning Single-tab fallback does NOT protect against concurrent tab writes.
 * Production deployments should ensure `navigator.locks` is available
 * (supported in all modern browsers as of 2023).
 */
export class MonotonicIdbCtrAllocator implements CtrAllocator {
	private readonly keyspace: string;
	private readonly allowSingleTab: boolean;
	private dbPromise: Promise<IDBDatabase> | null = null;

	/**
	 * @param keyspace Isolates counter stores per deployment/session.
	 * @param opts.allowSingleTab When `false` (default), throws if
	 * `navigator.locks` is unavailable — the single-tab fallback does NOT
	 * protect against concurrent tab writes and can cause CTR reuse (issue
	 * #47). Set to `true` for test environments where multi-tab safety is
	 * not required.
	 */
	constructor(keyspace: string, opts?: { allowSingleTab?: boolean }) {
		if (!keyspace) {
			throw new Error('MonotonicIdbCtrAllocator: ctrKeyspace is required');
		}
		this.keyspace = keyspace;
		this.allowSingleTab = opts?.allowSingleTab ?? false;
		const hasLocks =
			typeof navigator !== 'undefined' && navigator.locks != null;
		if (!hasLocks && !this.allowSingleTab) {
			throw new Error(
				'MonotonicIdbCtrAllocator: navigator.locks is unavailable — ' +
				'multi-tab CTR safety cannot be guaranteed. Set `allowSingleTab: true` ' +
				'in the constructor options for test environments only (issue #47).',
			);
		}
	}

	private db(): Promise<IDBDatabase> {
		if (!this.dbPromise) {
			this.dbPromise = openDb(this.keyspace);
		}
		return this.dbPromise;
	}

	async next(roomId: string, senderUid: string): Promise<bigint> {
		const idbKey = `${roomId}|${senderUid}`;
		const lockName = `sframe-ctr|${this.keyspace}|${roomId}|${senderUid}`;

		const hasLocks =
			typeof navigator !== 'undefined' &&
			navigator.locks != null;

		const db = await this.db();

		if (hasLocks) {
			// Multi-tab safe: exclusive lock serializes concurrent increments.
			return navigator.locks.request(lockName, { mode: 'exclusive' }, async () => {
				return atomicIncrement(db, idbKey);
			});
		} else {
			// Single-tab fallback (Node.js, old browsers).
			// No cross-tab protection; document this limitation.
			return atomicIncrement(db, idbKey);
		}
	}
}
