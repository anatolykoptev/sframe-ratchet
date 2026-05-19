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
 * (via SDK) to reset the CTR space.
 */
export class RandomCtrAllocator implements CtrAllocator {
	async next(_roomId: string, _senderUid: string): Promise<bigint> {
		// getRandomValues fills a BigUint64Array with uniform 64-bit unsigned values.
		const buf = new BigUint64Array(1);
		crypto.getRandomValues(buf);
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
	private dbPromise: Promise<IDBDatabase> | null = null;

	constructor(keyspace: string) {
		if (!keyspace) {
			throw new Error('MonotonicIdbCtrAllocator: ctrKeyspace is required');
		}
		this.keyspace = keyspace;
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
