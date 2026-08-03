// sframe-ratchet/chat — high-level chat-mode provider.
//
// Wraps HKDF key derivation, CTR allocation, KID encoding, replay protection,
// and the existing sframeEncrypt/sframeDecrypt primitives into a single
// easy-to-use API for non-WebRTC chat applications.
//
// Subpath export: import { createChatProvider } from 'sframe-ratchet/chat'
//
// Threat model (see design doc §C):
//   Defends: AEAD confidentiality+integrity, in-session sender auth via HKDF
//            info, in-session replay (sliding window), cross-room key isolation,
//            cross-reload replay when `durableReplay` is enabled (CWE-294).
//   Does NOT defend: forward secrecy, post-compromise security, traffic analysis.
//   WARNING: Symmetric AEAD only — any room member can forge messages from any
//            other member. Sender non-repudiation requires sign-then-encrypt
//            (v0.6+ roadmap item).
//
// See design doc 2026-05-18-sframe-ratchet-chat-api-v0.5.md for full rationale.

import { sframeEncrypt, sframeDecrypt, parseHeader } from '../sframe.ts';
import { makeKid } from '../ratchet-ids.ts';
import { SFrameError } from '../errors.ts';
import { deriveAesKeyAndSalt, KeyDerivationCache } from './derive.ts';
import { RandomCtrAllocator, MonotonicIdbCtrAllocator, type CtrAllocator } from './ctr-allocator.ts';
import { SlidingReplayWindow } from './replay.ts';
import { DurableReplayGuard } from './durable-replay.ts';
import { getOrCreateNested } from '../internal/collections.ts';

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Context passed to seal/unseal identifying the room and sender. */
export interface SealContext {
	roomId: string;
	senderUid: string;
}

/** Options for createChatProvider. */
export interface ChatProviderOptions {
	/**
	 * Return an HKDF base-key with usages `['deriveKey', 'deriveBits']`.
	 * The library uses this to derive per-(roomId, senderUid) AES-128-GCM keys
	 * via HKDF-SHA-256 with room-scoped salt and sender-scoped info strings.
	 */
	getKey: (roomId: string) => Promise<CryptoKey>;
	/**
	 * CTR allocation strategy.
	 * - `'random-64'` (default): 64-bit random CTR per frame. Stateless.
	 *   Birthday bound: ~2^32 messages before collision risk becomes non-negligible.
	 *   Replay protection is bounded-set only (not monotonic — random CTRs are
	 *   non-ordered). Cross-session replay is possible (page reload wipes
	 *   replay state). Use monotonic-idb for stronger guarantees.
	 * - `'monotonic-idb'`: IDB-backed atomic counter. Requires `ctrKeyspace`.
	 *   Multi-tab safe via navigator.locks (when available). Falls back to
	 *   single-tab mode in environments without navigator.locks (Node.js).
	 */
	ctrStrategy?: 'random-64' | 'monotonic-idb';
	/** Required when ctrStrategy is 'monotonic-idb'. Namespaces the IDB store. */
	ctrKeyspace?: string;
	/**
	 * Replay window size (number of recent CTRs to track per sender per room).
	 * Default: 1024. Set to 0 to disable replay protection (debug only).
	 *
	 * Under random-64 strategy: bounded-set semantics only (no high-watermark
	 * check), since random CTRs are non-monotonic and HWM checks would
	 * incorrectly reject most messages.
	 */
	replayWindow?: number;
	/**
	 * Enable durable, cross-reload receiver-side anti-replay (CWE-294).
	 * Default: `false` (opt-in). When enabled, accepted CTRs are persisted to
	 * IndexedDB so the replay defense survives a page reload — without it, a
	 * malicious / compromised app-server can re-serve an OLD authentic sealed
	 * frame under a fresh msg_id and it verifies (the ciphertext is genuinely
	 * authentic, just old).
	 *
	 * Requires BOTH IndexedDB AND the Web Locks API. Degrades to a no-op
	 * (with a one-time warning) when either is unavailable (SSR / Node /
	 * legacy Safari <15.4). The in-memory `replayWindow` remains the
	 * session-scoped backstop in that case.
	 *
	 * `namespace` is REQUIRED when enabled — it isolates independent
	 * deployments sharing the same origin. Two deployments with the same
	 * namespace and a colliding (roomId, senderUid) would share a replay
	 * window and could false-reject each other.
	 *
	 * Defaults to `true` when a `namespace` is provided (issue #41: the
	 * previous default of `false` left the cross-reload replay vulnerability
	 * CWE-294 open by default). Set to `false` to explicitly opt out.
	 */
	durableReplay?: boolean;
	/**
	 * Namespace for the durable replay IDB store. REQUIRED when
	 * `durableReplay` is `true`. Isolates independent deployments sharing the
	 * same origin. Use a per-tenant identifier (e.g. appId or tenantId).
	 */
	namespace?: string;
	/**
	 * Durable replay window size (distinct recent CTRs per sender per room,
	 * persisted). Default: equals `replayWindow`. Must be <= `replayWindow`
	 * — the in-memory window is the session-scoped backstop, and a durable
	 * window LARGER than the in-memory one removes that backstop for the
	 * extra span (reopens a narrow in-session replay window). `0` disables
	 * the durable window (mirrors `replayWindow: 0`).
	 */
	durableReplayWindow?: number;
	/** Called synchronously when rotate(roomId) is invoked. */
	onKeyRotated?: (roomId: string) => void;
}

/** The provider returned by createChatProvider. */
export interface ChatSFrameProvider {
	/**
	 * Encrypt plaintext into an SFrame buffer for the given (roomId, senderUid).
	 * Derives AEAD key via HKDF (cached per provider instance, max 256 entries).
	 */
	seal(plaintext: Uint8Array, ctx: SealContext): Promise<Uint8Array>;
	/**
	 * Decrypt an SFrame buffer. Validates AEAD, checks replay window.
	 * Throws ReplayError on replay; throws AEADAuthError on key/uid/room mismatch.
	 */
	unseal(sealed: Uint8Array, ctx: SealContext): Promise<Uint8Array>;
	/**
	 * Evict derived-key cache and replay state for roomId.
	 * Does NOT clear CTR allocator state — CTR space is independent of crypto key.
	 * Calls onKeyRotated if provided.
	 */
	rotate(roomId: string): void;
	/** Release any resources (no-op in v0.5; reserved for future cleanup). */
	dispose(): void;
}

// ---------------------------------------------------------------------------
// Error class
// ---------------------------------------------------------------------------

/**
 * Thrown when unseal detects a replayed CTR value.
 * Extends SFrameError for uniform error handling.
 */
export class ReplayError extends SFrameError {
	readonly code = 'REPLAY' as const;

	constructor(
		message: string,
		public override readonly context?: {
			roomId?: string;
			senderUid?: string;
			ctr?: bigint;
		},
	) {
		super(message, context);
	}
}

// ---------------------------------------------------------------------------
// KID derivation for chat mode
// ---------------------------------------------------------------------------

/**
 * Compute peerIndex from senderUid: first 2 bytes of SHA-256(utf8(senderUid)) & 0xFFFF.
 * This is a convenience check only — the actual security anchor is the
 * HKDF info string which contains the full senderUid. A 16-bit hash collision
 * between two senders results in an AEAD auth failure (not a security breach).
 */
async function peerIndexForUid(senderUid: string): Promise<number> {
	const enc = new TextEncoder();
	const digest = await crypto.subtle.digest('SHA-256', enc.encode(senderUid));
	const view = new DataView(digest);
	return view.getUint16(0, false) & 0xffff; // big-endian, top 2 bytes
}

// ---------------------------------------------------------------------------
// Provider implementation
// ---------------------------------------------------------------------------

/**
 * Create a chat-mode SFrame provider.
 *
 * All state (key cache, replay windows) is scoped to the returned provider
 * instance — concurrent providers do NOT share state.
 *
 * @example
 * ```ts
 * const key = await crypto.subtle.importKey(
 *   'raw', sharedSecret32Bytes, 'HKDF', false, ['deriveKey', 'deriveBits']
 * );
 * const provider = createChatProvider({
 *   getKey: async (roomId) => key,
 * });
 * const sealed = await provider.seal(plaintext, { roomId, senderUid });
 * const plain  = await provider.unseal(sealed,  { roomId, senderUid });
 * ```
 */
export function createChatProvider(opts: ChatProviderOptions): ChatSFrameProvider {
	const replayWindow = opts.replayWindow ?? 1024;
	const ctrStrategy = opts.ctrStrategy ?? 'random-64';

	// Validate monotonic-idb requirements at construction time
	if (ctrStrategy === 'monotonic-idb' && !opts.ctrKeyspace) {
		throw new Error('createChatProvider: ctrKeyspace is required when ctrStrategy is monotonic-idb');
	}

	// Durable replay defaults to ENABLED when a namespace is provided (issue
	// #41: the previous opt-in default left CWE-294 cross-reload replay open
	// by default). Explicit `durableReplay: false` opts out. Without a
	// namespace the guard cannot be constructed — warn unless the caller
	// explicitly set durableReplay: true (which is a hard error).
	if (opts.durableReplay === true && !opts.namespace) {
		throw new Error('createChatProvider: namespace is required when durableReplay is true');
	}
	const durableReplayEnabled = opts.durableReplay !== false && !!opts.namespace;
	if (!durableReplayEnabled && opts.durableReplay !== false && !opts.namespace) {
		console.warn(
			'createChatProvider: durableReplay defaults to true but no namespace provided — ' +
			'cross-reload replay protection (CWE-294) is DISABLED. Provide a namespace to enable it.',
		);
	}
	const durableReplayWindow = opts.durableReplayWindow ?? replayWindow;
	// Architecture-council nit #5: a durable window LARGER than the in-memory
	// one removes the in-memory backstop for the extra span.
	if (durableReplayEnabled && durableReplayWindow > replayWindow) {
		throw new Error(
			`createChatProvider: durableReplayWindow (${durableReplayWindow}) must be <= replayWindow (${replayWindow})`,
		);
	}

	const allocator: CtrAllocator =
		ctrStrategy === 'monotonic-idb'
			? new MonotonicIdbCtrAllocator(opts.ctrKeyspace!, { allowSingleTab: true })
			: new RandomCtrAllocator();

	// Instance-scoped key derivation cache (LRU, max 256 entries)
	const keyCache = new KeyDerivationCache();

	// Per-(roomId, senderUid) replay windows.
	// Map<roomId, Map<senderUid, SlidingReplayWindow>> — two-level to avoid
	// separator collision issues when IDs contain arbitrary characters.
	const replayWindows = new Map<string, Map<string, SlidingReplayWindow>>();
	// Issue #48: cap the number of tracked rooms to prevent unbounded growth.
	// When the cap is exceeded, the oldest room (by insertion order) is evicted.
	const MAX_REPLAY_ROOMS = 1024;
	function evictOldReplayRooms(): void {
		while (replayWindows.size > MAX_REPLAY_ROOMS) {
			const oldest = replayWindows.keys().next().value;
			if (oldest === undefined) break;
			replayWindows.delete(oldest);
		}
	}

	// Durable cross-reload replay guard (CWE-294). Opt-in — default null.
	// When enabled, persists accepted CTRs to IndexedDB so the replay defense
	// survives a page reload. Feature-detected: no-op when IDB or Web Locks
	// is unavailable (the in-memory window remains the session-scoped backstop).
	const durable = durableReplayEnabled
		? new DurableReplayGuard({
				namespace: opts.namespace!,
				window: durableReplayWindow,
			})
		: null;

	function getReplayWindow(roomId: string, senderUid: string): SlidingReplayWindow {
		const isNew = !replayWindows.has(roomId);
		const w = getOrCreateNested(
			replayWindows, roomId, senderUid,
			() => new SlidingReplayWindow(replayWindow),
		);
		if (isNew) evictOldReplayRooms();
		return w;
	}

	/** Composite key for the durable guard — chat uses (roomId, senderUid). */
	function durableKey(roomId: string, senderUid: string): string {
		return `${roomId}|${senderUid}`;
	}

	async function seal(plaintext: Uint8Array, ctx: SealContext): Promise<Uint8Array> {
		const { roomId, senderUid } = ctx;

		const userKey = await opts.getKey(roomId);
		if (!userKey.usages.includes('deriveKey')) {
			throw new Error(
				'chat-provider: getKey must return HKDF base-key with usages [deriveKey,deriveBits]',
			);
		}

		const { aesCryptoKey, salt } = await deriveAesKeyAndSalt(userKey, roomId, senderUid, keyCache);
		const peerIndex = await peerIndexForUid(senderUid);
		const kid = makeKid(0 /* epoch=0 reserved for chat mode */, peerIndex);
		const sframeKey = { kid, epoch: 0, peerIndex, cryptoKey: aesCryptoKey, salt };

		const ctr = await allocator.next(roomId, senderUid);
		return sframeEncrypt(plaintext, sframeKey, ctr);
	}

	async function unseal(sealed: Uint8Array, ctx: SealContext): Promise<Uint8Array> {
		const { roomId, senderUid } = ctx;

		const userKey = await opts.getKey(roomId);
		if (!userKey.usages.includes('deriveKey')) {
			throw new Error(
				'chat-provider: getKey must return HKDF base-key with usages [deriveKey,deriveBits]',
			);
		}

		const { aesCryptoKey, salt } = await deriveAesKeyAndSalt(userKey, roomId, senderUid, keyCache);
		const peerIndex = await peerIndexForUid(senderUid);
		const kid = makeKid(0, peerIndex);
		const sframeKey = { kid, epoch: 0, peerIndex, cryptoKey: aesCryptoKey, salt };

		// Parse header to extract CTR for replay check BEFORE AEAD attempt
		// (avoids AEAD oracle amplification on replayed frames).
		const hdr = parseHeader(sealed);
		const ctr = hdr.ctr;

		// Replay check before AEAD. Architecture-council nit #1: in-memory
		// check FIRST (cheap, synchronous), durable check only if in-memory
		// passes (avoids the expensive IDB read on the common replay path).
		const rw = getReplayWindow(roomId, senderUid);
		if (!rw.check(ctr)) {
			throw new ReplayError(
				`sframe-chat: replay detected (ctr=${ctr}, room=${roomId}, uid=${senderUid})`,
				{ roomId, senderUid, ctr },
			);
		}
		if (durable?.available) {
			if (!(await durable.check(durableKey(roomId, senderUid), ctr))) {
				throw new ReplayError(
					`sframe-chat: durable cross-reload replay detected (ctr=${ctr}, room=${roomId}, uid=${senderUid})`,
					{ roomId, senderUid, ctr },
				);
			}
		}

		const plaintext = await sframeDecrypt(sealed, () => sframeKey);

		// Record CTR only after successful AEAD (prevents replay-set pollution
		// on bad frames). In-memory first (synchronous), durable second (async
		// write-through — non-fatal on failure, the in-memory window still
		// defends this session).
		rw.accept(ctr);
		if (durable?.available) {
			await durable.accept(durableKey(roomId, senderUid), ctr);
		}
		return plaintext;
	}

	function rotate(roomId: string): void {
		// Evict derived-key cache for all (roomId, *) pairs
		keyCache.evictRoom(roomId);
		// Clear in-memory replay state for all senders in this room
		const senders = replayWindows.get(roomId);
		replayWindows.delete(roomId);
		// Clear durable replay state for all senders in this room
		// (architecture-council nit #2: matching clear on key rotation so
		// stale CTRs from the rotated key do not false-reject fresh frames
		// under the new key). Best-effort — fire-and-forget; clear() swallows
		// IDB errors internally.
		if (durable?.available && senders) {
			for (const senderUid of senders.keys()) {
				void durable.clear(durableKey(roomId, senderUid));
			}
		}
		// Notify caller
		opts.onKeyRotated?.(roomId);
	}

	function dispose(): void {
		// No-op in v0.5; reserved for future cleanup (IDB connections, etc.)
	}

	return { seal, unseal, rotate, dispose };
}
