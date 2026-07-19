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
//            info, in-session replay (sliding window), cross-room key isolation.
//   Does NOT defend: forward secrecy, post-compromise security, cross-session
//            replay under random-64, traffic analysis.
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

	const allocator: CtrAllocator =
		ctrStrategy === 'monotonic-idb'
			? new MonotonicIdbCtrAllocator(opts.ctrKeyspace!)
			: new RandomCtrAllocator();

	// Instance-scoped key derivation cache (LRU, max 256 entries)
	const keyCache = new KeyDerivationCache();

	// Per-(roomId, senderUid) replay windows.
	// Map<roomId, Map<senderUid, SlidingReplayWindow>> — two-level to avoid
	// separator collision issues when IDs contain arbitrary characters.
	const replayWindows = new Map<string, Map<string, SlidingReplayWindow>>();

	function getReplayWindow(roomId: string, senderUid: string): SlidingReplayWindow {
		return getOrCreateNested(
			replayWindows, roomId, senderUid,
			() => new SlidingReplayWindow(replayWindow),
		);
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

		// Replay check before AEAD
		const rw = getReplayWindow(roomId, senderUid);
		if (!rw.check(ctr)) {
			throw new ReplayError(
				`sframe-chat: replay detected (ctr=${ctr}, room=${roomId}, uid=${senderUid})`,
				{ roomId, senderUid, ctr },
			);
		}

		const plaintext = await sframeDecrypt(sealed, () => sframeKey);

		// Record CTR only after successful AEAD (prevents replay-set pollution on bad frames)
		rw.accept(ctr);
		return plaintext;
	}

	function rotate(roomId: string): void {
		// Evict derived-key cache for all (roomId, *) pairs
		keyCache.evictRoom(roomId);
		// Clear replay state for all senders in this room
		replayWindows.delete(roomId);
		// Notify caller
		opts.onKeyRotated?.(roomId);
	}

	function dispose(): void {
		// No-op in v0.5; reserved for future cleanup (IDB connections, etc.)
	}

	return { seal, unseal, rotate, dispose };
}
