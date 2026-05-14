// Shared test helpers — imported by multiple test suites.
// Consolidated from per-file copies; bodies are byte-for-byte identical.

import { deriveSenderKeys, deriveEpochKeyTable } from '../ratchet-crypto.ts';
import type { PerSenderKeyBundle } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';

/**
 * Wrap a Uint8Array body in a minimal RTCEncodedVideoFrame mock.
 * Data is copied so mutations to `body` after construction don't alias the frame.
 */
export function makeFrame(body: Uint8Array): RTCEncodedVideoFrame {
	const buf = new ArrayBuffer(body.byteLength);
	new Uint8Array(buf).set(body);
	return { data: buf } as unknown as RTCEncodedVideoFrame;
}

/**
 * Build a PerSenderKeyBundle for a single sender at the initial ratchet step.
 */
export async function makeBundle(
	chainKey: Uint8Array,
	epoch: number,
	peerIndex: PeerIndex,
): Promise<PerSenderKeyBundle> {
	const k = await deriveSenderKeys(chainKey, epoch, peerIndex);
	return { cryptoKey: k.cryptoKey, salt: k.salt, rawKey: k.rawKey };
}

/**
 * Build a Map<PeerIndex, PerSenderKeyBundle> for all peers in `peerIndexMap`.
 */
export async function makeBundles(
	chainKey: Uint8Array,
	epoch: number,
	peerIndexMap: Record<string, PeerIndex>,
): Promise<Map<PeerIndex, PerSenderKeyBundle>> {
	const table = await deriveEpochKeyTable(chainKey, epoch, peerIndexMap);
	const out = new Map<PeerIndex, PerSenderKeyBundle>();
	for (const [pi, k] of table) out.set(pi, { cryptoKey: k.cryptoKey, salt: k.salt, rawKey: k.rawKey });
	return out;
}
