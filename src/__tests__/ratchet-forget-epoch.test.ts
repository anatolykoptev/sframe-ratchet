// Memory-leak fix verification: rotating epochs must release old key
// material via forgetEpoch after the spec §7.4 grace window.
//
// Found via go-code dead-code audit: RoomRatchet.forgetEpoch existed
// since the original SFrame ratchet but had no callers, so the
// `epochs` Map grew unbounded across membership changes. In long
// calls (SFU room with frequent join/leave churn) this accumulates
// per-rotation state and never frees it. This test pins the new
// scheduled cleanup so a regression that breaks the wire-up surfaces
// in CI rather than after a multi-hour soak.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { RoomRatchet } from '../ratchet.ts';

// We bypass the real startNewEpoch path (which needs subtle.crypto +
// X25519 wrapping) by reaching directly into the private installEpoch
// seam. The thing we care about — that a setTimeout schedules a
// forgetEpoch on the prior version — is structural and lives in
// installEpoch alone.

const PEER_SELF = { peerId: 'aaa', kpub: new Uint8Array(32) };
const PEER_B = { peerId: 'bbb', kpub: new Uint8Array(32) };

interface RatchetSeam {
	installEpoch(version: number, chainKey: Uint8Array, peerIndexMap: Record<string, number>): Promise<void>;
	epochs: Map<number, unknown>;
	currentEpoch: number;
}

async function install(r: RoomRatchet, version: number): Promise<void> {
	const seam = r as unknown as RatchetSeam;
	await seam.installEpoch(version, new Uint8Array(32), { aaa: 0, bbb: 1 });
}

describe('RoomRatchet — forgetEpoch wiring (#60-followup)', () => {
	beforeEach(() => {
		vi.useFakeTimers();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it('keeps prior epoch during the 5s grace window', async () => {
		const r = new RoomRatchet({
			identity: PEER_SELF as never,
			initialPeers: [PEER_B as never],
		});
		await install(r, 0);
		await install(r, 1);
		// Advance up to but not past the 5s grace.
		vi.advanceTimersByTime(4_900);
		const seam = r as unknown as RatchetSeam;
		// Both epochs MUST still be queryable — late frames from epoch 0
		// must be decryptable until the grace expires.
		expect(seam.epochs.has(0)).toBe(true);
		expect(seam.epochs.has(1)).toBe(true);
	});

	it('drops the prior epoch after the grace window', async () => {
		const r = new RoomRatchet({
			identity: PEER_SELF as never,
			initialPeers: [PEER_B as never],
		});
		await install(r, 0);
		await install(r, 1);
		vi.advanceTimersByTime(5_100);
		const seam = r as unknown as RatchetSeam;
		expect(seam.epochs.has(0)).toBe(false);
		expect(seam.epochs.has(1)).toBe(true);
	});

	it('chains across many rotations — only the current epoch is kept long-term', async () => {
		const r = new RoomRatchet({
			identity: PEER_SELF as never,
			initialPeers: [PEER_B as never],
		});
		await install(r, 0);
		for (let v = 1; v <= 4; v++) {
			vi.advanceTimersByTime(1_000);
			await install(r, v);
		}
		// Advance past the LAST scheduled cleanup so every prior
		// timer fires.
		vi.advanceTimersByTime(10_000);
		const seam = r as unknown as RatchetSeam;
		expect(seam.epochs.size).toBe(1);
		expect(seam.epochs.has(4)).toBe(true);
	});
});
