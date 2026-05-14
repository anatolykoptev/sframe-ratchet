// Tests for SIF (Secure Interoperable Frame) trailer support.
// The trailer is an optional suffix on encrypted frames that lets a receiver
// detect "this frame is SFrame-encrypted" before attempting AEAD — enabling
// mixed-room deployments where some participants run E2EE and others do not.

import { describe, it, expect } from 'vitest';
import { DEFAULT_SIF_TRAILER, getDefaultSifTrailer } from '../sif-trailer.ts';
import { createWorkerState, handleMessage, installEpoch } from '../worker-state.ts';
import { encodeFrame, decodeFrame } from '../worker-frame.ts';
import { randomChainKey } from '../ratchet-crypto.ts';
import { sframeEncrypt } from '../sframe.ts';
import type { OutMsg } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';
import { makeFrame, makeBundle, makeBundles } from './helpers.ts';

// --- DEFAULT_SIF_TRAILER / getDefaultSifTrailer ---------------------------

describe('getDefaultSifTrailer', () => {
	it('returns a 9-byte sequence', () => {
		const t = getDefaultSifTrailer();
		expect(t).toBeInstanceOf(Uint8Array);
		expect(t.byteLength).toBe(9);
	});

	it('returns the same bytes each call (constant identity)', () => {
		const a = getDefaultSifTrailer();
		const b = getDefaultSifTrailer();
		expect(a).toEqual(b);
	});

	it('returns a fresh copy (mutation does not affect subsequent calls)', () => {
		const a = getDefaultSifTrailer();
		a[0] = 0xff;
		const b = getDefaultSifTrailer();
		expect(b[0]).toBe(DEFAULT_SIF_TRAILER[0]);
	});

	it('DEFAULT_SIF_TRAILER is 9 bytes and matches getDefaultSifTrailer', () => {
		expect(DEFAULT_SIF_TRAILER.byteLength).toBe(9);
		expect(DEFAULT_SIF_TRAILER).toEqual(getDefaultSifTrailer());
	});
});

// --- Round-trip with trailer enabled -------------------------------------

describe('SIF trailer round-trip', () => {
	async function makeRoundTrip(trailer: Uint8Array) {
		const chainKey = randomChainKey();
		const epoch = 0;
		const peerIndexMap = { alice: 0 as PeerIndex, bob: 1 as PeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const emittedSend: OutMsg[] = [];
		const sender = createWorkerState((m) => emittedSend.push(m));
		sender.sifTrailer = new Uint8Array(trailer); // copy
		installEpoch(sender, epoch, 0 as PeerIndex, bundles);

		const emittedRecv: OutMsg[] = [];
		const receiver = createWorkerState((m) => emittedRecv.push(m));
		receiver.sifTrailer = new Uint8Array(trailer);
		installEpoch(receiver, epoch, 1 as PeerIndex, bundles);

		const plaintext = new TextEncoder().encode('hello mixed room');
		const frame = makeFrame(plaintext);

		await encodeFrame(sender, frame);
		const wireBytes = new Uint8Array(frame.data);

		return { wireBytes, frame, receiver, emittedRecv, plaintext };
	}

	it('encoded frame ends with the trailer bytes', async () => {
		const trailer = getDefaultSifTrailer();
		const { wireBytes } = await makeRoundTrip(trailer);

		const tail = wireBytes.subarray(wireBytes.byteLength - trailer.byteLength);
		expect(tail).toEqual(trailer);
	});

	it('decode strips trailer and recovers plaintext', async () => {
		const trailer = getDefaultSifTrailer();
		const { frame, receiver, plaintext } = await makeRoundTrip(trailer);

		await decodeFrame(receiver, frame);
		expect(new Uint8Array(frame.data)).toEqual(plaintext);
	});

	it('no decrypt_failure emitted on a clean round-trip', async () => {
		const trailer = getDefaultSifTrailer();
		const { frame, receiver, emittedRecv } = await makeRoundTrip(trailer);

		await decodeFrame(receiver, frame);
		expect(emittedRecv.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);
	});

	it('custom 16-byte trailer: round-trip works', async () => {
		const trailer = new Uint8Array(16).fill(0xab);
		const { frame, receiver, plaintext } = await makeRoundTrip(trailer);

		await decodeFrame(receiver, frame);
		expect(new Uint8Array(frame.data)).toEqual(plaintext);
	});
});

// --- Pass-through: frame WITHOUT trailer when trailer enabled -----------

describe('SIF pass-through (non-E2EE frame)', () => {
	it('plain frame without trailer is passed through unchanged', async () => {
		const chainKey = randomChainKey();
		const bundles = await makeBundles(chainKey, 0, { alice: 0 as PeerIndex });

		const receiver = createWorkerState(() => {});
		receiver.sifTrailer = getDefaultSifTrailer();
		installEpoch(receiver, 0, 0 as PeerIndex, bundles);

		const plainBytes = new TextEncoder().encode('plain unencrypted frame');
		const frame = makeFrame(plainBytes);
		const originalData = new Uint8Array(frame.data).slice();

		// Must not throw, must not change frame.data.
		await expect(decodeFrame(receiver, frame)).resolves.toBeUndefined();
		expect(new Uint8Array(frame.data)).toEqual(originalData);
	});

	it('no decrypt_failure emitted for pass-through frame', async () => {
		const emitted: OutMsg[] = [];
		const receiver = createWorkerState((m) => emitted.push(m));
		receiver.sifTrailer = getDefaultSifTrailer();
		// No epoch needed — pass-through exits before any epoch lookup.

		const frame = makeFrame(new TextEncoder().encode('plain'));
		await decodeFrame(receiver, frame);
		expect(emitted.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);
	});
});

// --- Trailer NOT enabled: frame WITH trailer bytes treated as ciphertext --

describe('SIF trailer not enabled', () => {
	it('frame carrying trailer bytes (trailer disabled) → AEAD fails → decrypt_failure emitted', async () => {
		// Sender has trailer enabled; receiver has it disabled.
		const chainKey = randomChainKey();
		const epoch = 0;
		const peerIndexMap = { alice: 0 as PeerIndex, bob: 1 as PeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const sender = createWorkerState(() => {});
		sender.sifTrailer = getDefaultSifTrailer();
		installEpoch(sender, epoch, 0 as PeerIndex, bundles);

		const emittedRecv: OutMsg[] = [];
		const receiver = createWorkerState((m) => emittedRecv.push(m));
		// sifTrailer intentionally left undefined (feature disabled)
		installEpoch(receiver, epoch, 1 as PeerIndex, bundles);

		const frame = makeFrame(new TextEncoder().encode('hello'));
		await encodeFrame(sender, frame); // encoded with trailer

		// Receiver tries to parse & decrypt including the trailer bytes → AEAD fails.
		await expect(decodeFrame(receiver, frame)).rejects.toBeDefined();
		const failures = emittedRecv.filter((m) => m.type === 'decrypt_failure');
		expect(failures.length).toBeGreaterThan(0);
	});
});

// --- Control message: set-sif-trailer at runtime -------------------------

describe('set-sif-trailer control message', () => {
	it('enables trailer mid-stream, frames before are plain pass-through, after are E2EE', async () => {
		const chainKey = randomChainKey();
		const epoch = 0;
		const peerIndexMap = { alice: 0 as PeerIndex, bob: 1 as PeerIndex };
		const bundles = await makeBundles(chainKey, epoch, peerIndexMap);

		const sender = createWorkerState(() => {});
		installEpoch(sender, epoch, 0 as PeerIndex, bundles);

		const emittedRecv: OutMsg[] = [];
		const receiver = createWorkerState((m) => emittedRecv.push(m));
		installEpoch(receiver, epoch, 1 as PeerIndex, bundles);

		// --- Before enabling trailer ---
		// Sender: no trailer; receiver: no trailer.
		const plainFrame = makeFrame(new TextEncoder().encode('before e2ee'));
		const originalBytes = new Uint8Array(plainFrame.data).slice();
		// Encode without trailer: this is a real SFrame-encrypted frame, no suffix.
		await encodeFrame(sender, plainFrame);

		// Receiver without trailer decrypts normally.
		await decodeFrame(receiver, plainFrame);
		expect(emittedRecv.filter((m) => m.type === 'decrypt_failure')).toHaveLength(0);

		// --- Enable trailer on both sender and receiver ---
		const trailer = getDefaultSifTrailer();
		await handleMessage(sender, { type: 'set-sif-trailer', trailer });
		await handleMessage(receiver, { type: 'set-sif-trailer', trailer });

		// After enabling: a plain frame (no trailer) passes through on receiver.
		const afterPlainFrame = makeFrame(new TextEncoder().encode('still plain'));
		const afterPlainOriginal = new Uint8Array(afterPlainFrame.data).slice();
		await expect(decodeFrame(receiver, afterPlainFrame)).resolves.toBeUndefined();
		expect(new Uint8Array(afterPlainFrame.data)).toEqual(afterPlainOriginal);

		// After enabling: sender appends trailer; receiver strips it and decrypts.
		const e2eeFrame = makeFrame(new TextEncoder().encode('now e2ee'));
		const e2eePlaintext = new TextEncoder().encode('now e2ee');
		await encodeFrame(sender, e2eeFrame);
		const wireBytes = new Uint8Array(e2eeFrame.data);
		expect(wireBytes.subarray(wireBytes.byteLength - trailer.byteLength)).toEqual(trailer);
		await decodeFrame(receiver, e2eeFrame);
		expect(new Uint8Array(e2eeFrame.data)).toEqual(e2eePlaintext);

		// --- Disable trailer ---
		await handleMessage(sender, { type: 'set-sif-trailer', trailer: null });
		await handleMessage(receiver, { type: 'set-sif-trailer', trailer: null });

		// After disabling: normal round-trip (no trailer appended/checked).
		const postDisableFrame = makeFrame(new TextEncoder().encode('post disable'));
		const postDisablePlain = new TextEncoder().encode('post disable');
		await encodeFrame(sender, postDisableFrame);
		// Wire should NOT end with old trailer.
		const postWire = new Uint8Array(postDisableFrame.data);
		const oldTail = postWire.subarray(postWire.byteLength - trailer.byteLength);
		expect(oldTail).not.toEqual(trailer);
		await decodeFrame(receiver, postDisableFrame);
		expect(new Uint8Array(postDisableFrame.data)).toEqual(postDisablePlain);
	});
});

// --- Pathological: short frame shorter than trailer ----------------------

describe('pathological short frame', () => {
	it('frame shorter than trailer length → pass-through (no crash)', async () => {
		const receiver = createWorkerState(() => {});
		receiver.sifTrailer = getDefaultSifTrailer(); // 9 bytes

		// Frame shorter than 9 bytes.
		const tinyFrame = makeFrame(new Uint8Array([0x01, 0x02]));
		const originalData = new Uint8Array(tinyFrame.data).slice();

		await expect(decodeFrame(receiver, tinyFrame)).resolves.toBeUndefined();
		expect(new Uint8Array(tinyFrame.data)).toEqual(originalData);
	});

	it('frame exactly 0 bytes → pass-through (no crash)', async () => {
		const receiver = createWorkerState(() => {});
		receiver.sifTrailer = getDefaultSifTrailer();

		const emptyFrame = makeFrame(new Uint8Array(0));
		await expect(decodeFrame(receiver, emptyFrame)).resolves.toBeUndefined();
		expect(new Uint8Array(emptyFrame.data)).toHaveLength(0);
	});
});
