// Tests for the telemetry hook (MetricsEvent postMessage events).
//
// The worker posts `{ type: 'metrics'; event: MetricsEvent }` when
// `state.metricsEnabled` is true. These tests drive the frame pipeline
// directly (no DOM / no real Worker) — same pattern as worker-frame-queue.test.ts.
//
// Coverage requirements:
//   - encrypt event fires with correct epoch/peer/bytes
//   - decrypt event fires
//   - decrypt_fail fires with the typed error code
//   - ratchet_retry fires when the window succeeds
//   - ratchet_retry fires with succeeded=false on exhaustion
//   - queue_drop fires for pre_epoch_full reason
//   - queue_drop fires for stale_epoch reason
//   - epoch_advance fires on epoch promotion
//   - metrics OFF by default — no events emitted
//   - set-metrics-enabled toggles on then off

import { describe, it, expect } from 'vitest';
import { createWorkerState, installEpoch, handleMessage } from '../worker-state.ts';
import { encodeFrame, decodeFrame, drainPreEpochQueue } from '../worker-frame.ts';
import {
	deriveSenderKeys,
	randomChainKey,
	deriveNextSenderKey,
} from '../ratchet-crypto.ts';
import { sframeEncrypt } from '../sframe.ts';
import type { MetricsEvent, OutMsg } from '../worker-types.ts';
import type { PeerIndex } from '../types.ts';
import { PRE_EPOCH_QUEUE_CAP } from '../worker-types.ts';
import { makeBundles } from './helpers.ts';

function makeEncryptedFrame(body: Uint8Array): RTCEncodedVideoFrame {
	const buf = new ArrayBuffer(body.byteLength);
	new Uint8Array(buf).set(body);
	return { data: buf } as unknown as RTCEncodedVideoFrame;
}

function makePlainFrame(body: Uint8Array): RTCEncodedVideoFrame {
	const buf = new ArrayBuffer(body.byteLength);
	new Uint8Array(buf).set(body);
	return { data: buf } as unknown as RTCEncodedVideoFrame;
}

function metricsOf(msgs: OutMsg[]): MetricsEvent[] {
	return msgs
		.filter((m): m is { type: 'metrics'; event: MetricsEvent } => m.type === 'metrics')
		.map((m) => m.event);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('metrics — disabled by default', () => {
	it('no metrics events emitted when metricsEnabled=false', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		// state.metricsEnabled is false by default

		const chainKey = randomChainKey();
		const peerIndexMap = { alice: 0 as PeerIndex };
		const bundles = await makeBundles(chainKey, 0, peerIndexMap);
		installEpoch(state, 0, 0, bundles);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new TextEncoder().encode('hello');
		const ciphertext = await sframeEncrypt(plaintext, key, 0n);
		const frame = makeEncryptedFrame(ciphertext);
		await decodeFrame(state, frame);

		expect(metricsOf(emitted)).toHaveLength(0);
	});
});

describe('metrics — encrypt event', () => {
	it('fires with correct epoch, peerIndex, bytes after encodeFrame', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.metricsEnabled = true;

		const chainKey = randomChainKey();
		const bundles = await makeBundles(chainKey, 0, { alice: 0 as PeerIndex });
		installEpoch(state, 0, 0 as PeerIndex, bundles);

		const body = new TextEncoder().encode('frame-body');
		const frame = makePlainFrame(body);
		await encodeFrame(state, frame);

		const events = metricsOf(emitted);
		const enc = events.find((e) => e.kind === 'encrypt');
		expect(enc).toBeDefined();
		expect(enc).toMatchObject({ kind: 'encrypt', epoch: 0, peerIndex: 0, bytes: body.byteLength });
	});
});

describe('metrics — decrypt event', () => {
	it('fires with correct epoch, peerIndex, bytes after decodeFrame', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.metricsEnabled = true;

		const chainKey = randomChainKey();
		const peerIndexMap = { alice: 0 as PeerIndex };
		const bundles = await makeBundles(chainKey, 0, peerIndexMap);
		installEpoch(state, 0, 0 as PeerIndex, bundles);

		const key = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new TextEncoder().encode('decrypt-me');
		const ciphertext = await sframeEncrypt(plaintext, key, 0n);
		const frame = makeEncryptedFrame(ciphertext);
		await decodeFrame(state, frame);

		const events = metricsOf(emitted);
		const dec = events.find((e) => e.kind === 'decrypt');
		expect(dec).toBeDefined();
		expect(dec).toMatchObject({ kind: 'decrypt', epoch: 0, peerIndex: 0 });
		expect((dec as { bytes: number }).bytes).toBeGreaterThan(0);
	});
});

describe('metrics — decrypt_fail event', () => {
	it('fires with a typed error code when AEAD fails', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.metricsEnabled = true;
		state.ratchetWindowSize = 0; // disable retry so failure is immediate

		const chainKey = randomChainKey();
		const peerIndexMap = { alice: 0 as PeerIndex };
		const bundles = await makeBundles(chainKey, 0, peerIndexMap);
		installEpoch(state, 0, 0 as PeerIndex, bundles);

		// Encrypt with a DIFFERENT chain key so the receiver can't decrypt.
		const wrongChainKey = randomChainKey();
		const wrongKey = await deriveSenderKeys(wrongChainKey, 0, 0);
		const plaintext = new TextEncoder().encode('bad-frame');
		const ciphertext = await sframeEncrypt(plaintext, wrongKey, 0n);
		const frame = makeEncryptedFrame(ciphertext);

		await expect(decodeFrame(state, frame)).rejects.toThrow();

		const events = metricsOf(emitted);
		const fail = events.find((e) => e.kind === 'decrypt_fail');
		expect(fail).toBeDefined();
		expect((fail as { code: string }).code).toBeTruthy();
	});

	it('fires with STALE_EPOCH code for stale-epoch drop', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.metricsEnabled = true;

		const chainKey = randomChainKey();
		const bundles0 = await makeBundles(chainKey, 0, { alice: 0 as PeerIndex });
		installEpoch(state, 0, 0 as PeerIndex, bundles0);
		// Advance to epoch 1 then wipe epoch 0 by advancing the gate directly.
		const bundles1 = await makeBundles(chainKey, 1, { alice: 0 as PeerIndex });
		installEpoch(state, 1, 0 as PeerIndex, bundles1);
		// Force min-valid forward to block epoch 0.
		state.currentMinValidEpoch = 1;

		// Encrypt a frame under epoch 0 (now stale).
		const key0 = await deriveSenderKeys(chainKey, 0, 0);
		const plaintext = new TextEncoder().encode('stale');
		const ciphertext = await sframeEncrypt(plaintext, key0, 0n);
		const frame = makeEncryptedFrame(ciphertext);

		await expect(decodeFrame(state, frame)).rejects.toThrow();

		const events = metricsOf(emitted);
		const fail = events.find((e) => e.kind === 'decrypt_fail');
		expect(fail).toBeDefined();
		expect((fail as { code: string }).code).toBe('STALE_EPOCH');
	});
});

describe('metrics — ratchet_retry event', () => {
	it('fires with succeeded=true when window finds the advanced key', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.metricsEnabled = true;
		state.ratchetWindowSize = 4;

		const chainKey = randomChainKey();
		const peerIndexMap = { alice: 0 as PeerIndex };
		const bundles = await makeBundles(chainKey, 0, peerIndexMap);
		installEpoch(state, 0, 0 as PeerIndex, bundles);

		// Advance the sender key 2 steps.
		const baseKey = await deriveSenderKeys(chainKey, 0, 0);
		const step1 = await deriveNextSenderKey(baseKey.rawKey, baseKey.salt, 0, 0);
		const step2 = await deriveNextSenderKey(step1.rawKey, step1.salt, 0, 0);

		const plaintext = new TextEncoder().encode('advanced');
		const ciphertext = await sframeEncrypt(plaintext, step2, 0n);
		const frame = makeEncryptedFrame(ciphertext);
		await decodeFrame(state, frame);

		const events = metricsOf(emitted);
		const retry = events.find((e) => e.kind === 'ratchet_retry');
		expect(retry).toBeDefined();
		expect((retry as { succeeded: boolean }).succeeded).toBe(true);
		expect((retry as { steps: number }).steps).toBe(2);
	});

	it('fires with succeeded=false when window is exhausted', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.metricsEnabled = true;
		state.ratchetWindowSize = 2;

		const chainKey = randomChainKey();
		const bundles = await makeBundles(chainKey, 0, { alice: 0 as PeerIndex });
		installEpoch(state, 0, 0 as PeerIndex, bundles);

		// Advance sender key 5 steps — beyond the window of 2.
		const baseKey = await deriveSenderKeys(chainKey, 0, 0);
		const s1 = await deriveNextSenderKey(baseKey.rawKey, baseKey.salt, 0, 0);
		const s2 = await deriveNextSenderKey(s1.rawKey, s1.salt, 0, 0);
		const s3 = await deriveNextSenderKey(s2.rawKey, s2.salt, 0, 0);
		const s4 = await deriveNextSenderKey(s3.rawKey, s3.salt, 0, 0);
		const s5 = await deriveNextSenderKey(s4.rawKey, s4.salt, 0, 0);

		const ciphertext = await sframeEncrypt(new TextEncoder().encode('too-far'), s5, 0n);
		const frame = makeEncryptedFrame(ciphertext);
		await expect(decodeFrame(state, frame)).rejects.toThrow();

		const events = metricsOf(emitted);
		const retry = events.find((e) => e.kind === 'ratchet_retry');
		expect(retry).toBeDefined();
		expect((retry as { succeeded: boolean }).succeeded).toBe(false);
	});
});

describe('metrics — queue_drop event', () => {
	it('fires with reason pre_epoch_full when the ring is overflowed', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.metricsEnabled = true;
		// No epoch installed → all frames queue.

		const chainKey = randomChainKey();
		const key = await deriveSenderKeys(chainKey, 0, 0);

		// Fill the queue to capacity + 1 to trigger a drop.
		for (let i = 0; i <= PRE_EPOCH_QUEUE_CAP; i++) {
			const ct = await sframeEncrypt(new TextEncoder().encode(`f${i}`), key, BigInt(i));
			await decodeFrame(state, makeEncryptedFrame(ct));
		}

		const events = metricsOf(emitted);
		const drop = events.find((e) => e.kind === 'queue_drop' && e.reason === 'pre_epoch_full');
		expect(drop).toBeDefined();
	});

	it('fires with reason stale_epoch for stale-epoch gate drop', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.metricsEnabled = true;

		const chainKey = randomChainKey();
		const bundles = await makeBundles(chainKey, 0, { alice: 0 as PeerIndex });
		installEpoch(state, 0, 0 as PeerIndex, bundles);
		state.currentMinValidEpoch = 1; // epoch 0 is now stale

		const key0 = await deriveSenderKeys(chainKey, 0, 0);
		const ciphertext = await sframeEncrypt(new TextEncoder().encode('stale'), key0, 0n);
		const frame = makeEncryptedFrame(ciphertext);
		await expect(decodeFrame(state, frame)).rejects.toThrow();

		const events = metricsOf(emitted);
		const drop = events.find((e) => e.kind === 'queue_drop' && e.reason === 'stale_epoch');
		expect(drop).toBeDefined();
		expect((drop as { epoch?: number }).epoch).toBe(0);
	});
});

describe('metrics — epoch_advance event', () => {
	it('fires when epoch advances from an established epoch', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.metricsEnabled = true;

		const chainKey = randomChainKey();
		const b0 = await makeBundles(chainKey, 0, { alice: 0 as PeerIndex });
		installEpoch(state, 0, 0 as PeerIndex, b0);
		const b1 = await makeBundles(chainKey, 1, { alice: 0 as PeerIndex });
		installEpoch(state, 1, 0 as PeerIndex, b1);

		const events = metricsOf(emitted);
		const advance = events.find((e) => e.kind === 'epoch_advance');
		expect(advance).toBeDefined();
		expect(advance).toMatchObject({ kind: 'epoch_advance', from: 0, to: 1 });
	});

	it('does NOT fire for the first epoch install (no prior epoch)', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));
		state.metricsEnabled = true;

		const chainKey = randomChainKey();
		const b0 = await makeBundles(chainKey, 0, { alice: 0 as PeerIndex });
		installEpoch(state, 0, 0 as PeerIndex, b0);

		const events = metricsOf(emitted);
		expect(events.find((e) => e.kind === 'epoch_advance')).toBeUndefined();
	});
});

describe('metrics — set-metrics-enabled control message', () => {
	it('toggles metrics on then off', async () => {
		const emitted: OutMsg[] = [];
		const state = createWorkerState((m) => emitted.push(m));

		const chainKey = randomChainKey();
		const bundles = await makeBundles(chainKey, 0, { alice: 0 as PeerIndex });

		// Enable metrics via handleMessage.
		await handleMessage(state, { type: 'set-metrics-enabled', enabled: true });
		installEpoch(state, 0, 0 as PeerIndex, bundles);
		const key = await deriveSenderKeys(chainKey, 0, 0);
		const ct1 = await sframeEncrypt(new TextEncoder().encode('on'), key, 0n);
		await decodeFrame(state, makeEncryptedFrame(ct1));

		const afterOn = metricsOf(emitted).length;
		expect(afterOn).toBeGreaterThan(0);

		// Disable.
		await handleMessage(state, { type: 'set-metrics-enabled', enabled: false });
		const ct2 = await sframeEncrypt(new TextEncoder().encode('off'), key, 1n);
		await decodeFrame(state, makeEncryptedFrame(ct2));

		const afterOff = metricsOf(emitted).length;
		expect(afterOff).toBe(afterOn); // no new events
	});
});
