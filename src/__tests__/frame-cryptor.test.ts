// Tests for the frame-cryptor transit-only graceful-degrade path.
//
// vitest/jsdom exposes neither RTCRtpScriptTransform nor
// RTCRtpSender.prototype.createEncodedStreams, so supportsSFrame() returns
// { native: false, fallback: false } without any manual stubbing.
// That makes the jsdom environment a natural harness for the transit-only
// branch — no mocking needed.
import { describe, it, expect, vi } from 'vitest';
import { supportsSFrame, FrameCryptor } from '../frame-cryptor.ts';

describe('supportsSFrame', () => {
	it('returns {native:false, fallback:false} in jsdom (no WebRTC transform APIs)', () => {
		const { native, fallback } = supportsSFrame();
		expect(native).toBe(false);
		expect(fallback).toBe(false);
	});
});

describe('FrameCryptor transit-only mode', () => {
	function makeWorker(): Worker {
		return { postMessage: vi.fn(), terminate: vi.fn() } as unknown as Worker;
	}

	it('transitOnly is true when no SFrame APIs are present', () => {
		const cryptor = new FrameCryptor({
			worker: makeWorker(), role: 'sender', peerId: 'p1', peerIndex: 0,
		});
		expect(cryptor.transitOnly).toBe(true);
	});

	it('attachSender does not throw in transit-only mode', () => {
		const worker = makeWorker();
		const cryptor = new FrameCryptor({
			worker, role: 'sender', peerId: 'p1', peerIndex: 0,
		});
		const sender = {} as RTCRtpSender;
		expect(() => cryptor.attachSender(sender)).not.toThrow();
	});

	it('attachSender does not post init message to worker in transit-only mode', () => {
		const worker = makeWorker();
		const cryptor = new FrameCryptor({
			worker, role: 'sender', peerId: 'p1', peerIndex: 0,
		});
		const sender = {} as RTCRtpSender;
		cryptor.attachSender(sender);
		// ensureInit is bypassed → postMessage should never be called
		expect((worker.postMessage as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
	});

	it('attachReceiver does not throw in transit-only mode', () => {
		const worker = makeWorker();
		const cryptor = new FrameCryptor({
			worker, role: 'receiver', peerId: 'p1', peerIndex: 0,
		});
		const receiver = {} as RTCRtpReceiver;
		expect(() => cryptor.attachReceiver(receiver)).not.toThrow();
	});

	it('attachReceiver does not post init message in transit-only mode', () => {
		const worker = makeWorker();
		const cryptor = new FrameCryptor({
			worker, role: 'receiver', peerId: 'p1', peerIndex: 0,
		});
		const receiver = {} as RTCRtpReceiver;
		cryptor.attachReceiver(receiver);
		expect((worker.postMessage as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
	});

	it('detach is safe when nothing was attached (transit-only)', () => {
		const worker = makeWorker();
		const cryptor = new FrameCryptor({
			worker, role: 'sender', peerId: 'p1', peerIndex: 0,
		});
		expect(() => cryptor.detach()).not.toThrow();
		// No teardown message posted since worker was never init'd
		expect((worker.postMessage as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
	});

	it('multiple attachSender calls in transit-only mode do not accumulate detach callbacks', () => {
		const worker = makeWorker();
		const cryptor = new FrameCryptor({
			worker, role: 'sender', peerId: 'p1', peerIndex: 0,
		});
		const sender = {} as RTCRtpSender;
		cryptor.attachSender(sender);
		cryptor.attachSender(sender);
		cryptor.attachSender(sender);
		// detach with no attached transforms — should still be safe
		expect(() => cryptor.detach()).not.toThrow();
	});
});
