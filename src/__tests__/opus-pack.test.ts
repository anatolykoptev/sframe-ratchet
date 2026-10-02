// Opus frame packing (opus-pack.ts). The packet format is checked against
// real libopus (opusscript), not against our own parser: a packed packet must
// decode to exactly the PCM its frames decode to one by one. A
// parse(build()) round trip alone would only encode one guess twice.

import { describe, it, expect } from 'vitest';
import OpusScript from 'opusscript';
import {
	buildOpusPacket,
	opusFrameSamples,
	OpusPacker,
	OPUS_MAX_PACKET_SAMPLES,
	parseOpusPacket,
} from '../opus-pack.ts';
import { createWorkerState, handleMessage, installEpoch } from '../worker-state.ts';
import { decodeFrame, pipe } from '../worker-frame.ts';
import { randomChainKey } from '../ratchet-crypto.ts';
import { makeBundles } from './helpers.ts';
import type { PeerIndex } from '../types.ts';

const OPUS_SET_VBR = 4006;
const OPUS_SET_BITRATE = 4002;

/** 20 ms frames from real libopus: a 140 Hz sawtooth with a 3 Hz tremolo. */
function encodeFrames(n: number, opts: { bitrate: number; vbr: boolean }): Uint8Array[] {
	const enc = new OpusScript(48000, 1, OpusScript.Application.VOIP);
	enc.encoderCTL(OPUS_SET_BITRATE, opts.bitrate);
	enc.encoderCTL(OPUS_SET_VBR, opts.vbr ? 1 : 0);
	const out: Uint8Array[] = [];
	let t = 0;
	for (let f = 0; f < n; f++) {
		const pcm = new Int16Array(960);
		for (let i = 0; i < 960; i++, t++) {
			const saw = ((t * 140) / 48000) % 1;
			const amp = 0.25 * (0.7 + 0.3 * Math.sin((2 * Math.PI * 3 * t) / 48000));
			// Some noise so VBR frames differ in size.
			pcm[i] = Math.round((saw - 0.5) * 2 * amp * 32767 + (Math.random() - 0.5) * 2000);
		}
		out.push(new Uint8Array(enc.encode(Buffer.from(pcm.buffer), 960)));
	}
	enc.delete();
	return out;
}

function decodeAll(packets: Uint8Array[]): Int16Array {
	const dec = new OpusScript(48000, 1, OpusScript.Application.VOIP);
	const chunks: Int16Array[] = [];
	for (const p of packets) {
		const pcm = dec.decode(Buffer.from(p));
		chunks.push(new Int16Array(pcm.buffer.slice(pcm.byteOffset, pcm.byteOffset + pcm.byteLength)));
	}
	dec.delete();
	const total = chunks.reduce((s, c) => s + c.length, 0);
	const all = new Int16Array(total);
	let o = 0;
	for (const c of chunks) { all.set(c, o); o += c.length; }
	return all;
}

function frameOf(bytes: Uint8Array): { data: ArrayBuffer } {
	return { data: bytes.slice().buffer };
}

describe('buildOpusPacket against libopus', () => {
	// opusscript decodes into a 60 ms buffer, so libopus can check packets of
	// up to three 20 ms frames here. 120 ms packets were checked live: Chromium,
	// Firefox and WebKit receivers decoded them with no concealment.
	for (const [label, opts] of [
		['CBR 16 kbps (equal frames: no length bytes)', { bitrate: 16000, vbr: false }],
		['VBR 24 kbps (unequal frames: length bytes)', { bitrate: 24000, vbr: true }],
		['VBR 128 kbps (frames over 252 B: two-byte lengths)', { bitrate: 128000, vbr: true }],
	] as const) {
		it(`${label}: a packed packet decodes to the same PCM as its frames one by one`, () => {
			const frames = encodeFrames(9, opts);
			for (const f of frames) expect(f[0]! & 3).toBe(0); // encoder emits one frame per packet
			if (opts.bitrate === 128000) expect(frames.some((f) => f.length - 1 > 252)).toBe(true);
			const reference = decodeAll(frames);
			for (const per of [2, 3]) {
				const packed: Uint8Array[] = [];
				for (let i = 0; i < frames.length; i += per) {
					const group = frames.slice(i, i + per);
					expect(new Set(group.map((f) => f[0]! & 0xfc)).size).toBe(1);
					packed.push(buildOpusPacket(group[0]![0]!, group.map((f) => f.subarray(1))));
				}
				expect(packed.length).toBe(Math.ceil(frames.length / per));
				const got = decodeAll(packed);
				expect(got.length).toBe(reference.length);
				expect(Buffer.from(got.buffer).equals(Buffer.from(reference.buffer))).toBe(true);
			}
		});
	}

	it('CBR frames cost one header for the whole packet', () => {
		const frames = encodeFrames(6, { bitrate: 16000, vbr: false });
		const packed = buildOpusPacket(frames[0]![0]!, frames.map((f) => f.subarray(1)));
		const separate = frames.reduce((s, f) => s + f.length, 0);
		// six TOC bytes become one TOC byte plus one frame-count byte
		expect(packed.length).toBe(separate - 6 + 2);
		expect(packed[1]).toBe(6); // v=0 (CBR), p=0, M=6
	});
});

describe('parseOpusPacket (RFC 6716 §3.2)', () => {
	const toc20 = 0b01001_0_00; // config 9: SILK WB 20 ms, mono
	it('reads codes 0-3, CBR and VBR, with padding', () => {
		const a = new Uint8Array([1, 2, 3]), b = new Uint8Array([4, 5, 6]), c = new Uint8Array([7]);
		expect(parseOpusPacket(new Uint8Array([toc20, ...a]))!.frames).toEqual([a]);
		expect(parseOpusPacket(new Uint8Array([toc20 | 1, ...a, ...b]))!.frames).toEqual([a, b]);
		expect(parseOpusPacket(new Uint8Array([toc20 | 2, 3, ...a, ...c]))!.frames).toEqual([a, c]);
		// code 3 CBR, 2 frames, 2 bytes of padding (p=1, padding length 2)
		const cbrPadded = parseOpusPacket(new Uint8Array([toc20 | 3, 0x40 | 2, 2, ...a, ...b, 0, 0]))!;
		expect(cbrPadded.frames).toEqual([a, b]);
		// code 3 VBR, 3 frames: lengths 3 and 3, the last takes the rest
		const vbr = parseOpusPacket(new Uint8Array([toc20 | 3, 0x80 | 3, 3, 3, ...a, ...b, ...c]))!;
		expect(vbr.frames).toEqual([a, b, c]);
		expect(vbr.samples).toBe(3 * 960);
	});

	it('rejects malformed packets instead of guessing', () => {
		expect(parseOpusPacket(new Uint8Array([]))).toBeNull();
		expect(parseOpusPacket(new Uint8Array([toc20 | 1, 1, 2, 3]))).toBeNull(); // odd code-1 payload
		expect(parseOpusPacket(new Uint8Array([toc20 | 2, 9, 1]))).toBeNull(); // length past the end
		expect(parseOpusPacket(new Uint8Array([toc20 | 3, 0]))).toBeNull(); // M = 0
		expect(parseOpusPacket(new Uint8Array([toc20 | 3, 3, 1, 2]))).toBeNull(); // CBR bytes not divisible by M
		// 7 × 20 ms = 140 ms > 120 ms
		expect(parseOpusPacket(new Uint8Array([toc20 | 3, 7, 1, 2, 3, 4, 5, 6, 7]))).toBeNull();
	});

	it('frame durations follow Table 2', () => {
		expect(opusFrameSamples(9 << 3)).toBe(960); // SILK WB 20 ms
		expect(opusFrameSamples(11 << 3)).toBe(2880); // SILK WB 60 ms
		expect(opusFrameSamples(13 << 3)).toBe(960); // Hybrid SWB 20 ms
		expect(opusFrameSamples(16 << 3)).toBe(120); // CELT NB 2.5 ms
		expect(opusFrameSamples(31 << 3)).toBe(960); // CELT FB 20 ms
	});
});

describe('OpusPacker', () => {
	const toc = 9 << 3;
	const pkt = (n: number) => new Uint8Array([toc, n, n, n]);
	const TS = 1_000_000;

	it('packs contiguous frames up to the target; the packet keeps the first frame', () => {
		const p = new OpusPacker<{ data: ArrayBuffer }>();
		p.setTarget(3 * 960);
		const fs = [0, 1, 2, 3, 4, 5].map((i) => frameOf(pkt(i)));
		const out = fs.flatMap((f, i) => p.push(f, TS + i * 960));
		expect(out).toEqual([fs[0], fs[3]]);
		const first = parseOpusPacket(new Uint8Array(out[0]!.data))!;
		expect(first.frames.map((f) => f[0])).toEqual([0, 1, 2]);
		expect(p.stats).toMatchObject({ packed: 2, single: 0, staleDropped: 0 });
	});

	it('a short gap releases what is held; a long jump drops it as stale', () => {
		const p = new OpusPacker<{ data: ArrayBuffer }>();
		p.setTarget(6 * 960);
		const a = frameOf(pkt(1)), b = frameOf(pkt(2)), c = frameOf(pkt(3)), d = frameOf(pkt(4));
		expect(p.push(a, TS)).toEqual([]);
		expect(p.push(b, TS + 960)).toEqual([]);
		// 40 ms gap (an encoder hiccup): a+b go out, c starts a new packet
		expect(p.push(c, TS + 4 * 960)).toEqual([a]);
		expect(parseOpusPacket(new Uint8Array(a.data))!.frames.length).toBe(2);
		// 2 s jump (Opus deactivated, then resumed): c could only arrive late
		expect(p.push(d, TS + 4 * 960 + 96_000)).toEqual([]);
		expect(p.stats.staleDropped).toBe(1);
		expect(p.release()).toEqual([d]);
	});

	it('a TOC change or the 120 ms cap closes the packet', () => {
		const p = new OpusPacker<{ data: ArrayBuffer }>();
		p.setTarget(OPUS_MAX_PACKET_SAMPLES);
		const nb = frameOf(new Uint8Array([1 << 3, 7])); // SILK NB 20 ms
		const wb = frameOf(pkt(8));
		expect(p.push(nb, TS)).toEqual([]);
		expect(p.push(wb, TS + 960)).toEqual([nb]); // different config
		// 40 ms frames: three of them would be 120 ms, a fourth over the cap
		const q = new OpusPacker<{ data: ArrayBuffer }>();
		q.setTarget(OPUS_MAX_PACKET_SAMPLES);
		const f40 = (n: number) => frameOf(new Uint8Array([(10 << 3), n]));
		const fs = [f40(1), f40(2), f40(3), f40(4)];
		const out = fs.flatMap((f, i) => q.push(f, TS + i * 1920));
		expect(out).toEqual([fs[0]]);
		expect(parseOpusPacket(new Uint8Array(fs[0]!.data))!.samples).toBe(OPUS_MAX_PACKET_SAMPLES);
	});

	it('passes frames through when off, when the timestamp is unknown, or when a packet is malformed', () => {
		const p = new OpusPacker<{ data: ArrayBuffer }>();
		const f = frameOf(pkt(1));
		expect(p.push(f, TS)).toEqual([f]); // target 20 ms: off
		p.setTarget(3 * 960);
		const g = frameOf(pkt(2));
		expect(p.push(g, undefined)).toEqual([g]);
		const held = frameOf(pkt(3));
		expect(p.push(held, TS)).toEqual([]);
		const bad = frameOf(new Uint8Array([toc | 1, 1, 2, 3])); // odd code-1 payload
		expect(p.push(bad, TS + 960)).toEqual([held, bad]);
		// turning packing off releases what is held
		const h = frameOf(pkt(4));
		p.push(h, TS + 1920);
		p.setTarget(960);
		const k = frameOf(pkt(5));
		expect(p.push(k, TS + 2880)).toEqual([h, k]);
	});
});

describe('encode pipe with set-audio-packing', () => {
	interface FakeAudioFrame { data: ArrayBuffer; getMetadata(): { rtpTimestamp: number; mimeType: string } }
	const audio = (bytes: Uint8Array, ts: number): FakeAudioFrame => ({
		data: bytes.slice().buffer,
		getMetadata: () => ({ rtpTimestamp: ts, mimeType: 'audio/opus' }),
	});

	async function runPipe(ms: number | null, frames: FakeAudioFrame[]) {
		const chainKey = randomChainKey();
		const peers = { '0': 0 as PeerIndex, '1': 1 as PeerIndex };
		const bundles = await makeBundles(chainKey, 1, peers);
		const sender = createWorkerState(() => {});
		await handleMessage(sender, { type: 'init', role: 'sender', peerId: '0', peerIndex: 0 });
		installEpoch(sender, 1, 0, bundles);
		if (ms !== null) await handleMessage(sender, { type: 'set-audio-packing', ms });
		const out: FakeAudioFrame[] = [];
		const readable = new ReadableStream<FakeAudioFrame>({
			start(c) { for (const f of frames) c.enqueue(f); c.close(); },
		});
		const done = new Promise<void>((resolve) => {
			const writable = new WritableStream<FakeAudioFrame>({ write(f) { out.push(f); }, close() { resolve(); } });
			pipe(sender, 'encode', readable as never, writable as never);
		});
		await done;
		const receiver = createWorkerState(() => {});
		await handleMessage(receiver, { type: 'init', role: 'receiver', peerId: '1', peerIndex: 1 });
		installEpoch(receiver, 1, 1, bundles);
		for (const f of out) await decodeFrame(receiver, f as never);
		return out;
	}

	it('one SFrame per packed packet; the receiver gets the encoder frames back', async () => {
		const opus = encodeFrames(12, { bitrate: 16000, vbr: false });
		const frames = opus.map((o, i) => audio(o, 7_000 + i * 960));
		const out = await runPipe(120, frames);
		expect(out.length).toBe(2);
		const got = out.flatMap((f) => parseOpusPacket(new Uint8Array(f.data))!.frames.map((x) => Buffer.from(x).toString('hex')));
		expect(got).toEqual(opus.map((o) => Buffer.from(o.subarray(1)).toString('hex')));
	});

	it('without set-audio-packing every frame is its own SFrame, as before', async () => {
		const opus = encodeFrames(6, { bitrate: 16000, vbr: false });
		const out = await runPipe(null, opus.map((o, i) => audio(o, 7_000 + i * 960)));
		expect(out.length).toBe(6);
		expect(out.map((f) => Buffer.from(new Uint8Array(f.data)).toString('hex'))).toEqual(opus.map((o) => Buffer.from(o).toString('hex')));
	});

	it('video frames never enter the packer', async () => {
		const chainKey = randomChainKey();
		const bundles = await makeBundles(chainKey, 1, { '0': 0 as PeerIndex });
		const sender = createWorkerState(() => {});
		await handleMessage(sender, { type: 'init', role: 'sender', peerId: '0', peerIndex: 0 });
		installEpoch(sender, 1, 0, bundles);
		await handleMessage(sender, { type: 'set-audio-packing', ms: 120 });
		const video = [0, 1, 2].map((i) => ({ type: 'delta', data: new Uint8Array([9 << 3, i]).buffer, getMetadata: () => ({ rtpTimestamp: i * 960 }) }));
		const out: unknown[] = [];
		const readable = new ReadableStream({ start(c) { for (const f of video) c.enqueue(f); c.close(); } });
		await new Promise<void>((resolve) => {
			pipe(sender, 'encode', readable as never, new WritableStream({ write(f) { out.push(f); }, close() { resolve(); } }) as never);
		});
		expect(out.length).toBe(3);
	});

	it('rejects pack durations that are not 20 ms steps up to 120 ms', async () => {
		const s = createWorkerState(() => {});
		for (const [ms, want] of [[60, 2880], [120, 5760], [20, 960], [140, 960], [50, 960], [0, 960], [Number.NaN, 960]] as const) {
			await handleMessage(s, { type: 'set-audio-packing', ms });
			expect(s.audioPackSamples).toBe(want);
		}
	});
});
