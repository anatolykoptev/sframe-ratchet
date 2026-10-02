// Opus frame packing (RFC 6716 §3.2). Pure, no crypto.
//
// A WebRTC Opus sender emits one 20 ms frame per RTP packet: 50 packets/s.
// Each packet pays RTP + extensions + SRTP + SFrame + UDP/IP, about 90 bytes,
// so at low bitrates the headers cost several times the voice (Opus 6 kbps is
// ~43 kbps on the wire under SFrame). Packing N consecutive frames into one
// RFC 6716 multi-frame ("code 3") packet pays that tax once per N frames,
// up to 120 ms per packet. Every RFC 6716 decoder reads multi-frame packets,
// so the receiver needs nothing: packing is a sender-only decision.
//
// The packer runs BEFORE encryption, so one packed packet is one SFrame
// (one header, one tag, one CTR).

/** RFC 6716 §3.2.5: a packet carries at most 120 ms of audio. */
export const OPUS_MAX_PACKET_SAMPLES = 5760; // 120 ms at 48 kHz
/** One 20 ms frame at 48 kHz: the unit pack targets are expressed in. */
export const OPUS_FRAME_20MS_SAMPLES = 960;
/** RFC 6716 §3.2.5: M (frame count) is at most 48. */
const MAX_FRAMES_PER_PACKET = 48;

/** Duration in 48 kHz samples of each frame under a TOC byte (RFC 6716 §3.1, Table 2). */
export function opusFrameSamples(toc: number): number {
	const config = toc >> 3;
	if (config < 12) return [480, 960, 1920, 2880][config & 3]!; // SILK NB/MB/WB: 10/20/40/60 ms
	if (config < 16) return [480, 960][config & 1]!; // Hybrid SWB/FB: 10/20 ms
	return [120, 240, 480, 960][config & 3]!; // CELT: 2.5/5/10/20 ms
}

export interface OpusPacket {
	/** TOC byte with the frame-count code (c) cleared: config + stereo flag.
	 *  Frames can share one packet only when this matches (§3.2). */
	toc: number;
	frames: Uint8Array[];
	/** Total duration in 48 kHz samples. */
	samples: number;
}

/** §3.2.1 frame-length coding: one byte below 252, two bytes otherwise. */
function readLength(d: Uint8Array, i: number): [length: number, bytes: number] | null {
	const b = d[i];
	if (b === undefined) return null;
	if (b < 252) return [b, 1];
	const b2 = d[i + 1];
	if (b2 === undefined) return null;
	return [4 * b2 + b, 2];
}

function writeLength(n: number, out: number[]): void {
	if (n < 252) { out.push(n); return; }
	const first = 252 + ((n - 252) & 3);
	out.push(first, (n - first) / 4);
}

/**
 * Split an Opus packet into its frames (RFC 6716 §3.2, codes 0-3, with
 * padding). Returns null for anything that is not a well-formed packet, so a
 * caller can pass it through untouched.
 */
export function parseOpusPacket(d: Uint8Array): OpusPacket | null {
	if (d.length < 1) return null;
	const toc = d[0]!;
	const code = toc & 3;
	const L = d.length;
	const frames: Uint8Array[] = [];
	if (code === 0) {
		frames.push(d.subarray(1));
	} else if (code === 1) {
		if ((L - 1) % 2 !== 0) return null;
		const n = (L - 1) / 2;
		frames.push(d.subarray(1, 1 + n), d.subarray(1 + n));
	} else if (code === 2) {
		const len = readLength(d, 1);
		if (!len || 1 + len[1] + len[0] > L) return null;
		const start = 1 + len[1];
		frames.push(d.subarray(start, start + len[0]), d.subarray(start + len[0]));
	} else {
		if (L < 2) return null;
		const vbr = (d[1]! & 0x80) !== 0;
		const padded = (d[1]! & 0x40) !== 0;
		const M = d[1]! & 0x3f;
		if (M === 0) return null;
		let i = 2;
		let padding = 0;
		if (padded) {
			for (;;) {
				const b = d[i++];
				if (b === undefined) return null;
				padding += b === 255 ? 254 : b;
				if (b !== 255) break;
			}
		}
		const end = L - padding;
		if (end < i) return null;
		if (vbr) {
			const lengths: number[] = [];
			for (let m = 0; m < M - 1; m++) {
				const len = readLength(d, i);
				if (!len) return null;
				i += len[1];
				lengths.push(len[0]);
			}
			let o = i;
			for (const n of lengths) {
				if (o + n > end) return null;
				frames.push(d.subarray(o, o + n));
				o += n;
			}
			if (o > end) return null;
			frames.push(d.subarray(o, end));
		} else {
			if ((end - i) % M !== 0) return null;
			const n = (end - i) / M;
			for (let m = 0; m < M; m++) frames.push(d.subarray(i + m * n, i + (m + 1) * n));
		}
	}
	const samples = frames.length * opusFrameSamples(toc);
	if (samples > OPUS_MAX_PACKET_SAMPLES) return null;
	return { toc: toc & 0xfc, frames, samples };
}

/**
 * Build one code-3 packet from frames that share `toc` (config + stereo).
 * Equal-length frames (cbr=1) use the CBR form: no length bytes at all.
 */
export function buildOpusPacket(toc: number, frames: readonly Uint8Array[]): Uint8Array {
	const M = frames.length;
	if (M < 1 || M > MAX_FRAMES_PER_PACKET) throw new RangeError(`opus-pack: ${M} frames`);
	if (M * opusFrameSamples(toc) > OPUS_MAX_PACKET_SAMPLES) throw new RangeError('opus-pack: over 120 ms');
	const cbr = frames.every((f) => f.length === frames[0]!.length);
	const head: number[] = [(toc & 0xfc) | 3, (cbr ? 0 : 0x80) | M];
	if (!cbr) for (let m = 0; m < M - 1; m++) writeLength(frames[m]!.length, head);
	let size = head.length;
	for (const f of frames) size += f.length;
	const out = new Uint8Array(size);
	out.set(head, 0);
	let o = head.length;
	for (const f of frames) { out.set(f, o); o += f.length; }
	return out;
}

export interface PackableFrame {
	data: ArrayBuffer;
}

export interface OpusPackerStats {
	/** Packets sent carrying more than one encoder frame. */
	packed: number;
	/** Packets sent as the encoder made them. */
	single: number;
	/** Held frames dropped: the stream jumped more than a packet's worth of
	 *  time (a gated or restarted sender), so they could only arrive late. */
	staleDropped: number;
}

/**
 * Accumulates consecutive Opus frames from one sender and releases them as
 * packets of up to `targetSamples`. The released packet is the FIRST held
 * frame object with the packed bytes — it keeps that frame's RTP timestamp,
 * which is where the packed audio starts; the frames after it are consumed.
 *
 * Frames join a packet only while they are contiguous in RTP time and share
 * a TOC config. A gap of up to one packet (an encoder hiccup) releases what
 * is held; a larger jump (Opus deactivated and resumed, a restarted encoder)
 * drops it, since it could only arrive behind the receiver's playout.
 */
export class OpusPacker<F extends PackableFrame> {
	private target = OPUS_FRAME_20MS_SAMPLES;
	private held: F[] = [];
	private frames: Uint8Array[] = [];
	private toc = -1;
	private samples = 0;
	private nextTs = 0;
	readonly stats: OpusPackerStats = { packed: 0, single: 0, staleDropped: 0 };

	/** Samples per packet at 48 kHz; 960 (20 ms) or less turns packing off. */
	setTarget(samples: number): void {
		this.target = Math.max(OPUS_FRAME_20MS_SAMPLES, Math.min(OPUS_MAX_PACKET_SAMPLES, Math.floor(samples)));
	}

	get active(): boolean {
		return this.target > OPUS_FRAME_20MS_SAMPLES || this.held.length > 0;
	}

	/** Push one encoder frame; returns the frames to send now, in order. */
	push(frame: F, rtpTimestamp: number | undefined): F[] {
		const out: F[] = [];
		const p = rtpTimestamp === undefined || this.target <= OPUS_FRAME_20MS_SAMPLES
			? null
			: parseOpusPacket(new Uint8Array(frame.data));
		if (p === null) {
			out.push(...this.release());
			this.stats.single++;
			out.push(frame);
			return out;
		}
		if (this.held.length > 0) {
			const gap = ((rtpTimestamp! - this.nextTs) >>> 0);
			if (gap !== 0 && gap <= OPUS_MAX_PACKET_SAMPLES) out.push(...this.release());
			else if (gap !== 0) this.drop();
			else if (p.toc !== this.toc || this.samples + p.samples > OPUS_MAX_PACKET_SAMPLES) out.push(...this.release());
		}
		this.held.push(frame);
		this.frames.push(...p.frames);
		this.toc = p.toc;
		this.samples += p.samples;
		this.nextTs = (rtpTimestamp! + p.samples) >>> 0;
		if (this.samples >= this.target) out.push(...this.release());
		return out;
	}

	/** Release whatever is held as one packet (or nothing). */
	release(): F[] {
		if (this.held.length === 0) return [];
		const first = this.held[0]!;
		if (this.held.length === 1) {
			this.stats.single++;
		} else {
			// buildOpusPacket copies, so the views into the consumed frames'
			// buffers are read before `first.data` is replaced.
			first.data = buildOpusPacket(this.toc, this.frames).buffer as ArrayBuffer;
			this.stats.packed++;
		}
		this.reset();
		return [first];
	}

	private drop(): void {
		this.stats.staleDropped += this.held.length;
		this.reset();
	}

	private reset(): void {
		this.held = [];
		this.frames = [];
		this.toc = -1;
		this.samples = 0;
	}
}
