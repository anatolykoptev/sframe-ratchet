// SFrame header codec per RFC 9605 §4.3. Pure, no crypto.
// Split out from sframe.ts to keep the AEAD module focused on the WebCrypto
// pipeline; this file is the wire-format layer.

/**
 * Parsed SFrame header. `bodyOffset` is the number of bytes consumed from the
 * input buffer — the ciphertext (including 16-byte GCM tag) starts there.
 */
export interface SFrameHeader {
	kid: number;
	ctr: bigint;
	bodyOffset: number;
}

/**
 * Serialise an RFC 9605 §4.3 header. We always set K=1 (extended KID) with
 * **fixed 4-byte big-endian KID** per spec §6.1: KID = (epoch_version << 16) |
 * peer_index (32 bits total). Fixed width keeps header size deterministic and
 * matches the spec wording "KID (variable-length extension, 4 bytes in v1)".
 * KLEN is therefore always 3 (byte count − 1).
 *
 * CTR keeps the minimal-big-endian encoding per RFC 9605 (1..8 bytes).
 *
 * Config byte layout: `K(1) | KLEN(3) | C(1) | CLEN(3)`.
 * With K=1 and C=1 the layout is:
 *   byte 0: 1 KKK 1 CCC   (KKK = KLEN = 3 always, CCC = CLEN)
 *   bytes 1..4           : big-endian 32-bit KID
 *   bytes 5..5+CLEN      : big-endian CTR
 */
export const SFRAME_KID_WIDTH = 4;

export function serializeHeader(kid: number, ctr: bigint): Uint8Array {
	if (!Number.isInteger(kid) || kid < 0 || kid > 0xffffffff) {
		throw new RangeError(`sframe: kid out of range: ${kid}`);
	}
	if (ctr < 0n || ctr > 0xffffffffffffffffn) {
		throw new RangeError(`sframe: ctr out of range: ${ctr}`);
	}

	const kidBytes = fixedBigEndian(BigInt(kid), SFRAME_KID_WIDTH);
	const ctrBytes = minimalBigEndian(ctr);
	const klen = SFRAME_KID_WIDTH - 1; // always 3
	const clen = ctrBytes.length - 1;

	const header = new Uint8Array(1 + kidBytes.length + ctrBytes.length);
	// K=1, KLEN=klen, C=1, CLEN=clen → 1kkk1ccc
	header[0] = 0b1000_1000 | ((klen & 0b111) << 4) | (clen & 0b111);
	header.set(kidBytes, 1);
	header.set(ctrBytes, 1 + kidBytes.length);
	return header;
}

/** Parse an RFC 9605 §4.3 header. Pure. Throws on malformed input. */
export function parseHeader(buf: Uint8Array): SFrameHeader {
	if (buf.length < 1) throw new Error('sframe: empty buffer');
	const cfg = buf[0];
	const kExt = (cfg & 0b1000_0000) !== 0;
	const klen = (cfg >> 4) & 0b111; // byte count - 1 when kExt=1
	const cExt = (cfg & 0b0000_1000) !== 0;
	const clen = cfg & 0b111;

	let offset = 1;
	let kid: number;
	if (kExt) {
		const need = klen + 1;
		if (buf.length < offset + need) throw new Error('sframe: short kid');
		kid = readBigEndianNumber(buf, offset, need);
		offset += need;
	} else {
		kid = klen; // 3-bit inline KID in the KLEN position
	}

	let ctr: bigint;
	if (cExt) {
		const need = clen + 1;
		if (buf.length < offset + need) throw new Error('sframe: short ctr');
		ctr = readBigEndianBigInt(buf, offset, need);
		offset += need;
	} else {
		ctr = BigInt(clen); // 3-bit inline CTR
	}

	return { kid, ctr, bodyOffset: offset };
}

function minimalBigEndian(v: bigint): Uint8Array {
	if (v === 0n) return new Uint8Array([0]);
	const bytes: number[] = [];
	let x = v;
	while (x > 0n) {
		bytes.push(Number(x & 0xffn));
		x >>= 8n;
	}
	bytes.reverse();
	if (bytes.length > 8) throw new RangeError('sframe: field exceeds 8 bytes');
	return new Uint8Array(bytes);
}

/** Fixed-width big-endian encoding. Zero-pads on the left. */
function fixedBigEndian(v: bigint, width: number): Uint8Array {
	const out = new Uint8Array(width);
	let x = v;
	for (let i = width - 1; i >= 0; i--) {
		out[i] = Number(x & 0xffn);
		x >>= 8n;
	}
	if (x !== 0n) throw new RangeError(`sframe: value exceeds ${width} bytes`);
	return out;
}

function readBigEndianNumber(buf: Uint8Array, off: number, len: number): number {
	// len is 1..8. Our KID is fixed 32 bits per spec §6.1 so safe-integer range
	// is sufficient; reject anything larger to catch mis-parsed frames loudly.
	let out = 0;
	for (let i = 0; i < len; i++) {
		out = out * 256 + buf[off + i];
	}
	if (!Number.isSafeInteger(out)) {
		throw new RangeError('sframe: extended KID exceeds safe integer range');
	}
	return out;
}

function readBigEndianBigInt(buf: Uint8Array, off: number, len: number): bigint {
	let out = 0n;
	for (let i = 0; i < len; i++) {
		out = (out << 8n) | BigInt(buf[off + i]);
	}
	return out;
}
