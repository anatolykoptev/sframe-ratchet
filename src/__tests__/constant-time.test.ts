// Tests for src/internal/constant-time.ts
//
// Note: these tests verify FUNCTIONAL correctness (all bytes compared,
// correct boolean result). They do NOT verify wall-clock constant time —
// JS runtime timing measurement is too noisy to be meaningful as a test
// assertion. The goal of the implementation is to remove the most obvious
// branch-predictable oracle; see the module-level TSDoc for the full caveat.

import { describe, it, expect } from 'vitest';
import { ctEqual, ctEndsWith } from '../internal/constant-time.ts';

// ---------------------------------------------------------------------------
// ctEqual
// ---------------------------------------------------------------------------

describe('ctEqual', () => {
	it('equal short arrays → true', () => {
		const a = new Uint8Array([0x01, 0x02, 0x03]);
		const b = new Uint8Array([0x01, 0x02, 0x03]);
		expect(ctEqual(a, b)).toBe(true);
	});

	it('equal long arrays → true', () => {
		const a = new Uint8Array(256).fill(0xab);
		const b = new Uint8Array(256).fill(0xab);
		expect(ctEqual(a, b)).toBe(true);
	});

	it('first byte differs → false', () => {
		const a = new Uint8Array([0xff, 0x02, 0x03]);
		const b = new Uint8Array([0x00, 0x02, 0x03]);
		expect(ctEqual(a, b)).toBe(false);
	});

	it('last byte differs → false', () => {
		const a = new Uint8Array([0x01, 0x02, 0x03]);
		const b = new Uint8Array([0x01, 0x02, 0xff]);
		expect(ctEqual(a, b)).toBe(false);
	});

	it('middle byte differs → false', () => {
		const a = new Uint8Array([0x01, 0x99, 0x03]);
		const b = new Uint8Array([0x01, 0x00, 0x03]);
		expect(ctEqual(a, b)).toBe(false);
	});

	it('same length, all zero → true', () => {
		const a = new Uint8Array(16).fill(0);
		const b = new Uint8Array(16).fill(0);
		expect(ctEqual(a, b)).toBe(true);
	});

	it('empty arrays → true', () => {
		expect(ctEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
	});

	it('length mismatch → false', () => {
		const a = new Uint8Array([0x01, 0x02]);
		const b = new Uint8Array([0x01, 0x02, 0x03]);
		expect(ctEqual(a, b)).toBe(false);
	});

	it('length mismatch (b shorter) → false', () => {
		const a = new Uint8Array([0x01, 0x02, 0x03]);
		const b = new Uint8Array([0x01, 0x02]);
		expect(ctEqual(a, b)).toBe(false);
	});

	it('single byte equal → true', () => {
		expect(ctEqual(new Uint8Array([0x42]), new Uint8Array([0x42]))).toBe(true);
	});

	it('single byte unequal → false', () => {
		expect(ctEqual(new Uint8Array([0x42]), new Uint8Array([0x43]))).toBe(false);
	});

	it('XOR-OR fold correctly accumulates multiple differing bytes', () => {
		// All bytes differ — acc should be non-zero
		const a = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
		const b = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
		expect(ctEqual(a, b)).toBe(false);
	});
});

// ---------------------------------------------------------------------------
// ctEndsWith
// ---------------------------------------------------------------------------

describe('ctEndsWith', () => {
	it('frame ends with trailer → true', () => {
		const trailer = new Uint8Array([0x53, 0x49, 0x46]);
		const frame = new Uint8Array([0x00, 0x01, 0x02, 0x53, 0x49, 0x46]);
		expect(ctEndsWith(frame, trailer)).toBe(true);
	});

	it("frame doesn't end with trailer (different last byte) → false", () => {
		const trailer = new Uint8Array([0x53, 0x49, 0x46]);
		const frame = new Uint8Array([0x00, 0x01, 0x02, 0x53, 0x49, 0x00]);
		expect(ctEndsWith(frame, trailer)).toBe(false);
	});

	it('frame shorter than trailer → false', () => {
		const trailer = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
		const frame = new Uint8Array([0x01, 0x02]);
		expect(ctEndsWith(frame, trailer)).toBe(false);
	});

	it('frame equals trailer → true', () => {
		const trailer = new Uint8Array([0x53, 0x49, 0x46]);
		expect(ctEndsWith(trailer, trailer)).toBe(true);
	});

	it('empty trailer → true (every frame ends with empty)', () => {
		const frame = new Uint8Array([0x01, 0x02, 0x03]);
		expect(ctEndsWith(frame, new Uint8Array(0))).toBe(true);
	});

	it('empty frame and empty trailer → true', () => {
		expect(ctEndsWith(new Uint8Array(0), new Uint8Array(0))).toBe(true);
	});

	it('first byte of suffix differs → false', () => {
		const trailer = new Uint8Array([0xff, 0x02, 0x03]);
		const frame = new Uint8Array([0x00, 0x01, 0x00, 0x02, 0x03]);
		expect(ctEndsWith(frame, trailer)).toBe(false);
	});

	it('9-byte default SIF trailer matches correctly', () => {
		// Mirrors the real DEFAULT_SIF_TRAILER bytes
		const sifTrailer = new Uint8Array([
			0x53, 0x49, 0x46, 0x54, 0x52, 0x41, 0x49, 0x4c, 0x52,
		]);
		const prefix = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
		const frame = new Uint8Array(prefix.length + sifTrailer.length);
		frame.set(prefix);
		frame.set(sifTrailer, prefix.length);
		expect(ctEndsWith(frame, sifTrailer)).toBe(true);
	});

	it('9-byte SIF trailer with corrupted last byte → false', () => {
		const sifTrailer = new Uint8Array([
			0x53, 0x49, 0x46, 0x54, 0x52, 0x41, 0x49, 0x4c, 0x52,
		]);
		const prefix = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
		const frame = new Uint8Array(prefix.length + sifTrailer.length);
		frame.set(prefix);
		frame.set(sifTrailer, prefix.length);
		frame[frame.length - 1] = 0x00; // corrupt last byte
		expect(ctEndsWith(frame, sifTrailer)).toBe(false);
	});
});
