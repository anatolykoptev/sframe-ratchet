// Tests for SlidingReplayWindow.
// TDD RED phase.

import { describe, it, expect } from 'vitest';
import { SlidingReplayWindow } from '../replay.ts';

describe('SlidingReplayWindow', () => {
	it('accepts first occurrence of a CTR', () => {
		const w = new SlidingReplayWindow(1024);
		expect(w.check(100n)).toBe(true);
	});

	it('rejects exact duplicate CTR', () => {
		const w = new SlidingReplayWindow(1024);
		w.accept(100n);
		expect(w.check(100n)).toBe(false);
	});

	it('check does not modify state', () => {
		const w = new SlidingReplayWindow(1024);
		w.accept(42n);
		// check on 100n should pass (not in set)
		expect(w.check(100n)).toBe(true);
		expect(w.check(100n)).toBe(true); // still passes, not recorded
	});

	it('accept + check flow', () => {
		const w = new SlidingReplayWindow(1024);
		expect(w.check(200n)).toBe(true);
		w.accept(200n);
		expect(w.check(200n)).toBe(false);
	});

	it('window size 0 always accepts (replay disabled)', () => {
		const w = new SlidingReplayWindow(0);
		w.accept(999n);
		expect(w.check(999n)).toBe(true);
	});

	it('evicts oldest entry when window full', () => {
		const windowSize = 4;
		const w = new SlidingReplayWindow(windowSize);
		for (let i = 0n; i < 4n; i++) w.accept(i);
		// Window is full with 0n,1n,2n,3n
		// Adding 4n should evict the oldest (0n)
		w.accept(4n);
		// 0n should no longer be tracked — check returns true (not in set)
		expect(w.check(0n)).toBe(true);
		// 4n is still in the set
		expect(w.check(4n)).toBe(false);
	});

	it('clear() resets all state', () => {
		const w = new SlidingReplayWindow(1024);
		w.accept(1n);
		w.accept(2n);
		w.clear();
		expect(w.check(1n)).toBe(true);
		expect(w.check(2n)).toBe(true);
	});
});
