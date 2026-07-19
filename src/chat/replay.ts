// SlidingReplayWindow moved to src/internal/replay.ts to fix the core→chat
// boundary violation (repo-review-council NOISE: worker-types.ts and
// worker-frame.ts were importing from ./chat/replay.ts, creating an outward
// dependency from core to a sub-package).
//
// Re-exported here for backward compatibility — existing chat/ consumers
// that import from './replay.ts' continue to work.
export { SlidingReplayWindow } from '../internal/replay.ts';
