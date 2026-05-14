/// <reference lib="webworker" />
// Encoded-frame worker runtime glue. Dual entry points:
//   - RTCRtpScriptTransform (`onrtctransform`)
//   - postMessage streams (legacy fallback)
// All state-machine logic is in worker-state.ts; frame I/O is in
// worker-frame.ts; message + state types are in worker-types.ts. This file
// owns only the module-level singleton and the `self` wiring.
//
// Revision 2026-04-21 (fix-round 2): CTR is a single sender-wide bigint
// (spec §2 L42 + §2.2) and the grace-window wipe is self-scheduled by
// installEpoch (spec §7.4), so the stale-epoch gate is reachable on both
// sender and receiver roles.

import type { InMsg, Side } from './worker-types.ts';
import { createWorkerState, handleMessage } from './worker-state.ts';
import { pipe } from './worker-frame.ts';

declare const self: DedicatedWorkerGlobalScope;
const workerScope = self as unknown as DedicatedWorkerGlobalScope;
const state = createWorkerState((m) => workerScope.postMessage(m));

workerScope.addEventListener('message', (ev: MessageEvent<InMsg>) => {
	handleMessage(state, ev.data).catch((err) => {
		workerScope.postMessage({ type: 'error', detail: String(err) });
	});
});

// RTCRtpScriptTransform native path.
(workerScope as unknown as { onrtctransform: (e: Event) => void }).onrtctransform = (
	ev: Event,
) => {
	const transformer = (ev as unknown as {
		transformer: {
			readable: ReadableStream<RTCEncodedVideoFrame | RTCEncodedAudioFrame>;
			writable: WritableStream<RTCEncodedVideoFrame | RTCEncodedAudioFrame>;
			options?: { side?: Side };
		};
	}).transformer;
	const side = transformer.options?.side ?? (state.role === 'sender' ? 'encode' : 'decode');
	pipe(state, side, transformer.readable, transformer.writable);
};

// Signal readiness if the worker is constructed without an init message first.
workerScope.postMessage({ type: 'spawned' });
