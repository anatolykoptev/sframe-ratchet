// Lightweight metrics emission helper for the encoded-frame worker.
// Concern: fire-and-forget telemetry posting — never throws, never blocks.
//
// Design: worker posts `{ type: 'metrics'; event: MetricsEvent }` messages to the
// main thread when `state.metricsEnabled` is true. Main thread subscribes via
// `onMetrics(worker, handler)` exported from src/index.ts.

import type { MetricsEvent, WorkerState } from './worker-types.ts';

/**
 * Post a MetricsEvent to the main thread if metrics are enabled.
 * Any error from `postMessage` (e.g. DataCloneError on an un-transferable value)
 * is swallowed — metrics must never interrupt the frame pipeline.
 */
export function emitMetric(state: WorkerState, event: MetricsEvent): void {
	if (!state.metricsEnabled) return;
	try {
		state.emit({ type: 'metrics', event });
	} catch {
		// Swallow — telemetry failures must never propagate.
	}
}
