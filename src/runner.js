'use strict';

/**
 * Batch test runner for the Aegis mutual-authentication protocol.
 * Executes N handshakes, aggregates statistics, and tracks session-key
 * uniqueness / collisions.
 */

const { runHandshake, FAULT_MODES } = require('./protocol');

/**
 * Run a batch of handshakes.
 *
 * @param {object} options
 * @param {number} [options.count=1000] number of iterations
 * @param {string} [options.fault='legitimate'] fault mode
 * @param {(progress: object) => void} [options.onProgress] called periodically
 * @param {number} [options.progressEvery] emit progress every N runs
 *        (defaults to ~1% of count, min 1)
 * @returns {object} { summary, results }
 */
function runBatch(options = {}) {
  const count = Number.isFinite(options.count) ? Math.max(1, Math.floor(options.count)) : 1000;
  const fault = options.fault || 'legitimate';
  if (!FAULT_MODES.includes(fault)) {
    throw new Error(`Unknown fault mode: ${fault}. Valid: ${FAULT_MODES.join(', ')}`);
  }
  const onProgress = typeof options.onProgress === 'function' ? options.onProgress : null;
  const progressEvery = options.progressEvery || Math.max(1, Math.floor(count / 100));

  const results = [];
  const sessionKeyCounts = new Map(); // hex -> occurrences

  let passed = 0;
  let failed = 0;
  let totalLatency = 0;
  let minLatency = Infinity;
  let maxLatency = -Infinity;

  // Per-phase breakdown — tells the paper reader exactly where failures occur.
  const phaseBreakdown = {
    phase1PassCount: 0,
    phase1FailCount: 0,
    phase2PassCount: 0,
    phase2FailCount: 0,
    phase3ReachedCount: 0,
  };

  for (let i = 0; i < count; i++) {
    const trace = runHandshake({ fault });

    if (trace.passed) passed++;
    else failed++;

    totalLatency += trace.latencyMs;
    if (trace.latencyMs < minLatency) minLatency = trace.latencyMs;
    if (trace.latencyMs > maxLatency) maxLatency = trace.latencyMs;

    if (trace.phases.phase1) phaseBreakdown.phase1PassCount++;
    else phaseBreakdown.phase1FailCount++;
    if (trace.trace.phase2.ran) {
      if (trace.phases.phase2) phaseBreakdown.phase2PassCount++;
      else phaseBreakdown.phase2FailCount++;
    }
    if (trace.phases.phase3) phaseBreakdown.phase3ReachedCount++;

    if (trace.sessionKey) {
      sessionKeyCounts.set(
        trace.sessionKey,
        (sessionKeyCounts.get(trace.sessionKey) || 0) + 1
      );
    }

    results.push({
      run: i + 1,
      passed: trace.passed,
      latencyMs: trace.latencyMs,
      fault: trace.appliedFault,
      trace: trace.trace,
    });

    if (onProgress && ((i + 1) % progressEvery === 0 || i + 1 === count)) {
      onProgress(buildLiveProgress({
        done: i + 1,
        count,
        passed,
        failed,
        totalLatency,
        minLatency,
        maxLatency,
        sessionKeyCounts,
        fault,
        lastTrace: trace,
      }));
    }
  }

  const summary = buildSummary({
    count,
    passed,
    failed,
    totalLatency,
    minLatency,
    maxLatency,
    sessionKeyCounts,
    fault,
    phaseBreakdown,
  });

  return { summary, results };
}

/** Compute the number of session-key collisions (extra occurrences). */
function countCollisions(sessionKeyCounts) {
  let collisions = 0;
  for (const occurrences of sessionKeyCounts.values()) {
    if (occurrences > 1) collisions += occurrences - 1;
  }
  return collisions;
}

/** Build the final summary object from accumulated counters. */
function buildSummary(acc) {
  const {
    count, passed, failed, totalLatency, minLatency, maxLatency, sessionKeyCounts, fault,
    phaseBreakdown,
  } = acc;

  const summary = {
    totalRuns: count,
    passed,
    failed,
    successRate: count > 0 ? (passed / count) * 100 : 0,
    avgLatencyMs: count > 0 ? totalLatency / count : 0,
    minLatencyMs: Number.isFinite(minLatency) ? minLatency : 0,
    maxLatencyMs: Number.isFinite(maxLatency) ? maxLatency : 0,
    uniqueSessionKeys: sessionKeyCounts.size,
    sessionKeyCollisions: countCollisions(sessionKeyCounts),
    faultMode: fault,
  };
  if (phaseBreakdown) summary.phaseBreakdown = phaseBreakdown;
  return summary;
}

/** Build an interim progress payload (used for live streaming to the UI). */
function buildLiveProgress(acc) {
  const summary = buildSummary({ ...acc, count: acc.count });
  // Override totalRuns/derived stats to reflect work done so far.
  const done = acc.done;
  return {
    done,
    total: acc.count,
    percent: acc.count > 0 ? (done / acc.count) * 100 : 0,
    passed: acc.passed,
    failed: acc.failed,
    successRate: done > 0 ? (acc.passed / done) * 100 : 0,
    avgLatencyMs: done > 0 ? acc.totalLatency / done : 0,
    minLatencyMs: Number.isFinite(acc.minLatency) ? acc.minLatency : 0,
    maxLatencyMs: Number.isFinite(acc.maxLatency) ? acc.maxLatency : 0,
    uniqueSessionKeys: acc.sessionKeyCounts.size,
    sessionKeyCollisions: countCollisions(acc.sessionKeyCounts),
    faultMode: acc.fault,
    lastTrace: acc.lastTrace,
  };
}

module.exports = {
  runBatch,
  countCollisions,
};
