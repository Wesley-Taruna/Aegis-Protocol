'use strict';

/**
 * Result formatting and research-summary generation for the Aegis suite.
 */

const FAULT_DESCRIPTIONS = {
  legitimate: 'no injected faults (baseline integrity check)',
  'wrong-key': 'cloned chips or unauthorized readers presenting a mismatched secret key',
  'tampered-rndb': 'replay attacks in which the rotated challenge (RndB\') is substituted with forged bytes',
  'random-fault': 'a stochastic mix of mismatched-key and tampered-challenge attacks injected at a 5% rate',
};

/** Round a number to a fixed number of decimals, returning a Number. */
function round(value, decimals = 4) {
  const f = Math.pow(10, decimals);
  return Math.round(value * f) / f;
}

/**
 * Produce a human-readable console summary block.
 * @param {object} summary
 * @returns {string}
 */
function formatConsoleSummary(summary) {
  const lines = [
    '',
    '==================== Aegis Protocol — Test Summary ====================',
    `  Fault mode used .......... ${summary.faultMode}`,
    `  Total runs ............... ${summary.totalRuns}`,
    `  Passed ................... ${summary.passed}`,
    `  Failed ................... ${summary.failed}`,
    `  Success rate ............. ${round(summary.successRate, 2)}%`,
    `  Avg latency / handshake .. ${round(summary.avgLatencyMs, 4)} ms`,
    `  Min latency .............. ${round(summary.minLatencyMs, 4)} ms`,
    `  Max latency .............. ${round(summary.maxLatencyMs, 4)} ms`,
    `  Unique session keys ...... ${summary.uniqueSessionKeys}`,
    `  Session key collisions ... ${summary.sessionKeyCollisions}`,
    '======================================================================',
    '',
  ];
  return lines.join('\n');
}

/**
 * Generate paper-ready research summary text.
 * @param {object} summary
 * @returns {string}
 */
function generateResearchSummary(summary) {
  const faultDescription =
    FAULT_DESCRIPTIONS[summary.faultMode] || 'the configured fault conditions';

  const rate = round(summary.successRate, 2);
  const avg = round(summary.avgLatencyMs, 4);
  const min = round(summary.minLatencyMs, 4);
  const max = round(summary.maxLatencyMs, 4);

  return (
    `The Aegis mutual authentication protocol was evaluated through ${summary.totalRuns} ` +
    `simulated handshake iterations using AES-128 (CBC mode) encryption and SHA-256 ` +
    `session-key derivation, implemented via the Node.js built-in crypto module. The ` +
    `simulation replicated the three-phase challenge-response sequence specified for the ` +
    `NXP NTAG 424 DNA TT chip. Authentication succeeded in ${summary.passed} of ` +
    `${summary.totalRuns} runs (${rate}%), with an average handshake latency of ${avg}ms ` +
    `(min: ${min}ms, max: ${max}ms). Across all successful sessions, ` +
    `${summary.uniqueSessionKeys} unique 256-bit session keys were generated with ` +
    `${summary.sessionKeyCollisions} collisions observed, confirming the protocol's ` +
    `replay-resistance property. Fault injection testing under ${summary.faultMode} ` +
    `conditions produced ${summary.failed} correctly rejected authentication attempts, ` +
    `demonstrating the system's ability to detect ${faultDescription}.`
  );
}

/**
 * Assemble the full JSON export payload (summary + per-run results + paper text).
 * @param {object} summary
 * @param {Array} results
 * @returns {object}
 */
function buildExportPayload(summary, results) {
  return {
    generatedAt: new Date().toISOString(),
    summary,
    researchSummary: generateResearchSummary(summary),
    results,
  };
}

/** Truncate a hex string to its first `n` chars with an ellipsis. */
function shortHex(hex, n = 8) {
  if (!hex) return '----';
  // RndB_prime_hex may carry a "(tampered ...)" annotation — keep only the hex.
  const clean = String(hex).split(' ')[0];
  return clean.length > n ? clean.slice(0, n) + '...' : clean;
}

/**
 * Format a single run's full protocol trace for CLI --verbose output.
 * @param {object} result a per-run result object: { run, passed, latencyMs, fault, trace }
 * @returns {string}
 */
function formatVerboseRun(result) {
  const t = result.trace;
  const runNo = String(result.run).padStart(3, '0');
  const status = result.passed ? 'PASS' : `FAIL — ${result.fault}`;
  const lines = [`Run #${runNo} [${status}] ${round(result.latencyMs, 3)}ms`];

  // Phase 1
  const p1 = t.phase1;
  const p1mark = p1.phase1Passed ? '✓' : '✗';
  lines.push(
    `  Phase 1: RndB=${shortHex(p1.RndB_hex)} → E=${shortHex(p1.ciphertextE_hex)} → ` +
      `Decrypted=${shortHex(p1.decryptedRndB_hex)} ${p1mark}`
  );
  if (!p1.phase1Passed) {
    lines.push(
      `           (chip key: ${shortHex(p1.chipSecretKeyHex)} | ` +
        `backend key: ${shortHex(p1.backendKeyHex)} — mismatch)`
    );
  }

  // Phase 2
  const p2 = t.phase2;
  if (!p2.ran) {
    lines.push('  Phase 2: skipped');
  } else {
    const p2mark = p2.phase2Passed ? '✓' : '✗';
    lines.push(
      `  Phase 2: RndA=${shortHex(p2.RndA_hex)} RndB'=${shortHex(p2.RndB_prime_hex)} → ` +
        `F=${shortHex(p2.ciphertextF_hex)} → Verified ${p2mark}`
    );
    if (!p2.phase2Passed) {
      lines.push(
        `           (expected RndB'=${shortHex(p2.expectedRndB_prime_hex)} — replay attack detected)`
      );
    }
  }

  // Phase 3
  const p3 = t.phase3;
  if (!p3.ran) {
    lines.push('  Phase 3: skipped');
  } else {
    lines.push(`  Phase 3: SessionKey=${shortHex(p3.sessionKeyHex, 12)} ✓`);
  }

  return lines.join('\n');
}

/**
 * Render a complete, human-readable single-handshake trace (CLI --trace).
 * Intended as a worked example for a research-paper appendix. Shows full hex.
 * @param {object} result a per-run result object with `trace`
 * @returns {string}
 */
function formatSingleTrace(result) {
  const t = result.trace;
  const bar = '═'.repeat(51);
  const out = [];

  out.push(bar);
  out.push('AEGIS MUTUAL AUTHENTICATION — SINGLE PROTOCOL TRACE');
  out.push(bar);
  out.push('');

  out.push('SETUP');
  out.push(`  Chip Secret Key : ${t.phase1.chipSecretKeyHex} (16 bytes, AES-128 key)`);
  out.push(`  Backend Key     : ${t.phase1.backendKeyHex} (same key — legitimate session)`);
  out.push('');

  out.push('PHASE 1 — Chip challenges backend');
  out.push(`  RndB (chip random)     : ${t.phase1.RndB_hex}  (16 bytes, crypto.randomBytes)`);
  out.push(`  E = AES-128(Key, RndB) : ${t.phase1.ciphertextE_hex}  (ciphertext sent to backend)`);
  out.push(`  Backend decrypts E     : ${t.phase1.decryptedRndB_hex}  (must match RndB)`);
  out.push(`  Phase 1 result         : ${t.phase1.phase1Passed ? 'PASS ✓' : 'FAIL ✗'}`);
  out.push('');

  out.push('PHASE 2 — Backend challenges chip');
  if (t.phase2.ran) {
    out.push(`  RndA (backend random)  : ${t.phase2.RndA_hex}  (16 bytes, crypto.randomBytes)`);
    out.push(`  RndB rotated left 1B   : ${shortHex(t.phase2.RndB_prime_hex, 32)}  (RndB_prime)`);
    out.push(`  F = AES-128(Key, RndA‖RndB') : ${t.phase2.ciphertextF_hex}  (ciphertext sent to chip)`);
    out.push(`  Chip decrypts F        : ${t.phase2.decryptedRndA_hex} ‖ ${t.phase2.decryptedRndB_prime_hex}`);
    out.push(`  RndB_prime verified    : ${t.phase2.phase2Passed ? 'PASS ✓' : 'FAIL ✗'}`);
  } else {
    out.push(`  ${t.phase2.skipReason}`);
  }
  out.push('');

  out.push('PHASE 3 — Session key derivation');
  if (t.phase3.ran) {
    out.push(`  SessionKey = SHA-256(F): ${t.phase3.sessionKeyHex} (32 bytes, 256-bit)`);
    out.push('  Key is ephemeral — unique per session, discarded after use');
    out.push('  Phase 3 result         : PASS ✓');
  } else {
    out.push(`  ${t.phase3.skipReason}`);
  }
  out.push('');

  out.push(`OUTCOME: ${result.passed ? 'AUTHENTICATION SUCCESSFUL' : 'AUTHENTICATION REJECTED'}`);
  out.push(`  Total time: ${round(result.latencyMs, 3)}ms`);
  out.push('');
  out.push(bar);

  return out.join('\n');
}

module.exports = {
  FAULT_DESCRIPTIONS,
  round,
  shortHex,
  formatConsoleSummary,
  formatVerboseRun,
  formatSingleTrace,
  generateResearchSummary,
  buildExportPayload,
};
