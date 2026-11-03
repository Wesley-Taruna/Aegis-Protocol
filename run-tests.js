#!/usr/bin/env node
'use strict';

/**
 * Aegis Protocol — CLI test runner.
 *
 * Usage:
 *   node run-tests.js [options]
 *
 * Options:
 *   --count <n>       Number of iterations (default: 1000)
 *   --fault <mode>    legitimate | wrong-key | tampered-rndb | random-fault (default: legitimate)
 *   --output <file>   Save full results to a JSON file (optional)
 *   --verbose         Print each iteration result (default: summary only)
 *   --help            Show this help text
 */

const fs = require('fs');
const path = require('path');

const { FAULT_MODES, runHandshake } = require('./src/protocol');
const { runBatch } = require('./src/runner');
const {
  formatConsoleSummary,
  formatVerboseRun,
  formatSingleTrace,
  generateResearchSummary,
  buildExportPayload,
} = require('./src/report');

function parseArgs(argv) {
  const opts = {
    count: 1000, fault: 'legitimate', output: null, verbose: false, trace: false, help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--count':
        opts.count = parseInt(argv[++i], 10);
        break;
      case '--fault':
        opts.fault = argv[++i];
        break;
      case '--output':
        opts.output = argv[++i];
        break;
      case '--verbose':
        opts.verbose = true;
        break;
      case '--trace':
        opts.trace = true;
        break;
      case '--help':
      case '-h':
        opts.help = true;
        break;
      default:
        console.error(`Unknown option: ${arg}`);
        opts.help = true;
    }
  }
  return opts;
}

function printHelp() {
  console.log(`
Aegis Protocol — CLI test runner

Usage:
  node run-tests.js [options]

Options:
  --count <n>       Number of iterations (default: 1000)
  --fault <mode>    Fault mode: ${FAULT_MODES.join(' | ')} (default: legitimate)
  --output <file>   Save full results to a JSON file (optional)
  --verbose         Print each iteration's full protocol trace (default: summary only)
  --trace           Run ONE legitimate handshake and print the complete,
                    labelled protocol trace (worked example for paper appendix)
  --help, -h        Show this help text

Examples:
  node run-tests.js --count 1000 --fault legitimate
  node run-tests.js --count 1000 --fault wrong-key
  node run-tests.js --count 1000 --fault tampered-rndb
  node run-tests.js --count 1000 --fault random-fault --output results.json
  node run-tests.js --trace
`);
}

function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.help) {
    printHelp();
    process.exit(0);
  }

  // Single-trace mode: one legitimate handshake, fully labelled.
  if (opts.trace) {
    const result = runHandshake({ fault: 'legitimate' });
    console.log(formatSingleTrace(result));
    process.exit(0);
  }

  if (!Number.isFinite(opts.count) || opts.count < 1) {
    console.error('Error: --count must be a positive integer.');
    process.exit(1);
  }
  if (!FAULT_MODES.includes(opts.fault)) {
    console.error(`Error: --fault must be one of: ${FAULT_MODES.join(', ')}`);
    process.exit(1);
  }

  console.log(
    `Running ${opts.count} Aegis handshake(s) under fault mode "${opts.fault}"...`
  );

  const { summary, results } = runBatch({
    count: opts.count,
    fault: opts.fault,
    onProgress: opts.verbose
      ? null // verbose prints every run below instead
      : null,
  });

  if (opts.verbose) {
    for (const r of results) {
      console.log(formatVerboseRun(r));
      console.log('');
    }
  }

  console.log(formatConsoleSummary(summary));

  console.log('Research summary:\n');
  console.log(generateResearchSummary(summary));
  console.log('');

  if (opts.output) {
    const payload = buildExportPayload(summary, results);
    const outPath = path.resolve(process.cwd(), opts.output);
    fs.writeFileSync(outPath, JSON.stringify(payload, null, 2));
    console.log(`Saved full results to ${outPath}`);
  }
}

main();
