# Aegis Protocol — Mutual Authentication Testing Suite

A standalone Node.js testing suite that simulates and validates the **Aegis mutual
authentication protocol**: an AES-128 + SHA-256 three-phase challenge-response handshake
modelled on the NXP **NTAG 424 DNA TT** NFC chip authentication system.

It provides:

1. A **CLI test runner** (`run-tests.js`) that executes thousands of simulated handshakes
   and reports real timing/integrity statistics.
2. A **local web UI** (`server.js` → http://localhost:3000) for running tests
   interactively with live metrics, a protocol trace, a latency histogram, and
   paper-ready research text.

All cryptography uses the **Node.js built-in `crypto` module only** — no external crypto
libraries. The single runtime dependency is Express (web server); Chart.js is loaded via
CDN for the histogram.

---

## The protocol

| Phase | Direction | What happens |
|-------|-----------|--------------|
| **1** | Chip → Backend | Chip picks random `RndB` (16 B), sends `Ciphertext_E = AES-128(ChipKey, RndB)`. Backend decrypts and checks it recovered `RndB`. Confirms **chip identity**. |
| **2** | Backend → Chip | Backend picks random `RndA` (16 B), rotates `RndB` left by one byte → `RndB'`, sends `Ciphertext_F = AES-128(ChipKey, RndA ‖ RndB')`. Chip decrypts and checks `RndB'` equals its own rotated `RndB`. Confirms **backend identity**. |
| **3** | Both | Each side derives the ephemeral `SessionKey = SHA-256(Ciphertext_F)`. Unique per session, discarded after use. |

AES-128 runs in **CBC mode with a zero IV** and no padding (data is block-aligned),
matching the NTAG 424 DNA TT challenge-response behaviour.

### Fault injection modes

| Mode | Behaviour | Models |
|------|-----------|--------|
| `legitimate` | Chip and backend share the correct key. | Baseline — should always pass. |
| `wrong-key` | Backend uses a different key. | Cloned chip / unauthorized reader. |
| `tampered-rndb` | `RndB'` is replaced with random bytes before Phase 2 encryption. | Replay attack. |
| `random-fault` | 5% of runs randomly inject `wrong-key` or `tampered-rndb`. | Mixed adversarial traffic. |

---

## Install

```bash
cd aegis-protocol-test
npm install
```

Requires **Node.js 18+** (tested on Node 22).

---

## Run the CLI

```
node run-tests.js [options]

  --count <n>       Number of iterations (default: 1000)
  --fault <mode>    legitimate | wrong-key | tampered-rndb | random-fault (default: legitimate)
  --output <file>   Save full results to a JSON file (optional)
  --verbose         Print each iteration's full per-phase protocol trace
  --trace           Run ONE legitimate handshake and print the complete,
                    labelled protocol trace (worked example for the paper appendix)
  --help, -h        Show help
```

### Example commands (all four fault modes, 1000 iterations each)

```bash
node run-tests.js --count 1000 --fault legitimate
node run-tests.js --count 1000 --fault wrong-key
node run-tests.js --count 1000 --fault tampered-rndb
node run-tests.js --count 1000 --fault random-fault --output results.json
```

Or via npm scripts:

```bash
npm run legitimate
npm run wrong-key
npm run tampered-rndb
npm run random-fault
```

### Reading the CLI output

The summary block always prints:

```
==================== Aegis Protocol — Test Summary ====================
  Fault mode used .......... legitimate
  Total runs ............... 1000
  Passed ................... 1000
  Failed ................... 0
  Success rate ............. 100%
  Avg latency / handshake .. 0.0XXX ms
  Min latency .............. 0.0XXX ms
  Max latency .............. 0.XXXX ms
  Unique session keys ...... 1000
  Session key collisions ... 0
======================================================================
```

followed by the auto-generated **Research summary** paragraph.

The summary object also carries a **`phaseBreakdown`** showing exactly where failures
occur — the key evidence for the paper's security section:

```json
"phaseBreakdown": {
  "phase1PassCount": 1000, "phase1FailCount": 0,
  "phase2PassCount": 1000, "phase2FailCount": 0,
  "phase3ReachedCount": 1000
}
```

- `legitimate` → all pass phase 1, 2, and 3.
- `wrong-key` → all **fail at phase 1** (phase 2 never runs); proves clone rejection.
- `tampered-rndb` → all **pass phase 1 but fail at phase 2**; proves replay rejection.

### Per-run protocol trace

With `--output results.json` you get a JSON file containing all summary stats, the
research paragraph, and an array of per-run results. Each run now carries the **full
cryptographic trace** (proving the steps are genuinely executed):

```json
{
  "run": 1,
  "passed": true,
  "latencyMs": 0.045,
  "fault": "legitimate",
  "trace": {
    "phase1": { "chipSecretKeyHex": "…", "backendKeyHex": "…", "RndB_hex": "…",
                "ciphertextE_hex": "…", "decryptedRndB_hex": "…", "phase1Passed": true },
    "phase2": { "ran": true, "RndA_hex": "…", "RndB_prime_hex": "…", "ciphertextF_hex": "…",
                "decryptedRndA_hex": "…", "decryptedRndB_prime_hex": "…", "phase2Passed": true },
    "phase3": { "ran": true, "sessionKeyInput_hex": "…", "sessionKeyHex": "…" },
    "sessionKeyHex": "…"
  }
}
```

Failed phases include a human-readable reason (`phase1FailReason` / `phase2FailReason`),
and skipped phases include a `skipReason`. The session key for a run is at
`results[i].trace.sessionKeyHex` (or `null` when authentication failed).

### Single worked-example trace (for the paper appendix)

```bash
node run-tests.js --trace
```

Runs one legitimate handshake and prints a fully labelled, human-readable trace of all
three phases (with every hex value and what it means) — drop it straight into an appendix.

---

## Run the web UI

```bash
node server.js
# or: npm start
```

Open **http://localhost:3000**. The page lets you:

- Set the iteration count and fault mode.
- Click **Run Test** — progress streams live over Server-Sent Events.
- Watch the **progress bar** and **metric cards** update (Total / Passed / Failed /
  Success rate / Avg latency / Unique keys / Collisions).
- Inspect the **protocol trace** for the last handshake (every hex value + per-phase
  pass/fail).
- Read the **results log** table (last 100 runs).
- View the **latency histogram** (Chart.js).
- Click **Export JSON** to download the full results of the most recent run.
- Copy the **Research Summary** text box straight into your paper.

---

## Project structure

```
aegis-protocol-test/
├── package.json
├── README.md
├── run-tests.js          # CLI entry point
├── server.js             # Express server + SSE endpoint
├── src/
│   ├── protocol.js       # pure crypto logic (exports unit-testable functions)
│   ├── runner.js         # batch runner + statistics
│   └── report.js         # console/JSON formatting + research-summary generator
└── public/
    └── index.html        # single-file web UI
```

`protocol.js` exports the individually testable functions:
`generateRandomBytes(n)`, `aes128Encrypt(key, data)`, `aes128Decrypt(key, data)`,
`rotateLeft(buffer)`, `deriveSessionKey(ciphertextF)`, and `runHandshake(options)`.
Every handshake is timed with `process.hrtime.bigint()` for sub-millisecond precision.

---

## Using these results in your research paper

| Paper claim | Where the number comes from |
|-------------|------------------------------|
| **Functional correctness** — "the protocol authenticates legitimate parties." | `legitimate` run → **Success rate = 100%**, **Failed = 0**. |
| **Attack detection** — "cloned chips / unauthorized readers are rejected." | `wrong-key` run → **Success rate = 0%**, **Failed = N** (all rejected at Phase 1). |
| **Replay resistance (challenge tampering)** — "forged `RndB'` is detected." | `tampered-rndb` run → **Success rate = 0%**, **Failed = N** (all rejected at Phase 2). |
| **Mixed-traffic robustness** — "the system isolates faults in realistic traffic." | `random-fault` run → roughly **5% Failed**, ~95% pass. |
| **Session-key uniqueness / replay resistance** — "each session yields a fresh key." | **Unique session keys** ≈ Passed count, **Collisions = 0**. |
| **Failure localisation** — "rejections happen at the correct protocol phase." | `summary.phaseBreakdown` — wrong-key fails at phase 1, tampered-rndb fails at phase 2. |
| **Implementation authenticity** — "the crypto steps are genuinely executed." | Per-run `trace` objects + the `node run-tests.js --trace` worked example. |
| **Performance** — "the handshake is lightweight." | **Avg / Min / Max latency (ms)**. |
| **Method paragraph** | The auto-generated **Research Summary** text (CLI output, JSON `researchSummary` field, or the web UI text box). |

The research-summary generator produces text in exactly this shape:

> The Aegis mutual authentication protocol was evaluated through *N* simulated handshake
> iterations using AES-128 (CBC mode) encryption and SHA-256 session-key derivation,
> implemented via the Node.js built-in crypto module. … Authentication succeeded in
> *N_pass* of *N_total* runs (*rate*%), with an average handshake latency of *avg*ms
> (min: *min*ms, max: *max*ms). Across all successful sessions, *unique* unique 256-bit
> session keys were generated with *collisions* collisions observed, confirming the
> protocol's replay-resistance property. Fault injection testing under *fault_mode*
> conditions produced *fail* correctly rejected authentication attempts, demonstrating
> the system's ability to detect *fault_description*.

> **Note on the model.** This suite is a faithful *software simulation* of the
> challenge-response logic and its cryptographic primitives for protocol validation and
> performance characterisation. Latency figures reflect host-CPU crypto throughput, not
> physical NFC transceiver timing. State that distinction in your paper.
# Aegis-Protocol
