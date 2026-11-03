'use strict';

/**
 * Aegis mutual authentication protocol — pure crypto logic.
 *
 * Implements the three-phase challenge-response handshake modelled on the
 * NXP NTAG 424 DNA TT chip authentication flow using only the Node.js
 * built-in `crypto` module:
 *   - AES-128 in CBC mode with a zero IV (no padding; data is block-aligned)
 *   - SHA-256 for ephemeral session-key derivation
 */

const crypto = require('crypto');

const BLOCK_SIZE = 16; // AES-128 block / RndA / RndB are all 16 bytes
const ZERO_IV = Buffer.alloc(BLOCK_SIZE, 0x00);

const FAULT_MODES = ['legitimate', 'wrong-key', 'tampered-rndb', 'random-fault'];

/**
 * Generate `n` cryptographically secure random bytes.
 * @param {number} n
 * @returns {Buffer}
 */
function generateRandomBytes(n) {
  return crypto.randomBytes(n);
}

/**
 * AES-128-CBC encrypt with a zero IV and no padding.
 * `data` length must be a non-zero multiple of 16 bytes.
 * @param {Buffer} key 16-byte key
 * @param {Buffer} data block-aligned plaintext
 * @returns {Buffer} ciphertext
 */
function aes128Encrypt(key, data) {
  if (key.length !== BLOCK_SIZE) {
    throw new Error(`AES-128 key must be ${BLOCK_SIZE} bytes, got ${key.length}`);
  }
  if (data.length === 0 || data.length % BLOCK_SIZE !== 0) {
    throw new Error(`AES-128-CBC data must be a non-zero multiple of ${BLOCK_SIZE} bytes`);
  }
  const cipher = crypto.createCipheriv('aes-128-cbc', key, ZERO_IV);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

/**
 * AES-128-CBC decrypt with a zero IV and no padding.
 * @param {Buffer} key 16-byte key
 * @param {Buffer} data block-aligned ciphertext
 * @returns {Buffer} plaintext
 */
function aes128Decrypt(key, data) {
  if (key.length !== BLOCK_SIZE) {
    throw new Error(`AES-128 key must be ${BLOCK_SIZE} bytes, got ${key.length}`);
  }
  if (data.length === 0 || data.length % BLOCK_SIZE !== 0) {
    throw new Error(`AES-128-CBC data must be a non-zero multiple of ${BLOCK_SIZE} bytes`);
  }
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, ZERO_IV);
  decipher.setAutoPadding(false);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

/**
 * Rotate a buffer left by one byte (the leading byte wraps to the end).
 * Matches the NTAG 424 DNA "RndB'" derivation.
 * @param {Buffer} buffer
 * @returns {Buffer} a new rotated buffer
 */
function rotateLeft(buffer) {
  if (buffer.length === 0) {
    return Buffer.alloc(0);
  }
  return Buffer.concat([buffer.subarray(1), buffer.subarray(0, 1)]);
}

/**
 * Derive the ephemeral session key as SHA-256 of Ciphertext_F.
 * @param {Buffer} ciphertextF
 * @returns {Buffer} 32-byte session key
 */
function deriveSessionKey(ciphertextF) {
  return crypto.createHash('sha256').update(ciphertextF).digest();
}

/**
 * Decide which concrete fault to apply for this run.
 * For "random-fault", 5% of runs inject either wrong-key or tampered-rndb.
 * @param {string} faultMode
 * @returns {string} one of: legitimate | wrong-key | tampered-rndb
 */
function resolveFault(faultMode) {
  if (faultMode === 'random-fault') {
    if (Math.random() < 0.05) {
      return Math.random() < 0.5 ? 'wrong-key' : 'tampered-rndb';
    }
    return 'legitimate';
  }
  return faultMode;
}

/**
 * Run a single three-phase mutual-authentication handshake.
 *
 * @param {object} [options]
 * @param {string} [options.fault='legitimate'] fault mode for this run
 * @param {Buffer} [options.chipKey] override the chip's secret key
 * @returns {object} full trace of the handshake
 */
function runHandshake(options = {}) {
  const faultMode = options.fault || 'legitimate';
  if (!FAULT_MODES.includes(faultMode)) {
    throw new Error(`Unknown fault mode: ${faultMode}`);
  }
  const appliedFault = resolveFault(faultMode);

  const start = process.hrtime.bigint();

  // --- Key provisioning -----------------------------------------------------
  const chipKey = options.chipKey || generateRandomBytes(BLOCK_SIZE);
  // The backend normally holds an identical copy of the chip's secret key.
  // Under "wrong-key" it holds a mismatched key (cloned chip / rogue reader).
  const backendKey =
    appliedFault === 'wrong-key' ? generateRandomBytes(BLOCK_SIZE) : Buffer.from(chipKey);

  // Top-level convenience fields (consumed by the web UI trace panel) plus the
  // structured, paper-ready `trace` object documenting every phase.
  const result = {
    fault: faultMode,
    appliedFault,
    chipSecretKey: chipKey.toString('hex'),
    backendKey: backendKey.toString('hex'),
    phases: { phase1: false, phase2: false, phase3: false },
  };

  const traceDetail = {
    phase1: {},
    phase2: { ran: false },
    phase3: { ran: false },
    sessionKeyHex: null,
  };

  // === Phase 1 — chip challenges backend ===================================
  const rndB = generateRandomBytes(BLOCK_SIZE);
  const ciphertextE = aes128Encrypt(chipKey, rndB);
  // Backend decrypts Ciphertext_E with its own key copy.
  const backendRndB = aes128Decrypt(backendKey, ciphertextE);
  const phase1Passed = backendRndB.equals(rndB);

  result.rndB = rndB.toString('hex');
  result.ciphertextE = ciphertextE.toString('hex');
  result.backendRndB = backendRndB.toString('hex');
  result.phases.phase1 = phase1Passed;

  traceDetail.phase1 = {
    chipSecretKeyHex: chipKey.toString('hex'),
    backendKeyHex: backendKey.toString('hex'),
    RndB_hex: rndB.toString('hex'),
    ciphertextE_hex: ciphertextE.toString('hex'),
    decryptedRndB_hex: backendRndB.toString('hex'),
    phase1Passed,
  };
  if (!phase1Passed) {
    traceDetail.phase1.phase1FailReason =
      'Backend key does not match chip key — decrypted value differs from RndB';
  }

  // === Phase 2 — backend challenges chip ===================================
  // Phase 2 only runs if the chip's identity was confirmed in Phase 1.
  let ciphertextF = null;
  let phase2Passed = false;
  if (phase1Passed) {
    const rndA = generateRandomBytes(BLOCK_SIZE);
    // Backend rotates the RndB it recovered (left by one byte).
    let rndBPrime = rotateLeft(backendRndB);
    const tampered = appliedFault === 'tampered-rndb';
    // Replay-attack simulation: corrupt RndB' before it is encrypted.
    if (tampered) {
      rndBPrime = generateRandomBytes(BLOCK_SIZE);
    }

    ciphertextF = aes128Encrypt(backendKey, Buffer.concat([rndA, rndBPrime]));

    // Chip decrypts Ciphertext_F with its own key and verifies RndB'.
    const chipDecryptedF = aes128Decrypt(chipKey, ciphertextF);
    const chipRndA = chipDecryptedF.subarray(0, BLOCK_SIZE);
    const chipRndBPrime = chipDecryptedF.subarray(BLOCK_SIZE, 2 * BLOCK_SIZE);
    const expectedRndBPrime = rotateLeft(rndB); // chip's own rotated RndB
    phase2Passed = chipRndBPrime.equals(expectedRndBPrime);

    result.rndA = rndA.toString('hex');
    result.rndBPrime = rndBPrime.toString('hex');
    result.ciphertextF = ciphertextF.toString('hex');
    result.chipRndBPrime = chipRndBPrime.toString('hex');
    result.expectedRndBPrime = expectedRndBPrime.toString('hex');
    result.phases.phase2 = phase2Passed;

    traceDetail.phase2 = {
      ran: true,
      RndA_hex: rndA.toString('hex'),
      RndB_prime_hex:
        rndBPrime.toString('hex') + (tampered ? ' (tampered — random bytes substituted)' : ''),
      ciphertextF_hex: ciphertextF.toString('hex'),
      decryptedRndA_hex: chipRndA.toString('hex'),
      decryptedRndB_prime_hex: chipRndBPrime.toString('hex'),
      phase2Passed,
    };
    if (!phase2Passed) {
      traceDetail.phase2.expectedRndB_prime_hex = expectedRndBPrime.toString('hex');
      traceDetail.phase2.phase2FailReason =
        'RndB_prime does not match expected rotation of RndB — replay attack detected';
    }
  } else {
    traceDetail.phase2 = {
      ran: false,
      skipReason: 'Phase 1 failed — handshake terminated',
    };
  }

  // === Phase 3 — session-key derivation ====================================
  // Only meaningful if both identities were confirmed.
  let sessionKey = null;
  if (phase1Passed && phase2Passed) {
    sessionKey = deriveSessionKey(ciphertextF);
    result.phases.phase3 = true;
    traceDetail.phase3 = {
      ran: true,
      sessionKeyInput_hex: ciphertextF.toString('hex'),
      sessionKeyHex: sessionKey.toString('hex'),
    };
    traceDetail.sessionKeyHex = sessionKey.toString('hex');
  } else {
    traceDetail.phase3 = {
      ran: false,
      skipReason: phase1Passed
        ? 'Phase 2 failed — no session key derived'
        : 'Phase 1 failed — no session key derived',
    };
  }

  result.sessionKey = sessionKey ? sessionKey.toString('hex') : null;
  result.trace = traceDetail;

  const end = process.hrtime.bigint();
  result.latencyMs = Number(end - start) / 1e6;

  result.passed = result.phases.phase1 && result.phases.phase2 && result.phases.phase3;

  return result;
}

module.exports = {
  BLOCK_SIZE,
  FAULT_MODES,
  generateRandomBytes,
  aes128Encrypt,
  aes128Decrypt,
  rotateLeft,
  deriveSessionKey,
  resolveFault,
  runHandshake,
};
