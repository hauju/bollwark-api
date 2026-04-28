// PoW Web Worker.
//
// Dispatches on `algorithm` from the message:
//   - "sha256"        → SubtleCrypto SHA-256(prefix_utf8 + nonce_le_8bytes)
//   - {argon2id: {…}} → hash-wasm Argon2id(password=nonce_le_8bytes, salt=prefix_utf8,
//                                          m_cost, t_cost, p_cost, hashLength=32)
//
// Both must match the server's `compute_sha256` / `compute_argon2id`. The
// nonce is written as a little-endian u64 in both paths.

self.onmessage = async function (e) {
  const { prefix, difficulty, algorithm } = e.data;

  try {
    if (algorithm === "sha256" || algorithm === undefined) {
      await solveSha256(prefix, difficulty);
    } else if (algorithm && typeof algorithm === "object" && algorithm.argon2id) {
      await solveArgon2id(prefix, difficulty, algorithm.argon2id);
    } else {
      self.postMessage({
        type: "error",
        message: "Unknown algorithm: " + JSON.stringify(algorithm),
      });
    }
  } catch (err) {
    self.postMessage({ type: "error", message: String(err && err.message || err) });
  }
};

// ── SHA-256 ──

async function solveSha256(prefix, difficulty) {
  const prefixBytes = new TextEncoder().encode(prefix);
  const data = new Uint8Array(prefixBytes.length + 8);
  data.set(prefixBytes, 0);
  const nonceView = new DataView(data.buffer, prefixBytes.length, 8);

  for (let nonce = 0; ; nonce++) {
    nonceView.setUint32(0, nonce >>> 0, true);
    nonceView.setUint32(4, 0, true); // high 32 bits 0 for nonces < 2^32

    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hash = new Uint8Array(hashBuffer);

    if (hasLeadingZeroBits(hash, difficulty)) {
      self.postMessage({ type: "solved", nonce });
      return;
    }

    if (nonce % 50000 === 0 && nonce > 0) {
      self.postMessage({ type: "progress", nonce });
    }
  }
}

// ── Argon2id ──

let _argon2Loaded = false;
function loadArgon2() {
  if (_argon2Loaded) return;
  // Bundled at build time; resolved relative to the worker URL.
  importScripts("vendor/argon2.umd.min.js");
  if (!self.hashwasm || !self.hashwasm.argon2id) {
    throw new Error("argon2 vendor bundle did not expose hashwasm.argon2id");
  }
  _argon2Loaded = true;
}

async function solveArgon2id(prefix, difficulty, params) {
  loadArgon2();
  const salt = new TextEncoder().encode(prefix);
  const password = new Uint8Array(8);
  const passwordView = new DataView(password.buffer);

  // Argon2id is orders of magnitude more expensive per hash than SHA-256,
  // so progress reporting cadence is much tighter.
  for (let nonce = 0; ; nonce++) {
    passwordView.setUint32(0, nonce >>> 0, true);
    passwordView.setUint32(4, 0, true);

    const hash = await self.hashwasm.argon2id({
      password,
      salt,
      parallelism: params.p_cost,
      iterations: params.t_cost,
      memorySize: params.m_cost, // KiB
      hashLength: 32,
      outputType: "binary",
    });

    if (hasLeadingZeroBits(hash, difficulty)) {
      self.postMessage({ type: "solved", nonce });
      return;
    }

    // Progress every 4 hashes — at typical params each hash is ~10–100ms,
    // so this updates the UI at a comfortable cadence.
    if (nonce % 4 === 0 && nonce > 0) {
      self.postMessage({ type: "progress", nonce });
    }
  }
}

// ── Shared ──

function hasLeadingZeroBits(hash, difficulty) {
  let remaining = difficulty;
  for (let i = 0; i < hash.length; i++) {
    if (remaining === 0) return true;
    if (remaining >= 8) {
      if (hash[i] !== 0) return false;
      remaining -= 8;
    } else {
      const mask = 0xff << (8 - remaining);
      return (hash[i] & mask) === 0;
    }
  }
  return remaining === 0;
}
