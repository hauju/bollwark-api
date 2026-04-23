// PoW Web Worker - SHA-256 brute-force solver
// Must match Rust's compute_hash(): SHA-256(prefix_utf8_bytes + nonce_le_8bytes)

self.onmessage = async function (e) {
  const { prefix, difficulty } = e.data;
  const prefixBytes = new TextEncoder().encode(prefix);
  const data = new Uint8Array(prefixBytes.length + 8);
  data.set(prefixBytes, 0);
  const nonceView = new DataView(data.buffer, prefixBytes.length, 8);

  for (let nonce = 0; ; nonce++) {
    // Write nonce as 8-byte little-endian u64
    nonceView.setUint32(0, nonce >>> 0, true);
    nonceView.setUint32(4, 0, true); // high 32 bits always 0 for nonces < 2^32

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
};

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
