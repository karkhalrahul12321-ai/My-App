// backend/totp.js
// Simple TOTP generator (RFC6238) with base32 secret decoding.
// No external deps needed.

const crypto = require('crypto');

function base32DecodeToBuffer(base32) {
  // remove padding and make uppercase
  const s = base32.replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  const lookup = {
    A:0, B:1, C:2, D:3, E:4, F:5, G:6, H:7,
    I:8, J:9, K:10, L:11, M:12, N:13, O:14, P:15,
    Q:16, R:17, S:18, T:19, U:20, V:21, W:22, X:23,
    Y:24, Z:25, '2':26, '3':27, '4':28, '5':29, '6':30, '7':31
  };

  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    const val = lookup[ch];
    if (val === undefined) continue;
    value = (value << 5) | val;
    bits += 5;
    while (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTOTP(secretBase32, options = {}) {
  // options: { step: 30, digits: 6, algo: 'sha1', timestamp: Date.now() }
  const step = options.step || 30;
  const digits = options.digits || 6;
  const algo = (options.algo || 'sha1').toLowerCase();
  const time = Math.floor((options.timestamp ? Math.floor(options.timestamp/1000) : Math.floor(Date.now()/1000)) / step);

  const key = base32DecodeToBuffer(secretBase32);
  if (!key || key.length === 0) throw new Error('Invalid TOTP secret');

  // 8-byte counter
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(time / Math.pow(2, 32)), 0); // high
  buf.writeUInt32BE(time & 0xffffffff, 4); // low

  const hmac = crypto.createHmac(algo, key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24) |
               ((hmac[offset + 1] & 0xff) << 16) |
               ((hmac[offset + 2] & 0xff) << 8) |
               (hmac[offset + 3] & 0xff);

  const otp = (code % Math.pow(10, digits)).toString().padStart(digits, '0');
  return otp;
}

module.exports = { generateTOTP };
