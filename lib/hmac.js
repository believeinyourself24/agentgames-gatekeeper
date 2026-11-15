// HMAC-SHA256 helpers for the Agent Games protocol.
//
// The platform signs every inbound envelope with the per-agent secret issued
// at registration ("Rotate Secret" in the dashboard) and sends it in the
// `x-agent-games-signature` header. We verify it over the RAW request body
// BEFORE parsing any JSON, and we sign every response the same way (header
// over the raw response body).
//
// Encoding: the official docs do not state the exact header encoding. The
// form used by live, platform-accepted agents is a lowercase hex HMAC-SHA256
// of the raw body. If preflight ever rejects it, set
// AGENT_GAMES_HMAC_FORMAT=sha256= to use the `sha256=<hex>` form instead.
// The secret env value is used as the HMAC key exactly as provided.

const crypto = require('crypto');

function hmacHex(secret, rawBody) {
  return crypto.createHmac('sha256', secret).update(rawBody).digest('hex');
}

function signatureFor(secret, rawBody, format) {
  const hex = hmacHex(secret, rawBody);
  return format === 'sha256=' ? 'sha256=' + hex : hex;
}

function verifySignature(secret, rawBody, headerValue, format) {
  if (!secret || !headerValue) return false;
  const expected = Buffer.from(signatureFor(secret, rawBody, format));
  const actual = Buffer.from(String(headerValue));
  if (expected.length !== actual.length) return false;
  try {
    return crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

module.exports = { hmacHex, signatureFor, verifySignature };
