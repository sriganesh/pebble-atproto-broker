/**
 * ES256 (P-256 ECDSA) signing for DPoP proofs and client assertions.
 *
 * Everything here is stock WebCrypto, which the Workers runtime provides
 * natively. This is the whole reason the broker exists: the watch's phone-side
 * JS sandbox has no WebCrypto at all, so it cannot speak AT Protocol OAuth.
 */

export function base64UrlEncode(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlDecode(value) {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/');
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const encoder = new TextEncoder();

function encodeSegment(value) {
  return base64UrlEncode(encoder.encode(JSON.stringify(value)));
}

export async function sha256Base64Url(text) {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(text));
  return base64UrlEncode(digest);
}

/** Generate a P-256 keypair as JWKs, for `npm run keygen` and per-session DPoP keys. */
export async function generateKeyPair() {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const privateJwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
  return { privateJwk, publicJwk };
}

async function importPrivateKey(jwk) {
  return crypto.subtle.importKey(
    'jwk',
    { ...jwk, key_ops: ['sign'], ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
}

/**
 * An ES256 keypair for private_key_jwt, as a private JWK.
 *
 * The same shape tools/keygen.js prints, so a key made here and a key pasted
 * in are interchangeable.
 */
export async function generateSigningKey() {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  // A kid lets you rotate later: publish both keys, sign with the new one.
  jwk.kid = 'pebble-broker-' + new Date().toISOString().slice(0, 10);
  jwk.alg = 'ES256';
  jwk.use = 'sig';
  return jwk;
}

/**
 * The public half of a private JWK, with the private component removed.
 * Leaking `d` in a DPoP header or a JWKS would hand over the key itself.
 */
export function publicPartOf(jwk) {
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
}

/** Sign a compact JWS. WebCrypto's ECDSA output is already the r||s JWS wants. */
async function signJws(header, payload, privateJwk) {
  const key = await importPrivateKey(privateJwk);
  const signingInput = `${encodeSegment(header)}.${encodeSegment(payload)}`;
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    encoder.encode(signingInput)
  );
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

/**
 * A DPoP proof (RFC 9449).
 *
 * `htu` is the request URI with query and fragment stripped. A proof whose htu
 * still carries a query string is rejected, and the resulting
 * `invalid_dpop_proof` looks baffling because the URLs appear identical.
 */
export async function dpopProof({ privateJwk, method, url, nonce, accessToken }) {
  const target = new URL(url);
  target.search = '';
  target.hash = '';

  const payload = {
    jti: crypto.randomUUID(),
    htm: method.toUpperCase(),
    htu: target.toString(),
    iat: Math.floor(Date.now() / 1000)
  };
  if (nonce) payload.nonce = nonce;
  if (accessToken) payload.ath = await sha256Base64Url(accessToken);

  return signJws(
    { typ: 'dpop+jwt', alg: 'ES256', jwk: publicPartOf(privateJwk) },
    payload,
    privateJwk
  );
}

/**
 * A private_key_jwt client assertion (RFC 7523), which is how a confidential
 * client authenticates to the token endpoint.
 */
export async function clientAssertion({ privateJwk, clientId, audience }) {
  const now = Math.floor(Date.now() / 1000);
  return signJws(
    { typ: 'JWT', alg: 'ES256', kid: privateJwk.kid },
    {
      iss: clientId,
      sub: clientId,
      aud: audience,
      jti: crypto.randomUUID(),
      iat: now,
      exp: now + 60
    },
    privateJwk
  );
}

// encryption at rest ---------------------------------------------------------

/**
 * Seal a value for storage.
 *
 * A session row holds a refresh token *and* the DPoP private key that binds
 * it. Side by side that pair defeats the point of DPoP, so rows are encrypted
 * under a key that lives in a Worker secret and never in storage.
 *
 * AES-256-GCM with a fresh 96-bit IV per write, stored as iv.ciphertext in
 * base64url. GCM authenticates too, so a tampered row fails to open rather
 * than decrypting to something attacker-chosen.
 */
async function storageKey(secret) {
  const raw = base64UrlDecode(secret);
  if (raw.length !== 32) {
    throw new Error('STORAGE_KEY must be 32 bytes, base64url encoded');
  }
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function seal(secret, value) {
  const key = await storageKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);
  return `${base64UrlEncode(iv)}.${base64UrlEncode(ciphertext)}`;
}

export async function open(secret, stored) {
  const [ivPart, dataPart] = String(stored || '').split('.');
  if (!ivPart || !dataPart) {
    throw new Error('stored value is not sealed');
  }
  const key = await storageKey(secret);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64UrlDecode(ivPart) },
    key,
    base64UrlDecode(dataPart)
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

/** A URL-safe random token. */
export function randomToken(bytes = 32) {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** PKCE: a verifier and its S256 challenge. */
export async function pkcePair() {
  const verifier = randomToken(32);
  return { verifier, challenge: await sha256Base64Url(verifier) };
}

export function decodeJwtPayload(token) {
  try {
    const part = token.split('.')[1];
    return JSON.parse(new TextDecoder().decode(base64UrlDecode(part)));
  } catch {
    return null;
  }
}
