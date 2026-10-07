import test from 'node:test';
import assert from 'node:assert';
import { webcrypto } from 'node:crypto';

// The worker modules assume a global `crypto`, as the Workers runtime provides.
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const load = () => import('../src/crypto.js');

function b64urlToBytes(value) {
  return Buffer.from(value.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function decodeSegment(segment) {
  return JSON.parse(b64urlToBytes(segment).toString('utf8'));
}

async function verifyJws(jws, publicJwk) {
  const [header, payload, signature] = jws.split('.');
  const key = await webcrypto.subtle.importKey(
    'jwk',
    { ...publicJwk, key_ops: ['verify'], ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
  return webcrypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    b64urlToBytes(signature),
    Buffer.from(`${header}.${payload}`, 'utf8')
  );
}

test('a DPoP proof is a verifiable ES256 JWS with the right header', async () => {
  const { generateKeyPair, dpopProof, publicPartOf } = await load();
  const { privateJwk, publicJwk } = await generateKeyPair();

  const proof = await dpopProof({
    privateJwk,
    method: 'post',
    url: 'https://pds.example/xrpc/com.atproto.repo.createRecord'
  });

  const [headerSegment, payloadSegment] = proof.split('.');
  const header = decodeSegment(headerSegment);
  const payload = decodeSegment(payloadSegment);

  assert.strictEqual(header.typ, 'dpop+jwt');
  assert.strictEqual(header.alg, 'ES256');
  assert.deepStrictEqual(header.jwk, publicPartOf(privateJwk));
  assert.strictEqual(header.jwk.d, undefined, 'the private component must never be published');

  assert.strictEqual(payload.htm, 'POST', 'the method is upper-cased');
  assert.strictEqual(payload.htu, 'https://pds.example/xrpc/com.atproto.repo.createRecord');
  assert.ok(payload.jti, 'has a jti');
  assert.ok(Math.abs(payload.iat - Math.floor(Date.now() / 1000)) < 5);

  assert.strictEqual(await verifyJws(proof, publicJwk), true);
});

test('htu drops the query and fragment', async () => {
  const { generateKeyPair, dpopProof } = await load();
  const { privateJwk } = await generateKeyPair();

  // A proof whose htu still carries a query string is rejected, and the
  // resulting invalid_dpop_proof is baffling because the URLs look identical.
  const proof = await dpopProof({
    privateJwk,
    method: 'GET',
    url: 'https://pds.example/xrpc/thing?cursor=abc&limit=5#frag'
  });
  assert.strictEqual(decodeSegment(proof.split('.')[1]).htu, 'https://pds.example/xrpc/thing');
});

test('ath is the base64url SHA-256 of the access token', async () => {
  const { generateKeyPair, dpopProof, sha256Base64Url } = await load();
  const { privateJwk } = await generateKeyPair();

  const accessToken = 'an-access-token';
  const proof = await dpopProof({
    privateJwk,
    method: 'POST',
    url: 'https://pds.example/xrpc/x',
    accessToken,
    nonce: 'server-nonce'
  });

  const payload = decodeSegment(proof.split('.')[1]);
  assert.strictEqual(payload.ath, await sha256Base64Url(accessToken));
  assert.strictEqual(payload.nonce, 'server-nonce');

  const expected = Buffer.from(
    await webcrypto.subtle.digest('SHA-256', Buffer.from(accessToken, 'utf8'))
  ).toString('base64url');
  assert.strictEqual(payload.ath, expected, 'matches an independent digest');
});

test('a proof without a token carries no ath or nonce', async () => {
  const { generateKeyPair, dpopProof } = await load();
  const { privateJwk } = await generateKeyPair();
  const payload = decodeSegment(
    (await dpopProof({ privateJwk, method: 'POST', url: 'https://as.example/oauth/par' })).split('.')[1]
  );
  assert.strictEqual(payload.ath, undefined);
  assert.strictEqual(payload.nonce, undefined);
});

test('a client assertion is signed, scoped to the audience, and short lived', async () => {
  const { generateKeyPair, clientAssertion } = await load();
  const { privateJwk, publicJwk } = await generateKeyPair();
  privateJwk.kid = 'test-key';

  const clientId = 'https://broker.example/client-metadata.json';
  const assertion = await clientAssertion({
    privateJwk,
    clientId,
    audience: 'https://bsky.social'
  });

  const header = decodeSegment(assertion.split('.')[0]);
  const payload = decodeSegment(assertion.split('.')[1]);
  assert.strictEqual(header.alg, 'ES256');
  assert.strictEqual(header.kid, 'test-key');
  assert.strictEqual(payload.iss, clientId);
  assert.strictEqual(payload.sub, clientId);
  assert.strictEqual(payload.aud, 'https://bsky.social');
  assert.ok(payload.exp - payload.iat <= 60, 'lives a minute at most');
  assert.strictEqual(await verifyJws(assertion, publicJwk), true);
});

test('PKCE produces an S256 challenge of its verifier', async () => {
  const { pkcePair, sha256Base64Url } = await load();
  const { verifier, challenge } = await pkcePair();
  assert.ok(verifier.length >= 43, 'RFC 7636 wants 43+ characters');
  assert.match(verifier, /^[A-Za-z0-9\-_]+$/, 'URL safe, unpadded');
  assert.strictEqual(challenge, await sha256Base64Url(verifier));
});

test('publicPartOf strips the private component', async () => {
  const { generateKeyPair, publicPartOf } = await load();
  const { privateJwk } = await generateKeyPair();
  assert.ok(privateJwk.d, 'the private JWK has d to begin with');
  const pub = publicPartOf(privateJwk);
  assert.strictEqual(pub.d, undefined);
  assert.deepStrictEqual(Object.keys(pub).sort(), ['crv', 'kty', 'x', 'y']);
});

test('random tokens are unique and URL safe', async () => {
  const { randomToken } = await load();
  const seen = new Set();
  for (let i = 0; i < 200; i++) {
    const token = randomToken(32);
    assert.match(token, /^[A-Za-z0-9\-_]+$/);
    assert.ok(!seen.has(token), 'no repeats');
    seen.add(token);
  }
});

test('pairing codes avoid ambiguous characters', async () => {
  const { newPairingCode, normalizeCode } = await import('../src/store.js');
  for (let i = 0; i < 100; i++) {
    const code = newPairingCode();
    assert.match(code, /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/,
      'no I, O, 0 or 1, and grouped for reading aloud');
    assert.strictEqual(normalizeCode(code.toLowerCase()), code.replace('-', ''));
  }
});

test('sealed values round-trip and resist tampering', async () => {
  const { seal, open, randomToken } = await load();
  const secret = randomToken(32);
  const session = { accessToken: 'at-123', refreshToken: 'rt-456', privateJwk: { d: 'secret' } };

  const sealed = await seal(secret, session);
  assert.ok(!sealed.includes('rt-456'), 'the refresh token is not readable in the stored value');
  assert.ok(!sealed.includes('secret'), 'the DPoP private component is not readable either');
  assert.match(sealed, /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/, 'iv.ciphertext, base64url');

  assert.deepStrictEqual(await open(secret, sealed), session);

  // A fresh IV per write: the same value must not produce the same ciphertext.
  assert.notStrictEqual(await seal(secret, session), sealed);

  // GCM authenticates, so a flipped byte fails to open instead of decrypting.
  const [iv, data] = sealed.split('.');
  const tampered = iv + '.' + (data[0] === 'A' ? 'B' : 'A') + data.slice(1);
  await assert.rejects(() => open(secret, tampered), 'tampered rows are rejected');

  // A different key cannot read it.
  await assert.rejects(() => open(randomToken(32), sealed), 'the wrong key is rejected');
});

test('a malformed or wrong-sized key is refused', async () => {
  const { seal, base64UrlEncode } = await load();
  await assert.rejects(() => seal(base64UrlEncode(new Uint8Array(16)), { a: 1 }),
    /32 bytes/, 'a short key is refused instead of silently weakening');
  await assert.rejects(() => seal('not-base64url-!!', { a: 1 }));
});

// scopes --------------------------------------------------------------------

const oauth = () => import('../src/oauth.js');

test('naming collections narrows the grant to exactly those', async () => {
  const { scopesFor } = await oauth();

  const wide = scopesFor({});
  assert.deepStrictEqual(wide, ['atproto', 'repo:*?action=create'],
    'no collections named means the whole repo');

  const narrow = scopesFor({ collections: ['app.bsky.feed.post', 'xyz.statusphere.status'] });
  assert.deepStrictEqual(narrow, [
    'atproto',
    'repo:app.bsky.feed.post?action=create',
    'repo:xyz.statusphere.status?action=create'
  ]);
  assert.ok(!narrow.includes('repo:*?action=create'),
    'a narrowed grant must not also carry the wildcard');

  // Spaces are opt-in: declaring them by default makes stock PDSes reject the login.
  assert.ok(!narrow.some((s) => s.startsWith('space:')));
  assert.ok(scopesFor({ spaces: true }).some((s) => s.startsWith('space:')));
});

test('collection lists normalise identically on both sides of the flow', async () => {
  const { normalizeCollections } = await oauth();

  // Order and duplicates must not change the client_id, or PAR sees scopes
  // that do not match what the server fetched.
  const a = normalizeCollections('xyz.statusphere.status, app.bsky.feed.post');
  const b = normalizeCollections(['app.bsky.feed.post', 'app.bsky.feed.post', ' xyz.statusphere.status ']);
  assert.deepStrictEqual(a, b);
  assert.deepStrictEqual(a, ['app.bsky.feed.post', 'xyz.statusphere.status']);

  // Empty entries are ignored, but a typo is refused instead of dropped:
  // dropping every entry leaves an empty list, and an empty list asks for
  // repo:*, so a typo would widen the grant instead of narrowing it.
  assert.deepStrictEqual(normalizeCollections('app.bsky.feed.post, ,'),
    ['app.bsky.feed.post']);
  assert.throws(() => normalizeCollections('not-an-nsid, app.bsky.feed.post'),
    /Not a collection name/);
  assert.throws(() => normalizeCollections('app.bsky.feed_post'), /Not a collection name/);
  assert.deepStrictEqual(normalizeCollections(''), [], 'nothing named is still "any"');
  assert.deepStrictEqual(normalizeCollections(''), []);
});

test('the client_id carries the grant and stays byte-identical', async () => {
  const { clientId, normalizeCollections } = await oauth();
  const env = { PUBLIC_URL: 'https://pebble.atproto.broker' };

  assert.strictEqual(clientId(env),
    'https://pebble.atproto.broker/oauth-client-metadata.json');

  const collections = normalizeCollections('xyz.statusphere.status,app.bsky.feed.post');
  const scoped = clientId(env, collections);
  assert.strictEqual(scoped,
    'https://pebble.atproto.broker/oauth-client-metadata.json?collections=app.bsky.feed.post%2Cxyz.statusphere.status');

  // Same inputs in a different order must produce the same string.
  assert.strictEqual(clientId(env, normalizeCollections('app.bsky.feed.post, xyz.statusphere.status')), scoped);
  assert.match(clientId(env, [], true), /\?spaces=1$/);
});

test('the metadata document declares exactly what was requested', async () => {
  const { clientMetadata, scopesFor, clientId } = await oauth();
  const env = { PUBLIC_URL: 'https://pebble.atproto.broker',
                CLIENT_NAME: 'Pebble atproto broker' };
  const collections = ['app.bsky.feed.post'];

  const meta = clientMetadata(env, { collections });
  assert.strictEqual(meta.scope, scopesFor({ collections }).join(' '),
    'declared scopes must equal requested scopes');
  assert.strictEqual(meta.client_id, clientId(env, collections));
  assert.ok(meta.client_id.endsWith('?collections=app.bsky.feed.post'));
  assert.strictEqual(meta.redirect_uris[0], 'https://pebble.atproto.broker/callback');
  assert.strictEqual(meta.jwks_uri, 'https://pebble.atproto.broker/jwks.json');
  assert.strictEqual(meta.dpop_bound_access_tokens, true);
  assert.strictEqual(meta.token_endpoint_auth_method, 'private_key_jwt');
});
