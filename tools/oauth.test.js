import test from 'node:test';
import assert from 'node:assert';

import { clientId, clientMetadata, normalizeCollections, scopesFor } from '../src/oauth.js';

const env = { PUBLIC_URL: 'https://pebble.atproto.broker', CLIENT_NAME: 'Catapult' };

/**
 * The authorization server fetches `client_id` verbatim and reads the document
 * it finds there. If that document names a different client_id, or declares
 * scopes other than the ones pushed, the flow breaks or succeeds while
 * asking for more than intended.
 */
function metadataAt(url) {
  const params = new URL(url).searchParams;
  return clientMetadata(env, {
    collections: normalizeCollections(params.get('collections') || ''),
    spaces: params.get('spaces') === '1',
    minimal: params.get('minimal') === '1'
  });
}

const VARIANTS = [
  { name: 'default', args: [[], false, false] },
  { name: 'named collections', args: [['app.bsky.feed.post', 'xyz.statusphere.status'], false, false] },
  { name: 'spaces', args: [[], true, false] },
  { name: 'collections and spaces', args: [['app.bsky.feed.post'], true, false] },
  { name: 'minimal', args: [[], false, true] }
];

test('the document at a client_id names that same client_id', () => {
  for (const { name, args } of VARIANTS) {
    const url = clientId(env, ...args);
    assert.strictEqual(metadataAt(url).client_id, url,
      `${name}: the served document must name the URL it was fetched from`);
  }
});

test('the document at a client_id declares the scopes that URL implies', () => {
  for (const { name, args } of VARIANTS) {
    const [collections, spaces, minimal] = args;
    const url = clientId(env, ...args);
    assert.strictEqual(metadataAt(url).scope,
      scopesFor({ collections, spaces, minimal }).join(' '),
      `${name}: pushed scopes and published scopes must agree`);
  }
});

test('removing an account asks for no write access at all', () => {
  assert.deepStrictEqual(scopesFor({ minimal: true }), ['atproto'],
    'proving the DID is yours needs a signature, not permission to write');

  // Even when write options are passed alongside it, minimal wins: the
  // removal flow must not be talked into a broader grant.
  assert.deepStrictEqual(
    scopesFor({ collections: ['app.bsky.feed.post'], spaces: true, minimal: true }),
    ['atproto']);

  const meta = clientMetadata(env, { minimal: true });
  assert.strictEqual(meta.scope, 'atproto');
  assert.ok(!meta.scope.includes('repo:'), 'no repo write scope');
  assert.ok(!meta.scope.includes('space:'), 'no space write scope');
});

test('an ordinary sign-in still asks for what it needs', () => {
  assert.deepStrictEqual(scopesFor({}), ['atproto', 'repo:*?action=create']);
  assert.deepStrictEqual(scopesFor({ collections: ['app.bsky.feed.post'] }),
    ['atproto', 'repo:app.bsky.feed.post?action=create']);
  assert.ok(scopesFor({ spaces: true }).some((s) => s.startsWith('space:')));
});

test('each variant gets a distinct client_id', () => {
  const seen = VARIANTS.map(({ args }) => clientId(env, ...args));
  assert.strictEqual(new Set(seen).size, seen.length,
    'two different grants sharing one client_id would serve each other’s scopes');
});

test('every published document is a usable AT Proto client', () => {
  for (const { name, args } of VARIANTS) {
    const meta = metadataAt(clientId(env, ...args));
    assert.strictEqual(meta.dpop_bound_access_tokens, true, `${name}: DPoP is mandatory`);
    assert.strictEqual(meta.token_endpoint_auth_method, 'private_key_jwt', name);
    assert.strictEqual(meta.token_endpoint_auth_signing_alg, 'ES256', name);
    assert.ok(meta.scope.startsWith('atproto'), `${name}: atproto comes first`);
    assert.deepStrictEqual(meta.redirect_uris, ['https://pebble.atproto.broker/callback'], name);
    assert.ok(!('jwks' in meta), `${name}: keys are served from jwks_uri, never inline`);
  }
});

import { assertSafeUrl, pdsFromDidDocument } from '../src/identity.js';

test('credentials are never sent to a plaintext or private destination', () => {
  // A DID document names its own PDS and anyone can publish one, so the host
  // it points at is attacker-controlled.
  for (const hostile of [
    'http://pds.example.com', 'https://127.0.0.1', 'https://localhost:3000',
    'https://169.254.169.254', 'https://10.1.2.3', 'https://192.168.0.5',
    'https://172.20.0.1', 'https://[::1]', 'https://foo.internal', 'not-a-url'
  ]) {
    assert.throws(() => assertSafeUrl(hostile), undefined, `allowed: ${hostile}`);
  }
  for (const fine of ['https://pds.example.com', 'https://bsky.social/']) {
    assert.doesNotThrow(() => assertSafeUrl(fine));
  }
  assert.throws(() => pdsFromDidDocument({
    service: [{ id: '#atproto_pds', type: 'AtprotoPersonalDataServer',
                serviceEndpoint: 'https://169.254.169.254' }]
  }), /PrivateUrl|public host/);
});

test('a handle cannot steer resolution at a private host', async () => {
  // The handle becomes a URL, so it is input like any other.
  for (const handle of ['localhost', '127.0.0.1', '169.254.169.254', 'foo.internal']) {
    assert.throws(() => assertSafeUrl(`https://${handle}/.well-known/atproto-did`, 'handle'),
      undefined, `allowed: ${handle}`);
  }
  assert.doesNotThrow(() => assertSafeUrl('https://sri.xyz/.well-known/atproto-did', 'handle'));
});

test('every fetch destination the protocol hands us is checked', async () => {
  const { resolveDid, discoverAuthServer } = await import('../src/identity.js');

  // A did:web names its own host.
  await assert.rejects(() => resolveDid('did:web:localhost%3A3000'), /public host|https/i);
  await assert.rejects(() => resolveDid('did:web:127.0.0.1'), /public host/i);

  // And a PDS names its own authorization server.
  await assert.rejects(() => discoverAuthServer('http://pds.example.com'), /https/i);
  await assert.rejects(() => discoverAuthServer('https://169.254.169.254'), /public host/i);
});

test('a redirect cannot steer a fetch somewhere private', async () => {
  const { safeFetch } = await import('../src/identity.js');
  const real = globalThis.fetch;
  const seen = [];
  globalThis.fetch = async (url) => {
    seen.push(String(url));
    // A perfectly public host answers 302 towards the metadata service.
    if (String(url).startsWith('https://pds.example.com/')) {
      return new Response(null, { status: 302, headers: { location: 'https://169.254.169.254/' } });
    }
    return new Response('{}', { status: 200 });
  };
  try {
    await assert.rejects(() => safeFetch('https://pds.example.com/x'), /public host|PrivateUrl/);
    assert.ok(!seen.some((u) => u.includes('169.254')), 'the redirect was never followed');
  } finally {
    globalThis.fetch = real;
  }
});

test('the address guard covers the ranges that matter', async () => {
  const { assertSafeUrl } = await import('../src/identity.js');
  for (const hostile of [
    'https://[fe80::1]/', 'https://[feb0::1]/',        // fe80::/10, not only fe80:
    'https://[::ffff:127.0.0.1]/',                     // IPv4 in IPv6 clothing
    'https://[::ffff:a9fe:a9fe]/',                     // the same, written in hex
    'https://0.1.2.3/', 'https://100.64.0.1/',         // this-host, CGNAT
    'https://192.0.0.1/', 'https://198.18.0.1/',       // protocol assignments, benchmarking
    'https://239.1.1.1/', 'https://255.255.255.255/',  // multicast, broadcast
    'https://[ff02::1]/', 'https://[ff05::1:3]/'       // ff00::/8, multicast again
  ]) {
    assert.throws(() => assertSafeUrl(hostile), undefined, `allowed: ${hostile}`);
  }
  for (const fine of ['https://bsky.social/', 'https://100.128.0.1/', 'https://[2606:4700::1111]/']) {
    assert.doesNotThrow(() => assertSafeUrl(fine), `refused: ${fine}`);
  }
});

// Token responses, checked the way the atproto OAuth spec requires --------------

import { completeAuthorization, refreshSession as refreshForSpec, xrpcPost } from '../src/oauth.js';
import { generateSigningKey as makeKey } from '../src/crypto.js';

async function withTokenServer(t, reply) {
  const real = globalThis.fetch;
  t.after(() => { globalThis.fetch = real; });
  globalThis.fetch = async () => reply();
}

function tokenReply({ scope = 'atproto repo:*?action=create', nonce = 'n1', sub } = {}) {
  const headers = { 'content-type': 'application/json' };
  if (nonce) headers['DPoP-Nonce'] = nonce;
  const body = { access_token: 'a', refresh_token: 'r', expires_in: 3600 };
  if (scope !== null) body.scope = scope;
  if (sub) body.sub = sub;
  return new Response(JSON.stringify(body), { status: 200, headers });
}

async function spec() {
  const key = await makeKey();
  const env = { PUBLIC_URL: 'https://broker.example.net', CLIENT_PRIVATE_JWK: JSON.stringify(key) };
  const grant = {
    did: 'did:plc:alice', refreshToken: 'r0', tokenEndpoint: 'https://auth.example.com/oauth/token',
    issuer: 'https://auth.example.com', privateJwk: await makeKey(), collections: [], spaces: false,
    minimal: false, pds: 'https://pds.example.com', verifier: 'v'
  };
  return { env, grant };
}

test('a callback without iss is refused', async () => {
  const { env, grant } = await spec();
  await assert.rejects(completeAuthorization(env, grant, { code: 'c' }), /different authorization server/);
});

test('a token response without the atproto scope is refused', async (t) => {
  const { env, grant } = await spec();
  await withTokenServer(t, () => tokenReply({ scope: 'transition:generic' }));
  await assert.rejects(refreshForSpec(env, grant), /atproto scope/);
  await withTokenServer(t, () => tokenReply({ scope: null }));
  await assert.rejects(refreshForSpec(env, grant), /atproto scope/, 'and so is one with no scope at all');
});

test('an authorization server answer without a DPoP nonce is refused', async (t) => {
  const { env, grant } = await spec();
  await withTokenServer(t, () => tokenReply({ nonce: null }));
  await assert.rejects(refreshForSpec(env, grant), /DPoP nonce/);
});

test('signing in as a different account from the one entered is refused', async (t) => {
  const { env, grant } = await spec();
  await withTokenServer(t, () => tokenReply({ sub: 'did:plc:mallory' }));
  await assert.rejects(
    completeAuthorization(env, grant, { code: 'c', iss: 'https://auth.example.com' }),
    /different account/);
});

test('a PDS answer to a post without a DPoP nonce is refused, and says the record may exist', async (t) => {
  const { env, grant } = await spec();
  const session = { ...grant, accessToken: 'a', expiresAt: Date.now() + 3600_000 };
  const post = () => xrpcPost(env, session, 'com.atproto.repo.createRecord', { collection: 'app.bsky.feed.post' });
  const answer = (nonce) => () => new Response(JSON.stringify({ uri: 'at://x', cid: 'c' }),
    { status: 200, headers: { 'content-type': 'application/json', ...(nonce ? { 'DPoP-Nonce': nonce } : {}) } });

  await withTokenServer(t, answer(null));
  await assert.rejects(post(), /may have been written/);

  await withTokenServer(t, answer('n2'));
  const { result } = await post();
  assert.strictEqual(result.uri, 'at://x', 'with a nonce it posts as before');
});
