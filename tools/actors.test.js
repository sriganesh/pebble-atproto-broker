import test from 'node:test';
import assert from 'node:assert';

import { PebbleBrokerAccount, PebbleBrokerCell } from '../src/actors.js';
import { Store } from '../src/store.js';
import { fakeNamespace } from './fake-do.mjs';
import { refreshSession } from '../src/oauth.js';
import { generateSigningKey } from '../src/crypto.js';

const SECRET = Buffer.from(new Uint8Array(32).fill(5)).toString('base64url');

function build(env = {}) {
  return new Store(SECRET, {
    accounts: fakeNamespace(PebbleBrokerAccount, env),
    cells: fakeNamespace(PebbleBrokerCell, env)
  });
}

test('a pairing code cannot be redeemed twice, even concurrently', async () => {
  const store = build();
  await store.putPairing('ABCD-EFGH', 'did:plc:alice');

  // Both redemptions in flight at once: the race the old get-then-delete lost.
  const [a, b] = await Promise.all([
    store.takePairing('ABCD-EFGH'),
    store.takePairing('ABCD-EFGH')
  ]);
  const winners = [a, b].filter(Boolean);
  assert.strictEqual(winners.length, 1, `both redemptions succeeded: ${a} / ${b}`);
  assert.strictEqual(winners[0].did, 'did:plc:alice');
  assert.strictEqual(await store.takePairing('ABCD-EFGH'), null, 'and it stays spent');
});

test('the signing key is made once and kept, even when asked for at once', async () => {
  const store = build();

  // A fresh deploy has no key. Several requests can arrive before the first
  // one has finished making it, and generating is crypto rather than storage,
  // so the storage gate does not cover the await.
  const [a, b, c] = await Promise.all([store.clientKey(), store.clientKey(), store.clientKey()]);
  assert.deepStrictEqual(a, b, 'two concurrent callers got different keys');
  assert.deepStrictEqual(a, c);

  // Whichever won, it is the one that stays: a second key would invalidate
  // every grant issued under the first.
  assert.deepStrictEqual(await store.clientKey(), a, 'the key changed after it was stored');

  assert.strictEqual(a.kty, 'EC');
  assert.strictEqual(a.crv, 'P-256');
  assert.strictEqual(a.alg, 'ES256');
  assert.ok(a.d, 'the private component is what the broker signs with');
});

test('a changed STORAGE_KEY replaces the signing key instead of breaking every page', async () => {
  const cells = fakeNamespace(PebbleBrokerCell, {});
  const accounts = fakeNamespace(PebbleBrokerAccount, {});
  const before = await new Store(SECRET, { accounts, cells }).clientKey();

  // Same storage, new STORAGE_KEY: the old key can no longer be opened.
  const OTHER = Buffer.from(new Uint8Array(32).fill(9)).toString('base64url');
  const after = await new Store(OTHER, { accounts, cells }).clientKey();
  assert.ok(after && after.d, 'a usable key comes back, not an error');
  assert.notDeepStrictEqual(after, before, 'it is a new one');
  assert.deepStrictEqual(await new Store(OTHER, { accounts, cells }).clientKey(), after,
    'and it stays the same from then on');
});

test('a deployment with only STORAGE_KEY can still refresh a session', async (t) => {
  // What the one-click deploy produces: no signing key, no PUBLIC_URL.
  const env = { STORAGE_KEY: SECRET };
  env.CELLS = fakeNamespace(PebbleBrokerCell, env);
  env.ACCOUNTS = fakeNamespace(PebbleBrokerAccount, env);
  const actor = new PebbleBrokerAccount({ storage: new Map() }, env);

  // The account object has to reach the key the Worker generated.
  const config = await actor.config();
  const generated = await new Store(SECRET, { accounts: env.ACCOUNTS, cells: env.CELLS }).clientKey();
  assert.deepStrictEqual(JSON.parse(config.CLIENT_PRIVATE_JWK), generated);

  // And a refresh presents the client_id the grant was issued under, even with
  // no PUBLIC_URL configured anywhere.
  const sent = [];
  const realFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = realFetch; });
  globalThis.fetch = async (url, init) => {
    sent.push(Object.fromEntries(new URLSearchParams(String(init.body))));
    return new Response(JSON.stringify({ access_token: 'a2', refresh_token: 'r2', expires_in: 3600,
                                         scope: 'atproto repo:*?action=create' }),
      { status: 200, headers: { 'content-type': 'application/json', 'DPoP-Nonce': 'n1' } });
  };
  const renewed = await refreshSession(config, {
    did: 'did:plc:alice', refreshToken: 'r1', publicUrl: 'https://broker.example.net',
    tokenEndpoint: 'https://auth.example.com/oauth/token', issuer: 'https://auth.example.com',
    privateJwk: await generateSigningKey(), collections: [], spaces: false, minimal: false
  });
  assert.strictEqual(sent[0].client_id, 'https://broker.example.net/oauth-client-metadata.json');
  assert.ok(sent[0].client_assertion, 'signed with the generated key');
  assert.strictEqual(renewed.refreshToken, 'r2');
});

test('a login in progress and a removal ticket are single use too', async () => {
  const store = build();
  await store.putPending('state-1', { verifier: 'v' });
  const pendings = await Promise.all([store.takePending('state-1'), store.takePending('state-1')]);
  assert.strictEqual(pendings.filter(Boolean).length, 1, 'a replayed callback cannot re-run');

  await store.putRemoval('tok', { session: { did: 'did:plc:alice' } });
  const tickets = await Promise.all([store.takeRemoval('tok'), store.takeRemoval('tok')]);
  assert.strictEqual(tickets.filter(Boolean).length, 1);
});

test('concurrent pairings both end up in the device list', async () => {
  const store = build();
  await store.putSession({ did: 'did:plc:alice', handle: 'sri.xyz' });

  // Two devices registering at once. Read-modify-write on a KV index lost one.
  const [one, two] = await Promise.all([
    store.createDevice('did:plc:alice', 'Watch A'),
    store.createDevice('did:plc:alice', 'Watch B')
  ]);
  const devices = await store.listDeviceDetails('did:plc:alice');
  assert.strictEqual(devices.length, 2, 'neither registration was lost');
  assert.ok(await store.getDevice(one));
  assert.ok(await store.getDevice(two));

  // And removal reaches both, because the index is complete.
  assert.strictEqual(await store.forgetDid('did:plc:alice'), 2);
  assert.strictEqual(await store.getDevice(one), null);
  assert.strictEqual(await store.getDevice(two), null);
});

test('a device token routes to its own account and nobody else', async () => {
  const store = build();
  await store.putSession({ did: 'did:plc:alice', handle: 'a' });
  await store.putSession({ did: 'did:plc:bob', handle: 'b' });
  const alice = await store.createDevice('did:plc:alice', 'A');

  assert.strictEqual((await store.getDevice(alice)).did, 'did:plc:alice');
  assert.strictEqual(Store.didFromToken(alice), 'did:plc:alice');
  assert.strictEqual(Store.didFromToken('nonsense'), null);
  assert.strictEqual(await store.getDevice('nonsense.deadbeef'), null);

  // Removing Bob must not touch Alice's device.
  await store.forgetDid('did:plc:bob');
  assert.ok(await store.getDevice(alice), 'Alice is unaffected');
});

test('two posts at once refresh only once, even when requests interleave', async () => {
  // The case the storage gate does NOT cover: a handler awaiting the network.
  // The runtime delivers the second request during that await, so without an
  // explicit hold both would rotate the refresh token and kill each other's.
  let rotations = 0;
  // Only the network is stubbed: rotate() itself is the code under test, so
  // its generation check, its comparison and its write all really run.
  class SlowNetwork extends PebbleBrokerAccount {
    async refresh(session) {
      rotations++;
      await new Promise((r) => setTimeout(r, 20));      // the authorization server
      return { ...session, accessToken: 'new', refreshToken: 'r' + rotations,
               expiresAt: Date.now() + 3600_000 };
    }
  }

  const accounts = fakeNamespace(SlowNetwork, {}, { serialize: false });
  const store = new Store(SECRET, { accounts, cells: fakeNamespace(PebbleBrokerCell, {}) });
  await store.putSession({ did: 'did:plc:alice', accessToken: 'old', refreshToken: 'r0', expiresAt: 0 });

  const [a, b] = await Promise.all([
    store.freshSession('did:plc:alice'),
    store.freshSession('did:plc:alice')
  ]);

  assert.strictEqual(rotations, 1, 'the second caller waited instead of rotating again');
  assert.strictEqual(a.refreshToken, b.refreshToken, 'and both hold the same token');
  assert.strictEqual((await store.getSession('did:plc:alice')).refreshToken, a.refreshToken,
    'which is the one that was stored');

  // A later press, once the token is spent again, still refreshes.
  await store.putSession({ ...a, expiresAt: 0 });
  await store.freshSession('did:plc:alice');
  assert.strictEqual(rotations, 2, 'the hold is released once it finishes');
});

test('a claim nobody redeems cleans itself up', async () => {
  // Durable Object storage has no TTL. Without an alarm every unredeemed
  // pairing code would sit in storage for good.
  const cells = fakeNamespace(PebbleBrokerCell, {});
  const store = new Store(SECRET, { accounts: fakeNamespace(PebbleBrokerAccount, {}), cells });

  await store.putPairing('ABCD-EFGH', 'did:plc:alice');
  assert.strictEqual(cells.alarmCount(), 1, 'an expiry was scheduled');
  assert.ok(cells.dump().length, 'and something is stored');

  // Ten minutes later, nobody typed it.
  const fired = await cells.runAlarms(Date.now() + 11 * 60 * 1000);
  assert.strictEqual(fired, 1);
  assert.strictEqual(cells.dump().length, 0, 'the object emptied itself');
  assert.strictEqual(await store.takePairing('ABCD-EFGH'), null);
});

test('a sign-in code from before a removal cannot add a device afterwards', async () => {
  const store = build();
  await store.putSession({ did: 'did:plc:alice', handle: 'a' });
  const before = await store.generation('did:plc:alice');
  await store.putPairing('OLDC-CODE', 'did:plc:alice', before);

  // The owner removes the account, then signs in again, all inside the old
  // code's ten minutes.
  await store.forgetDid('did:plc:alice');
  await store.putSession({ did: 'did:plc:alice', handle: 'a' });

  const claim = await store.takePairing('OLDC-CODE');
  assert.ok(claim, 'the code itself is still there to be taken');
  await assert.rejects(store.createDevice('did:plc:alice', 'thief', claim.generation), /wrong, used, or expired/,
    'but it cannot add a device to the new account');

  // A code from the new sign-in works as normal, once.
  await store.putPairing('NEWC-CODE', 'did:plc:alice', await store.generation('did:plc:alice'));
  const fresh = await store.takePairing('NEWC-CODE');
  assert.ok(await store.createDevice('did:plc:alice', 'mine', fresh.generation));
  assert.strictEqual(await store.takePairing('NEWC-CODE'), null, 'and only once');
});

test('redeeming a claim cancels its cleanup', async () => {
  const cells = fakeNamespace(PebbleBrokerCell, {});
  const store = new Store(SECRET, { accounts: fakeNamespace(PebbleBrokerAccount, {}), cells });
  await store.putPairing('ABCD-EFGH', 'did:plc:alice');
  assert.strictEqual((await store.takePairing('ABCD-EFGH')).did, 'did:plc:alice');
  assert.strictEqual(cells.alarmCount(), 0, 'no alarm left pending');
  assert.strictEqual(cells.dump().length, 0, 'and nothing left stored');
});

test('a rotation that finishes after removal does not resurrect the session', async () => {
  // /api/post can be awaiting the authorization server while the same account
  // is forgotten. Writing the rotation then would put back a session that was
  // deleted, and leave a live credential the user believes is gone.
  let arrived;
  const held = new Promise((r) => { arrived = r; });
  let release;
  const gate = new Promise((r) => { release = r; });

  // Only the network is stubbed: rotate() itself is the code under test, so
  // its generation check, its comparison and its write all really run.
  class SlowNetwork extends PebbleBrokerAccount {
    async refresh(session) {
      arrived();
      await gate;
      return { ...session, accessToken: 'new', refreshToken: 'rotated',
               expiresAt: Date.now() + 3600_000 };
    }
  }

  const accounts = fakeNamespace(SlowNetwork, {}, { serialize: false });
  const store = new Store(SECRET, { accounts, cells: fakeNamespace(PebbleBrokerCell, {}) });
  await store.putSession({ did: 'did:plc:alice', accessToken: 'old', refreshToken: 'r0', expiresAt: 0 });

  const refreshing = store.freshSession('did:plc:alice');
  await held;
  await store.forgetDid('did:plc:alice');           // the user removes the account
  release();

  // The caller is told, instead of silently getting a resurrected session.
  await assert.rejects(() => refreshing, /signed out|SessionChanged/);
  assert.strictEqual(await store.getSession('did:plc:alice'), null,
    'and the account stays removed');
});

test('a rotation that finishes after a new sign-in does not bury it', async () => {
  let arrived;
  const held = new Promise((r) => { arrived = r; });
  let release;
  const gate = new Promise((r) => { release = r; });

  // Only the network is stubbed: rotate() itself is the code under test, so
  // its generation check, its comparison and its write all really run.
  class SlowNetwork extends PebbleBrokerAccount {
    async refresh(session) {
      arrived();
      await gate;
      return { ...session, accessToken: 'new', refreshToken: 'rotated',
               expiresAt: Date.now() + 3600_000 };
    }
  }

  const accounts = fakeNamespace(SlowNetwork, {}, { serialize: false });
  const store = new Store(SECRET, { accounts, cells: fakeNamespace(PebbleBrokerCell, {}) });
  await store.putSession({ did: 'did:plc:alice', accessToken: 'old', refreshToken: 'r0', expiresAt: 0 });

  const refreshing = store.freshSession('did:plc:alice');
  await held;
  await store.putSession({ did: 'did:plc:alice', accessToken: 'new', refreshToken: 'fresh-login',
                          expiresAt: Date.now() + 3600_000 });
  release();

  await assert.rejects(() => refreshing, /signed out|SessionChanged/);
  assert.strictEqual((await store.getSession('did:plc:alice')).refreshToken, 'fresh-login',
    'the newer login survives');
});
