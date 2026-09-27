import test from 'node:test';
import assert from 'node:assert';

import { Store } from '../src/store.js';
import { PebbleBrokerAccount, PebbleBrokerCell } from '../src/actors.js';
import { fakeNamespace } from './fake-do.mjs';
import {
  configurePages, confirmRemovalPage, forgetPage, forgottenPage, loginPage, nothingToRemovePage,
  privacyPage
} from '../src/pages.js';

/** A store backed by in-memory Durable Objects, as the worker is. */
function buildStore() {
  const accounts = fakeNamespace(PebbleBrokerAccount, {});
  const cells = fakeNamespace(PebbleBrokerCell, {});
  const store = new Store(SECRET, { accounts, cells });
  store.dump = () => [...accounts.dump(), ...cells.dump()];
  return store;
}

// A real 32-byte key, base64url, as STORAGE_KEY must be.
const SECRET = Buffer.from(new Uint8Array(32).fill(7)).toString('base64url');

test('a removal ticket is single use', async () => {
  const store = buildStore();
  const session = { did: 'did:plc:alice', handle: 'sri.xyz' };

  await store.putRemoval('tok', { session, devices: 2 });
  const first = await store.takeRemoval('tok');
  assert.strictEqual(first.session.did, 'did:plc:alice');
  assert.strictEqual(first.devices, 2);

  assert.strictEqual(await store.takeRemoval('tok'), null,
    'a replayed confirmation must not delete anything a second time');
  assert.strictEqual(await store.takeRemoval(''), null);
  assert.strictEqual(await store.takeRemoval(undefined), null);
});

test('a parked removal is encrypted at rest like everything else', async () => {
  const store = buildStore();
  await store.putRemoval('tok', {
    session: { did: 'did:plc:alice', refreshToken: 'super-secret' }
  });
  const rows = store.dump().filter((r) => typeof r.value === 'string');
  assert.ok(rows.length, 'something was written');
  for (const row of rows) {
    assert.ok(!row.value.includes('super-secret'),
      `a live session sits in the clear at ${row.name}/${row.key}`);
    assert.ok(!row.value.includes('did:plc:alice'), `DID in the clear at ${row.name}/${row.key}`);
  }
});

const DEVICES = [
  { token: 'tok-a', label: 'Pebble', createdAt: '2026-09-18T10:00:00Z' },
  { token: 'tok-b', label: 'Pebble Time 2', createdAt: '2026-09-20T08:30:00Z' }
];

test('removal is confirmed by a POST, never by arriving at a URL', () => {
  const page = confirmRemovalPage('sri.xyz', DEVICES, 'tok');
  const forms = [...page.matchAll(/<form method="(\w+)" action="([^"]+)"/g)]
    .map((m) => `${m[1].toUpperCase()} ${m[2]}`);
  assert.deepStrictEqual(forms,
    ['POST /forget/devices', 'POST /forget', 'POST /forget/cancel'],
    'every outcome is a POST; a GET must never destroy anything');
  assert.match(page, /name="token" value="tok"/);
  assert.match(page, /Keep my account/, 'backing out is offered as plainly as going ahead');
});

test('the confirmation lists devices instead of counting them', () => {
  const page = confirmRemovalPage('sri.xyz', DEVICES, 't');
  assert.match(page, /Pebble Time 2/, 'each device is named');
  assert.match(page, /paired 18 Sep 2026/, 'and dated');
  assert.match(page, /paired 20 Sep 2026/);
  // What the button does, all three parts of it.
  assert.match(page, /revokes the broker\u2019s access at your account provider/);
  assert.match(page, /unpairs every\s+device/);
  assert.match(page, /deletes the stored session/);

  // A device token is a live credential; it must not sit in page source.
  assert.ok(!page.includes('tok-a') && !page.includes('tok-b'),
    'checkboxes carry positions, not tokens');
  assert.deepStrictEqual(
    [...page.matchAll(/name="device" value="(\d+)"/g)].map((m) => m[1]), ['0', '1']);

  const empty = confirmRemovalPage('sri.xyz', [], 't');
  assert.match(empty, /No device is signed in/);
  assert.ok(!/name="device"/.test(empty), 'nothing to select, so nothing is offered');
});

test('removing one device is offered separately from removing the account', () => {
  const page = confirmRemovalPage('sri.xyz', DEVICES, 't');
  assert.match(page, /Remove selected devices/);
  assert.match(page, /Your account stays/, 'the smaller action says it is smaller');
  assert.match(page, /Remove my account/);
});

test('nothing on the way in is destructive', () => {
  // The sign-in page offers removal as a link; that link must land on a form,
  // not on anything that acts.
  assert.match(loginPage(), /href="\/forget"/);
  assert.match(forgetPage(), /<form method="GET" action="\/login">/,
    'reaching /forget only starts a sign-in');
});

test('a name with markup in it cannot break the page', () => {
  const page = confirmRemovalPage('<script>x</script>', 1, '"><b>');
  assert.ok(!page.includes('<script>x</script>'), 'the handle is escaped');
  assert.ok(!page.includes('value=""><b>"'), 'the token is escaped');
});

test('an account with nothing here is told so, not offered a delete button', () => {
  const page = nothingToRemovePage('sri.xyz', { revoked: true });
  assert.match(page, /Nothing to remove/);
  assert.ok(!/<form/.test(page), 'no destructive action for a thing that does not exist');
  assert.ok(!/Remove my account/.test(page));
  assert.match(page, /has been revoked/, 'the proof-of-ownership grant is given back');

  const notRevoked = nothingToRemovePage('sri.xyz', { revoked: false });
  assert.match(notRevoked, /account settings at your provider/,
    'when the hand-back fails, say what to do instead');
});

test('a removal with nothing stored does not claim a revocation', () => {
  // revokeSession was never called, so saying access was revoked at the
  // provider would be a claim about a request that never happened.
  const text = forgottenPage('sri.xyz', 0, { revoked: false, nothing: true })
    .replace(/<[^>]+>/g, ' ');
  assert.match(text, /no stored session/i);
  assert.ok(!/revoked at your account provider/i.test(text), `claims a revocation: ${text}`);
  assert.ok(!/did not complete/i.test(text), 'and does not report a failure either');
});

test('spaces links out, and does not toggle the box on the way', () => {
  const page = loginPage();
  assert.match(page, /<a href="https:\/\/givemesome\.space"[^>]*>atproto\s+spaces<\/a>/);
  // New tab, because the form above it is half filled in by the time anyone
  // wonders what a space is.
  assert.match(page, /givemesome\.space" target="_blank" rel="noopener noreferrer"/);
});

test('every page carries the mark, and it survives a dark ground', () => {
  for (const page of [loginPage(), forgetPage(), privacyPage(),
                      confirmRemovalPage('sri.xyz', 2, 't'),
                      forgottenPage('sri.xyz', 1, { revoked: true })]) {
    assert.match(page, /<img class="logo" src="\/logo\.png"/, 'the logo is on the page');
    assert.match(page, /<link rel="icon" href="\/favicon\.ico" sizes="32x32">/, 'and in the tab');
    // The ico carries sizes so a browser that understands SVG does not prefer
    // it; the SVG is the one that can follow a dark tab bar.
    assert.match(page, /<link rel="icon" href="\/favicon\.svg" type="image\/svg\+xml">/);
    assert.match(page, /<link rel="manifest" href="\/manifest\.webmanifest">/);
    // Decorative: the heading underneath already says the name, so a screen
    // reader announcing it twice is worse than not announcing it.
    assert.match(page, /class="logo"[^>]*alt=""/);
    // The mark is black ink, so on a dark ground it has to be flipped.
    assert.match(page, /prefers-color-scheme: dark\) \{ \.logo \{ filter: invert\(1\)/);
  }
});

test('no page says "pair": that word is the watch and the phone', () => {
  const pages = [
    loginPage(), forgetPage(), confirmRemovalPage('sri.xyz', 2, 't'),
    nothingToRemovePage('sri.xyz', { revoked: true }),
    forgottenPage('sri.xyz', 1, { revoked: true }),
    forgottenPage('sri.xyz', 0, { revoked: false })
  ];
  for (const page of pages) {
    const visible = page.replace(/<style[\s\S]*?<\/style>/, '').replace(/<[^>]+>/g, ' ');
    assert.ok(!/\bpair(ed|ing|s)?\b/i.test(visible),
      `still says pair: ${visible.replace(/\s+/g, ' ').trim().slice(0, 90)}`);
  }
});

test('the privacy page states what is kept and how to get rid of it', () => {
  const page = privacyPage();
  const text = page.replace(/<style[\s\S]*?<\/style>/, '').replace(/<[^>]+>/g, ' ');

  for (const claim of [
    /never leave this server/i,      // the tokens
    /encrypted/i,
    /never sees/i,                   // the password
    /ten minutes/i,                  // the short-lived rows
    /without you being present/i,    // the honest part
    /no warranty/i
  ]) {
    assert.match(text, claim);
  }
  assert.match(page, /href="\/forget"/, 'removal is reachable from it');
});

test('the sign-in page offers a one-click deploy of your own', () => {
  const page = loginPage();
  const deploy = 'https://deploy.workers.cloudflare.com/?url=https://github.com/sriganesh/pebble-atproto-broker';
  assert.ok(page.includes(`href="${deploy}">Deploy your own broker</a>`), 'a text link');
  assert.ok(page.includes('src="https://deploy.workers.cloudflare.com/button"'), 'and the button');
});

test('a copy of this broker does not present itself as the original', () => {
  // Configured as a stranger's deployment: their URL, no contact set.
  configurePages({ PUBLIC_URL: 'https://broker.example.net/' });
  const bare = privacyPage();
  assert.ok(!/atproto\.broker/.test(bare), 'nothing names the original deployment');
  assert.ok(!/Contact/.test(bare), 'no contact section until one is configured');
  assert.match(loginPage(), /content="https:\/\/broker\.example\.net\/og\.png/, 'the share image is theirs');

  configurePages({ PUBLIC_URL: 'https://broker.example.net', CONTACT_EMAIL: 'ops@example.net' });
  assert.match(privacyPage(), /mailto:ops@example\.net/, 'and a contact appears when set');
  configurePages({});
});

test('the sign-in page links to it', () => {
  assert.match(loginPage(), /href="\/privacy"/);
});

test('a device token is never a storage key or a stored value', async () => {
  const store = buildStore();
  await store.putSession({ did: 'did:plc:alice', handle: 'sri.xyz' });
  const token = await store.createDevice('did:plc:alice', 'Pebble');

  // A reader with storage access and no decryption key must not find a live
  // credential anywhere in the inventory.
  for (const row of store.dump()) {
    assert.ok(!String(row.key).includes(token), `token exposed in key ${row.name}/${row.key}`);
    assert.ok(!String(row.value).includes(token), `token exposed in a value at ${row.name}`);
  }
  assert.strictEqual((await store.getDevice(token)).did, 'did:plc:alice',
    'and it still resolves for us');
});

test('a device cannot survive account removal, or come back after one', async () => {
  const store = buildStore();
  await store.putSession({ did: 'did:plc:alice', handle: 'sri.xyz' });
  const token = await store.createDevice('did:plc:alice', 'Pebble');
  assert.ok(await store.getDevice(token));

  await store.forgetDid('did:plc:alice');
  assert.strictEqual(await store.getDevice(token), null, 'dead right after removal');

  // The account signs in again. The old credential must stay dead: it is
  // stamped with the generation from before the removal.
  await store.putSession({ did: 'did:plc:alice', handle: 'sri.xyz' });
  assert.strictEqual(await store.getDevice(token), null,
    'a new session must not revive an old device');

  const fresh = await store.createDevice('did:plc:alice', 'Pebble');
  assert.ok(await store.getDevice(fresh), 'while a newly paired one works');
});

test('a rate-limit count never stores the address it came from', async () => {
  const store = buildStore();
  await store.countPairFailure('203.0.113.9');
  for (const row of store.dump()) {
    assert.ok(!String(row.key).includes('203.0.113.9'), `address in a key: ${row.key}`);
    assert.ok(!String(row.value).includes('203.0.113.9'), 'address in a value');
  }
  assert.strictEqual(await store.pairFailures('203.0.113.9'), 1);
  assert.strictEqual(await store.countPairFailure('203.0.113.9'), 2, 'it counts up');
  assert.strictEqual(await store.pairFailures('198.51.100.4'), 0, 'and is per caller');
});
