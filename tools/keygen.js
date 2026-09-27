#!/usr/bin/env node
/**
 * Generate the client signing key.
 *
 * The broker authenticates to authorization servers with private_key_jwt, so
 * it needs one ES256 keypair. The private half becomes a Worker secret; the
 * public half is served at /jwks.json for the authorization server to fetch.
 */

import { webcrypto } from 'node:crypto';

const pair = await webcrypto.subtle.generateKey(
  { name: 'ECDSA', namedCurve: 'P-256' },
  true,
  ['sign', 'verify']
);

const privateJwk = await webcrypto.subtle.exportKey('jwk', pair.privateKey);
// A kid lets you rotate later: publish both keys, sign with the new one.
privateJwk.kid = 'pebble-broker-' + new Date().toISOString().slice(0, 10);
privateJwk.alg = 'ES256';
privateJwk.use = 'sig';

const storageKey = Buffer.from(webcrypto.getRandomValues(new Uint8Array(32)))
  .toString('base64url');

console.log('Store this as the CLIENT_PRIVATE_JWK secret:\n');
console.log(JSON.stringify(privateJwk));
console.log('\n  npx wrangler secret put CLIENT_PRIVATE_JWK');
console.log('\nThen the storage key, which encrypts everything stored at rest:\n');
console.log(storageKey);
console.log('\n  npx wrangler secret put STORAGE_KEY');
console.log('\nPaste each line when prompted. Neither leaves your machine otherwise.');
console.log('Rotating STORAGE_KEY makes stored values unreadable: everyone signs in again.');
