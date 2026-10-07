/**
 * Pebble atproto broker.
 *
 * The watch's phone-side JS cannot speak AT Protocol OAuth: the PebbleKit JS
 * sandbox has no WebCrypto, so it cannot mint the ES256 DPoP proof that every
 * request needs, and a `data:` settings page has no origin to redirect back
 * to. This worker holds the OAuth session and exposes one thing the phone can
 * actually call: "create this record as me", behind a bearer device token.
 *
 * Routes
 *   GET  /                        sign-in page
 *   GET  /oauth-client-metadata.json  OAuth client metadata (this is the client_id)
 *   GET  /jwks.json               public half of the client signing key
 *   GET  /login?handle=...        start the flow (PAR) and redirect
 *   GET  /callback                finish the flow, show a pairing code
 *   POST /api/pair                { code } -> { token, did, handle }
 *   GET  /api/whoami              who a device token belongs to
 *   POST /api/post                { collection, record, rkey?, space? }
 *   POST /api/unpair              revoke the calling device token
 */

import { publicPartOf, randomToken } from './crypto.js';
// Re-exported because the runtime instantiates them from this entry point.
export { PebbleBrokerAccount, PebbleBrokerCell } from './actors.js';
import { BrokerError, configureIdentity } from './identity.js';
import {
  clientId,
  forGrant,
  clientMetadata,
  completeAuthorization,
  normalizeCollections,
  revokeSession,
  startAuthorization,
  xrpcPost
} from './oauth.js';
import {
  configurePages, confirmRemovalPage, errorPage, forgetPage, forgottenPage, loginPage,
  nothingToRemovePage, pairedPage, privacyPage
} from './pages.js';
import { PAIR_MAX_FAILURES, Store, newPairingCode } from './store.js';

const JSON_HEADERS = { 'content-type': 'application/json; charset=utf-8' };
const HTML_HEADERS = { 'content-type': 'text/html; charset=utf-8' };

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), { status, headers: { ...JSON_HEADERS, ...extra } });
}

function html(body, status = 200) {
  return new Response(body, { status, headers: HTML_HEADERS });
}

/**
 * The settings page runs from a `data:` URL, whose origin is opaque, so it
 * arrives as `Origin: null`. Allowing any origin is safe here only because
 * every /api route authenticates with a bearer token and none of them read a
 * cookie, so a hostile page gains nothing it could not do with curl.
 */
const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'authorization, content-type',
  'access-control-allow-methods': 'GET, POST, OPTIONS'
};

async function requireDevice(store, request) {
  const header = request.headers.get('authorization') || '';
  const token = header.toLowerCase().startsWith('bearer ') ? header.slice(7).trim() : '';
  const device = await store.getDevice(token);
  if (!device) throw new BrokerError(401, 'NotPaired', 'This device is not signed in');
  return { token, device };
}

async function readJson(request) {
  try {
    const body = await request.json();
    if (!body || typeof body !== 'object') throw new Error('not an object');
    return body;
  } catch {
    throw new BrokerError(400, 'BadRequest', 'Expected a JSON object');
  }
}

/** An empty or unset ALLOWED_DIDS means the broker accepts any account. */
function isAllowed(env, did) {
  const raw = String(env.ALLOWED_DIDS || '').trim();
  if (!raw) return true;
  return raw
    .split(/[\s,]+/)
    .filter(Boolean)
    .includes(did);
}

// One DO round trip per isolate, not per request. The key never changes for
// the life of a deployment.
let cachedKey = null;

/**
 * PUBLIC_URL and CLIENT_PRIVATE_JWK filled in, so a deploy needs neither.
 *
 * PUBLIC_URL is the client_id, and an authorization server compares it
 * byte-for-byte across PAR, token exchange, refresh and revoke. Defaulting it
 * to the origin this request arrived on is right for one hostname and wrong
 * for two: a session started on the workers.dev name and refreshed through a
 * custom domain is two different clients, and the second one gets
 * invalid_grant. Set PUBLIC_URL the moment a custom domain is attached.
 */
async function resolveConfig(env, store, origin) {
  if (!env.CLIENT_PRIVATE_JWK && !cachedKey) {
    cachedKey = JSON.stringify(await store.clientKey());
  }
  return {
    ...env,
    PUBLIC_URL: env.PUBLIC_URL || origin,
    CLIENT_PRIVATE_JWK: env.CLIENT_PRIVATE_JWK || cachedKey
  };
}

function requireConfig(env) {
  // STORAGE_KEY is the one that cannot be derived: it is the root key
  // everything else is sealed under, so it cannot live in what it protects.
  if (!env.STORAGE_KEY) {
    throw new BrokerError(500, 'NotConfigured',
      'STORAGE_KEY is not set. See broker/README.md');
  }
  if (!env.CELLS || !env.ACCOUNTS) {
    throw new BrokerError(500, 'NotConfigured',
      'The ACCOUNTS and CELLS Durable Object namespaces are not bound');
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    try {
      requireConfig(env);
      configureIdentity(env);
      const store = new Store(env.STORAGE_KEY,
                              { accounts: env.ACCOUNTS, cells: env.CELLS });
      env = await resolveConfig(env, store, url.origin);
      configurePages(env);

      if (pathname === '/' && request.method === 'GET') {
        return html(loginPage(url.searchParams.get('error')));
      }

      if (pathname === '/oauth-client-metadata.json') {
        // The authorization server fetches this URL verbatim, query string and
        // all, so the scopes it reads here must be the ones we asked for.
        return json(
          clientMetadata(env, {
            collections: normalizeCollections(url.searchParams.get('collections') || ''),
            spaces: url.searchParams.get('spaces') === '1',
            minimal: url.searchParams.get('minimal') === '1'
          }),
          200,
          { 'cache-control': 'no-store' }
        );
      }

      if (pathname === '/jwks.json') {
        const jwk = JSON.parse(env.CLIENT_PRIVATE_JWK);
        // Never serve `d`: that is the private key.
        return json(
          { keys: [{ ...publicPartOf(jwk), kid: jwk.kid, use: 'sig', alg: 'ES256' }] },
          200,
          { 'cache-control': 'no-store' }
        );
      }

      if (pathname === '/login' && request.method === 'GET') {
        const handle = url.searchParams.get('handle');
        if (!handle) return html(loginPage('Enter a handle'), 400);
        const forget = url.searchParams.get('forget') === '1';
        const { state, authorizeUrl, pending } = await startAuthorization(env, handle, {
          collections: url.searchParams.get('collections') || '',
          spaces: url.searchParams.get('spaces') === '1',
          // Removing an account asks for `atproto` and nothing more: the sign-in
          // is only there to prove the DID is yours. Asking for write access in
          // order to be deleted would be a strange thing to consent to.
          minimal: forget
        });
        pending.forget = forget;
        await store.putPending(state, pending);
        return Response.redirect(authorizeUrl, 302);
      }

      if (pathname === '/callback' && request.method === 'GET') {
        const error = url.searchParams.get('error');
        if (error) {
          return html(errorPage(url.searchParams.get('error_description') || error), 400);
        }
        const state = url.searchParams.get('state');
        const code = url.searchParams.get('code');
        if (!state || !code) return html(errorPage('The callback was missing state or code'), 400);

        const pending = await store.takePending(state);
        if (!pending) {
          return html(errorPage('That login expired or was already used. Start again.'), 400);
        }

        const session = await completeAuthorization(env, pending, {
          code,
          iss: url.searchParams.get('iss')
        });

        // A broker on a public URL will be found. ALLOWED_DIDS keeps it yours:
        // a stranger can still reach the login page, but their session is
        // discarded here instead of stored. Unset means open to all.
        if (!isAllowed(env, session.did)) {
          // The token exchange already happened, so a grant exists on their
          // account. Hand it back, so this broker is not left listed as an
          // authorized app nobody here will use.
          await revokeSession(env, session);
          return html(
            errorPage('This broker is not open to that account.'),
            403
          );
        }

        // Nothing is deleted here; the identity is parked and the next page
        // asks. Runs BEFORE putSession: storing a session for an account that
        // never had one would hide whether there was anything to remove.
        if (pending.forget) {
          const existing = await store.getSession(session.did);
          const devices = await store.listDevices(session.did);

          if (!existing && devices.length === 0) {
            // Nothing stored for this DID. Revoke the grant just made and say so.
            const outcome = await revokeSession(env, session);
            return html(nothingToRemovePage(session.handle || session.did, outcome));
          }

          // The ticket holds a live grant. If it is never confirmed the cell
          // empties itself on its alarm, which cannot revoke anything, so the
          // grant is handed back here and the ticket keeps only what the next
          // page needs. The account's own stored session does the revoking.
          const detail = await store.listDeviceDetails(session.did);
          await revokeSession(env, session);
          const token = randomToken(32);
          await store.putRemoval(token, {
            session: { did: session.did, handle: session.handle },
            devices: detail
          });
          return html(
            confirmRemovalPage(session.handle || session.did, detail, token)
          );
        }

        // A second sign-in with different collections or spaces is a different
        // client_id, so the old session is a separate grant. Overwriting it
        // would drop the only copy of its refresh token and leave that
        // authorization standing on the account for good.
        const previous = await store.getSession(session.did);
        const sameClient = previous &&
          clientId(forGrant(env, previous), previous.collections || [], !!previous.spaces, !!previous.minimal) ===
          clientId(forGrant(env, session), session.collections || [], !!session.spaces, !!session.minimal);
        if (previous && !sameClient) {
          // A different client_id is a separate authorization, and this is the
          // only copy of its refresh token. A different refresh token alone
          // proves nothing: one client can reissue.
          await revokeSession(env, previous);
        }
        await store.putSession(session);

        const pairingCode = newPairingCode();
        await store.putPairing(pairingCode, session.did, await store.generation(session.did));
        return html(pairedPage(pairingCode, session.handle || session.did));
      }

      if (pathname === '/api/pair' && request.method === 'POST') {
        const body = await readJson(request);
        const caller = request.headers.get('cf-connecting-ip') || 'unknown';
        if ((await store.pairFailures(caller)) >= PAIR_MAX_FAILURES) {
          throw new BrokerError(429, 'TooManyAttempts',
            'Too many wrong codes. Wait ten minutes and get a fresh one.');
        }

        const claim = await store.takePairing(body.code);
        if (!claim) {
          await store.countPairFailure(caller);
          throw new BrokerError(400, 'BadCode', 'That sign-in code is wrong, used, or expired');
        }
        const did = claim.did;
        const session = await store.getSession(did);
        if (!session) throw new BrokerError(400, 'NoSession', 'Sign in again on the broker');

        const token = await store.createDevice(did, body.label, claim.generation);
        return json({ token, did, handle: session.handle, pds: session.pds }, 200, CORS);
      }

      if (pathname === '/api/whoami' && request.method === 'GET') {
        const { device } = await requireDevice(store, request);
        const session = await store.getSession(device.did);
        if (!session) throw new BrokerError(401, 'NoSession', 'Sign in again on the broker');
        return json({ did: session.did, handle: session.handle, pds: session.pds }, 200, CORS);
      }

      // Remove this account from the broker entirely, from a paired device.
      if (pathname === '/api/forget' && request.method === 'POST') {
        const { device } = await requireDevice(store, request);
        const session = await store.getSession(device.did);
        const outcome = session
          ? await revokeSession(env, session)
          : { revoked: false, reason: 'no session stored' };
        const removed = await store.forgetDid(device.did);
        return json({ ok: true, did: device.did, devicesRemoved: removed, ...outcome }, 200, CORS);
      }

      if (pathname === '/privacy' && request.method === 'GET') {
        return html(privacyPage());
      }

      if (pathname === '/forget' && request.method === 'GET') {
        return html(forgetPage(url.searchParams.get('error')));
      }

      // The confirmed removal. A POST, because it destroys something.
      if (pathname === '/forget' && request.method === 'POST') {
        const form = await request.formData();
        const ticket = await store.takeRemoval(form.get('token'));
        if (!ticket) {
          return html(forgetPage('That removal expired or was already used. Start again.'), 400);
        }

        // The sign-in used to prove ownership was handed back when the ticket
        // was made, so the ticket carries an identity and nothing more. What
        // is left to revoke is the account's own stored session.
        const { session } = ticket;
        const existing = await store.getSession(session.did);
        const outcome = existing
          ? await revokeSession(env, existing)
          : { revoked: false, nothing: true };
        const removed = await store.forgetDid(session.did);
        return html(forgottenPage(session.handle || session.did, removed, outcome));
      }

      // Unpair some devices without giving up the account. The ticket is spent
      // and a fresh one issued, so the page can be used again without another
      // sign-in while each token still works exactly once.
      if (pathname === '/forget/devices' && request.method === 'POST') {
        const form = await request.formData();
        const ticket = await store.takeRemoval(form.get('token'));
        if (!ticket) {
          return html(forgetPage('That removal expired or was already used. Start again.'), 400);
        }

        const listed = ticket.devices || [];
        const picked = form.getAll('device')
          .map((value) => Number(value))
          .filter((i) => Number.isInteger(i) && i >= 0 && i < listed.length);

        for (const i of new Set(picked)) {
          await store.deleteDevice(ticket.session.did, listed[i].token);
        }

        const remaining = await store.listDeviceDetails(ticket.session.did);
        const next = randomToken(32);
        await store.putRemoval(next, { session: ticket.session, devices: remaining });
        const n = new Set(picked).size;
        return html(confirmRemovalPage(
          ticket.session.handle || ticket.session.did, remaining, next,
          n ? `${n} device${n === 1 ? '' : 's'} removed.` : 'Nothing was selected.'
        ));
      }

      // Changed their mind. The sign-in used to get here was already handed
      // back when the ticket was made, so this only drops the ticket.
      if (pathname === '/forget/cancel' && request.method === 'POST') {
        const form = await request.formData();
        await store.takeRemoval(form.get('token'));
        return Response.redirect(`${url.origin}/`, 303);
      }

      if (pathname === '/api/unpair' && request.method === 'POST') {
        const { device } = await requireDevice(store, request);
        await store.deleteDevice(device.did, device.hash);
        return json({ ok: true }, 200, CORS);
      }

      if (pathname === '/api/post' && request.method === 'POST') {
        const { device } = await requireDevice(store, request);
        // Refreshed inside the account's actor when needed, so two presses
        // landing together cannot both rotate the refresh token.
        const session = await store.freshSession(device.did);
        if (!session) throw new BrokerError(401, 'NoSession', 'Sign in again on the broker');

        const body = await readJson(request);
        if (!body.collection || typeof body.collection !== 'string') {
          throw new BrokerError(400, 'BadRequest', 'A collection is required');
        }
        if (!body.record || typeof body.record !== 'object') {
          throw new BrokerError(400, 'BadRequest', 'A record object is required');
        }

        // A space write goes to the caller's OWN PDS as well: a member writes
        // only their own slice, so `repo` is always their DID and no space
        // credential is involved (that is a read-side concern).
        const inSpace = typeof body.space === 'string' && body.space.length > 0;
        const params = {
          repo: session.did,
          collection: body.collection,
          record: body.record,
          ...(body.rkey ? { rkey: body.rkey } : {}),
          ...(body.validate === true || body.validate === false ? { validate: body.validate } : {}),
          ...(inSpace ? { space: body.space } : {})
        };

        const { result, session: renewed } = await xrpcPost(
          env,
          session,
          inSpace ? 'com.atproto.space.createRecord' : 'com.atproto.repo.createRecord',
          params,
          // Forced through the account actor, which is the only thing allowed
          // to rotate this session.
          async () => {
            const fresh = await store.freshSession(device.did, true);
            if (!fresh) throw new BrokerError(401, 'NoSession', 'Sign in again on the broker');
            return fresh;
          }
        );
        // Deliberately not written back: the actor owns the session, and
        // storing a whole snapshot here could overwrite a newer rotation. The
        // only thing lost is a DPoP nonce, which costs one extra round trip.
        void renewed;

        return json({ uri: result.uri, cid: result.cid, did: session.did }, 200, CORS);
      }

      return json({ error: 'NotFound' }, 404, CORS);
    } catch (error) {
      const status = error instanceof BrokerError ? error.status : 500;
      const code = error instanceof BrokerError ? error.code : 'InternalError';
      const message = error?.message || 'Something went wrong';

      if (url.pathname.startsWith('/api/')) {
        return json({ error: code, message }, status, CORS);
      }
      return html(errorPage(message), status);
    }
  }
};
