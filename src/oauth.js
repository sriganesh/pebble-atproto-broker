/**
 * The AT Protocol OAuth flow: PAR, PKCE, DPoP, token exchange and refresh.
 *
 * The broker is a CONFIDENTIAL client (private_key_jwt), so its refresh token
 * is not capped at the 14 days a public client gets.
 */

import {
  clientAssertion,
  decodeJwtPayload,
  dpopProof,
  generateKeyPair,
  pkcePair,
  randomToken
} from './crypto.js';
import {
  assertSafeUrl, BrokerError, discoverAuthServer, resolveIdentity, stripSlash, verifySubject
} from './identity.js';

/**
 * Least privilege: create records in the repo, and create/update/delete the
 * caller's own slice of a space. No read scopes: the watch only ever writes.
 * Space writes go to the user's OWN PDS (com.atproto.space.createRecord), so
 * no space credential is involved; that is a read-side concern.
 */
const NSID_RE = /^[a-zA-Z][a-zA-Z0-9-]*(\.[a-zA-Z][a-zA-Z0-9-]*)+$/;

/**
 * Normalise a collection list so both sides of the flow agree byte-for-byte.
 *
 * The list rides in the client_id query string, and the authorization server
 * fetches that exact URL to read the declared scopes. If our ordering differs
 * from theirs at all, the requested scopes do not match the declared ones and
 * PAR answers invalid_scope. Sorted, de-duplicated, validated.
 */
export function normalizeCollections(input) {
  const list = Array.isArray(input) ? input : String(input || '').split(',');
  const named = list.map((c) => c.trim()).filter(Boolean);
  const bad = named.filter((c) => !NSID_RE.test(c));
  if (bad.length) {
    // Silently dropping a typo meant an empty list, and an empty list asks for
    // repo:*, so a typo widened the grant instead of narrowing it.
    throw new BrokerError(400, 'BadCollection',
      `Not a collection name: ${bad[0]}. Use something like app.bsky.feed.post`);
  }
  return [...new Set(named)].sort();
}

/**
 * The scopes to request.
 *
 * No collections asks for `repo:*?action=create`: write anything in the repo.
 * Naming collections narrows it to exactly those.
 *
 * Spaces are opt-in for a different reason: declaring `space:` grants by
 * default makes a stock PDS reject every ordinary login with invalid_scope.
 *
 * `minimal` asks for `atproto` and nothing else. Removing an account needs a
 * signature proving the DID is yours and a token to revoke with. It writes
 * nothing, so asking for write access to get rid of us would be wrong.
 */
export function scopesFor({ collections = [], spaces = false, minimal = false } = {}) {
  if (minimal) {
    return ['atproto'];
  }
  const scopes = ['atproto'];
  if (collections.length) {
    for (const collection of collections) {
      scopes.push(`repo:${collection}?action=create`);
    }
  } else {
    scopes.push('repo:*?action=create');
  }
  if (spaces) {
    scopes.push('space:*?authority=*&collection=*&action=create&action=update&action=delete');
  }
  return scopes;
}

/**
 * The client_id IS this URL, and it must be byte-identical everywhere it
 * appears. Named oauth-client-metadata.json to match the ecosystem
 * convention, which also keeps consent screens showing the host instead of a
 * long path.
 */
export function clientId(env, collections = [], spaces = false, minimal = false) {
  const base = `${stripSlash(env.PUBLIC_URL)}/oauth-client-metadata.json`;
  const params = [];
  // A minimal client asks for `atproto` alone, so any collection or spaces
  // parameter alongside it would be noise the AS still has to read back.
  if (minimal) {
    params.push('minimal=1');
    return `${base}?${params.join('&')}`;
  }
  if (collections.length) {
    params.push(`collections=${encodeURIComponent(collections.join(','))}`);
  }
  if (spaces) {
    params.push('spaces=1');
  }
  return params.length ? `${base}?${params.join('&')}` : base;
}

export function redirectUri(env) {
  return `${stripSlash(env.PUBLIC_URL)}/callback`;
}

export function clientMetadata(env, { collections = [], spaces = false, minimal = false } = {}) {
  const base = stripSlash(env.PUBLIC_URL);
  return {
    client_id: clientId(env, collections, spaces, minimal),
    client_name: env.CLIENT_NAME || 'Pebble atproto broker',
    client_uri: `${base}/`,
    redirect_uris: [redirectUri(env)],
    scope: scopesFor({ collections, spaces, minimal }).join(' '),
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    application_type: 'web',
    dpop_bound_access_tokens: true,
    token_endpoint_auth_method: 'private_key_jwt',
    token_endpoint_auth_signing_alg: 'ES256',
    jwks_uri: `${base}/jwks.json`
  };
}

function signingKey(env) {
  if (!env.CLIENT_PRIVATE_JWK) {
    throw new BrokerError(500, 'NotConfigured', 'CLIENT_PRIVATE_JWK is not set');
  }
  try {
    return JSON.parse(env.CLIENT_PRIVATE_JWK);
  } catch {
    throw new BrokerError(500, 'NotConfigured', 'CLIENT_PRIVATE_JWK is not valid JSON');
  }
}

/**
 * POST to an authorization-server endpoint with a DPoP proof, retrying once
 * when the server demands a nonce. Every AS requires this handshake on the
 * first call, so treating it as an error would break every login.
 */
async function postWithDpop(url, body, { privateJwk, nonceStore, accessToken }) {
  assertSafeUrl(url, 'endpoint');
  async function attempt(nonce) {
    const proof = await dpopProof({ privateJwk, method: 'POST', url, nonce, accessToken });
    const response = await fetch(url, {
      method: 'POST',
      // Never followed. A DPoP proof is bound to this exact URL, and following
      // a redirect would hand the authorization header to somewhere else.
      redirect: 'manual',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        dpop: proof,
        ...(accessToken ? { authorization: `DPoP ${accessToken}` } : {})
      },
      body: new URLSearchParams(body)
    });
    return response;
  }

  let response = await attempt(nonceStore.get(url));
  const offered = response.headers.get('DPoP-Nonce');
  if (offered) nonceStore.set(url, offered);

  if (response.status >= 400 && offered) {
    const detail = await response.clone().json().catch(() => null);
    if (detail?.error === 'use_dpop_nonce' || response.status === 401) {
      response = await attempt(offered);
      const next = response.headers.get('DPoP-Nonce');
      if (next) nonceStore.set(url, next);
    }
  }
  // The spec requires it: an authorization server answers every DPoP request
  // with a fresh nonce, and a client must not accept an answer without one.
  if (response.ok && !response.headers.get('DPoP-Nonce')) {
    throw new BrokerError(502, 'NoDpopNonce', 'The authorization server answered without a DPoP nonce');
  }
  return response;
}

/** A token response must grant `atproto`, or it is not an atproto session. */
function requireAtprotoScope(tokens) {
  const granted = String(tokens.scope || '').split(/\s+/);
  if (!granted.includes('atproto')) {
    throw new BrokerError(502, 'BadScope', 'The authorization server did not grant the atproto scope');
  }
}

/** A per-request nonce cache, keyed by origin as RFC 9449 scopes them. */
export function createNonceStore(initial = {}) {
  const nonces = { ...initial };
  return {
    get: (url) => nonces[new URL(url).origin],
    set: (url, value) => {
      nonces[new URL(url).origin] = value;
    },
    all: () => ({ ...nonces })
  };
}

async function readError(response, fallback) {
  const detail = await response.json().catch(() => null);
  const code = detail?.error || String(response.status);
  const description = detail?.error_description || fallback;
  return new BrokerError(response.status, code, `${code}: ${description}`);
}

/**
 * The configuration a grant was issued under. Its client_id is built from the
 * address the sign-in began on, and every later exchange for that grant has to
 * present the same one, whatever address the current request arrived on.
 */
export function forGrant(env, grant) {
  const url = grant && grant.publicUrl;
  return url ? { ...env, PUBLIC_URL: url } : env;
}

/**
 * Begin a login. Returns the authorize URL to send the browser to, plus the
 * state that /callback will need.
 */
export async function startAuthorization(env, identifier, options = {}) {
  const minimal = !!options.minimal;
  const collections = minimal ? [] : normalizeCollections(options.collections || []);
  const spaces = minimal ? false : !!options.spaces;
  const identity = await resolveIdentity(identifier);
  const metadata = await discoverAuthServer(identity.pds);

  const { verifier, challenge } = await pkcePair();
  const state = randomToken(24);
  const { privateJwk } = await generateKeyPair();
  const nonceStore = createNonceStore();

  const parBody = {
    client_id: clientId(env, collections, spaces, minimal),
    redirect_uri: redirectUri(env),
    response_type: 'code',
    scope: scopesFor({ collections, spaces, minimal }).join(' '),
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    login_hint: identity.handle || identity.did,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    client_assertion: await clientAssertion({
      privateJwk: signingKey(env),
      clientId: clientId(env, collections, spaces, minimal),
      audience: metadata.issuer
    })
  };

  const parUrl = metadata.pushed_authorization_request_endpoint;
  const response = await postWithDpop(parUrl, parBody, { privateJwk, nonceStore });
  if (!response.ok) throw await readError(response, 'pushed authorization request failed');

  const { request_uri: requestUri } = await response.json();
  if (!requestUri) throw new BrokerError(502, 'BadPar', 'No request_uri in the PAR response');

  const authorizeUrl = new URL(metadata.authorization_endpoint);
  authorizeUrl.searchParams.set('client_id', clientId(env, collections, spaces, minimal));
  authorizeUrl.searchParams.set('request_uri', requestUri);

  return {
    state,
    authorizeUrl: authorizeUrl.toString(),
    pending: {
      verifier,
      privateJwk,
      issuer: metadata.issuer,
      tokenEndpoint: metadata.token_endpoint,
      revocationEndpoint: metadata.revocation_endpoint || null,
      pds: identity.pds,
      did: identity.did,
      handle: identity.handle,
      collections,
      spaces,
      minimal,
      publicUrl: stripSlash(env.PUBLIC_URL),
      nonces: nonceStore.all()
    }
  };
}

/** Exchange the authorization code for tokens and verify who they belong to. */
export async function completeAuthorization(env, pending, { code, iss }) {
  env = forGrant(env, pending);
  // RFC 9207: the issuer must come back and must be the one we pushed to,
  // otherwise a code from another server could be swapped in. atproto
  // servers always send it, so a callback without one is refused too.
  if (!iss || stripSlash(iss) !== stripSlash(pending.issuer)) {
    throw new BrokerError(400, 'IssuerMismatch', 'The callback came from a different authorization server');
  }

  const nonceStore = createNonceStore(pending.nonces);
  const response = await postWithDpop(
    pending.tokenEndpoint,
    {
      grant_type: 'authorization_code',
      code,
      redirect_uri: redirectUri(env),
      client_id: clientId(env, pending.collections || [], !!pending.spaces, !!pending.minimal),
      code_verifier: pending.verifier,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: await clientAssertion({
        privateJwk: signingKey(env),
        clientId: clientId(env, pending.collections || [], !!pending.spaces, !!pending.minimal),
        audience: pending.issuer
      })
    },
    { privateJwk: pending.privateJwk, nonceStore }
  );
  if (!response.ok) throw await readError(response, 'token exchange failed');

  const tokens = await response.json();
  requireAtprotoScope(tokens);
  const did = tokens.sub;
  if (!did) throw new BrokerError(502, 'BadToken', 'The token response carries no subject');
  // The account the person entered. Signing in as someone else on the
  // authorization server's page must not pair that other account instead.
  if (pending.did && did !== pending.did) {
    throw new BrokerError(400, 'AccountMismatch',
      'You signed in as a different account from the one you entered. Start again with that account.');
  }

  // Mandatory: without this, a hostile PDS can hand back any DID it likes.
  const verified = await verifySubject(did, pending.pds, pending.issuer);

  return {
    did,
    handle: verified.handle || pending.handle,
    pds: verified.pds,
    collections: pending.collections || [],
    spaces: !!pending.spaces,
    // Carried so refresh and revoke rebuild the same client_id this grant was
    // issued under: a different one is a different client to the AS.
    minimal: !!pending.minimal,
    publicUrl: stripSlash(env.PUBLIC_URL),
    issuer: pending.issuer,
    tokenEndpoint: pending.tokenEndpoint,
    revocationEndpoint: pending.revocationEndpoint || null,
    privateJwk: pending.privateJwk,
    accessToken: tokens.access_token,
    refreshToken: tokens.refresh_token,
    expiresAt: Date.now() + (Number(tokens.expires_in) || 3600) * 1000,
    nonces: nonceStore.all()
  };
}

/** Trade the refresh token for a new access token. */
export async function refreshSession(env, session) {
  env = forGrant(env, session);
  if (!session.refreshToken) {
    throw new BrokerError(401, 'NoRefreshToken', 'This session cannot be refreshed; sign in again');
  }

  const nonceStore = createNonceStore(session.nonces);
  const response = await postWithDpop(
    session.tokenEndpoint,
    {
      grant_type: 'refresh_token',
      refresh_token: session.refreshToken,
      client_id: clientId(env, session.collections || [], !!session.spaces, !!session.minimal),
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: await clientAssertion({
        privateJwk: signingKey(env),
        clientId: clientId(env, session.collections || [], !!session.spaces, !!session.minimal),
        audience: session.issuer
      })
    },
    { privateJwk: session.privateJwk, nonceStore }
  );
  if (!response.ok) throw await readError(response, 'refresh failed');

  const tokens = await response.json();
  requireAtprotoScope(tokens);
  return {
    ...session,
    accessToken: tokens.access_token,
    // Refresh tokens rotate: keeping the old one would invalidate the session
    // on its next use.
    refreshToken: tokens.refresh_token || session.refreshToken,
    expiresAt: Date.now() + (Number(tokens.expires_in) || 3600) * 1000,
    nonces: nonceStore.all()
  };
}

/**
 * Hand the tokens back to the authorization server.
 *
 * Deleting our copy is not enough: until the refresh token is revoked at the
 * source, the grant still exists on the user's account. Best effort: if the
 * server refuses or has no revocation endpoint, the local delete still goes
 * ahead, because a user asking to be removed must always be removed.
 */
export async function revokeSession(env, session) {
  env = forGrant(env, session);
  if (!session || !session.revocationEndpoint) {
    return { revoked: false, reason: 'the authorization server publishes no revocation endpoint' };
  }

  const nonceStore = createNonceStore(session.nonces);
  try {
    const response = await postWithDpop(
      session.revocationEndpoint,
      {
        token: session.refreshToken || session.accessToken,
        token_type_hint: session.refreshToken ? 'refresh_token' : 'access_token',
        client_id: clientId(env, session.collections || [], !!session.spaces, !!session.minimal),
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: await clientAssertion({
          privateJwk: signingKey(env),
          clientId: clientId(env, session.collections || [], !!session.spaces, !!session.minimal),
          audience: session.issuer
        })
      },
      { privateJwk: session.privateJwk, nonceStore }
    );
    return { revoked: response.ok, reason: response.ok ? null : `server answered ${response.status}` };
  } catch (error) {
    return { revoked: false, reason: error.message };
  }
}

/**
 * Call an XRPC method on the session's PDS, refreshing the token when it has
 * expired and retrying once on a nonce challenge.
 *
 * Returns { result, session }. The session may have been renewed, and the
 * caller must persist it or the next call will refresh all over again.
 * `refresh` performs the rotation through the account's own coordination, so
 * every refresh for one account is serialized and persisted before the
 * request that needed it is attempted.
 */
export async function xrpcPost(env, session, nsid, body, refresh) {
  let current = session;

  // `refresh` is the account's own coordinated rotation: it serializes with
  // every other refresh for this account and persists before returning. Doing
  // it here instead would put this outside that coordination.
  const rotate = refresh || (async () => refreshSession(env, current));

  if (!current.accessToken || Date.now() >= current.expiresAt - 30_000) {
    current = await rotate();
  }

  const url = assertSafeUrl(`${stripSlash(current.pds)}/xrpc/${nsid}`, 'PDS address');
  const nonceStore = createNonceStore(current.nonces);

  async function attempt(accessToken, nonce) {
    const proof = await dpopProof({
      privateJwk: current.privateJwk,
      method: 'POST',
      url,
      nonce,
      accessToken
    });
    return fetch(url, {
      method: 'POST',
      redirect: 'manual',   // as above: the proof is bound to this URL
      headers: {
        'content-type': 'application/json',
        authorization: `DPoP ${accessToken}`,
        dpop: proof
      },
      body: JSON.stringify(body)
    });
  }

  let response = await attempt(current.accessToken, nonceStore.get(url));
  let offered = response.headers.get('DPoP-Nonce');
  if (offered) nonceStore.set(url, offered);

  if (response.status === 401 && offered) {
    response = await attempt(current.accessToken, offered);
    offered = response.headers.get('DPoP-Nonce');
    if (offered) nonceStore.set(url, offered);
  }

  // An expired access token reads as 401 too; refresh once and try again.
  if (response.status === 401) {
    const detail = await response.clone().json().catch(() => null);
    const expired = detail?.error === 'invalid_token' || detail?.error === 'ExpiredToken';
    if (expired) {
      current = await rotate();
      response = await attempt(current.accessToken, nonceStore.get(url));
      const next = response.headers.get('DPoP-Nonce');
      if (next) nonceStore.set(url, next);
    }
  }

  current = { ...current, nonces: nonceStore.all() };

  // Required of every DPoP response, the PDS's included. By the time the PDS
  // answers, the write has happened, so the message cannot claim it failed.
  if (response.ok && !response.headers.get('DPoP-Nonce')) {
    throw new BrokerError(502, 'NoDpopNonce',
      'Your PDS answered without a DPoP nonce. The record may have been written; check before posting again.');
  }

  if (!response.ok) {
    const detail = await response.json().catch(() => null);
    throw new BrokerError(
      response.status,
      detail?.error || 'XrpcError',
      detail?.message || detail?.error_description || `${nsid} answered ${response.status}`
    );
  }

  return { result: await response.json(), session: current };
}

export { decodeJwtPayload };
