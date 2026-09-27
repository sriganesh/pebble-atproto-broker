/**
 * Identity and server discovery.
 *
 *   handle/DID -> DID document -> #atproto_pds
 *              -> /.well-known/oauth-protected-resource -> authorization server
 *              -> /.well-known/oauth-authorization-server -> endpoints
 *
 * The chain is walked again after the token exchange to verify the returned
 * `sub`: skipping that check leaves a window where a hostile PDS can hand back
 * someone else's DID.
 */

// Defaults, both overridable per deployment. Neither is required: a DID
// resolves without any resolver, and did:web resolves without a directory
// too. This is an AT Protocol broker: no host here is specific to any one PDS
// operator or appview.
const DEFAULTS = {
  // One call returns did + handle + pds. A convenience with a full fallback.
  resolver: 'https://slingshot.firehose.stream',
  // A did:plc registry. didplc.directory is a replica of plc.directory.
  plcDirectory: 'https://didplc.directory'
};

let SLINGSHOT = DEFAULTS.resolver;
let PLC_DIRECTORY = DEFAULTS.plcDirectory;

/** Called once per request so deployment config, not code, picks the hosts. */
/**
 * Reject a destination we should never send credentials to.
 *
 * A DID document names its own PDS, and anyone can publish one, so the host it
 * points at is untrusted input. HTTPS only, and no loopback or private ranges:
 * on a server those resolve to the metadata service and the internal network.
 */
export function assertSafeUrl(value, what = 'address') {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new BrokerError(400, 'BadUrl', `That ${what} is not a URL`);
  }
  if (url.protocol !== 'https:') {
    throw new BrokerError(400, 'InsecureUrl', `A ${what} must use https`);
  }
  let host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  // ::ffff:127.0.0.1 is 127.0.0.1 wearing a hat, and the URL parser rewrites it
  // to hex (::ffff:7f00:1), so unpack both spellings back to the IPv4 it is.
  const mapped = /^::ffff:(?:(\d+\.\d+\.\d+\.\d+)|([0-9a-f]{1,4}):([0-9a-f]{1,4}))$/.exec(host);
  if (mapped) {
    host = mapped[1] || [
      parseInt(mapped[2], 16) >> 8, parseInt(mapped[2], 16) & 0xff,
      parseInt(mapped[3], 16) >> 8, parseInt(mapped[3], 16) & 0xff
    ].join('.');
  }

  const blocked =
    host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal') ||
    host === '::1' || host === '::' || host === '' ||
    /^0\./.test(host) ||                                  // 0.0.0.0/8 routes to this host
    /^127\./.test(host) || /^10\./.test(host) || /^192\.168\./.test(host) ||
    /^169\.254\./.test(host) ||                          // link-local, incl. metadata
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host) ||  // CGNAT 100.64/10
    /^f[cd][0-9a-f]{2}:/.test(host) ||                    // fc00::/7 unique-local
    /^fe[89ab][0-9a-f]:/.test(host) ||                     // fe80::/10 link-local, all of it
    /^192\.0\.0\./.test(host) ||                          // IETF protocol assignments
    /^198\.1[89]\./.test(host) ||                          // benchmarking
    /^2(2[4-9]|3\d)\./.test(host) ||                       // multicast
    /^ff[0-9a-f]{2}:/.test(host) ||                        // ff00::/8, IPv6 multicast
    /^2(4\d|5[0-5])\./.test(host) ||                       // reserved, incl. broadcast
    host === '255.255.255.255';
  if (blocked) {
    throw new BrokerError(400, 'PrivateUrl', `A ${what} must be a public host`);
  }
  return url.toString();
}

export function configureIdentity(env) {
  SLINGSHOT = stripSlash(env.IDENTITY_RESOLVER || DEFAULTS.resolver);
  PLC_DIRECTORY = stripSlash(env.PLC_DIRECTORY || DEFAULTS.plcDirectory);
}

export class BrokerError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

function stripSlash(url) {
  return String(url || '').replace(/\/+$/, '');
}

/**
 * Fetch, checking every hop.
 *
 * `fetch` follows redirects itself, so validating only the URL we were given
 * lets a perfectly public host answer 302 and send us to 169.254.169.254.
 * Redirects are taken manually and each destination is checked like the first.
 */
export async function safeFetch(url, init, what = 'address') {
  let current = assertSafeUrl(url, what);
  for (let hop = 0; hop < 5; hop++) {
    const response = await fetch(current, { ...init, redirect: 'manual' });
    if (response.status < 300 || response.status > 399) {
      return response;
    }
    const location = response.headers.get('location');
    if (!location) {
      return response;
    }
    current = assertSafeUrl(new URL(location, current).toString(), what);
  }
  throw new BrokerError(502, 'TooManyRedirects', `${url} redirects too many times`);
}

async function getJson(url, init) {
  const response = await safeFetch(url, {
    ...init,
    headers: { accept: 'application/json', ...(init?.headers || {}) }
  });
  if (!response.ok) {
    throw new BrokerError(502, 'UpstreamError', `${url} answered ${response.status}`);
  }
  return response.json();
}

export function pdsFromDidDocument(document) {
  for (const service of document?.service || []) {
    if (!service?.serviceEndpoint) continue;
    const id = String(service.id || '');
    if (id.endsWith('#atproto_pds') || service.type === 'AtprotoPersonalDataServer') {
      // Whoever published this document chose this host.
      assertSafeUrl(service.serviceEndpoint, 'PDS address');
      return stripSlash(service.serviceEndpoint);
    }
  }
  return null;
}

export async function resolveDid(did) {
  let url;
  if (did.startsWith('did:plc:')) {
    url = `${PLC_DIRECTORY}/${encodeURIComponent(did)}`;
  } else if (did.startsWith('did:web:')) {
    // Colons separate path segments; a port inside a segment is %3A. Only a
    // bare host uses /.well-known. did:web:example.com:users:alice lives at
    // https://example.com/users/alice/did.json.
    const [rawHost, ...rest] = did.slice('did:web:'.length).split(':');
    const host = decodeURIComponent(rawHost);
    const path = rest.map(decodeURIComponent).join('/');
    // The DID names the host. Anyone can mint one, so this is user input.
    url = assertSafeUrl(
      `https://${host}${path ? `/${path}/did.json` : '/.well-known/did.json'}`, 'did:web host');
  } else {
    throw new BrokerError(400, 'UnsupportedDid', `Unsupported DID method: ${did}`);
  }

  const document = await getJson(url);
  const pds = pdsFromDidDocument(document);
  if (!pds) throw new BrokerError(400, 'NoPds', 'That DID document has no PDS');

  const aka = document.alsoKnownAs?.[0];
  return {
    did,
    pds,
    handle: typeof aka === 'string' && aka.startsWith('at://') ? aka.slice(5) : null
  };
}

/** Resolve a handle or DID to { did, handle, pds }. */
export async function resolveIdentity(identifier) {
  const value = String(identifier || '').trim().replace(/^@/, '');
  if (!value) throw new BrokerError(400, 'MissingHandle', 'Enter a handle');
  if (value.startsWith('did:')) return resolveDid(value);

  try {
    const doc = await getJson(
      `${SLINGSHOT}/xrpc/blue.microcosm.identity.resolveMiniDoc?identifier=${encodeURIComponent(value)}`
    );
    if (doc?.did && doc?.pds) {
      // The resolver's answer is as untrusted as a DID document: it names a
      // host we are about to send credentials to.
      assertSafeUrl(doc.pds, 'PDS address');
      return { did: doc.did, handle: doc.handle || value, pds: stripSlash(doc.pds) };
    }
  } catch {
    // Slingshot is a convenience, not a dependency.
  }

  // A handle is user input, so the URL built from it is checked like any other.
  const response = await safeFetch(
    `https://${encodeURIComponent(value)}/.well-known/atproto-did`, undefined, 'handle');
  if (!response.ok) throw new BrokerError(400, 'UnresolvedHandle', 'Could not resolve that handle');
  const did = (await response.text()).trim();
  if (!did.startsWith('did:')) {
    throw new BrokerError(400, 'UnresolvedHandle', 'Could not resolve that handle');
  }
  const resolved = await resolveDid(did);
  return { ...resolved, handle: value };
}

/** The authorization server a PDS delegates to, and its endpoints. */
export async function discoverAuthServer(pds) {
  assertSafeUrl(pds, 'PDS address');
  const protectedResource = await getJson(`${stripSlash(pds)}/.well-known/oauth-protected-resource`);
  const issuer = protectedResource?.authorization_servers?.[0];
  if (!issuer) {
    throw new BrokerError(502, 'NoAuthServer', 'That PDS advertises no authorization server');
  }
  // The PDS chose this issuer, and the PDS was chosen by a DID document.
  assertSafeUrl(issuer, 'authorization server');

  const metadata = await getJson(`${stripSlash(issuer)}/.well-known/oauth-authorization-server`);
  for (const field of ['issuer', 'pushed_authorization_request_endpoint', 'authorization_endpoint', 'token_endpoint']) {
    if (!metadata?.[field]) {
      throw new BrokerError(502, 'BadAuthServer', `Authorization server metadata is missing ${field}`);
    }
    // Every one of these becomes a request carrying a client assertion.
    assertSafeUrl(metadata[field], `authorization server ${field}`);
  }
  if (metadata.revocation_endpoint) {
    assertSafeUrl(metadata.revocation_endpoint, 'revocation endpoint');
  }
  // RFC 8414: the issuer in the document is authoritative and must match where
  // we fetched it from, or an attacker-chosen document could redirect the flow.
  if (stripSlash(metadata.issuer) !== stripSlash(issuer)) {
    throw new BrokerError(502, 'IssuerMismatch', 'Authorization server issuer does not match');
  }
  return metadata;
}

/**
 * Confirm the DID the token response claims really is served by the PDS and
 * authorization server we just talked to.
 */
export async function verifySubject(did, expectedPds, expectedIssuer) {
  const resolved = await resolveDid(did);
  if (stripSlash(resolved.pds) !== stripSlash(expectedPds)) {
    throw new BrokerError(400, 'IdentityMismatch', 'The signed-in DID is served by a different PDS');
  }
  const metadata = await discoverAuthServer(resolved.pds);
  if (stripSlash(metadata.issuer) !== stripSlash(expectedIssuer)) {
    throw new BrokerError(400, 'IdentityMismatch', 'The signed-in DID uses a different authorization server');
  }
  return resolved;
}

export { stripSlash };
