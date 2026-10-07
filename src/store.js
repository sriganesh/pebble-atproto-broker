/**
 * Storage, all of it in Durable Objects: one actor per account, and one
 * short-lived cell per code, ticket or counter.
 */

import { open, seal, sha256Base64Url } from './crypto.js';
import { BrokerError } from './identity.js';

const PENDING_TTL = 600;   // a login in progress
const REMOVAL_TTL = 600;   // a proven identity waiting for the user to confirm
const PAIR_TTL = 600;      // a pairing code waiting to be claimed
const PAIR_RATE_WINDOW = 600;   // how long failed pairing attempts are counted
export const PAIR_MAX_FAILURES = 10;

// No I, O, 0 or 1: a pairing code gets read off a screen and typed on a phone.
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function newPairingCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += CODE_ALPHABET[bytes[i] % CODE_ALPHABET.length];
    if (i === 3) code += '-';
  }
  return code;
}

export function normalizeCode(value) {
  return String(value || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export class Store {
  /** Every value goes through seal()/open(), so no caller can forget to. */
  constructor(secret, actors) {
    this.secret = secret;
    // ACCOUNTS and CELLS are Durable Object namespaces.
    this.accounts = actors?.accounts || null;
    this.cells = actors?.cells || null;
  }

  /** The actor for one account. */
  account(did) {
    return this.accounts.get(this.accounts.idFromName(`account:${did}`));
  }

  /** The actor for one short-lived keyed value. */
  cell(kind, key) {
    return this.cells.get(this.cells.idFromName(`${kind}:${key}`));
  }

  async callAccount(did, body) {
    const response = await this.account(did).fetch('https://actor/', {
      method: 'POST',
      body: JSON.stringify({ ...body, secret: this.secret })
    });
    return response.json();
  }

  async callCell(kind, key, body) {
    const response = await this.cell(kind, key).fetch('https://actor/', {
      method: 'POST',
      body: JSON.stringify({ ...body, secret: this.secret })
    });
    return response.json();
  }

  /** The client signing key, made on first use if nothing was configured. */
  async clientKey() {
    const { jwk } = await this.callCell('client', 'signing', { op: 'ensureKey' });
    return jwk;
  }

  /** The stored name for a device token. Never the token itself. */
  async deviceHash(token) {
    return sha256Base64Url(`${this.secret}:device:${token}`);
  }

  async putPending(state, pending) {
    await this.callCell('pending', state, { op: 'put', value: pending, ttlMs: PENDING_TTL * 1000 });
  }

  async takePending(state) {
    // Single use, and now actually single use: a replayed callback cannot
    // re-run the exchange even if it arrives while the first is still running.
    const { value } = await this.callCell('pending', state, { op: 'take' });
    return value || null;
  }

  /**
   * Park a proven identity between signing in and confirming the removal.
   *
   * Signing in proves the account is yours; it does not say you meant to
   * delete it. The ticket holds the live session so the confirm step can still
   * revoke, and is single use with a short life so an abandoned removal leaves
   * nothing behind.
   */
  async putRemoval(token, ticket) {
    await this.callCell('remove', String(token), {
      op: 'put', value: ticket, ttlMs: REMOVAL_TTL * 1000
    });
  }

  async takeRemoval(token) {
    if (!token) return null;
    const { value } = await this.callCell('remove', String(token), { op: 'take' });
    return value || null;
  }

  /**
   * A code carries the account's generation when it was issued, so removing
   * the account also voids any code still waiting to be used.
   */
  async putPairing(code, did, generation) {
    await this.callCell('pair', normalizeCode(code), {
      op: 'put', value: { did, generation }, ttlMs: PAIR_TTL * 1000
    });
  }

  async takePairing(code) {
    const { value } = await this.callCell('pair', normalizeCode(code), { op: 'take' });
    return value && value.did ? value : null;
  }

  async putSession(session) {
    await this.callAccount(session.did, { op: 'putSession', session });
  }

  async getSession(did) {
    const { session } = await this.callAccount(did, { op: 'getSession' });
    return session || null;
  }

  /**
   * A session with a usable access token, refreshed inside the actor if it is
   * spent. Two posts arriving together are serialized here, so they cannot
   * both refresh and invalidate each other's rotated token.
   */
  async freshSession(did, force) {
    const result = await this.callAccount(did, { op: 'freshSession', force: force === true });
    if (!result.session && result.error) {
      throw new BrokerError(401, result.error, result.message);
    }
    return result.session || null;
  }

  /** The account's current removal generation. */
  async generation(did) {
    const { generation } = await this.callAccount(did, { op: 'generation' });
    return generation;
  }

  async createDevice(did, label, generation) {
    const { token, error } = await this.callAccount(did, { op: 'addDevice', label, did, generation });
    if (error) {
      throw new BrokerError(400, 'BadCode', 'That sign-in code is wrong, used, or expired');
    }
    return token;
  }

  /** The account a device token belongs to, read out of the token itself. */
  static didFromToken(token) {
    const head = String(token || '').split('.')[0];
    if (!head) return null;
    try {
      const did = atob(head.replace(/-/g, '+').replace(/_/g, '/'));
      return /^did:[a-z]+:/.test(did) ? did : null;
    } catch {
      return null;
    }
  }

  async listDevices(did) {
    const { devices } = await this.callAccount(did, { op: 'listDevices' });
    return devices.map((d) => d.hash);
  }

  /** Every paired device with its label and when it was paired. */
  async listDeviceDetails(did) {
    const { devices } = await this.callAccount(did, { op: 'listDevices' });
    return devices.map((d) => ({ token: d.hash, label: d.label, createdAt: d.createdAt }));
  }

  /**
   * A device token names its account only by being registered under one, so a
   * lookup needs the DID as well. The bearer sends both.
   */
  async getDevice(token) {
    const did = Store.didFromToken(token);
    if (!did || !token) return null;
    const { device } = await this.callAccount(did, {
      op: 'getDevice', hash: await this.deviceHash(token)
    });
    return device ? { ...device, did } : null;
  }

  async deleteDevice(did, hash) {
    await this.callAccount(did, { op: 'removeDevice', hash });
  }

  async forgetDid(did) {
    const { removed } = await this.callAccount(did, { op: 'forget' });
    return removed;
  }

  /**
   * Count failed pairing attempts per caller.
   *
   * A code is 40 bits, so brute force is already impractical. This is depth
   * behind that. Kept against a one-way hash of the caller's address,
   * never the address itself.
   */
  async rateKey(caller) {
    return (await sha256Base64Url(`${this.secret}:${caller}`)).slice(0, 22);
  }

  async countPairFailure(caller) {
    const { n } = await this.callCell('rate', await this.rateKey(caller), {
      op: 'bump', ttlMs: PAIR_RATE_WINDOW * 1000
    });
    return n;
  }

  async pairFailures(caller) {
    const { n } = await this.callCell('rate', await this.rateKey(caller), { op: 'count' });
    return n;
  }
}
