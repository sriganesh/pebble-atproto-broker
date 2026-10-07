/**
 * Two Durable Objects: one per DID, one per short-lived key.
 *
 * Everything here is read-modify-write on state that must not race. A
 * single-use code must be redeemed once. Two devices signing in at the same
 * time must both land in the device index. Two posts arriving together must
 * not both refresh, because the authorization server rotates the refresh
 * token and the second rotation kills the first. An object is one instance
 * per id handling one request at a time, with consistent storage.
 *
 * Values are sealed before they are stored, so nothing readable sits at rest.
 */

import { generateSigningKey, open, randomToken, seal, sha256Base64Url } from './crypto.js';
import { refreshSession, revokeSession } from './oauth.js';
import { Store } from './store.js';

/**
 * One short-lived keyed value: a pairing code, a login in progress, a removal
 * ticket, or a count of failed attempts.
 *
 * `take` reads and deletes without anything interleaving, and `bump` reads and
 * increments the same way.
 */
export class PebbleBrokerCell {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    const { op, value, ttlMs, secret } = await request.json();

    if (op === 'put') {
      const expiresAt = Date.now() + ttlMs;
      await this.state.storage.put('claim', await seal(secret, value));
      await this.state.storage.put('expiresAt', expiresAt);
      // Storage here does not expire on its own, so a code nobody types would
      // sit for good. The alarm empties the object when the claim goes stale.
      await this.state.storage.setAlarm(expiresAt + 1000);
      return Response.json({ ok: true });
    }

    if (op === 'take') {
      const sealed = await this.state.storage.get('claim');
      const expiresAt = await this.state.storage.get('expiresAt');
      // Deleted before anything is returned, so a second caller finds nothing
      // even if it arrived while this one was still running.
      await this.state.storage.deleteAll();
      await this.state.storage.deleteAlarm();
      if (!sealed || (expiresAt && Date.now() > expiresAt)) {
        return Response.json({ value: null });
      }
      try {
        return Response.json({ value: await open(secret, sealed) });
      } catch {
        return Response.json({ value: null });
      }
    }

    // The client signing key, made here on first use so a fresh deploy needs
    // no keypair pasted into it. Permanent, so no alarm and no expiry.
    //
    // Generating is pure crypto, not storage, so the storage gate does not
    // cover the await: two callers arriving together would each make a key and
    // the second would overwrite the first, invalidating every grant issued
    // under it. The in-flight one is held on the instance and shared.
    //
    // A key sealed under a STORAGE_KEY that has since changed can never be
    // opened again, so it is replaced. That is the only failure caught here:
    // a storage error still surfaces, and never costs a working key.
    if (op === 'ensureKey') {
      if (!this.making) {
        this.making = (async () => {
          const stored = await this.state.storage.get('key');
          if (stored) {
            try {
              return await open(secret, stored);
            } catch {
              // Sealed under another STORAGE_KEY. Replaced below.
            }
          }
          const jwk = await generateSigningKey();
          await this.state.storage.put('key', await seal(secret, jwk));
          return jwk;
        })().finally(() => { this.making = null; });
      }
      return Response.json({ jwk: await this.making });
    }

    if (op === 'bump') {
      const expiresAt = await this.state.storage.get('expiresAt');
      const stale = !expiresAt || Date.now() > expiresAt;
      const n = (stale ? 0 : (await this.state.storage.get('n')) || 0) + 1;
      await this.state.storage.put('n', n);
      await this.state.storage.put('expiresAt', Date.now() + ttlMs);
      await this.state.storage.setAlarm(Date.now() + ttlMs + 1000);
      return Response.json({ n });
    }

    if (op === 'count') {
      const expiresAt = await this.state.storage.get('expiresAt');
      if (!expiresAt || Date.now() > expiresAt) return Response.json({ n: 0 });
      return Response.json({ n: (await this.state.storage.get('n')) || 0 });
    }

    return Response.json({ error: 'BadOp' }, { status: 400 });
  }

  /** Expired without being used. Nothing here is worth keeping. */
  async alarm() {
    await this.state.storage.deleteAll();
  }
}

/**
 * One account, keyed by DID: its session, its devices, and its refreshes.
 *
 * Everything that touches an account goes through here, so none of it can
 * interleave with itself.
 */
export class PebbleBrokerAccount {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async read(secret, key) {
    const sealed = await this.state.storage.get(key);
    if (!sealed) return null;
    try {
      return await open(secret, sealed);
    } catch {
      return null;
    }
  }

  async write(secret, key, value) {
    await this.state.storage.put(key, await seal(secret, value));
  }

  /**
   * A session with a usable access token.
   *
   * Being inside a Durable Object is NOT enough on its own. The storage gate
   * only covers storage: while this awaits the authorization server, the
   * runtime is free to deliver the next request to the same object, and two
   * refreshes would each rotate the token and invalidate the other. So the
   * in-flight refresh is held on the instance and the second caller waits for
   * it instead of starting its own.
   */
  async ensureFresh(secret, force) {
    const session = await this.read(secret, 'session');
    if (!session) return { session: null };
    if (!force && session.accessToken && Date.now() < session.expiresAt - 30_000) {
      return { session };
    }
    if (!this.refreshing) {
      this.refreshing = this.rotate(secret, session)
        .finally(() => { this.refreshing = null; });
    }
    return this.refreshing;
  }

  /** The network call, alone, so a test can stand in for it. */
  /**
   * This object's own env has no generated signing key: the Worker makes that
   * on first use and keeps it in a cell. Refresh and revoke need it here too.
   */
  async config() {
    if (this.env.CLIENT_PRIVATE_JWK) return this.env;
    if (!this.clientKey) {
      const store = new Store(this.env.STORAGE_KEY,
                              { accounts: this.env.ACCOUNTS, cells: this.env.CELLS });
      this.clientKey = JSON.stringify(await store.clientKey());
    }
    return { ...this.env, CLIENT_PRIVATE_JWK: this.clientKey };
  }

  async refresh(session) {
    return refreshSession(await this.config(), session);
  }

  async rotate(secret, session) {
    const before = await this.read(secret, 'generation');
    try {
      const rotated = await this.refresh(session);
      // The account can be removed, or sign in again, while this awaits the
      // network. Writing then would resurrect a session that was deleted, or
      // bury a newer login under a stale one.
      const now = await this.read(secret, 'session');
      if (!now || now.refreshToken !== session.refreshToken ||
          (await this.read(secret, 'generation')) !== before) {
        // We are throwing this rotation away, but the authorization server has
        // already issued it. Hand it back, so no credential is left alive that
        // nothing here will use or revoke.
        await this.config().then((config) => revokeSession(config, rotated)).catch(() => {});
        return {
          session: null,
          error: 'SessionChanged',
          message: 'That account was signed out while this was in flight'
        };
      }
      await this.write(secret, 'session', rotated);
      return { session: rotated };
    } catch (error) {
      return {
        session: null,
        error: error?.code || 'RefreshFailed',
        message: error?.message || 'Could not refresh the session'
      };
    }
  }

  async fetch(request) {
    const body = await request.json();
    const { op, secret } = body;

    switch (op) {
      case 'getSession':
        return Response.json({ session: await this.read(secret, 'session') });

      case 'putSession':
        await this.write(secret, 'session', body.session);
        return Response.json({ ok: true });

      /**
       * Hand back a session with a usable access token, refreshing first if
       * it is spent. Serialized, so two posts landing together cannot both
       * refresh and invalidate each other's rotated token; and the rotation is
       * written here, before the caller does anything with it.
       */
      case 'freshSession':
        return Response.json(await this.ensureFresh(secret, body.force === true));

      case 'generation':
        return Response.json({ generation: (await this.read(secret, 'generation')) || 0 });

      case 'addDevice': {
        // The token carries its account so a bearer alone can be routed to the
        // right actor. The DID is not a secret; the random half is.
        const did = body.did;
        const token = `${btoa(did).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')}.${randomToken(32)}`;
        const hash = await sha256Base64Url(`${secret}:device:${token}`);
        const generation = (await this.read(secret, 'generation')) || 0;
        // A code issued before the account was removed must not add a device
        // to the account that replaced it. Checked here, in the same step as
        // the write, so a removal cannot slip in between.
        if (typeof body.generation === 'number' && body.generation !== generation) {
          return Response.json({ error: 'StaleCode' });
        }
        const devices = (await this.read(secret, 'devices')) || {};
        devices[hash] = {
          label: body.label || 'Pebble',
          createdAt: new Date().toISOString(),
          generation
        };
        await this.write(secret, 'devices', devices);
        return Response.json({ token });
      }

      case 'getDevice': {
        const devices = (await this.read(secret, 'devices')) || {};
        const device = devices[body.hash];
        if (!device) return Response.json({ device: null });
        const generation = (await this.read(secret, 'generation')) || 0;
        // Stamped with an older era of this account: the account was removed
        // since, so this credential is not a credential any more.
        if ((device.generation || 0) !== generation) {
          return Response.json({ device: null });
        }
        return Response.json({ device: { ...device, hash: body.hash } });
      }

      case 'listDevices': {
        const devices = (await this.read(secret, 'devices')) || {};
        const generation = (await this.read(secret, 'generation')) || 0;
        return Response.json({
          devices: Object.entries(devices)
            .filter(([, d]) => (d.generation || 0) === generation)
            .map(([hash, d]) => ({ hash, label: d.label, createdAt: d.createdAt }))
            .sort((a, b) => String(a.createdAt).localeCompare(String(b.createdAt)))
        });
      }

      case 'removeDevice': {
        const devices = (await this.read(secret, 'devices')) || {};
        const existed = Object.prototype.hasOwnProperty.call(devices, body.hash);
        delete devices[body.hash];
        await this.write(secret, 'devices', devices);
        return Response.json({ removed: existed });
      }

      /**
       * Remove the account. Bumping the generation is what makes it final: a
       * device row that somehow survives is stamped with the old number and
       * can never authenticate again, even after a fresh sign-in.
       */
      case 'forget': {
        const devices = (await this.read(secret, 'devices')) || {};
        const count = Object.keys(devices).length;
        const generation = ((await this.read(secret, 'generation')) || 0) + 1;
        await this.state.storage.deleteAll();
        await this.write(secret, 'generation', generation);
        return Response.json({ removed: count });
      }

      default:
        return Response.json({ error: 'BadOp' }, { status: 400 });
    }
  }
}
