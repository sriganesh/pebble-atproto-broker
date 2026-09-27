/**
 * A stand-in for a Durable Object namespace.
 *
 * One instance per id, as the runtime does.
 *
 * Two modes, because the runtime has two behaviours. Its input gate defers
 * other events while a STORAGE operation is in flight, so work that only
 * touches storage is effectively serialized -- that is `serialize: true`, the
 * default, and it is what production gives for things like registering a
 * device. But the gate does not hold across other I/O: while a handler awaits
 * the network, the next request is delivered. `serialize: false` models that,
 * and anything relying on ordering there has to arrange it itself.
 */
export function fakeNamespace(ActorClass, env = {}, { serialize = true } = {}) {
  const instances = new Map();
  const queues = new Map();
  const storages = new Map();
  const alarms = new Map();

  return {
    /** Run any alarm due at `now`, as the runtime would. */
    async runAlarms(now = Date.now()) {
      let fired = 0;
      for (const [name, at] of [...alarms]) {
        if (at <= now) {
          alarms.delete(name);
          await instances.get(name).alarm();
          fired++;
        }
      }
      return fired;
    },
    alarmCount() { return alarms.size; },
    /** Everything written, so a test can check what sits at rest. */
    dump() {
      const out = [];
      for (const [name, storage] of storages) {
        for (const [key, value] of storage) out.push({ name, key, value });
      }
      return out;
    },
    idFromName(name) { return { name }; },
    get(id) {
      const name = id.name;
      if (!instances.has(name)) {
        const storage = new Map();
        storages.set(name, storage);
        instances.set(name, new ActorClass({
          storage: {
            async get(key) { return storage.get(key); },
            async put(key, value) { storage.set(key, value); },
            async delete(key) { storage.delete(key); },
            async deleteAll() { storage.clear(); },
            async setAlarm(at) { alarms.set(name, at); },
            async deleteAlarm() { alarms.delete(name); },
            async getAlarm() { return alarms.get(name) ?? null; }
          }
        }, env));
      }
      const actor = instances.get(name);
      return {
        fetch(url, init) {
          if (!serialize) {
            // What the runtime actually does: the storage gate covers storage,
            // but a request can be delivered while another is awaiting the
            // network. Anything relying on serialization has to arrange it.
            return actor.fetch(new Request(url, init));
          }
          const previous = queues.get(name) || Promise.resolve();
          const next = previous
            .catch(() => {})
            .then(() => actor.fetch(new Request(url, init)));
          queues.set(name, next);
          return next;
        }
      };
    }
  };
}
