/**
 * The two pages a person actually sees: sign in, and here is your pairing
 * code. Deliberately plain: this is a utility.
 */

// Bump when public/og.png changes: social caches key on the URL.
const OG_VERSION = 'b5161cdc54';

const OG_DESCRIPTION = 'Holds an AT Protocol OAuth session for a Pebble watch, which cannot hold one itself. Sign in once; the watch then posts through it without ever holding your password.';

// Who this deployment is. Set per request from config, because a copy of this
// broker must not present itself as ours.
let SITE = { url: '', contact: '' };

export function configurePages(env) {
  SITE = {
    url: String(env.PUBLIC_URL || '').replace(/\/+$/, ''),
    contact: String(env.CONTACT_EMAIL || '').trim()
  };
}

const SOURCE_URL = 'https://github.com/sriganesh/pebble-atproto-broker';
const DEPLOY_URL = 'https://deploy.workers.cloudflare.com/?url=' + SOURCE_URL;

function shell(title, body, footer) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>${title}</title>
<meta name="description" content="${escapeHtml(OG_DESCRIPTION)}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="Pebble atproto broker">
<meta property="og:title" content="Pebble atproto broker">
<meta property="og:description" content="${escapeHtml(OG_DESCRIPTION)}">
<meta property="og:image" content="${SITE.url}/og.png?v=${OG_VERSION}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:image:alt" content="A Pebble watch showing an at sign, thinking the words Pebble atproto broker.">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="Pebble atproto broker">
<meta name="twitter:description" content="${escapeHtml(OG_DESCRIPTION)}">
<meta name="twitter:image" content="${SITE.url}/og.png?v=${OG_VERSION}">
<link rel="icon" href="/favicon.ico" sizes="32x32">
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/favicon-96x96.png" type="image/png" sizes="96x96">
<link rel="apple-touch-icon" href="/apple-touch-icon.png">
<link rel="manifest" href="/manifest.webmanifest">
<style>
:root {
  color-scheme: light dark;
  --bg: #f6f6f4; --surface: #fff; --line: #dededa;
  --ink: #16160f; --ink-2: #5f5f58; --accent: #1f5fd0; --accent-ink: #fff; --danger: #b3261e;
}
@media (prefers-color-scheme: dark) {
  :root { --bg: #131315; --surface: #1c1c1f; --line: #34343a;
          --ink: #f2f2ef; --ink-2: #a8a8a2; --accent: #6ea8ff; --accent-ink: #10101a; --danger: #ff9a92; }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--ink); display: flex; min-height: 100vh;
  align-items: center; justify-content: center; padding: 24px;
  font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
/* The card is the task. Links away from it, like removing an account or going
   back, sit under the card so they do not read as one more field to fill in. */
.page { width: 100%; max-width: 420px; }
/* Black ink on transparent, with the watch screen left as a hole, so the page
   shows through it and inverting flips only the ink. */
.logo { display: block; width: 38px; height: 64px; margin: 0 auto 18px; }
@media (prefers-color-scheme: dark) { .logo { filter: invert(1); } }
main { background: var(--surface); border: 1px solid var(--line);
  border-radius: 14px; padding: 28px; }
footer { margin-top: 16px; text-align: center; }
footer .deploy { margin-top: 22px; display: flex; flex-direction: column;
  align-items: center; gap: 8px; }
footer .deploy img { display: block; }
h1 { margin: 0 0 6px; font-size: 20px; letter-spacing: -0.02em; }
h2 { margin: 22px 0 6px; font-size: 14px; letter-spacing: 0.01em; }
ul { margin: 0 0 18px; padding-left: 20px; color: var(--ink-2); }
li { margin: 3px 0; }
a { color: var(--accent); }
p { color: var(--ink-2); margin: 0 0 18px; }
label { display: block; font-size: 13px; font-weight: 560; color: var(--ink-2); margin-bottom: 6px; }
input { width: 100%; padding: 11px 12px; font: inherit; color: var(--ink); background: var(--bg);
  border: 1px solid var(--line); border-radius: 9px; }
input:focus, select:focus { outline: none; border-color: var(--accent); }
.choice { display: flex; gap: 9px; align-items: flex-start; margin: 14px 0 0; }
.choice input { width: auto; margin-top: 3px; }
.choice span { font-size: 13px; color: var(--ink-2); }
.hint { font-size: 12.5px; color: var(--ink-2); margin: 6px 0 0; }
.choice .hint { display: block; margin: 3px 0 0; }
.danger { background: var(--danger); }
.quiet-button { background: transparent; color: var(--ink-2); border: 1px solid var(--line); }
.ok-note { color: var(--ink); font-weight: 560; }
.choice .hint { display: block; margin: 3px 0 0; }
a.quiet { color: var(--ink-2); font-size: 13px; }
button { width: 100%; margin-top: 16px; padding: 12px; font: inherit; font-weight: 600;
  background: var(--accent); color: var(--accent-ink); border: 0; border-radius: 9px; cursor: pointer; }
.code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 30px;
  letter-spacing: 0.1em; text-align: center; padding: 20px; margin: 4px 0 18px;
  background: var(--bg); border: 1px solid var(--line); border-radius: 10px; }
.who { font-size: 13px; color: var(--ink-2); margin-top: 18px; }
.error { color: var(--danger); }
</style>
</head>
<body><div class="page"><img class="logo" src="/logo.png" alt="" width="38" height="64"><main>${body}</main>${footer ? `<footer>${footer}</footer>` : ''}</div></body>
</html>`;
}

export function loginPage(error) {
  return shell(
    'Pebble atproto broker',
    `<h1>Pebble atproto broker</h1>
<p>Sign in once. Your watch can then post through this broker without ever
holding your password, and one sign-in covers any app on that watch.</p>
${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
<form method="GET" action="/login">
  <label for="handle">Handle or DID</label>
  <input id="handle" name="handle" placeholder="alice.bsky.social" autocapitalize="none"
         autocorrect="off" spellcheck="false" required>

  <label for="collections" style="margin-top:18px">Limit to these collections</label>
  <input id="collections" name="collections" placeholder="app.bsky.feed.post, xyz.statusphere.status"
         autocapitalize="none" autocorrect="off" spellcheck="false">
  <p class="hint">Comma separated. The broker will be allowed to create records
  <em>only</em> in the collections you name here. Leave it empty to allow any
  collection.</p>

  <label class="choice">
    <input type="checkbox" name="spaces" value="1">
    <span>Also allow writing into
      <a href="https://givemesome.space" target="_blank" rel="noopener noreferrer">atproto
      spaces</a>, which stay private.
      <span class="hint">Needs a spaces-compatible server.</span></span>
  </label>

  <button type="submit">Continue</button>
</form>`,
    `<a class="quiet" href="/privacy">Privacy and terms</a>
     <span class="quiet" aria-hidden="true"> &middot; </span>
     <a class="quiet" href="/forget">Remove my account from this broker</a>
     <span class="quiet" aria-hidden="true"> &middot; </span>
     <a class="quiet" href="${SOURCE_URL}">Source</a>
     <div class="deploy">
       <a class="quiet" href="${DEPLOY_URL}">Deploy your own broker</a>
       <a href="${DEPLOY_URL}"><img src="https://deploy.workers.cloudflare.com/button"
          alt="Deploy to Cloudflare" width="140" height="32"></a>
     </div>`
  );
}

export function privacyPage() {
  return shell(
    'Privacy and terms',
    `<h1>Privacy and terms</h1>

<h2>What this is</h2>
<p>This broker holds an AT Protocol OAuth session for a device that cannot hold
one itself. The device asks it to write a record; the broker signs the request
and sends it to your PDS. Access and refresh tokens never leave this server.</p>

<h2>What it stores</h2>
<ul>
  <li>Your OAuth session: access token, refresh token, and the key that binds them.</li>
  <li>One token per paired device.</li>
  <li>While you sign in, a pending login and a sign-in code. Both expire in ten minutes.</li>
  <li>A count of wrong sign-in codes, to limit guessing. It is stored against
      a one-way hash of the address it came from, never the address itself,
      and expires in ten minutes.</li>
</ul>
<p>Your session, device tokens and sign-in codes are encrypted before they are written, with a key held only by this server. The wrong-code count and expiry times are not encrypted, and contain nothing about your account.</p>

<h2>What it does not store</h2>
<p>You sign in at your own provider, so this broker never sees your password.
It does not keep the records you write; those go to your repo. There is no
analytics, no logging of what you publish, and nothing is shared with anyone.</p>

<h2>What it can do</h2>
<p>Within the permissions you grant, this broker can create records in your repo
whenever your device asks, without you being present. Naming collections when
you sign in limits it to exactly those. You can review or revoke the grant at
your account provider at any time.</p>

<h2>Who else is involved</h2>
<p>Cloudflare runs this and stores the encrypted rows. Your PDS and its
authorization server receive the requests. A public identity service is used to
turn a handle into a DID.</p>

<h2>Removing yourself</h2>
<p><a href="/forget">Remove my account</a> revokes this broker's access at your
provider, unpairs every device and deletes the stored session.</p>

<h2>Terms</h2>
<p>Provided as-is, with no warranty and no promise that it keeps running. You
are responsible for what you publish through it. The operator may remove any
account.</p>

${SITE.contact ? `<h2>Contact</h2>
<p><a href="mailto:${escapeHtml(SITE.contact)}">${escapeHtml(SITE.contact)}</a></p>` : ''}`,
    `<a class="quiet" href="/">Back</a>`
  );
}

export function forgetPage(error) {
  return shell(
    'Remove your account',
    `<h1>Remove your account</h1>
<p>This revokes the broker\u2019s access at your account provider, unpairs every
device, and deletes the stored session.</p>
<p>Sign in to prove the account is yours.</p>
${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
<form method="GET" action="/login">
  <input type="hidden" name="forget" value="1">
  <label for="handle">Handle or DID</label>
  <input id="handle" name="handle" placeholder="alice.bsky.social" autocapitalize="none"
         autocorrect="off" spellcheck="false" required>
  <button type="submit" class="danger">Sign in and remove</button>
</form>`,
    `<a class="quiet" href="/">Back</a>`
  );
}

/**
 * The confirmation. Signing in proved the account is yours; this is where you
 * say you meant to delete it. It shows what is stored first, so the decision is
 * made against the real thing.
 */
/** "20 Sep 2026" from an ISO timestamp, or nothing if it is unusable. */
function shortDate(iso) {
  const at = new Date(iso);
  if (isNaN(at.getTime())) return '';
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                  'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  return `${at.getUTCDate()} ${months[at.getUTCMonth()]} ${at.getUTCFullYear()}`;
}

/**
 * The confirmation. Signing in proved the account is yours; this is where you
 * say what to remove. Devices are listed by name, and each can go
 * on its own without giving up the account.
 *
 * Checkbox values are positions in the ticket's list, never device tokens: a
 * device token is a live credential and does not belong in page source.
 */
export function confirmRemovalPage(handle, devices, token, notice) {
  const list = devices.length
    ? `<h2>Signed-in devices</h2>
<form method="POST" action="/forget/devices">
  <input type="hidden" name="token" value="${escapeHtml(token)}">
${devices.map((d, i) => `  <label class="choice">
    <input type="checkbox" name="device" value="${i}">
    <span><b>${escapeHtml(d.label)}</b>${d.createdAt
      ? `<span class="hint">paired ${escapeHtml(shortDate(d.createdAt))}</span>` : ''}</span>
  </label>`).join('\n')}
  <button type="submit" class="quiet-button">Remove selected devices</button>
</form>
<p class="hint">Removing a device stops that watch posting. Your account stays.</p>`
    : `<p>No device is signed in right now, but this broker still holds your
sign-in.</p>`;

  return shell(
    'Remove your account',
    `<h1>Remove ${escapeHtml(handle)}?</h1>
${notice ? `<p class="ok-note">${escapeHtml(notice)}</p>` : ''}
${list}

<h2>Or remove everything</h2>
<p>This revokes the broker\u2019s access at your account provider, unpairs every
device and deletes the stored session.</p>
<form method="POST" action="/forget">
  <input type="hidden" name="token" value="${escapeHtml(token)}">
  <button type="submit" class="danger">Remove my account</button>
</form>
<form method="POST" action="/forget/cancel">
  <input type="hidden" name="token" value="${escapeHtml(token)}">
  <button type="submit" class="quiet-button">Keep my account</button>
</form>`
  );
}

/**
 * Signed in, proved it, and there was nothing here. Shown instead of a
 * destructive button for something that does not exist.
 */
export function nothingToRemovePage(handle, outcome) {
  const handed = outcome && outcome.revoked
    ? 'The sign-in you just made has been revoked, so this broker has no access to your account.'
    : 'You can remove this app from your account settings at your provider.';
  return shell(
    'Nothing to remove',
    `<h1>Nothing to remove</h1>
<p>${escapeHtml(handle)} is not on this broker. There is no stored sign-in and
no watch signed in.</p>
<p class="hint">${escapeHtml(handed)}</p>`,
    `<a class="quiet" href="/">Back</a>`
  );
}

export function forgottenPage(handle, devicesRemoved, outcome) {
  const revoked = outcome && outcome.nothing
    ? 'There was no stored session here to revoke.'
    : outcome && outcome.revoked
      ? 'Access was revoked at your account provider.'
      : `The stored session was deleted, but revoking at your provider did not complete${
          outcome && outcome.reason ? ` (${escapeHtml(outcome.reason)})` : ''
        }. You can remove this app from your account settings there.`;
  return shell(
    'Removed',
    `<h1>Removed</h1>
<p>${escapeHtml(handle)} is no longer on this broker.
${devicesRemoved === 1 ? 'One watch was' : `${escapeHtml(String(devicesRemoved))} watches were`} signed out.</p>
<p class="hint">${revoked}</p>`,
    `<a class="quiet" href="/">Back</a>`
  );
}

export function pairedPage(code, handle) {
  return shell(
    'Sign-in code',
    `<h1>Your sign-in code</h1>
<p>Enter this in the settings for the app you are setting up. It expires in
ten minutes and can be used once.</p>
<div class="code">${escapeHtml(code)}</div>
<p class="who">Signed in as ${escapeHtml(handle)}</p>`
  );
}

export function errorPage(message) {
  return shell(
    'Something went wrong',
    `<h1>Something went wrong</h1><p class="error">${escapeHtml(message)}</p>`,
    `<a class="quiet" href="/">Start again</a>`
  );
}

export function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]
  );
}
