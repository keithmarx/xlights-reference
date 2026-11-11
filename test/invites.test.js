'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

const DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'xlights-test-'));
Object.assign(process.env, {
  DATA_DIR, SMTP_HOST: 'json', MAIL_FROM: 'test <noreply@example.test>', APP_URL: 'https://xlights.example.test',
});
const app = require('../server');
const mailer = require('../lib/mailer');

let base, server;
test.before(() => new Promise(r => { server = app.listen(0, '127.0.0.1', () => { base = `http://127.0.0.1:${server.address().port}`; r(); }); }));
test.after(() => { server.close(); fs.rmSync(DATA_DIR, { recursive: true, force: true }); });

// Tiny fetch wrapper with a cookie jar.
function client() {
  let cookie = '';
  return async (method, url, body) => {
    const res = await fetch(base + url, {
      method, headers: { 'Content-Type': 'application/json', ...(cookie ? { Cookie: cookie } : {}) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const set = res.headers.get('set-cookie');
    if (set) cookie = set.split(';')[0];
    return { status: res.status, body: await res.json().catch(() => null) };
  };
}
const tokenFrom = (text, key) => text.match(new RegExp(`#${key}=([A-Za-z0-9_-]+)`))[1];
const waitForMail = async (n) => { for (let i = 0; i < 40 && mailer.outbox.length < n; i++) await new Promise(r => setTimeout(r, 25)); };

const admin = client();
let inviteToken;

test('first-run setup creates an admin with an email', async () => {
  const r = await admin('POST', '/api/auth/setup', { username: 'keith', password: 'correct-horse-1', email: 'Keith@Example.test' });
  assert.equal(r.status, 200);
  assert.equal(r.body.user.email, 'keith@example.test');
});

test('only admins can create invites', async () => {
  assert.equal((await client()('POST', '/api/invites', { email: 'a@b.test' })).status, 401);
});

test('invite rejects bad email, bad role and existing account email', async () => {
  assert.equal((await admin('POST', '/api/invites', { email: 'not-an-email' })).status, 400);
  assert.equal((await admin('POST', '/api/invites', { email: 'x@y.test', role: 'root' })).status, 400);
  assert.equal((await admin('POST', '/api/invites', { email: 'keith@example.test' })).status, 400);
});

test('invite is emailed with a link built from APP_URL, token not returned to the admin', async () => {
  const r = await admin('POST', '/api/invites', { email: 'Friend@Example.test' });
  assert.equal(r.status, 200);
  assert.equal(r.body.emailed, true);
  assert.equal(r.body.link, undefined);
  const mail = mailer.outbox.at(-1);
  assert.equal(mail.to, 'friend@example.test');
  assert.match(mail.text, /https:\/\/xlights\.example\.test\/#invite=/);
  inviteToken = tokenFrom(mail.text, 'invite');
  // only a hash is stored on disk
  assert.ok(!fs.readFileSync(path.join(DATA_DIR, 'invites.json'), 'utf8').includes(inviteToken));
});

test('lookup shows the invited address; garbage tokens fail', async () => {
  const c = client();
  assert.equal((await c('POST', '/api/invites/lookup', { token: inviteToken })).body.email, 'friend@example.test');
  assert.equal((await c('POST', '/api/invites/lookup', { token: 'nope' })).status, 404);
});

test('registration validates, creates the account with the invited role, logs in, and is single-use', async () => {
  const c = client();
  assert.equal((await c('POST', '/api/auth/register', { token: inviteToken, username: '../evil', password: 'long-enough-pw-1' })).status, 400);
  assert.equal((await c('POST', '/api/auth/register', { token: inviteToken, username: 'friend', password: 'short' })).status, 400);
  assert.equal((await c('POST', '/api/auth/register', { token: inviteToken, username: 'KEITH', password: 'long-enough-pw-1' })).status, 400); // taken (case-insensitive)
  const ok = await c('POST', '/api/auth/register', { token: inviteToken, username: 'friend', password: 'long-enough-pw-1' });
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.body.user, { username: 'friend', role: 'user', email: 'friend@example.test' });
  assert.equal((await c('GET', '/api/auth/me')).body.username, 'friend');
  assert.equal((await c('GET', '/api/users')).status, 403);                        // invited as a normal user
  assert.equal((await client()('POST', '/api/auth/register', { token: inviteToken, username: 'friend2', password: 'long-enough-pw-1' })).status, 400); // reused
});

test('a newer invite for the same address replaces the old one; revoke works; expiry is enforced', async () => {
  await admin('POST', '/api/invites', { email: 'new@example.test' });
  const t1 = tokenFrom(mailer.outbox.at(-1).text, 'invite');
  await admin('POST', '/api/invites', { email: 'new@example.test' });
  const t2 = tokenFrom(mailer.outbox.at(-1).text, 'invite');
  const c = client();
  assert.equal((await c('POST', '/api/invites/lookup', { token: t1 })).status, 404);
  assert.equal((await c('POST', '/api/invites/lookup', { token: t2 })).status, 200);

  const list = (await admin('GET', '/api/invites')).body;
  assert.equal(list.length, 1);
  assert.equal(list[0].token, undefined); assert.equal(list[0].tokenHash, undefined);
  assert.equal((await admin('DELETE', `/api/invites/${list[0].id}`)).status, 200);
  assert.equal((await c('POST', '/api/invites/lookup', { token: t2 })).status, 404);

  await admin('POST', '/api/invites', { email: 'late@example.test' });
  const t3 = tokenFrom(mailer.outbox.at(-1).text, 'invite');
  const file = path.join(DATA_DIR, 'invites.json');
  const data = JSON.parse(fs.readFileSync(file, 'utf8')); data.forEach(i => { i.expiresAt = Date.now() - 1000; });
  fs.writeFileSync(file, JSON.stringify(data));
  assert.equal((await c('POST', '/api/invites/lookup', { token: t3 })).status, 404);
});

test('without mail configured, the admin gets the link to pass on', async () => {
  const saved = process.env.SMTP_HOST; delete process.env.SMTP_HOST;
  try {
    const r = await admin('POST', '/api/invites', { email: 'manual@example.test' });
    assert.equal(r.body.emailed, false);
    assert.match(r.body.link, /^https:\/\/xlights\.example\.test\/#invite=[A-Za-z0-9_-]+$/);
  } finally { process.env.SMTP_HOST = saved; }
});

test('forgot password: same answer for unknown and known addresses; reset signs everyone out', async () => {
  const c = client();
  const before = mailer.outbox.length;
  const unknown = await c('POST', '/api/auth/forgot', { email: 'nobody@example.test' });
  const known = await c('POST', '/api/auth/forgot', { email: 'friend@example.test' });
  assert.deepEqual(unknown.body, known.body);
  await waitForMail(before + 1);
  assert.equal(mailer.outbox.length, before + 1);                                  // only the real account got mail
  const mail = mailer.outbox.at(-1);
  assert.equal(mail.to, 'friend@example.test');
  const token = tokenFrom(mail.text, 'reset');

  const friend = client();
  assert.equal((await friend('POST', '/api/auth/login', { username: 'friend', password: 'long-enough-pw-1' })).status, 200);

  assert.equal((await c('POST', '/api/auth/reset', { token, password: 'short' })).status, 400);
  assert.equal((await c('POST', '/api/auth/reset', { token: 'bogus-bogus-bogus-bogus-bogus', password: 'brand-new-pass-22' })).status, 400);
  assert.equal((await c('POST', '/api/auth/reset', { token, password: 'brand-new-pass-22' })).status, 200);
  assert.equal((await c('POST', '/api/auth/reset', { token, password: 'another-new-pass-3' })).status, 400); // single-use

  assert.equal((await friend('GET', '/api/auth/me')).status, 401);                  // old session ended
  assert.equal((await client()('POST', '/api/auth/login', { username: 'friend', password: 'long-enough-pw-1' })).status, 401);
  assert.equal((await client()('POST', '/api/auth/login', { username: 'friend', password: 'brand-new-pass-22' })).status, 200);
});

test('admin can add an email to an existing account; duplicates are refused', async () => {
  assert.equal((await admin('PUT', '/api/users/friend/email', { email: 'keith@example.test' })).status, 400);
  assert.equal((await admin('PUT', '/api/users/friend/email', { email: 'friend2@example.test' })).status, 200);
  assert.equal((await admin('PUT', '/api/users/ghost/email', { email: 'g@example.test' })).status, 404);
});
