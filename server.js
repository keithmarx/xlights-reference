'use strict';
const express   = require('express');
const multer    = require('multer');
const session   = require('express-session');
const bcrypt    = require('bcryptjs');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto    = require('crypto');
const { XMLParser } = require('fast-xml-parser');
const fs   = require('fs');
const path = require('path');
const { HttpError, readJson, writeFileAtomic, writeJsonAtomic } = require('./lib/storage');
const FileSessionStore = require('./lib/session-store');

const app        = express();
const PORT       = process.env.PORT     || 3000;
const DATA_DIR   = process.env.DATA_DIR || '/data';
const USERS_FILE = path.join(DATA_DIR, 'users.json');

const BCRYPT_COST   = 12;
const MIN_PASSWORD  = 10;
const MAX_PASSWORD  = 72;                       // bcrypt only uses the first 72 bytes
const USERNAME_RE   = /^[A-Za-z0-9_-]{3,32}$/;  // rule for newly created accounts
const SAFE_NAME_RE  = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/; // anything used to build a file name
const UNSAFE_KEYS   = new Set(['__proto__', 'constructor', 'prototype']);
const ROLES         = ['user', 'admin'];

fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Session secret ────────────────────────────────────────────────────────────
// SESSION_SECRET wins if set to something real; otherwise generate a random secret once and
// keep it in the data volume (never fall back to a secret that is public in the source).
function resolveSessionSecret() {
  const env = process.env.SESSION_SECRET;
  if (env && env !== 'xlights-change-this-secret' && env.length >= 16) return env;
  if (env) console.warn('SESSION_SECRET is missing, too short (<16) or the old default; using a generated secret instead.');
  const file = path.join(DATA_DIR, '.session-secret');
  try {
    const existing = fs.readFileSync(file, 'utf8').trim();
    if (existing.length >= 32) return existing;
  } catch (e) { if (e.code !== 'ENOENT') throw e; }
  const secret = crypto.randomBytes(48).toString('hex');
  writeFileAtomic(file, secret, { mode: 0o600 });
  return secret;
}

// ── App setup ─────────────────────────────────────────────────────────────────
// Number of reverse proxies in front of the app (Apache in the bundled vhost = 1).
const tp = process.env.TRUST_PROXY;
app.set('trust proxy', tp === undefined ? 1 : /^\d+$/.test(tp) ? Number(tp) : tp === 'true' ? true : tp === 'false' ? false : tp);

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"],
      // The UI uses inline <script>/<style> and inline event handlers; moving them out is a follow-up.
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"],
    },
  },
}));

app.get('/healthz', (_req, res) => res.json({ ok: true }));

app.use('/api/bulk', express.json({ limit: '5mb' }));   // bulk fill can be large; everything else is small
app.use(express.json({ limit: '1mb' }));
app.use(session({
  name: 'xlights.sid',
  secret: resolveSessionSecret(),
  store: new FileSessionStore(path.join(DATA_DIR, 'sessions')),
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    // 'auto' = Secure when the request arrived over HTTPS (needs X-Forwarded-Proto from the proxy).
    secure: process.env.COOKIE_SECURE === 'true' ? true : process.env.COOKIE_SECURE === 'false' ? false : 'auto',
  },
}));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024, files: 2 } });
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const limiterOpts = { standardHeaders: true, legacyHeaders: false };
const loginLimiter = rateLimit({ ...limiterOpts, windowMs: 15 * 60 * 1000, limit: 10, skipSuccessfulRequests: true,
  message: { error: 'Too many attempts. Try again in a few minutes.' } });
const setupLimiter = rateLimit({ ...limiterOpts, windowMs: 60 * 60 * 1000, limit: 10,
  message: { error: 'Too many attempts. Try again later.' } });
const sensitiveLimiter = rateLimit({ ...limiterOpts, windowMs: 15 * 60 * 1000, limit: 30,
  message: { error: 'Too many requests. Try again in a few minutes.' } });

// ── Persistence ───────────────────────────────────────────────────────────────
// Saves are synchronous on purpose: with no await between load and save, a handler's
// read-modify-write cannot interleave with another request in this single process.
function dataFile(username) {
  if (!SAFE_NAME_RE.test(String(username))) throw new Error('Unsafe username for file path');
  return path.join(DATA_DIR, `show-data-${username}.json`);
}
function emptyData() { return { show: {}, controllers: [], models: [], groups: [], wiring: {}, lrBoards: {} }; }
function loadData(username) { return readJson(dataFile(username), null) || emptyData(); }
function saveData(data, username) { writeJsonAtomic(dataFile(username), data, { backup: true }); }
function loadUsers() { return readJson(USERS_FILE, []); }
function saveUsers(users) { writeJsonAtomic(USERS_FILE, users); }

// ── Users & validation ────────────────────────────────────────────────────────
// Usernames are matched case-insensitively (exact match preferred for legacy accounts that differ only by case).
function findUser(users, name) {
  const n = String(name || '');
  return users.find(u => u.username === n) || users.find(u => u.username.toLowerCase() === n.toLowerCase());
}
function validateNewUsername(username, users) {
  if (typeof username !== 'string' || !USERNAME_RE.test(username))
    throw new HttpError(400, 'Username must be 3–32 characters: letters, numbers, "_" or "-"');
  if (users.some(u => u.username.toLowerCase() === username.toLowerCase()))
    throw new HttpError(400, 'Username already exists');
}
function validatePassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD)
    throw new HttpError(400, `Password must be at least ${MIN_PASSWORD} characters`);
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD)
    throw new HttpError(400, `Password must be at most ${MAX_PASSWORD} bytes`);
}
const DUMMY_HASH = bcrypt.hashSync('timing-equalizer', BCRYPT_COST); // so unknown usernames cost the same as wrong passwords

// ── Sessions / auth middleware ────────────────────────────────────────────────
function startSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate(err => {                       // new session id on login (prevents fixation)
      if (err) return reject(err);
      req.session.user = { username: user.username, role: user.role, v: user.sessionVersion || 0 };
      req.session.save(err2 => (err2 ? reject(err2) : resolve()));
    });
  });
}
// The session only stores who logged in; the account itself is re-read each request so deleted users,
// role changes and password changes/resets take effect immediately.
function currentUser(req) {
  const s = req.session && req.session.user;
  if (!s) return null;
  const rec = loadUsers().find(u => u.username === s.username);
  if (!rec || (rec.sessionVersion || 0) !== (s.v || 0)) return null;
  return rec;
}
function requireAuth(req, res, next) {
  const rec = currentUser(req);
  if (!rec) {
    if (req.session && req.session.user) return req.session.destroy(() => res.status(401).json({ error: 'Unauthorized' }));
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.user = rec;
  next();
}
function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  res.status(403).json({ error: 'Forbidden' });
}
const publicUser = u => ({ username: u.username, role: u.role });

// ── Auth routes ───────────────────────────────────────────────────────────────
const SETUP_TOKEN = process.env.ADMIN_SETUP_TOKEN || '';
function sameToken(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

app.get('/api/auth/needs-setup', wrap((_req, res) => {
  const needsSetup = loadUsers().length === 0;
  res.json({ needsSetup, requiresToken: needsSetup && !!SETUP_TOKEN });
}));

app.post('/api/auth/setup', setupLimiter, wrap(async (req, res) => {
  if (loadUsers().length > 0) throw new HttpError(400, 'Setup already complete');
  const { username, password, setupToken } = req.body || {};
  if (SETUP_TOKEN && !sameToken(setupToken || '', SETUP_TOKEN)) throw new HttpError(403, 'Invalid setup token');
  validateNewUsername(username, []);
  validatePassword(password);
  const passwordHash = await bcrypt.hash(password, BCRYPT_COST);
  if (loadUsers().length > 0) throw new HttpError(400, 'Setup already complete'); // re-check after the await
  const user = { username, passwordHash, role: 'admin', sessionVersion: 0 };
  saveUsers([user]);
  await startSession(req, user);
  res.json({ success: true, user: publicUser(user) });
}));

app.post('/api/auth/login', loginLimiter, wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || password.length > 1000)
    throw new HttpError(400, 'Username and password required');
  const user = findUser(loadUsers(), username);
  const ok = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);
  if (!user || !ok) throw new HttpError(401, 'Invalid username or password');
  let fresh = user;
  if (bcrypt.getRounds(user.passwordHash) < BCRYPT_COST) {      // upgrade old cost-10 hashes transparently
    const newHash = await bcrypt.hash(password, BCRYPT_COST);
    const users = loadUsers();
    const rec = users.find(u => u.username === user.username);
    if (rec) { rec.passwordHash = newHash; saveUsers(users); fresh = rec; }
  }
  await startSession(req, fresh);
  res.json({ success: true, user: publicUser(fresh) });
}));

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => { res.clearCookie('xlights.sid'); res.json({ success: true }); });
});

app.get('/api/auth/me', wrap((req, res) => {
  const rec = currentUser(req);
  if (rec) res.json(publicUser(rec));
  else res.status(401).json({ error: 'Not authenticated' });
}));

// ── User management ───────────────────────────────────────────────────────────
app.get('/api/users', requireAuth, requireAdmin, (_req, res) => {
  res.json(loadUsers().map(publicUser));
});

app.post('/api/users', requireAuth, requireAdmin, sensitiveLimiter, wrap(async (req, res) => {
  const { username, password, role } = req.body || {};
  if (role !== undefined && !ROLES.includes(role)) throw new HttpError(400, 'Invalid role');
  validateNewUsername(username, loadUsers());
  validatePassword(password);
  const passwordHash = await bcrypt.hash(password, BCRYPT_COST);
  const users = loadUsers();                                   // re-load after the await
  validateNewUsername(username, users);
  users.push({ username, passwordHash, role: role || 'user', sessionVersion: 0 });
  saveUsers(users);
  res.json({ success: true });
}));

app.delete('/api/users/:username', requireAuth, requireAdmin, (req, res) => {
  const users = loadUsers();
  const target = users.find(u => u.username === req.params.username);
  if (!target) throw new HttpError(404, 'User not found');
  if (target.username === req.user.username) throw new HttpError(400, 'Cannot delete your own account');
  saveUsers(users.filter(u => u !== target));
  // Keep (don't delete) the show data, but move it aside so a newly created user with the same
  // name can't inherit it. The user's sessions die because requireAuth re-checks the account.
  if (SAFE_NAME_RE.test(target.username)) {
    const file = dataFile(target.username);
    if (fs.existsSync(file)) fs.renameSync(file, `${file}.deleted-${Date.now()}`);
  }
  res.json({ success: true });
});

app.put('/api/users/:username/password', requireAuth, sensitiveLimiter, wrap(async (req, res) => {
  const target = req.params.username;
  const self = req.user.username === target;
  if (!self && req.user.role !== 'admin') throw new HttpError(403, 'Forbidden');
  const { password, currentPassword } = req.body || {};
  validatePassword(password);
  if (self && !(typeof currentPassword === 'string' && await bcrypt.compare(currentPassword, req.user.passwordHash)))
    throw new HttpError(403, 'Current password is incorrect');
  const hash = await bcrypt.hash(password, BCRYPT_COST);
  const users = loadUsers();
  const user = users.find(u => u.username === target);
  if (!user) throw new HttpError(404, 'User not found');
  user.passwordHash = hash;
  user.sessionVersion = (user.sessionVersion || 0) + 1;       // logs the user out everywhere else
  saveUsers(users);
  if (self) req.session.user.v = user.sessionVersion;         // ...but keep this session
  res.json({ success: true });
}));

// ── XML Parsers ───────────────────────────────────────────────────────────────
function parseXml(parser, xml) {
  try { return parser.parse(xml) || {}; }
  catch { throw new HttpError(400, 'Could not parse the uploaded XML file'); }
}

function parseNetworks(xml) {
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_',
    isArray: n => n === 'Controller' });
  const net = parseXml(parser, xml).Networks;
  if (!net) throw new HttpError(400, 'That does not look like an xlights_networks.xml file');
  return (net.Controller || []).map(c => {
    const netEl = Array.isArray(c.network) ? c.network[0] : c.network;
    return {
      name:        c['@_Name']        || '',
      ip:          c['@_IP']          || '',
      protocol:    c['@_Protocol']    || '',
      description: c['@_Description'] || '',
      vendor:      c['@_Vendor']      || '',
      model:       c['@_Model']       || '',
      state:       c['@_ActiveState'] || 'Active',
      maxChannels: netEl ? parseInt(netEl['@_MaxChannels'] || 0) : 0,
    };
  });
}

// Custom models without a PixelCount attribute store their layout in CustomModelCompressed
// ("node,row,col;...") or the legacy CustomModel grid. The node count is the number of distinct node numbers.
function countCustomNodes(m) {
  const set = new Set();
  const comp = m['@_CustomModelCompressed'];
  if (comp) {
    String(comp).split(';').forEach(e => { const n = parseInt(e.split(',')[0]); if (n > 0) set.add(n); });
  } else if (m['@_CustomModel']) {
    String(m['@_CustomModel']).split(/[;,|]/).forEach(t => { const n = parseInt(t); if (n > 0) set.add(n); });
  }
  return set.size;
}

function parseRgbEffects(xml) {
  const parser = new XMLParser({
    ignoreAttributes: false, attributeNamePrefix: '@_',
    isArray: n => ['model','subModel','alias','modelGroup','faceInfo'].includes(n),
  });
  const xrgb   = parseXml(parser, xml).xrgb;
  if (!xrgb) throw new HttpError(400, 'That does not look like an xlights_rgbeffects.xml file');
  const models = [], groups = [];

  (xrgb?.models?.model || []).forEach(m => {
    const cc   = m.ControllerConnection;
    const subs = (m.subModel || []).map(s => s['@_name']).filter(Boolean);
    const aliasList = (m.Aliases?.alias || []).map(a => a['@_name']).filter(Boolean);
    const displayAs = m['@_DisplayAs'] || '';

    let nodes = 0;
    if (m['@_PixelCount'])                nodes = parseInt(m['@_PixelCount']);
    else if (displayAs==='DmxFloodlight') nodes = parseInt(m['@_DmxChannelCount'] || 3);
    else if (m['@_NodesPerArch']  && m['@_NumArches'])  nodes = parseInt(m['@_NodesPerArch'])  * parseInt(m['@_NumArches']);
    else if (m['@_NodesPerCane']  && m['@_NumCanes'])   nodes = parseInt(m['@_NodesPerCane'])  * parseInt(m['@_NumCanes']);
    else if (m['@_NodesPerString']) nodes = parseInt(m['@_NodesPerString']) * parseInt(m['@_NumStrings'] || 1);
    else if (displayAs==='Custom')       nodes = countCustomNodes(m);

    const channels  = displayAs==='DmxFloodlight' ? parseInt(m['@_DmxChannelCount']||3) : nodes*3;
    const startCh   = m['@_StartChannel'] || '';
    const isRel     = startCh.startsWith('!');
    const ctrlRelCh = isRel ? parseInt(startCh.split(':')[1]||1) : null;
    const absStartCh = isRel ? null : (parseInt(startCh)||0);

    const dim = m.dimmingCurve;
    let brightness = null;
    if (dim) { const a = Array.isArray(dim.all)?dim.all[0]:dim.all; if (a) brightness = parseInt(a['@_brightness']); }

    models.push({
      name: m['@_name']||'', type: displayAs,
      startChannel: startCh, controller: m['@_Controller']||'No Controller',
      port: cc ? parseInt(cc['@_Port']) : null,
      protocol: cc ? (cc['@_Protocol']||'') : '',
      nodes, channels, absStartCh, ctrlRelCh,
      endCh:    absStartCh ? absStartCh+channels-1 : null,
      ctrlEndCh: ctrlRelCh ? ctrlRelCh+channels-1 : null,
      stringType: m['@_StringType']||'RGB Nodes',
      subModels: subs, aliases: aliasList, brightness,
      hasFace: (m.faceInfo||[]).length>0, groups:[],
    });
  });

  const mgList = xrgb?.modelGroups?.modelGroup || [];
  (Array.isArray(mgList)?mgList:[mgList]).forEach(g => {
    if (!g||!g['@_name']) return;
    const aliasList = (g.Aliases?.alias||[]).map(a=>a['@_name']).filter(Boolean);
    groups.push({ name:g['@_name'], members:(g['@_models']||'').split(',').map(s=>s.trim()).filter(Boolean), aliases:aliasList });
  });

  groups.forEach(grp => grp.members.forEach(mname => {
    const m = models.find(x => x.name === mname.split('/')[0]);
    if (m && !m.groups.includes(grp.name)) m.groups.push(grp.name);
  }));

  return { models, groups };
}

// ── Protected API routes ──────────────────────────────────────────────────────
const WIRING_FIELDS = ['color','connector','location','route','power','lrUnit','lrPort','repUnit','repPort','notes'];
const today = () => new Date().toISOString().slice(0, 10);
const clip  = (v, n) => String(v ?? '').trim().slice(0, n);

// Keys that address objects by user-supplied name (model / controller names).
function checkKey(name) {
  if (typeof name !== 'string' || !name || name.length > 200 || UNSAFE_KEYS.has(name))
    throw new HttpError(400, 'Invalid name');
  return name;
}
function sanitizeWiring(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw new HttpError(400, 'Invalid body');
  const out = {};
  WIRING_FIELDS.forEach(f => { out[f] = clip(body[f], 2000); });
  out.updatedAt = today();
  return out;
}
function sanitizeBoards(list) {
  if (!Array.isArray(list) || list.length > 200) throw new HttpError(400, 'Invalid LR board list');
  return list
    .map(b => ({
      unit: parseInt(b && b.unit, 10),
      label: clip(b && b.label, 200),
      channels: Array.from({ length: 32 }, (_, i) => clip(((b && b.channels) || [])[i], 200)),
    }))
    .filter(b => Number.isFinite(b.unit))
    .sort((a, b) => a.unit - b.unit);
}

app.get('/api/data', requireAuth, (req, res) => res.json(loadData(req.user.username)));

app.post('/api/import', requireAuth, upload.fields([
  { name: 'networks', maxCount: 1 }, { name: 'rgbeffects', maxCount: 1 }
]), (req, res) => {
  const u = req.user.username;
  const current = loadData(u);
  // Parse everything first so a bad second file doesn't leave a half-applied import.
  const net = req.files?.networks   ? parseNetworks(req.files.networks[0].buffer.toString('utf8')) : null;
  const rgb = req.files?.rgbeffects ? parseRgbEffects(req.files.rgbeffects[0].buffer.toString('utf8')) : null;
  if (!net && !rgb) throw new HttpError(400, 'No files uploaded');
  if (net) current.controllers = net;
  if (rgb) { current.models = rgb.models; current.groups = rgb.groups; }
  if (!current.wiring) current.wiring = {};
  saveData(current, u);
  res.json({ success: true, data: current });
});

// NOTE: Express has already URL-decoded req.params, so do not decodeURIComponent again
// (a model named "50%" used to throw URIError, and "a%41" was silently renamed).
app.get('/api/wiring', requireAuth, (req, res) => res.json(loadData(req.user.username).wiring || {}));
app.put('/api/wiring/:modelName', requireAuth, (req, res) => {
  const name = checkKey(req.params.modelName);
  const u = req.user.username;
  const data = loadData(u); if (!data.wiring) data.wiring = {};
  data.wiring[name] = sanitizeWiring(req.body);
  saveData(data, u);
  res.json({ success: true });
});
app.delete('/api/wiring/:modelName', requireAuth, (req, res) => {
  const name = checkKey(req.params.modelName);
  const u = req.user.username;
  const data = loadData(u);
  if (data.wiring) delete data.wiring[name];
  saveData(data, u);
  res.json({ success: true });
});

// Bulk fill: merge wiring fields per model and replace LR boards per controller in one save.
app.post('/api/bulk', requireAuth, (req, res) => {
  const u = req.user.username;
  const data = loadData(u);
  if (!data.wiring)   data.wiring   = {};
  if (!data.lrBoards) data.lrBoards = {};
  const { wiring, lrBoards } = req.body || {};
  let models = 0, boards = 0;
  if (wiring && typeof wiring === 'object') {
    for (const [name, patch] of Object.entries(wiring)) {
      if (UNSAFE_KEYS.has(name) || name.length > 200 || !patch || typeof patch !== 'object') continue;
      const cur = data.wiring[name] || {};
      WIRING_FIELDS.forEach(f => {
        const v = patch[f];
        if (v !== undefined && v !== null && String(v).trim() !== '') cur[f] = clip(v, 2000);
      });
      cur.updatedAt = today();
      data.wiring[name] = cur; models++;
    }
  }
  if (lrBoards && typeof lrBoards === 'object') {
    for (const [ctrl, list] of Object.entries(lrBoards)) {
      if (UNSAFE_KEYS.has(ctrl) || ctrl.length > 200 || !Array.isArray(list)) continue;
      data.lrBoards[ctrl] = sanitizeBoards(list);
      boards++;
    }
  }
  saveData(data, u);
  res.json({ success: true, models, boards, wiring: data.wiring, lrBoards: data.lrBoards });
});

app.put('/api/show', requireAuth, (req, res) => {
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const u = req.user.username;
  const data = loadData(u);
  data.show = data.show || {};
  ['name', 'xlightsVersion'].forEach(k => { if (body[k] !== undefined) data.show[k] = clip(body[k], 200); });
  saveData(data, u);
  res.json({ success: true });
});

app.get('/api/lrboards/:ctrl', requireAuth, (req, res) => {
  const data = loadData(req.user.username);
  res.json((data.lrBoards || {})[checkKey(req.params.ctrl)] || []);
});
app.put('/api/lrboards/:ctrl', requireAuth, (req, res) => {
  const ctrl = checkKey(req.params.ctrl);
  const u = req.user.username;
  const data = loadData(u);
  if (!data.lrBoards) data.lrBoards = {};
  data.lrBoards[ctrl] = sanitizeBoards(req.body);
  saveData(data, u);
  res.json({ success: true });
});

// ── Errors ────────────────────────────────────────────────────────────────────
app.use('/api', (_req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, _req, res, next) => {
  if (res.headersSent) return next(err);
  if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
  if (err.type === 'entity.too.large' || err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: 'Upload too large' });
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  if (err instanceof multer.MulterError) return res.status(400).json({ error: 'Invalid upload' });
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });   // never leak internals (paths, parser messages) to clients
});

app.listen(PORT, () => console.log(`xLights Reference running on :${PORT}`));
