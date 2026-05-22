const express  = require('express');
const multer   = require('multer');
const session  = require('express-session');
const bcrypt   = require('bcryptjs');
const { XMLParser } = require('fast-xml-parser');
const fs   = require('fs');
const path = require('path');

const app       = express();
const PORT      = process.env.PORT     || 3000;
const DATA_DIR  = process.env.DATA_DIR || '/data';
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSION_SECRET = process.env.SESSION_SECRET || 'xlights-change-this-secret';

app.use(express.json({ limit: '50mb' }));
app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000, httpOnly: true }
}));
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ── Persistence ───────────────────────────────────────────────────────────────
function dataFile(username) {
  return path.join(DATA_DIR, `show-data-${username}.json`);
}
function loadData(username) {
  const file = dataFile(username);
  if (fs.existsSync(file)) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch {}
  }
  return { show: {}, controllers: [], models: [], groups: [], wiring: {} };
}
function saveData(data, username) {
  fs.writeFileSync(dataFile(username), JSON.stringify(data, null, 2), 'utf8');
}
function loadUsers() {
  if (fs.existsSync(USERS_FILE)) {
    try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch {}
  }
  return [];
}
function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

// ── Auth middleware ────────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session.user) return next();
  res.status(401).json({ error: 'Unauthorized' });
}
function requireAdmin(req, res, next) {
  if (req.session.user?.role === 'admin') return next();
  res.status(403).json({ error: 'Forbidden' });
}

// ── Auth routes ───────────────────────────────────────────────────────────────
app.get('/api/auth/needs-setup', (_req, res) => {
  res.json({ needsSetup: loadUsers().length === 0 });
});

app.post('/api/auth/setup', async (req, res) => {
  if (loadUsers().length > 0) return res.status(400).json({ error: 'Setup already complete' });
  const { username, password } = req.body;
  if (!username || !password || password.length < 6)
    return res.status(400).json({ error: 'Username and password (min 6 chars) required' });
  const passwordHash = await bcrypt.hash(password, 10);
  const users = [{ username, passwordHash, role: 'admin' }];
  saveUsers(users);
  req.session.user = { username, role: 'admin' };
  res.json({ success: true, user: req.session.user });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const user  = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok)  return res.status(401).json({ error: 'Invalid username or password' });
  req.session.user = { username: user.username, role: user.role };
  res.json({ success: true, user: req.session.user });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

app.get('/api/auth/me', (req, res) => {
  if (req.session.user) res.json(req.session.user);
  else res.status(401).json({ error: 'Not authenticated' });
});

// ── User management (admin) ───────────────────────────────────────────────────
app.get('/api/users', requireAuth, requireAdmin, (_req, res) => {
  res.json(loadUsers().map(u => ({ username: u.username, role: u.role })));
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || password.length < 6)
    return res.status(400).json({ error: 'Username and password (min 6 chars) required' });
  const users = loadUsers();
  if (users.find(u => u.username === username))
    return res.status(400).json({ error: 'Username already exists' });
  users.push({ username, passwordHash: await bcrypt.hash(password, 10), role: role || 'user' });
  saveUsers(users);
  res.json({ success: true });
});

app.delete('/api/users/:username', requireAuth, requireAdmin, (req, res) => {
  if (req.params.username === req.session.user.username)
    return res.status(400).json({ error: 'Cannot delete your own account' });
  saveUsers(loadUsers().filter(u => u.username !== req.params.username));
  res.json({ success: true });
});

app.put('/api/users/:username/password', requireAuth, async (req, res) => {
  const target = req.params.username;
  if (req.session.user.role !== 'admin' && req.session.user.username !== target)
    return res.status(403).json({ error: 'Forbidden' });
  const { password } = req.body;
  if (!password || password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  const users = loadUsers();
  const user  = users.find(u => u.username === target);
  if (!user) return res.status(404).json({ error: 'User not found' });
  user.passwordHash = await bcrypt.hash(password, 10);
  saveUsers(users);
  res.json({ success: true });
});

// ── XML Parsers ───────────────────────────────────────────────────────────────
function parseNetworks(xml) {
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_',
    isArray: n => n === 'Controller' });
  const net = (parser.parse(xml)).Networks || {};
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

function parseRgbEffects(xml) {
  const parser = new XMLParser({
    ignoreAttributes: false, attributeNamePrefix: '@_',
    isArray: n => ['model','subModel','alias','modelGroup','faceInfo'].includes(n),
  });
  const xrgb   = (parser.parse(xml)).xrgb || {};
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
app.get('/api/data', requireAuth, (req, res) => res.json(loadData(req.session.user.username)));

app.post('/api/import', requireAuth, upload.fields([
  { name:'networks', maxCount:1 }, { name:'rgbeffects', maxCount:1 }
]), (req, res) => {
  try {
    const u = req.session.user.username;
    const current = loadData(u);
    if (req.files?.networks)   current.controllers = parseNetworks(req.files.networks[0].buffer.toString('utf8'));
    if (req.files?.rgbeffects) {
      const { models, groups } = parseRgbEffects(req.files.rgbeffects[0].buffer.toString('utf8'));
      current.models = models; current.groups = groups;
    }
    if (!current.wiring) current.wiring = {};
    saveData(current, u);
    res.json({ success:true, data:current });
  } catch(e) { console.error(e); res.status(500).json({ error:e.message }); }
});

app.get('/api/wiring',                requireAuth, (req,res) => res.json(loadData(req.session.user.username).wiring||{}));
app.put('/api/wiring/:modelName',     requireAuth, (req,res) => {
  const u = req.session.user.username;
  const data = loadData(u); if (!data.wiring) data.wiring={};
  data.wiring[decodeURIComponent(req.params.modelName)] = req.body;
  saveData(data, u); res.json({ success:true });
});
app.delete('/api/wiring/:modelName',  requireAuth, (req,res) => {
  const u = req.session.user.username;
  const data = loadData(u); if (data.wiring) delete data.wiring[decodeURIComponent(req.params.modelName)];
  saveData(data, u); res.json({ success:true });
});
app.put('/api/show', requireAuth, (req,res) => {
  const u = req.session.user.username;
  const data = loadData(u); data.show = { ...data.show, ...req.body };
  saveData(data, u); res.json({ success:true });
});

app.listen(PORT, () => console.log(`xLights Reference running on :${PORT}`));
