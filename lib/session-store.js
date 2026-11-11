'use strict';
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const { writeFileAtomic } = require('./storage');

const SID_RE = /^[A-Za-z0-9_-]{16,128}$/;

// Minimal file-backed session store: one JSON file per session under `dir`, so logins
// survive container restarts (the default MemoryStore loses them and leaks memory).
class FileSessionStore extends session.Store {
  constructor(dir, { pruneIntervalMs = 60 * 60 * 1000 } = {}) {
    super();
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    this.prune();
    this.timer = setInterval(() => this.prune(), pruneIntervalMs);
    this.timer.unref();
  }

  _file(sid) { return SID_RE.test(String(sid)) ? path.join(this.dir, `${sid}.json`) : null; }

  get(sid, cb) {
    const file = this._file(sid);
    if (!file) return cb(null, null);
    fs.readFile(file, 'utf8', (err, raw) => {
      if (err) return cb(err.code === 'ENOENT' ? null : err, null);
      let sess;
      try { sess = JSON.parse(raw); } catch { return this.destroy(sid, () => cb(null, null)); }
      const exp = sess.cookie && sess.cookie.expires;
      if (exp && new Date(exp).getTime() <= Date.now()) return this.destroy(sid, () => cb(null, null));
      cb(null, sess);
    });
  }

  set(sid, sess, cb = () => {}) {
    const file = this._file(sid);
    if (!file) return cb(new Error('Invalid session id'));
    try { writeFileAtomic(file, JSON.stringify(sess)); cb(null); } catch (e) { cb(e); }
  }

  // Sessions have a fixed lifetime from login (cookie maxAge); no need to rewrite on every request.
  touch(_sid, _sess, cb = () => {}) { cb(null); }

  destroy(sid, cb = () => {}) {
    const file = this._file(sid);
    if (!file) return cb(null);
    fs.unlink(file, err => cb(err && err.code !== 'ENOENT' ? err : null));
  }

  prune() {
    fs.readdir(this.dir, (err, names) => {
      if (err) return;
      for (const name of names) {
        const file = path.join(this.dir, name);
        if (name.endsWith('.tmp')) {
          fs.stat(file, (e, st) => { if (!e && Date.now() - st.mtimeMs > 24 * 3600e3) fs.unlink(file, () => {}); });
        } else if (name.endsWith('.json')) {
          fs.readFile(file, 'utf8', (e, raw) => {
            if (e) return;
            let exp; try { exp = new Date(JSON.parse(raw).cookie.expires).getTime(); } catch { exp = 0; }
            if (!(exp > Date.now())) fs.unlink(file, () => {});
          });
        }
      }
    });
  }
}

module.exports = FileSessionStore;
