'use strict';
const crypto = require('crypto');
const path = require('path');
const { readJson, writeJsonAtomic } = require('./storage');

// One-time tokens (invites, password resets). Only a SHA-256 hash of each token is stored, so a copy of the
// data volume does not hand out usable links. Tokens are 256-bit random, so a plain hash is sufficient.
const hash = t => crypto.createHash('sha256').update(String(t)).digest('hex');

class TokenStore {
  constructor(file) { this.file = file; }

  _load() {
    const now = Date.now();
    return readJson(this.file, []).filter(t => !t.usedAt && t.expiresAt > now);   // drop used/expired on every load
  }
  _save(list) { writeJsonAtomic(this.file, list); }

  // Returns the raw token (shown/sent once, never stored). `replace(entry)` removes older entries for the same subject.
  create(fields, ttlMs, replace) {
    const raw = crypto.randomBytes(32).toString('base64url');
    const list = this._load().filter(t => !(replace && replace(t)));
    list.push({ id: crypto.randomBytes(8).toString('hex'), tokenHash: hash(raw), createdAt: Date.now(), expiresAt: Date.now() + ttlMs, ...fields });
    this._save(list);
    return raw;
  }
  find(raw) {
    if (typeof raw !== 'string' || raw.length < 20 || raw.length > 100) return null;
    const h = hash(raw);
    return this._load().find(t => t.tokenHash === h) || null;
  }
  consume(id) { this._save(this._load().filter(t => t.id !== id)); }   // single use: remove it
  list() { return this._load(); }
  revoke(id) {
    const list = this._load(); const next = list.filter(t => t.id !== id);
    this._save(next); return next.length !== list.length;
  }
}

module.exports = { TokenStore, hash, tokenFile: (dir, name) => path.join(dir, name) };
