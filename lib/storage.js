'use strict';
const fs = require('fs');
const crypto = require('crypto');

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// Returns `fallback` only when the file does not exist. A file that exists but cannot be
// parsed is an error: silently treating it as empty would let the next save overwrite
// (or, for users.json, re-open first-run setup to the next visitor).
function readJson(file, fallback) {
  let raw;
  try { raw = fs.readFileSync(file, 'utf8'); }
  catch (e) { if (e.code === 'ENOENT') return fallback; throw e; }
  try { return JSON.parse(raw); }
  catch (e) { throw new Error(`Corrupt JSON in ${file}: ${e.message}`); }
}

// Write to a temp file in the same directory, fsync, then rename over the target so a
// crash mid-write can never leave a truncated file. Optionally keep the previous version as <file>.bak.
function writeFileAtomic(file, content, { mode = 0o600, backup = false } = {}) {
  const tmp = `${file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  const fd = fs.openSync(tmp, 'w', mode);
  try { fs.writeSync(fd, content); fs.fsyncSync(fd); }
  catch (e) { fs.closeSync(fd); try { fs.unlinkSync(tmp); } catch {} throw e; }
  fs.closeSync(fd);
  if (backup && fs.existsSync(file)) { try { fs.copyFileSync(file, file + '.bak'); } catch {} }
  fs.renameSync(tmp, file);
}

function writeJsonAtomic(file, value, opts) {
  writeFileAtomic(file, JSON.stringify(value, null, 2), opts);
}

module.exports = { HttpError, readJson, writeFileAtomic, writeJsonAtomic };
