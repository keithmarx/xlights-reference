'use strict';
const nodemailer = require('nodemailer');

// SMTP settings come from the environment (never from the repo or the UI):
//   SMTP_HOST, SMTP_PORT (587), SMTP_SECURE ("true" for implicit TLS on 465), SMTP_USER, SMTP_PASS,
//   MAIL_FROM  e.g. "xLights Reference <noreply@keithmarx.com>",  APP_URL e.g. https://xlights.keithmarx.com
// SMTP_HOST=json is a test mode: messages are built but not sent, and kept in `outbox`.
const outbox = [];
let transport = null;

function configured() {
  return !!(process.env.SMTP_HOST && process.env.MAIL_FROM && process.env.APP_URL);
}

function getTransport() {
  if (transport) return transport;
  if (process.env.SMTP_HOST === 'json') {
    transport = nodemailer.createTransport({ jsonTransport: true });
  } else {
    const port = Number(process.env.SMTP_PORT || 587);
    transport = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port,
      secure: process.env.SMTP_SECURE ? process.env.SMTP_SECURE === 'true' : port === 465,
      requireTLS: port !== 465 && process.env.SMTP_REQUIRE_TLS !== 'false',  // refuse to send credentials/links in clear text
      auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS || '' } : undefined,
      connectionTimeout: 10000, greetingTimeout: 10000, socketTimeout: 20000,
    });
  }
  return transport;
}

// Links in emails are built only from APP_URL, never from the request's Host header
// (a forged Host on "forgot password" would otherwise let an attacker aim the reset link at their own site).
function appLink(hash) {
  return `${process.env.APP_URL.replace(/\/+$/, '')}/#${hash}`;
}

async function send({ to, subject, text }) {
  if (!configured()) throw new Error('Mail is not configured');
  const info = await getTransport().sendMail({ from: process.env.MAIL_FROM, to, subject, text });
  if (process.env.SMTP_HOST === 'json') outbox.push({ to, subject, text });
  return info;
}

module.exports = { configured, send, appLink, outbox };
