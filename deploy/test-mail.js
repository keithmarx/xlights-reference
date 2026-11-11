'use strict';
// Send one test email using the app's real SMTP settings, to check them without sending an invite.
//   docker compose exec xlights-reference node deploy/test-mail.js you@example.com
const mailer = require('../lib/mailer');
const to = process.argv[2];
if (!to) { console.error('Usage: node deploy/test-mail.js <recipient>'); process.exit(2); }
if (!mailer.configured()) {
  console.error('Mail is not configured. Set APP_URL, SMTP_HOST and MAIL_FROM (plus SMTP_USER / SMTP_PASS if your server needs a login) in .env, then recreate the container.');
  process.exit(1);
}
mailer.send({ to, subject: 'xLights Show Reference test email', text: 'If you can read this, outgoing email works.' })
  .then(info => { console.log('Sent. Server response:', info.response || 'ok'); })
  .catch(e => { console.error('Failed:', e.code || '', e.message); process.exit(1); });
