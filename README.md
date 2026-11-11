# xLights Show Reference

A self-hosted web app for documenting and troubleshooting your xLights lighting show. Import your xLights XML config files and get a fast, searchable reference for channel numbers, controller ports, wiring details, and physical prop locations — all in one place.

![Dark themed UI with controllers, models, and wiring documentation](https://raw.githubusercontent.com/keithmarx/xlights-reference/main/preview.png)

## Features

- **Models tab** — searchable, sortable table of every prop/model with start/end channels, node counts, controller, port, and protocol
- **Controllers tab** — card view of every controller with port-by-port model assignments and wiring summaries
- **LR Boards** — document long range receiver boards per controller, label up to 32 channels each
- **Groups tab** — all xLights model groups with member lists and aliases
- **Overview** — at-a-glance stats per controller (channels used, model count, IP)
- **Wiring documentation** — per-model notes for wire color, connector type, physical location, wire route, power injection, LR receiver, repeater, and general notes
- **Bulk Fill** — record what's on the end of each LR port in seconds: type `unit-port prop name` lines (e.g. `2-3 Mega Tree`) or upload a CSV; props match by name and the LR board grids fill themselves in
- **Print sheets** — print-ready controller port sheets, props-by-location checklists, and LR board maps for use while installing
- **Multi-user** — each user has their own independent show data; admin can manage users
- **Persistent data** — all data survives container restarts via a Docker volume

## Requirements

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose

That's it. No database to set up, no cloud account needed.

## Quick Start

```bash
git clone https://github.com/keithmarx/xlights-reference.git
cd xlights-reference
docker compose up -d --build
```

Then open **http://localhost:3030** in your browser.

On first run you'll be prompted to create an admin account.

## Importing Your xLights Data

Click **↑ Import XML** in the header. You'll need two files from your xLights show folder:

| File | Contains |
|---|---|
| `xlights_networks.xml` | Controller definitions (IPs, protocols, channel counts) |
| `xlights_rgbeffects.xml` | Model layout (props, nodes, ports, groups) |

You can upload either file independently to refresh just that section. **Wiring notes are always preserved** across re-imports.

## Bulk Fill (LR boards and wiring)

Click **⇪ Bulk Fill** in the header. Either:

- **Type or paste lines** — `LR unit`, `LR port`, then the xLights prop name:

  ```
  1-1  Gutter Garage
  1-3  Garage + Animated Bell
  2.1  Mega Tree
  ```

  Separators can be `-`, `.`, `:` or a space; use `+` or a comma for several props on one port.
- **Use the CSV template** — click *Download CSV template* (pre-filled with every prop, its controller and xLights port), fill in the `LR Unit` / `LR Port` columns and any other wiring columns you want, and upload it. Blank cells leave existing data untouched.

Props are matched by name (exact, then prefix, then contains); ambiguous or unknown names are flagged in a preview and skipped. Nothing is saved until you click **Apply**.

## Configuration

The app works out of the box with no configuration required. Optional environment variables in `docker-compose.yml`:

| Variable | Default | Description |
|---|---|---|
| `SESSION_SECRET` | *(generated)* | Secret for session cookies, at least 16 characters. If unset, a random secret is generated once and kept in the data volume (`/data/.session-secret`) |
| `ADMIN_SETUP_TOKEN` | *(none)* | If set, creating the first admin account requires this token, so a stranger can't claim a fresh install |
| `TRUST_PROXY` | `1` | Number of reverse proxies in front of the app (used for client IPs / rate limiting). Set `0`/`false` if exposed directly |
| `COOKIE_SECURE` | `auto` | `auto` marks the session cookie `Secure` when the request arrived over HTTPS (the bundled Apache config sends `X-Forwarded-Proto`); set `true`/`false` to force |
| `APP_URL` | *(none)* | Public address of the app (e.g. `https://xlights.keithmarx.com`). Required for emailed links; links are never built from the request's `Host` header |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM` | *(none)* | Outgoing email for invites and password resets. Port 587 uses STARTTLS (required by default), 465 uses implicit TLS; `SMTP_SECURE=true/false` and `SMTP_REQUIRE_TLS=false` override |
| `DATA_DIR` | `/data` | Where show data is stored inside the container |
| `PORT` | `3000` | Internal port (the compose file maps this to 3030 externally) |

## Accounts, invites and password reset

Registration is **invite-only**. There is no public sign-up page.

1. The first visit creates the admin account (protect it with `ADMIN_SETUP_TOKEN`; add an email so you can reset your own password).
2. An admin opens **Users → Invite by email**, enters an address and a role, and clicks **Send invite**.
3. The invitee gets an email with a single-use link (valid 7 days). They choose their own username and password. Using the link proves they own the address.
4. Admins can see pending invites and revoke them. A new invite to the same address replaces the old one.
5. **Forgot password?** on the sign-in page emails a one-hour, single-use reset link to the account's address. It always shows the same message, so it can't be used to discover who has an account. Resetting signs the user out everywhere.

If email isn't configured (or sending fails), the invite is still created and the admin is shown the link once to pass on themselves. Accounts created before this feature have no email; an admin can add one by clicking "+ add email" in the Users list. Invite and reset tokens are stored only as SHA-256 hashes and travel in the URL fragment (`#invite=…`), which browsers don't send to servers or log; the page removes it from the address bar after reading it.

Run the tests with `npm test`.

## Security notes

- Passwords: 10–72 characters, bcrypt (cost 12; older hashes are upgraded on next login). Usernames are 3–32 letters, numbers, `_` or `-`, and are case-insensitive.
- Logins are rate limited (10 failed attempts per 15 minutes per IP). Sessions are stored in `/data/sessions`, so they survive restarts, and are ended immediately when a user is removed or their password changes.
- Changing your own password requires your current password.
- Removing a user moves their show data aside (`show-data-<name>.json.deleted-<timestamp>`) instead of leaving it for a future account with the same name.
- Show data and `users.json` are written atomically; the previous version of each show file is kept as `.bak`. A corrupt `users.json` stops the app instead of re-opening first-run setup.
- The container starts as root only to fix ownership of the data volume, then runs as the unprivileged `node` user.

To change the external port, edit the `ports` line in `docker-compose.yml`:
```yaml
ports:
  - "8080:3000"   # change 8080 to whatever you want
```

## Reverse Proxy (Optional)

An example Apache virtual host config for putting the app behind a domain with SSL is included in `apache-vhost.conf`. Adjust the domain name and certificate paths for your setup.

## Data Storage

Show data is stored in a Docker named volume (`xlights-data`). To find the data files on Linux:

```bash
docker volume inspect xlights-reference_xlights-data
```

Data is stored per user as `/data/show-data-{username}.json`.

## Updating

```bash
git pull
docker compose up -d --build
```

Your data is safe — the volume is not affected by rebuilds.

## Built With

- [Node.js](https://nodejs.org/) + [Express](https://expressjs.com/)
- [fast-xml-parser](https://github.com/NaturalIntelligence/fast-xml-parser)
- Vanilla HTML/CSS/JS (no frontend framework)
- Docker

## License

MIT — free to use, modify, and share.
