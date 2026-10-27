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
| `SESSION_SECRET` | `xlights-change-this-secret` | Secret for session cookies — change this in production |
| `DATA_DIR` | `/data` | Where show data is stored inside the container |
| `PORT` | `3000` | Internal port (the compose file maps this to 3030 externally) |

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
