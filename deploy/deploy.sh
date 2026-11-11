#!/usr/bin/env bash
# Deploy/update xLights Show Reference on the server. Run from anywhere inside the checkout:
#   ./deploy/deploy.sh [branch]        (default: main)
# It backs up the data volume, fast-forwards the checkout, rebuilds the container and waits for it to be healthy.
set -euo pipefail
cd "$(dirname "$0")/.."

BRANCH="${1:-main}"
SERVICE=xlights-reference

command -v docker >/dev/null || { echo "docker not found"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "docker compose (v2) not found"; exit 1; }
[ -f .env ] || { echo "Missing .env - copy .env.example to .env and fill it in first."; exit 1; }
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "The checkout has local changes; commit or discard them first:"; git status --short --untracked-files=no; exit 1
fi

PREV="$(git rev-parse --short HEAD)"

# 1. Back up the data volume (keeps the 5 newest). Skipped on a first install when no volume exists yet.
VOL="$(docker volume ls -q --filter name=xlights-data | head -n1 || true)"
if [ -n "$VOL" ]; then
  mkdir -p backups
  STAMP="$(date +%Y%m%d-%H%M%S)"
  docker run --rm -v "$VOL":/data:ro -v "$PWD/backups":/backup alpine \
    tar czf "/backup/data-$STAMP.tar.gz" -C /data .
  echo "Backed up volume $VOL -> backups/data-$STAMP.tar.gz"
  ls -1t backups/data-*.tar.gz | tail -n +6 | xargs -r rm --
fi

# 2. Update the code
git fetch origin "$BRANCH"
git checkout "$BRANCH"
git merge --ff-only "origin/$BRANCH"
NEW="$(git rev-parse --short HEAD)"
echo "Deploying $BRANCH: $PREV -> $NEW"

# 3. Rebuild and restart
docker compose up -d --build

# 4. Wait for the health check
echo -n "Waiting for the app to become healthy"
for _ in $(seq 1 40); do
  CID="$(docker compose ps -q "$SERVICE")"
  STATUS="$([ -n "$CID" ] && docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CID" || echo none)"
  if [ "$STATUS" = "healthy" ]; then echo " - healthy"; docker compose ps; exit 0; fi
  echo -n "."; sleep 2
done
echo " - NOT healthy after 80s. Recent logs:"
docker compose logs --tail 40 "$SERVICE"
echo
echo "Roll back with:  git checkout $PREV && docker compose up -d --build"
exit 1
