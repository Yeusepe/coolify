#!/usr/bin/env bash
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
mkdir -p "$temp/bin"
export FORK_TEST_DIR="$temp"
export PATH="$temp/bin:$PATH"

cat > "$temp/bin/docker" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$FORK_TEST_DIR/docker-calls"
case "$*" in
    'image inspect --format {{index .RepoDigests 0}}'*) printf 'ghcr.io/yeusepe/coolify@sha256:%064d\n' 1 ;;
    *'org.opencontainers.image.source'*) echo https://github.com/Yeusepe/coolify ;;
    *'org.opencontainers.image.revision'*) printf '%040d\n' 1 ;;
    'inspect --format {{.Image}} coolify') echo sha256:old ;;
    'image inspect --format {{.Id}}'*) echo "${FORK_TEST_NEW_IMAGE:-sha256:new}" ;;
    'exec coolify sh -c'*) echo old-migrations ;;
    'run --rm --network none --read-only'*) echo "${FORK_TEST_MIGRATIONS:-old-migrations}" ;;
    'exec coolify curl'*)
        [[ "$*" == *'http://127.0.0.1:8080/'* ]]
        [[ ${FORK_TEST_FAIL_HEALTH:-false} == false ]] ;;
    'exec coolify-db sh -c'*) echo database-backup ;;
    'exec -i coolify-db pg_restore --list') cat >/dev/null; echo valid-archive ;;
    'compose '* )
        if [[ ${FORK_TEST_FAIL:-false} == true && ! -f "$FORK_TEST_DIR/failed-once" ]]; then
            touch "$FORK_TEST_DIR/failed-once"
            exit 1
        fi ;;
esac
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$temp/bin/curl"
chmod +x "$temp/bin/docker" "$temp/bin/curl"

prepare() {
    mkdir -p "$temp/source" "$temp/backups"
    printf 'APP_KEY=test-key\n' > "$temp/source/.env"
    chmod 600 "$temp/source/.env"
    sed -e "s|source_dir=/data/coolify/source|source_dir=$temp/source|" \
        -e "s|backup_base=/data/coolify/backups/fork-updates|backup_base=$temp/backups|" \
        "$root/scripts/fork-update.sh" > "$temp/update.sh"
    : > "$temp/docker-calls"
}

prepare
FORK_TEST_NEW_IMAGE=sha256:old bash "$temp/update.sh"
test ! -f "$temp/source/docker-compose.fork.yml"

bash "$temp/update.sh"
grep -q 'ghcr.io/yeusepe/coolify@sha256:' "$temp/source/docker-compose.fork.yml"
test -s "$temp/source/.fork-deployed"
test "$(stat -c %a "$(find "$temp/backups" -name database.dump -print -quit)")" = 600
grep -q 'docker-compose.fork.yml up -d --no-deps' "$temp/docker-calls"

FORK_TEST_FAIL=true bash "$temp/update.sh" && exit 1
grep -q 'image: sha256:old' "$temp/source/docker-compose.fork.yml"
test -s "$temp/source/.fork-failed"

rm "$temp/source/.fork-failed"
FORK_TEST_MIGRATIONS=new-migrations bash "$temp/update.sh" && exit 1
grep -q 'image: sha256:old' "$temp/source/docker-compose.fork.yml"

FORK_TEST_MIGRATIONS=new-migrations bash "$temp/update.sh" --allow-migrations
grep -q 'ghcr.io/yeusepe/coolify@sha256:' "$temp/source/docker-compose.fork.yml"
rm "$temp/source/.fork-failed"
FORK_TEST_FAIL_HEALTH=true bash "$temp/update.sh" && exit 1
grep -q 'image: sha256:old' "$temp/source/docker-compose.fork.yml"
echo 'Fork updater checks passed: no-op, deploy, rollback, migration gate, reviewed migration, failed health probe.'
