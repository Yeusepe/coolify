#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

source_dir=/data/coolify/source
backup_base=/data/coolify/backups/fork-updates
image=ghcr.io/yeusepe/coolify:fork-main
allow_migrations=false
retry=false
for arg in "$@"; do
    case "$arg" in
        --allow-migrations) allow_migrations=true ;;
        --retry) retry=true ;;
        *) echo "Usage: $0 [--allow-migrations] [--retry]" >&2; exit 64 ;;
    esac
done

cd "$source_dir"
exec 9>.fork-update.lock
flock -n 9 || exit 0
docker pull "$image" >/dev/null
digest=$(docker image inspect --format '{{index .RepoDigests 0}}' "$image")
[[ "$digest" =~ ^ghcr\.io/yeusepe/coolify@sha256:[a-f0-9]{64}$ ]] || exit 1
[[ $(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$digest") == https://github.com/Yeusepe/coolify ]] || exit 1
revision=$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$digest")
[[ "$revision" =~ ^[a-f0-9]{40}$ ]] || exit 1
old_image=$(docker inspect --format '{{.Image}}' coolify)
new_image=$(docker image inspect --format '{{.Id}}' "$digest")
[[ "$old_image" != "$new_image" ]] || exit 0
if [[ -f .fork-failed && $(cat .fork-failed) == "$digest" && "$retry" == false && "$allow_migrations" == false ]]; then
    exit 0
fi

migration_command='find database/migrations -type f -exec sha256sum {} \; | sort'
current_migrations=$(docker exec coolify sh -c "$migration_command")
next_migrations=$(docker run --rm --network none --read-only --entrypoint sh "$digest" -c "$migration_command")
if [[ "$current_migrations" != "$next_migrations" && "$allow_migrations" == false ]]; then
    printf '%s\n' "$digest" > .fork-failed
    echo 'Database migrations changed. Review them and run fork-update.sh --allow-migrations manually.' >&2
    exit 78
fi

install -d -m 0700 "$backup_base"
backup_dir=$(mktemp -d "$backup_base/$(date -u +%Y%m%dT%H%M%S)-${revision:0:12}.XXXXXX")
docker exec coolify-db sh -c 'pg_dump --format=custom --username="$POSTGRES_USER" "$POSTGRES_DB"' > "$backup_dir/database.dump"
test -s "$backup_dir/database.dump"
docker exec -i coolify-db pg_restore --list < "$backup_dir/database.dump" > "$backup_dir/database-contents.txt"
cp -p .env "$backup_dir/.env"
printf '%s\n' "$old_image" > "$backup_dir/previous-image"
if [[ -f docker-compose.fork.yml ]]; then
    cp -p docker-compose.fork.yml "$backup_dir/docker-compose.fork.yml"
fi
(cd "$backup_dir" && sha256sum database.dump .env > SHA256SUMS)
docker tag "$old_image" "coolify-fork-rollback:$(basename "$backup_dir")"

compose=(docker compose --env-file .env -f docker-compose.yml -f docker-compose.prod.yml)
for file in docker-compose.custom.yml docker-compose.postgres-upgrade.yml; do
    if [[ -f "$file" ]]; then compose+=(-f "$file"); fi
done
compose+=(-f docker-compose.fork.yml)

write_image() {
    printf 'services:\n  coolify:\n    image: %s\n' "$1" > docker-compose.fork.yml.tmp
    mv docker-compose.fork.yml.tmp docker-compose.fork.yml
}

rollback() {
    trap - ERR INT TERM
    set +e
    printf '%s\n' "$digest" > .fork-failed
    write_image "$old_image"
    if "${compose[@]}" up -d --no-deps --force-recreate --wait --wait-timeout 180 coolify; then
        echo "Deployment failed; restored the previous image. Database recovery copy: $backup_dir" >&2
    else
        echo "Deployment and image rollback failed. Recovery copy: $backup_dir" >&2
    fi
    exit 1
}

trap rollback ERR INT TERM
write_image "$digest"
"${compose[@]}" up -d --no-deps --force-recreate --wait --wait-timeout 180 coolify
curl --fail --silent --show-error --max-time 10 http://127.0.0.1:8000/api/health >/dev/null
curl --fail --silent --show-error --max-time 10 http://127.0.0.1:8000/login >/dev/null
trap - ERR INT TERM
printf '%s %s %s\n' "$revision" "$digest" "$(date -u +%FT%TZ)" > .fork-deployed
echo "Deployed $revision. Recovery copy: $backup_dir"
