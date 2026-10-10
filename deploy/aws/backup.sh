#!/bin/bash
# Daily backup (hook-backup.timer): PostgreSQL dumps and the private configuration
# to the encrypted private bucket given as the only argument.
set -euo pipefail
umask 077
bucket="$1"
backup_dir=$(mktemp -d /opt/silicon-hook/backup.XXXXXX)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
databases=(hook_prod)
# The shared test database of Hook before 1.0 is kept, and backed up, until it is dropped.
if [ "$(docker exec hook-postgres psql -U postgres -tAc "SELECT 1 FROM pg_database WHERE datname = 'hook_test'")" = 1 ]; then
  databases+=(hook_test)
fi
for database in "${databases[@]}"; do
  docker exec hook-postgres pg_dump -U postgres -Fc "$database" > "$backup_dir/$database.dump"
done
config_files=(credentials.json db-tls)
for optional in accounts.json accounts.env iam.json telemetry.env; do
  if [ -f "/opt/silicon-hook/$optional" ]; then config_files+=("$optional"); fi
done
tar -czf "$backup_dir/config.tar.gz" -C /opt/silicon-hook "${config_files[@]}"
if [ -d /etc/silicon-hook ]; then
  native_files=(etc/silicon-hook opt/silicon-hook/current
    etc/systemd/system/silicon-hook-api.service
    etc/systemd/system/silicon-hook-worker.service)
  tar -czf "$backup_dir/native-config.tar.gz" -C / "${native_files[@]}"
fi
aws s3 cp "$backup_dir/" "s3://$bucket/backups/$stamp/" --recursive --sse AES256 --only-show-errors
rm -f "$backup_dir"/*.dump "$backup_dir/config.tar.gz" "$backup_dir/native-config.tar.gz"
rmdir "$backup_dir"
