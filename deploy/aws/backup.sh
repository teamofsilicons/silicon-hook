#!/bin/bash
set -euo pipefail
umask 077
bucket="$1"
backup_dir=$(mktemp -d /opt/silicon-hook/backup.XXXXXX)
stamp=$(date -u +%Y%m%dT%H%M%SZ)
docker exec hook-postgres pg_dump -U postgres -Fc hook_prod > "$backup_dir/hook_prod.dump"
docker exec hook-postgres pg_dump -U postgres -Fc hook_test > "$backup_dir/hook_test.dump"
config_files=(credentials.json iam.json db-tls)
if [ -f /opt/silicon-hook/telemetry.env ]; then config_files+=(telemetry.env); fi
tar -czf "$backup_dir/config.tar.gz" -C /opt/silicon-hook "${config_files[@]}"
aws s3 cp "$backup_dir/" "s3://$bucket/backups/$stamp/" --recursive --sse AES256 --only-show-errors
rm "$backup_dir/hook_prod.dump" "$backup_dir/hook_test.dump" "$backup_dir/config.tar.gz"
rmdir "$backup_dir"
