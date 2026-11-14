#!/usr/bin/env bash
# Restore a full archive into a newly created PostgreSQL database.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 INPUT.dump NEW_DATABASE" >&2
    echo "NEW_DATABASE must not already exist." >&2
    exit 2
fi

export PGHOST="${PGHOST:-localhost}"
export PGPORT="${PGPORT:-5432}"
export PGUSER="${PGUSER:-${POSTGRES_USER:-}}"
if [[ ! -v PGPASSWORD && -v POSTGRES_PASSWORD ]]; then
    export PGPASSWORD="$POSTGRES_PASSWORD"
fi

# Check the archive before creating anything. createdb refuses existing names.
pg_restore --list "$1" > /dev/null
createdb --template=template0 -- "$2"
if ! pg_restore --single-transaction --exit-on-error \
    --no-owner --no-privileges --dbname="$2" "$1"; then
    echo "Restore failed; the newly created database '$2' remains for inspection." >&2
    exit 1
fi
echo "Database restored to $2"
