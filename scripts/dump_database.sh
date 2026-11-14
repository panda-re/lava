#!/usr/bin/env bash
# Back up an entire LAVA PostgreSQL database to a custom-format archive.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: $0 DATABASE OUTPUT.dump" >&2
    echo "DATABASE is the actual PostgreSQL name, including any LAVA db_suffix." >&2
    exit 2
fi

# Standard PostgreSQL settings take precedence over LAVA credentials.
export PGHOST="${PGHOST:-localhost}"
export PGPORT="${PGPORT:-5432}"
export PGUSER="${PGUSER:-${POSTGRES_USER:-}}"
if [[ ! -v PGPASSWORD && -v POSTGRES_PASSWORD ]]; then
    export PGPASSWORD="$POSTGRES_PASSWORD"
fi

umask 077
archive=$2
if [[ -e "$archive" || -L "$archive" ]]; then
    echo "Refusing to overwrite: $archive" >&2
    exit 1
fi
temporary=$(mktemp "${archive}.partial.XXXXXX")
trap 'rm -f -- "$temporary"' EXIT
pg_dump --format=custom --file="$temporary" --dbname="$1"
# Publish only completed dumps; linking also refuses a concurrent overwrite.
ln -- "$temporary" "$archive"
echo "Database backup saved to $archive"
