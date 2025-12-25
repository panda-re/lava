#!/bin/bash
set -ex

# shellcheck disable=SC2034
sudo=""
if [ $EUID -ne 0 ]; then
  SUDO=sudo
fi

# Ensure POSTGRES_USER and POSTGRES_PASSWORD are set
if [ -z "${POSTGRES_USER}" ] || [ -z "${POSTGRES_PASSWORD}" ]; then
  echo "Error: POSTGRES_USER and POSTGRES_PASSWORD environment variables must be set."
  exit 1
fi

PG_VERSION=$(psql --version | awk '{print $3}' | cut -d '.' -f 1)
pg_hba="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"

# Check if pg_hba.conf exists
if [ ! -f "$pg_hba" ]; then
  echo "Error: PostgreSQL is not installed or configured correctly. File $pg_hba does not exist."
  exit 1
fi

# Ensure PostgreSQL is running
sudo service postgresql start

# Update the password for POSTGRES_USER
password_sql="ALTER USER \"${POSTGRES_USER}\" WITH PASSWORD '${POSTGRES_PASSWORD}';"
$SUDO -u postgres psql -c "${password_sql}"
$SUDO service postgresql reload

# Define the configuration file paths
PG_CONF="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"
PG_HBA="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"

# Update listen_addresses in postgresql.conf
$SUDO sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '0.0.0.0, localhost'/g" $PG_CONF

# Avoid duplicate entries in pg_hba.conf
if ! $SUDO grep -q "host all all 0.0.0.0/0 scram-sha-256" $PG_HBA; then
  echo "host all all 0.0.0.0/0 scram-sha-256" | $SUDO tee -a $PG_HBA > /dev/null
fi

# Restart PostgreSQL service
$SUDO service postgresql restart