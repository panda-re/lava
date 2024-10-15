#!/bin/bash
set -ex

# shellcheck disable=SC2034
sudo=""
if [ $EUID -ne 0 ]; then
  SUDO=sudo
fi

PGPASS="${HOME}/.pgpass"
PG_VERSION=$(psql --version | awk '{print $3}' | cut -d '.' -f 1)

if [ ! -f "${PGPASS}" ]; then
    pg_hba="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"
    postgres_password='postgrespostgres'

    $SUDO sed -i.bak -E 's/^(local\s+all\s+postgres\s+)md5$/\1peer/' "${pg_hba}"
    $SUDO service postgresql reload

    password_sql="ALTER USER postgres WITH PASSWORD '${postgres_password}';"
    $SUDO -u postgres psql -c "${password_sql}"

    echo "*:*:*:postgres:${postgres_password}" > "${PGPASS}"
    chmod 600 "${PGPASS}"

    $SUDO sed -i.bak -E 's/^(local\s+all\s+postgres\s+)peer$/\1md5/' "${pg_hba}"
    $SUDO service postgresql reload
fi

# Define the PostgreSQL version


# Define the configuration file paths
PG_CONF="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"
PG_HBA="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"

# Update listen_addresses and password_encryption in postgresql.conf
$SUDO sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '0.0.0.0, localhost'/g" $PG_CONF
$SUDO sed -i "s/#password_encryption = scram-sha-256/password_encryption = md5/g" $PG_CONF

# Update pg_hba.conf
$SUDO echo "host all all 0.0.0.0/0 md5" >> $PG_HBA
$SUDO sed -i 's/scram-sha-256/md5/g' $PG_HBA

# Restart PostgreSQL service
$SUDO service postgresql restart
