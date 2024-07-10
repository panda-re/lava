#!/bin/bash
set -ex

PGPASS="${HOME}/.pgpass"

if [ ! -f "${PGPASS}" ]; then
    postgres_depends=$(dpkg-query -W -f='${depends}' 'postgresql')
    postgres_pkg=$(echo "${postgres_depends}" | grep -oP 'postgresql-[0-9]+.?[0-9]+')
    postgres_version=${postgres_pkg/postgresql-/}
    pg_hba="/etc/postgresql/${postgres_version}/main/pg_hba.conf"
    postgres_password='postgrespostgres'

    sudo sed -i.bak -E 's/^(local\s+all\s+postgres\s+)md5$/\1peer/' "${pg_hba}"
    sudo service postgresql reload

    password_sql="ALTER USER postgres WITH PASSWORD '${postgres_password}';"
    sudo -u postgres psql -c "${password_sql}"

    echo "*:*:*:postgres:${postgres_password}" > "${PGPASS}"
    chmod 600 "${PGPASS}"

    sudo sed -i.bak -E 's/^(local\s+all\s+postgres\s+)peer$/\1md5/' "${pg_hba}"
    sudo service postgresql reload
fi

# Define the PostgreSQL version
PG_VERSION=$(psql --version | awk '{print $3}' | cut -d '.' -f 1)

# Define the configuration file paths
PG_CONF="/etc/postgresql/${PG_VERSION}/main/postgresql.conf"
PG_HBA="/etc/postgresql/${PG_VERSION}/main/pg_hba.conf"

# Update listen_addresses and password_encryption in postgresql.conf
sed -i "s/#listen_addresses = 'localhost'/listen_addresses = '0.0.0.0, localhost'/g" $PG_CONF
sed -i "s/#password_encryption = scram-sha-256/password_encryption = md5/g" $PG_CONF

# Update pg_hba.conf
echo "host all all 0.0.0.0/0 md5" >> $PG_HBA
sed -i 's/scram-sha-256/md5/g' $PG_HBA

# Restart PostgreSQL service
service postgresql restart