import os
import re
import shlex
import stat
import subprocess

# Setup postgres. Mostly copied from setup.py


def cmd_to_list(cmd):
    cmd_args = shlex.split(cmd) if isinstance(cmd, str) else cmd
    cmd = subprocess.list2cmdline(cmd_args)
    return cmd, cmd_args


def run(cmd):
    cmd, cmd_args = cmd_to_list(cmd)
    try:
        print("Running [{}] . . . ".format(cmd))
        subprocess.check_call(cmd_args)
    except subprocess.CalledProcessError:
        print("[{}] cmd did not execute properly.".format(cmd))
        raise


def main():
    if not os.path.isfile(os.path.join(os.environ['HOME'], '.pgpass')):
        postgres_depends = subprocess.check_output(['dpkg-query', '-W', '-f',
                                                    '${depends}',
                                                    'postgresql']).splitlines()
        postgres_pkg = [d for d in postgres_depends
                        if re.match(r'postgresql-[0-9]+.?[0-9]+', d)][0]
        postgres_version = postgres_pkg.replace('postgresql-', '')
        pg_hba = "/etc/postgresql/{}/main/pg_hba.conf".format(postgres_version)
        postgres_password = 'postgrespostgres'
        run(['sudo', 'sed', '-i.bak', '-E',
             r's/^(local\s+all\s+postgres\s+)md5$/\1peer/', pg_hba])
        run("sudo service postgresql reload")
        password_sql = "ALTER USER postgres WITH PASSWORD '{}';" \
            .format(postgres_password)
        run(['sudo', '-u', 'postgres', 'psql', '-c', password_sql])
        pgpass = os.path.join(os.environ['HOME'], '.pgpass')
        with open(pgpass, 'w') as f:
            f.write('*:*:*:postgres:{}'.format(postgres_password))
        os.chmod(pgpass, stat.S_IRUSR | stat.S_IWUSR)
        run(['sudo', 'sed', '-i.bak', '-E',
             r's/^(local\s+all\s+postgres\s+)peer$/\1md5/', pg_hba])
        run("sudo service postgresql reload")


if __name__ == "__main__":
    main()
