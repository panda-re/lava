#include <utmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

static void write_record(
    int fd,
    short type,
    const char *user,
    const char *line,
    const char *host,
    int pid)
{
    struct utmp u;

    memset(&u, 0, sizeof(u));

    u.ut_type = type;
    u.ut_pid = pid;

    strncpy(u.ut_user, user, sizeof(u.ut_user) - 1);
    strncpy(u.ut_line, line, sizeof(u.ut_line) - 1);
    strncpy(u.ut_host, host, sizeof(u.ut_host) - 1);

    u.ut_tv.tv_sec = time(NULL);

    write(fd, &u, sizeof(u));
}

int main(void)
{
    int fd = open("seed.utmp", O_CREAT | O_WRONLY | O_TRUNC, 0644);

    if (fd < 0) {
        perror("open");
        return 1;
    }

    write_record(fd, BOOT_TIME,
                 "", "", "", 1);

    write_record(fd, USER_PROCESS,
                 "alice", "pts/0",
                 "10.0.0.1", 1001);

    write_record(fd, USER_PROCESS,
                 "bob", "pts/1",
                 "192.168.1.55", 1002);

    write_record(fd, USER_PROCESS,
                 "charlie", "tty1",
                 "", 1003);

    write_record(fd, LOGIN_PROCESS,
                 "LOGIN", "tty2",
                 "", 1004);

    write_record(fd, DEAD_PROCESS,
                 "", "pts/9",
                 "", 1005);

    close(fd);

    printf("created seed.utmp (%zu-byte records)\n",
           sizeof(struct utmp));

    return 0;
}