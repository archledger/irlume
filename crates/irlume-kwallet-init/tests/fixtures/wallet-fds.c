// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* Synthetic exec target only. Never starts or contacts a desktop wallet. */
int main(int argc, char **argv) {
    if (argc != 4 || strcmp(argv[1], "--pam-login") != 0)
        return 10;
    int key = atoi(argv[2]), listener = atoi(argv[3]);
    if (key <= 2 || listener <= 2 || key == listener)
        return 11;
    if (fcntl(key, F_GETFD) != 0 || fcntl(listener, F_GETFD) != 0)
        return 12;
    int accepting = 0;
    socklen_t len = sizeof(accepting);
    if (getsockopt(listener, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &len) != 0 || !accepting)
        return 13;
    struct stat null_stat, stream_stat;
    if (stat("/dev/null", &null_stat) != 0)
        return 14;
    for (int fd = 0; fd <= 2; ++fd) {
        if (fstat(fd, &stream_stat) != 0 || !S_ISCHR(stream_stat.st_mode) ||
            stream_stat.st_rdev != null_stat.st_rdev)
            return 15;
    }
    DIR *fds = opendir("/proc/self/fd");
    if (!fds)
        return 16;
    struct dirent *entry;
    int unexpected = 0;
    while ((entry = readdir(fds))) {
        if (entry->d_name[0] == '.')
            continue;
        int fd = atoi(entry->d_name);
        if (fd > 2 && fd != key && fd != listener && fd != dirfd(fds))
            unexpected = 1;
    }
    closedir(fds);
    if (unexpected)
        return 17;
    unsigned char buffer[56];
    size_t total = 0;
    while (total < sizeof(buffer)) {
        ssize_t got = read(key, buffer + total, sizeof(buffer) - total);
        if (got <= 0)
            return 18;
        total += (size_t)got;
    }
    for (size_t i = 0; i < sizeof(buffer); ++i) {
        if (buffer[i] != 0x5a)
            return 19;
    }
    return 0;
}
