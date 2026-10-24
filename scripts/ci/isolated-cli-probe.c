// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static void require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "hermetic preflight refused: %s\n", message);
        exit(125);
    }
}

static int empty(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return 0;
    struct dirent *entry;
    int result = 1;
    while ((entry = readdir(dir))) {
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) result = 0;
    }
    closedir(dir);
    return result;
}

int main(int argc, char **argv) {
    require(argc >= 2, "missing subject");
    require(!strcmp(argv[1], "/work/subject"), "unexpected subject");
    const char *dirs[] = {"/sys", "/run", "/var", "/home/fixture"};
    for (size_t i = 0; i < sizeof(dirs) / sizeof(*dirs); i++)
        require(empty(dirs[i]), "unexpected host directory content");
    struct statfs fs;
    require(!statfs("/", &fs) && fs.f_type == 0x01021994, "root is not private tmpfs");
    const char *absent[] = {"/dev/video0", "/dev/media0", "/dev/tpm0", "/dev/tpmrm0", "/dev/dri",
        "/etc/irlume", "/etc/pam.d", "/var/lib/irlume", "/run/irlume", "/run/dbus",
        "/usr/share/irlume", "/usr/lib/irlume", "/usr/local", "/run/irlume-test-host"};
    struct stat st;
    for (size_t i = 0; i < sizeof(absent) / sizeof(*absent); i++) {
        errno = 0;
        require(lstat(absent[i], &st) < 0 && errno == ENOENT, "host input is visible");
    }
    DIR *devices = opendir("/dev");
    require(devices != NULL, "missing private dev");
    struct dirent *entry;
    while ((entry = readdir(devices))) {
        require(strncmp(entry->d_name, "video", 5) && strncmp(entry->d_name, "media", 5)
                && strncmp(entry->d_name, "tpm", 3) && strcmp(entry->d_name, "dri")
                && strncmp(entry->d_name, "accel", 5), "hardware device visible");
    }
    closedir(devices);
    require(fstat(STDIN_FILENO, &st) == 0 && S_ISCHR(st.st_mode)
            && major(st.st_rdev) == 1 && minor(st.st_rdev) == 3,
            "stdin is not the null device");
    DIR *fds = opendir("/proc/self/fd");
    require(fds != NULL, "missing private proc");
    int own = dirfd(fds);
    while ((entry = readdir(fds))) {
        if (entry->d_name[0] == '.') continue;
        int fd = atoi(entry->d_name);
        require(fd <= 2 || fd == own, "inherited descriptor");
    }
    closedir(fds);
    FILE *status = fopen("/proc/self/status", "r");
    require(status != NULL, "process status unavailable");
    char line[256];
    int caps = 0, privileges = 0;
    while (fgets(line, sizeof(line), status)) {
        unsigned long long value;
        if (sscanf(line, "CapEff: %llx", &value) == 1) caps = value == 0;
        if (sscanf(line, "NoNewPrivs: %llu", &value) == 1) privileges = value == 1;
    }
    fclose(status);
    require(caps && privileges, "capabilities or new privileges available");
    FILE *receipt = fopen("/work/state/preflight.json", "w");
    require(receipt != NULL, "cannot record preflight");
    require(fputs("{\"empty_root\":true,\"host_inputs_absent\":true,\"inherited_fds_absent\":true,\"no_new_privileges\":true}\n", receipt) >= 0,
            "cannot write preflight");
    require(fclose(receipt) == 0, "cannot close preflight");
    const char *subject = argv[1];
    char *name = getenv("IRLUME_SANDBOX_ARGV0");
    require(name != NULL && name[0] != '\0', "missing subject name");
    argv[1] = name;
    execv(subject, &argv[1]);
    perror("hermetic subject exec");
    return 126;
}
