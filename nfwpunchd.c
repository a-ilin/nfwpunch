
#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#define SOCKET_PATH "/run/nfwpunch/nfwpunch.sock"
#define NFT_PATH    "/usr/sbin/nft"
#define NFT_TABLE   "dynamic_access"

#define MAX_LINE    256
#define MAX_TIMEOUT 3600
#define MIN_TIMEOUT 60
#define BACKLOG     32

/*
 * Only these services can be authorized.
 * Corresponding nftables sets must already exist.
 */
struct service {
    const char *name;
    const char *set4;
    const char *set6;
};

static const struct service services[] = {
    { "web",   "authorized_web4",   "authorized_web6"   },
    { "admin", "authorized_admin4", "authorized_admin6" }
};

static const size_t service_count =
    sizeof(services) / sizeof(services[0]);

static volatile sig_atomic_t stopping = 0;
static int listen_fd = -1;


/* ---------- Signal handling ---------- */

static void on_signal(int sig)
{
    (void)sig;
    stopping = 1;

    if (listen_fd >= 0)
        close(listen_fd);
}


/* ---------- Validation ---------- */

static const struct service *
find_service(const char *name)
{
    for (size_t i = 0; i < service_count; i++) {
        if (strcmp(name, services[i].name) == 0)
            return &services[i];
    }

    return NULL;
}


static int
valid_ip(const char *text,
         int *family,
         char *normalized,
         size_t size)
{
    struct in_addr a4;
    struct in6_addr a6;

    if (inet_pton(AF_INET, text, &a4) == 1) {
        if (!inet_ntop(AF_INET, &a4, normalized, size))
            return -1;

        *family = AF_INET;
        return 0;
    }

    if (inet_pton(AF_INET6, text, &a6) == 1) {
        if (!inet_ntop(AF_INET6, &a6, normalized, size))
            return -1;

        *family = AF_INET6;
        return 0;
    }

    return -1;
}


/* ---------- nftables execution ---------- */

/*
 * Executes nft directly.
 *
 * No shell is involved.
 * Table and set names are selected internally.
 * IP addresses have already been validated.
 */
static int
run_nft(const char *operation,
        const char *setname,
        const char *ip,
        unsigned timeout)
{
    char element[INET6_ADDRSTRLEN + 32];

    char *argv[12];
    int argc = 0;

    if (strcmp(operation, "add") == 0) {

        snprintf(element, sizeof(element),
                 "%s timeout %us", ip, timeout);

        argv[argc++] = (char *)NFT_PATH;
        argv[argc++] = "add";
        argv[argc++] = "element";
        argv[argc++] = "inet";
        argv[argc++] = NFT_TABLE;
        argv[argc++] = (char *)setname;
        argv[argc++] = "{";
        argv[argc++] = element;
        argv[argc++] = "}";

    } else if (strcmp(operation, "delete") == 0) {

        snprintf(element, sizeof(element), "%s", ip);

        argv[argc++] = (char *)NFT_PATH;
        argv[argc++] = "delete";
        argv[argc++] = "element";
        argv[argc++] = "inet";
        argv[argc++] = NFT_TABLE;
        argv[argc++] = (char *)setname;
        argv[argc++] = "{";
        argv[argc++] = element;
        argv[argc++] = "}";

    } else {
        return -1;
    }

    argv[argc] = NULL;

    pid_t pid = fork();

    if (pid < 0)
        return -1;

    if (pid == 0) {

        int nullfd = open("/dev/null", O_RDWR);

        if (nullfd >= 0) {
            dup2(nullfd, STDIN_FILENO);
            dup2(nullfd, STDOUT_FILENO);
            dup2(nullfd, STDERR_FILENO);

            if (nullfd > STDERR_FILENO)
                close(nullfd);
        }

        execv(NFT_PATH, argv);

        _exit(127);
    }

    int status;

    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        return 0;

    return -1;
}


/* ---------- Socket protocol ---------- */

static int
write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {

        ssize_t n = write(fd, buf, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;

            return -1;
        }

        buf += n;
        len -= (size_t)n;
    }

    return 0;
}


static void
reply(int fd, const char *message)
{
    write_all(fd, message, strlen(message));
}


/*
 * Protocol:
 *
 * authorize <IP> <SERVICE> <SECONDS>\n
 * revoke    <IP> <SERVICE>\n
 *
 * Exactly one request per connection.
 */
static void
handle_client(int fd)
{
    char line[MAX_LINE];
    size_t used = 0;
    bool got_line = false;

    /* Read a single bounded line. */
    while (used < sizeof(line) - 1) {

        char c;

        ssize_t n = read(fd, &c, 1);

        if (n == 0)
            break;

        if (n < 0) {
            if (errno == EINTR)
                continue;

            reply(fd, "ERROR io\n");
            return;
        }

        if (c == '\n') {
            got_line = true;
            break;
        }

        if (c == '\r' || c == '\0') {
            reply(fd, "ERROR invalid_request\n");
            return;
        }

        line[used++] = c;
    }

    line[used] = '\0';

    if (!got_line || used == 0) {
        reply(fd, "ERROR invalid_request\n");
        return;
    }

    char action[16] = {0};
    char ip_text[INET6_ADDRSTRLEN + 1] = {0};
    char service_name[32] = {0};
    char timeout_text[32] = {0};

    int fields = sscanf(
        line,
        "%15s %46s %31s %31s",
        action,
        ip_text,
        service_name,
        timeout_text
    );

    const struct service *svc =
        find_service(service_name);

    int family;

    char ip[INET6_ADDRSTRLEN];

    if (!svc ||
        valid_ip(ip_text, &family, ip, sizeof(ip)) != 0) {

        reply(fd, "ERROR invalid_request\n");
        return;
    }

    const char *setname =
        family == AF_INET ? svc->set4 : svc->set6;


    /* ---------- Authorize ---------- */

    if (strcmp(action, "authorize") == 0) {

        if (fields != 4) {
            reply(fd, "ERROR invalid_request\n");
            return;
        }

        char *end = NULL;

        errno = 0;

        unsigned long parsed =
            strtoul(timeout_text, &end, 10);

        if (errno ||
            !end ||
            *end ||
            parsed < MIN_TIMEOUT ||
            parsed > MAX_TIMEOUT) {

            reply(fd, "ERROR invalid_timeout\n");
            return;
        }

        unsigned timeout = (unsigned)parsed;

        if (run_nft("add", setname, ip, timeout) == 0)
            reply(fd, "OK authorized\n");
        else
            reply(fd, "ERROR firewall_operation_failed\n");

        return;
    }


    /* ---------- Revoke ---------- */

    if (strcmp(action, "revoke") == 0) {

        if (fields != 3) {
            reply(fd, "ERROR invalid_request\n");
            return;
        }

        if (run_nft("delete", setname, ip, 0) == 0)
            reply(fd, "OK revoked\n");
        else
            reply(fd, "ERROR firewall_operation_failed\n");

        return;
    }

    reply(fd, "ERROR invalid_action\n");
}


/* ---------- Main ---------- */

int
main(void)
{
    struct sockaddr_un addr;

    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = on_signal;

    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    signal(SIGPIPE, SIG_IGN);


    /*
     * Remove a stale socket only.
     * Never replace an unexpected filesystem object.
     */
    struct stat st;

    if (lstat(SOCKET_PATH, &st) == 0) {

        if (!S_ISSOCK(st.st_mode)) {
            fprintf(stderr,
                    "Refusing to replace non-socket %s\n",
                    SOCKET_PATH);

            return 1;
        }

        if (unlink(SOCKET_PATH) != 0) {
            perror("unlink");
            return 1;
        }

    } else if (errno != ENOENT) {

        perror("lstat");
        return 1;
    }


    /* Create Unix socket. */

    listen_fd = socket(
        AF_UNIX,
        SOCK_STREAM | SOCK_CLOEXEC,
        0
    );

    if (listen_fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;

    strncpy(
        addr.sun_path,
        SOCKET_PATH,
        sizeof(addr.sun_path) - 1
    );

    if (bind(
        listen_fd,
        (struct sockaddr *)&addr,
        sizeof(addr)
    ) != 0) {

        perror("bind");
        return 1;
    }


    /* Restrict access to the process's primary group. */

    gid_t gid = getegid();

    if (chown(SOCKET_PATH, 0, gid) != 0 ||
        chmod(SOCKET_PATH, 0660) != 0) {

        perror("socket permissions");

        unlink(SOCKET_PATH);
        return 1;
    }


    if (listen(listen_fd, BACKLOG) != 0) {
        perror("listen");
        return 1;
    }


    /* ---------- Accept loop ---------- */

    while (!stopping) {

        int client = accept4(
            listen_fd,
            NULL,
            NULL,
            SOCK_CLOEXEC
        );

        if (client < 0) {

            if (errno == EINTR)
                continue;

            if (stopping || errno == EBADF)
                break;

            perror("accept");
            continue;
        }

        handle_client(client);

        close(client);
    }


    unlink(SOCKET_PATH);

    return 0;
}
