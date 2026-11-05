#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
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

#define CONFIG_FILE "/etc/nfwpunch.conf"
#define SOCKET_PATH "/run/nfwpunch/nfwpunch.sock"
#define NFT_PATH    "/usr/sbin/nft"
#define NFT_TABLE   "nfwpunch"

#define MAX_LINE    256
#define MAX_TIMEOUT 3600
#define MIN_TIMEOUT 60
#define BACKLOG     32

#define MAX_SERVICES   64
#define MAX_RULES      64
#define MAX_NAME       32
#define MAX_PORTS_TEXT 256

struct rule {
    bool v6;
    char proto[4];
    char ports[MAX_PORTS_TEXT];
};

/* Only services declared in the config file can be authorized. */
struct service {
    char name[MAX_NAME];
    char set4[MAX_NAME + 16];
    char set6[MAX_NAME + 16];
    struct rule rules[MAX_RULES];
    size_t rule_count;
};

static struct service services[MAX_SERVICES];
static size_t service_count;
static int hook_priority;

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


static const struct service *find_service(const char *name);


/* ---------- Configuration ---------- */

/* Parses "family:proto:port,port,..." into r. */
static int
parse_rule(char *tok, struct rule *r)
{
    char *proto = strchr(tok, ':');
    char *ports = proto ? strchr(proto + 1, ':') : NULL;

    if (!proto || !ports)
        return -1;

    *proto++ = '\0';
    *ports++ = '\0';

    if (strcmp(tok, "ip") == 0)
        r->v6 = false;
    else if (strcmp(tok, "ip6") == 0)
        r->v6 = true;
    else
        return -1;

    if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0)
        return -1;

    snprintf(r->proto, sizeof(r->proto), "%s", proto);

    r->ports[0] = '\0';

    char *save = NULL;
    int count = 0;

    for (char *p = strtok_r(ports, ",", &save); p;
         p = strtok_r(NULL, ",", &save)) {

        char *end = NULL;

        errno = 0;

        unsigned long port = strtoul(p, &end, 10);

        if (errno || end == p || *end || port < 1 || port > 65535)
            return -1;

        size_t len = strlen(r->ports);

        if (snprintf(r->ports + len, sizeof(r->ports) - len,
                     "%s%lu", count ? ", " : "", port)
            >= (int)(sizeof(r->ports) - len))
            return -1;

        count++;
    }

    return count ? 0 : -1;
}


static int
valid_service_name(const char *name)
{
    size_t len = strlen(name);

    if (len == 0 || len >= MAX_NAME)
        return 0;

    for (size_t i = 0; i < len; i++) {
        char c = name[i];

        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '_'))
            return 0;
    }

    return 1;
}


static char *
trim(char *s)
{
    while (*s == ' ' || *s == '\t')
        s++;

    char *e = s + strlen(s);

    while (e > s && (e[-1] == ' ' || e[-1] == '\t' ||
                     e[-1] == '\n' || e[-1] == '\r'))
        *--e = '\0';

    return s;
}


static int
config_error(unsigned lineno, const char *msg)
{
    fprintf(stderr, "%s:%u: %s\n", CONFIG_FILE, lineno, msg);
    return -1;
}


/* Reads global options and service declarations from CONFIG_FILE. */
static int
load_config(void)
{
    FILE *f = fopen(CONFIG_FILE, "r");

    if (!f) {
        perror(CONFIG_FILE);
        return -1;
    }

    char buf[1024];
    unsigned lineno = 0;
    enum { SECTION_NONE, SECTION_GLOBAL, SECTION_SERVICES } section = SECTION_NONE;
    bool priority_seen = false;
    int ret = 0;

    while (ret == 0 && fgets(buf, sizeof(buf), f)) {

        lineno++;

        if (!strchr(buf, '\n') && !feof(f)) {
            ret = config_error(lineno, "line too long");
            break;
        }

        char *line = trim(buf);

        if (*line == '\0' || *line == ';' || *line == '#')
            continue;

        if (*line == '[') {
            if (strcmp(line, "[global]") == 0)
                section = SECTION_GLOBAL;
            else if (strcmp(line, "[services]") == 0)
                section = SECTION_SERVICES;
            else {
                ret = config_error(lineno, "unknown section");
                break;
            }
            continue;
        }

        char *eq = strchr(line, '=');

        if (section == SECTION_NONE || !eq) {
            ret = config_error(lineno, "expected name = value in [services]");
            break;
        }

        *eq = '\0';

        char *name = trim(line);
        char *value = trim(eq + 1);

        if (section == SECTION_GLOBAL) {
            if (strcmp(name, "hook_priority") != 0 || priority_seen) {
                ret = config_error(lineno, "unknown or duplicate global option");
                break;
            }

            char *end = NULL;
            errno = 0;
            long parsed = strtol(value, &end, 10);

            if (errno == ERANGE || end == value || *end != '\0' ||
                parsed < INT_MIN || parsed > INT_MAX) {
                ret = config_error(lineno, "invalid hook priority");
                break;
            }

            hook_priority = (int)parsed;
            priority_seen = true;
            continue;
        }

        if (!valid_service_name(name)) {
            ret = config_error(lineno, "invalid service name");
            break;
        }

        if (service_count >= MAX_SERVICES || find_service(name)) {
            ret = config_error(lineno, "too many or duplicate services");
            break;
        }

        struct service *svc = &services[service_count];

        memset(svc, 0, sizeof(*svc));
        snprintf(svc->name, sizeof(svc->name), "%s", name);
        snprintf(svc->set4, sizeof(svc->set4), "authorized_%s4", name);
        snprintf(svc->set6, sizeof(svc->set6), "authorized_%s6", name);

        char *save = NULL;

        for (char *tok = strtok_r(value, " \t", &save); tok;
             tok = strtok_r(NULL, " \t", &save)) {

            if (svc->rule_count >= MAX_RULES ||
                parse_rule(tok, &svc->rules[svc->rule_count]) != 0) {
                ret = config_error(lineno, "invalid or too many port specifications");
                break;
            }

            svc->rule_count++;
        }

        if (ret == 0 && svc->rule_count == 0)
            ret = config_error(lineno, "service has no ports");

        if (ret == 0)
            service_count++;
    }

    fclose(f);

    if (ret == 0 && service_count == 0) {
        // Allow empty config without services, but warn the user.
        fprintf(stderr, "%s: no services defined\n", CONFIG_FILE);
    }

    return ret;
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
 * Executes nft with a fixed argument vector (argv is NULL-terminated).
 * No shell is involved.
 */
static int
run_nft_argv(char *const argv[])
{
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


/* Creates the sets of each service and the accept rules referencing them. */
static int
setup_services(void)
{
    static const char *hooks[] = { "input", "forward" };

    for (size_t i = 0; i < service_count; i++) {

        const struct service *svc = &services[i];

        for (int v6 = 0; v6 < 2; v6++) {

            const char *fam = v6 ? "ip6" : "ip";
            const char *set = v6 ? svc->set6 : svc->set4;
            char spec[96];

            snprintf(spec, sizeof(spec),
                     "{ type %s; flags timeout; size 10000; }",
                     v6 ? "ipv6_addr" : "ipv4_addr");

            char *argv[] = {
                (char *)NFT_PATH, "add", "set", (char *)fam,
                (char *)NFT_TABLE, (char *)set, spec, NULL
            };

            if (run_nft_argv(argv) != 0)
                return -1;
        }

        for (size_t r = 0; r < svc->rule_count; r++) {

            const struct rule *rule = &svc->rules[r];
            const char *fam = rule->v6 ? "ip6" : "ip";
            char setref[MAX_NAME + 20];
            char ports[MAX_PORTS_TEXT + 4];

            snprintf(setref, sizeof(setref), "@%s",
                     rule->v6 ? svc->set6 : svc->set4);
            snprintf(ports, sizeof(ports), "{ %s }", rule->ports);

            for (size_t h = 0; h < 2; h++) {

                char chain[48];

                snprintf(chain, sizeof(chain), "nfwpunch_%s%d",
                         hooks[h], rule->v6 ? 6 : 4);

                char *argv[] = {
                    (char *)NFT_PATH, "add", "rule", (char *)fam,
                    (char *)NFT_TABLE, chain,
                    (char *)fam, "saddr", setref,
                    (char *)rule->proto, "dport", ports,
                    "accept", NULL
                };

                if (run_nft_argv(argv) != 0)
                    return -1;
            }
        }
    }

    return 0;
}


/*
 * Creates tables and base chains used by the daemon.
 * Idempotent: "add" does not fail if objects already exist.
 */
static int
init_nft(void)
{
    static const struct {
        const char *family;
        const char *chain;
        const char *hook;
    } chains[] = {
        { "ip",  "nfwpunch_input4",   "input"   },
        { "ip6", "nfwpunch_input6",   "input"   },
        { "ip",  "nfwpunch_forward4", "forward" },
        { "ip6", "nfwpunch_forward6", "forward" },
    };

    static const char *families[] = { "ip", "ip6" };

    for (size_t i = 0; i < sizeof(families) / sizeof(families[0]); i++) {

        char *argv[] = {
            (char *)NFT_PATH, "add", "table",
            (char *)families[i], (char *)NFT_TABLE, NULL
        };

        if (run_nft_argv(argv) != 0)
            return -1;
    }

    for (size_t i = 0; i < sizeof(chains) / sizeof(chains[0]); i++) {

        char spec[96];

        snprintf(spec, sizeof(spec),
                 "{ type filter hook %s priority %d; policy accept; }",
                 chains[i].hook, hook_priority);

        char *argv[] = {
            (char *)NFT_PATH, "add", "chain",
            (char *)chains[i].family, (char *)NFT_TABLE,
            (char *)chains[i].chain, spec, NULL
        };

        if (run_nft_argv(argv) != 0)
            return -1;

        /* Drop rules from a previous run. */
        char *flush[] = {
            (char *)NFT_PATH, "flush", "chain",
            (char *)chains[i].family, (char *)NFT_TABLE,
            (char *)chains[i].chain, NULL
        };

        if (run_nft_argv(flush) != 0)
            return -1;
    }

    return setup_services();
}


/*
 * Executes nft directly.
 *
 * No shell is involved.
 * Table and set names are selected internally.
 * IP addresses have already been validated.
 */
static int
run_nft(const char *operation,
        const char *family,
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
        argv[argc++] = (char *)family;
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
        argv[argc++] = (char *)family;
        argv[argc++] = NFT_TABLE;
        argv[argc++] = (char *)setname;
        argv[argc++] = "{";
        argv[argc++] = element;
        argv[argc++] = "}";

    } else {
        return -1;
    }

    argv[argc] = NULL;

    return run_nft_argv(argv);
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
    const char *nftfam = family == AF_INET ? "ip" : "ip6";


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

        if (run_nft("add", nftfam, setname, ip, timeout) == 0)
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

        if (run_nft("delete", nftfam, setname, ip, 0) == 0)
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

    if (load_config() != 0)
        return 1;

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

  /* Call init_nft() to create the necessary nftables tables and chains */

    if (init_nft() != 0) {
        fprintf(stderr, "failed to initialize nftables\n");
        close(listen_fd);
        unlink(SOCKET_PATH);
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
