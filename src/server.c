#include "server.h"
#include "util.h"
#include "auth.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#define MAX_CLIENTS 64
#define BUFFER_SIZE 256
#define SAVE_INTERVAL 5  /* seconds between saves */

typedef struct {
    ServerClient clients[MAX_CLIENTS];
    int client_count;
    LoginStore *store;
    ServerConfig *cfg;
    int listen_fd;
    time_t last_save;
} ServerState;

static volatile int shutdown_flag = 0;

static void sigint_handler(int sig) {
    (void)sig;
    shutdown_flag = 1;
}

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int server_socket(const char *bind_host, uint16_t bind_port) {
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bind_port);
    
    if (inet_pton(AF_INET, bind_host, &addr.sin_addr) != 1) {
        fprintf(stderr, "error: invalid bind address\n");
        return -1;
    }
    
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }
    
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    
    if (listen(fd, 128) < 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    
    set_nonblocking(fd);
    return fd;
}

static bool read_line(int fd, char *buf, size_t len) {
    size_t pos = 0;
    
    while (pos < len - 1) {
        ssize_t n = recv(fd, buf + pos, 1, 0);
        if (n <= 0)
            return false;
        
        if (buf[pos] == '\n') {
            buf[pos] = '\0';
            return true;
        }
        pos++;
    }
    
    return false;
}

static bool write_line(int fd, const char *msg) {
    String s = string_from_cstr(msg);
    string_append_cstr(&s, "\n");
    
    ssize_t written = send(fd, string_cstr(&s), s.len, MSG_NOSIGNAL);
    bool result = written == (ssize_t)s.len;
    string_free(&s);
    
    return result;
}

static bool client_authenticate(ServerState *state, int fd) {
    if (!write_line(fd, "AUTH"))
        return false;
    
    char line[512];
    if (!read_line(fd, line, sizeof(line)))
        return false;
    
    /* Parse "username:password" */
    char *colon = strchr(line, ':');
    if (!colon)
        return false;
    
    size_t username_len = colon - line;
    if (username_len == 0 || username_len >= 256)
        return false;
    
    char username[256];
    memcpy(username, line, username_len);
    username[username_len] = '\0';
    
    const char *password = colon + 1;
    
    Login *login = loginstore_get(state->store, username);
    if (!login || !verify_password(password, login->passwd_hash)) {
        write_line(fd, "ERR invalid credentials");
        return false;
    }
    
    if (!write_line(fd, "OK"))
        return false;
    
    /* Find or create client slot */
    for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i].socket_fd == fd) {
            memset(state->clients[i].username, 0, 256);
            strncpy(state->clients[i].username, username, 254);
            state->clients[i].authenticated = true;
            return true;
        }
    }
    
    return false;
}

static bool client_claim_port(ServerState *state, int fd, uint16_t port) {
    ServerClient *client = NULL;
    for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i].socket_fd == fd) {
            client = &state->clients[i];
            break;
        }
    }
    
    if (!client)
        return false;
    
    /* Validate port range */
    if (port < state->cfg->min_port || port > state->cfg->max_port) {
        write_line(fd, "ERR port out of range");
        return false;
    }
    
    /* Check restricted ports */
    if (config_port_restricted(state->cfg, port)) {
        write_line(fd, "ERR port restricted");
        return false;
    }
    
    /* Check if port already claimed */
    for (size_t i = 0; i < state->store->count; i++) {
        if (loginstore_has_port(state->store, state->store->logins[i].username, port)) {
            write_line(fd, "ERR port already claimed");
            return false;
        }
    }
    
    /* Check user port quota */
    Login *login = loginstore_get(state->store, client->username);
    if (login && login->claimed_count >= state->cfg->ports_per_login) {
        write_line(fd, "ERR port quota exceeded");
        return false;
    }
    
    /* Claim port */
    if (!loginstore_claim_port(state->store, client->username, port)) {
        write_line(fd, "ERR failed to claim port");
        return false;
    }
    
    String msg = string_from_cstr("OK ");
    char port_str[16];
    sprintf(port_str, "%u", port);
    string_append_cstr(&msg, port_str);
    char *cstr = string_cstr(&msg);
    bool result = write_line(fd, cstr);
    string_free(&msg);
    
    return result;
}

static bool client_unclaim_port(ServerState *state, int fd, uint16_t port) {
    ServerClient *client = NULL;
    for (int i = 0; i < state->client_count; i++) {
        if (state->clients[i].socket_fd == fd) {
            client = &state->clients[i];
            break;
        }
    }
    
    if (!client)
        return false;
    
    if (!loginstore_has_port(state->store, client->username, port)) {
        write_line(fd, "ERR port not claimed by you");
        return false;
    }
    
    if (!loginstore_unclaim_port(state->store, client->username, port)) {
        write_line(fd, "ERR failed to unclaim port");
        return false;
    }
    
    return write_line(fd, "OK");
}

static bool handle_command(ServerState *state, int fd, const char *line) {
    char cmd[64];
    uint16_t port = 0;
    int parsed = sscanf(line, "%63s %hu", cmd, &port);
    
    if (parsed < 1)
        return write_line(fd, "ERR invalid command");
    
    if (strcmp(cmd, CMD_CLAIM) == 0) {
        if (parsed < 2)
            return write_line(fd, "ERR missing port");
        return client_claim_port(state, fd, port);
    } else if (strcmp(cmd, CMD_UNCLAIM) == 0) {
        if (parsed < 2)
            return write_line(fd, "ERR missing port");
        return client_unclaim_port(state, fd, port);
    } else if (strcmp(cmd, CMD_LIST) == 0) {
        /* List all claimed ports for this user */
        ServerClient *client = NULL;
        for (int i = 0; i < state->client_count; i++) {
            if (state->clients[i].socket_fd == fd) {
                client = &state->clients[i];
                break;
            }
        }
        
        if (!client)
            return false;
        
        Login *login = loginstore_get(state->store, client->username);
        if (!login)
            return write_line(fd, "OK");
        
        String msg = string_new(256);
        for (size_t j = 0; j < login->claimed_count; j++) {
            if (j > 0)
                string_append_cstr(&msg, ",");
            char port_str[16];
            sprintf(port_str, "%u", login->claimed_ports[j]);
            string_append_cstr(&msg, port_str);
        }
        
        char *cstr = string_cstr(&msg);
        bool result = write_line(fd, cstr);
        string_free(&msg);
        return result;
    } else if (strcmp(cmd, CMD_QUIT) == 0) {
        write_line(fd, "OK");
        return false;  /* Signal disconnect */
    } else {
        return write_line(fd, "ERR unknown command");
    }
}

static void process_clients(ServerState *state) {
    fd_set readfds;
    FD_ZERO(&readfds);
    int max_fd = state->listen_fd;
    
    for (int i = 0; i < state->client_count; i++) {
        FD_SET(state->clients[i].socket_fd, &readfds);
        if (state->clients[i].socket_fd > max_fd)
            max_fd = state->clients[i].socket_fd;
    }
    FD_SET(state->listen_fd, &readfds);
    
    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    int select_res = select(max_fd + 1, &readfds, NULL, NULL, &tv);
    
    if (select_res < 0 && errno != EINTR) {
        perror("select");
        return;
    }
    
    /* Accept new connections */
    if (FD_ISSET(state->listen_fd, &readfds)) {
        struct sockaddr_in addr;
        socklen_t addr_len = sizeof(addr);
        int client_fd = accept(state->listen_fd, (struct sockaddr *)&addr, &addr_len);
        
        if (client_fd >= 0) {
            if (state->client_count >= MAX_CLIENTS) {
                write_line(client_fd, "ERR server full");
                close(client_fd);
            } else {
                set_nonblocking(client_fd);
                ServerClient *client = &state->clients[state->client_count++];
                client->socket_fd = client_fd;
                client->authenticated = false;
                client->username[0] = '\0';
                
                if (!client_authenticate(state, client_fd)) {
                    close(client_fd);
                    state->client_count--;
                }
            }
        }
    }
    
    /* Process existing clients */
    for (int i = 0; i < state->client_count; ) {
        int fd = state->clients[i].socket_fd;
        
        if (!FD_ISSET(fd, &readfds)) {
            i++;
            continue;
        }
        
        char line[512];
        if (!read_line(fd, line, sizeof(line))) {
            close(fd);
            if (i < state->client_count - 1) {
                memmove(&state->clients[i], &state->clients[i + 1],
                       (state->client_count - i - 1) * sizeof(ServerClient));
            }
            state->client_count--;
            continue;
        }
        
        if (!state->clients[i].authenticated) {
            fprintf(stderr, "error: client sent command before auth\n");
            close(fd);
            if (i < state->client_count - 1) {
                memmove(&state->clients[i], &state->clients[i + 1],
                       (state->client_count - i - 1) * sizeof(ServerClient));
            }
            state->client_count--;
            continue;
        }
        
        bool keep_connected = handle_command(state, fd, line);
        if (!keep_connected) {
            close(fd);
            if (i < state->client_count - 1) {
                memmove(&state->clients[i], &state->clients[i + 1],
                       (state->client_count - i - 1) * sizeof(ServerClient));
            }
            state->client_count--;
        } else {
            i++;
        }
    }
    
    /* Periodic save */
    time_t now = time(NULL);
    if (now - state->last_save >= SAVE_INTERVAL) {
        if (!loginstore_save(state->store, "logins.conf")) {
            fprintf(stderr, "warning: failed to save logins\n");
        }
        state->last_save = now;
    }
}

int server_run(ServerConfig *cfg, LoginStore *store) {
    if (!cfg || !store)
        return 1;
    
    /* Parse bind address */
    char host[256];
    uint16_t port = 0;
    if (!parse_addr(cfg->host, host, sizeof(host), &port)) {
        fprintf(stderr, "error: invalid bind address '%s'\n", cfg->host);
        return 1;
    }
    
    int listen_fd = server_socket(host, port);
    if (listen_fd < 0) {
        return 1;
    }
    
    printf("=== SRP Server ===\n");
    printf("Listening on %s:%u\n", host, port);
    printf("Port range: %u-%u\n", cfg->min_port, cfg->max_port);
    printf("Ports per login: %u\n", cfg->ports_per_login);
    printf("Logins per IP: %u\n", cfg->logins_per_ip);
    printf("Users: %zu\n", store->count);
    printf("\nPress Ctrl+C to shutdown\n\n");
    
    signal(SIGINT, sigint_handler);
    
    ServerState state = {
        .listen_fd = listen_fd,
        .client_count = 0,
        .store = store,
        .cfg = cfg,
        .last_save = time(NULL),
    };
    
    while (!shutdown_flag) {
        process_clients(&state);
    }
    
    printf("\nShutting down...\n");
    
    /* Close all client connections */
    for (int i = 0; i < state.client_count; i++) {
        close(state.clients[i].socket_fd);
    }
    
    close(listen_fd);
    
    /* Final save */
    if (!loginstore_save(store, "logins.conf")) {
        fprintf(stderr, "warning: failed to save logins on shutdown\n");
    }
    
    printf("Server stopped\n");
    return 0;
}
