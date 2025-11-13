#include "client.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

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

SRPClient *client_connect(const char *host, uint16_t port, const char *username, const char *password) {
    if (!host || !username || !password)
        return NULL;

    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    sprintf(port_str, "%u", port);

    struct addrinfo *result;
    if (getaddrinfo(host, port_str, &hints, &result) != 0)
        return NULL;

    int fd = -1;
    for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;

        close(fd);
        fd = -1;
    }

    freeaddrinfo(result);

    if (fd == -1) {
        fprintf(stderr, "error: failed to connect to server\n");
        return NULL;
    }

    /* Receive AUTH request */
    char line[512];
    if (!read_line(fd, line, sizeof(line)) || strcmp(line, "AUTH") != 0) {
        fprintf(stderr, "error: invalid server response\n");
        close(fd);
        return NULL;
    }

    /* Send credentials */
    String creds = string_from_cstr(username);
    string_append_cstr(&creds, ":");
    string_append_cstr(&creds, password);
    char *creds_str = string_cstr(&creds);
    bool auth_sent = write_line(fd, creds_str);
    string_free(&creds);

    if (!auth_sent) {
        close(fd);
        return NULL;
    }

    /* Receive OK/ERR */
    if (!read_line(fd, line, sizeof(line))) {
        close(fd);
        return NULL;
    }

    if (strncmp(line, "ERR", 3) == 0) {
        fprintf(stderr, "error: authentication failed: %s\n", line);
        close(fd);
        return NULL;
    }

    if (strncmp(line, "OK", 2) != 0) {
        fprintf(stderr, "error: unexpected response: %s\n", line);
        close(fd);
        return NULL;
    }

    SRPClient *client = xmalloc(sizeof(SRPClient));
    client->socket_fd = fd;
    client->username = xstrdup(username);
    client->password = xstrdup(password);
    client->server_host = xstrdup(host);
    client->server_port = port;

    return client;
}

void client_disconnect(SRPClient *client) {
    if (!client)
        return;

    if (client->socket_fd >= 0) {
        write_line(client->socket_fd, "QUIT");
        close(client->socket_fd);
    }

    free(client->username);
    free(client->password);
    free(client->server_host);
    free(client);
}

bool client_claim_port(SRPClient *client, uint16_t port) {
    if (!client || client->socket_fd < 0)
        return false;

    String cmd = string_from_cstr("CLAIM ");
    char port_str[16];
    sprintf(port_str, "%u", port);
    string_append_cstr(&cmd, port_str);
    char *cmd_str = xstrdup(string_cstr(&cmd));
    string_free(&cmd);

    bool sent = write_line(client->socket_fd, cmd_str);
    free(cmd_str);

    if (!sent)
        return false;

    char line[512];
    if (!read_line(client->socket_fd, line, sizeof(line)))
        return false;

    if (strncmp(line, "ERR", 3) == 0) {
        fprintf(stderr, "error: %s\n", line);
        return false;
    }

    return strncmp(line, "OK", 2) == 0;
}

bool client_unclaim_port(SRPClient *client, uint16_t port) {
    if (!client || client->socket_fd < 0)
        return false;

    String cmd = string_from_cstr("UNCLAIM ");
    char port_str[16];
    sprintf(port_str, "%u", port);
    string_append_cstr(&cmd, port_str);
    char *cmd_str = xstrdup(string_cstr(&cmd));
    string_free(&cmd);

    bool sent = write_line(client->socket_fd, cmd_str);
    free(cmd_str);

    if (!sent)
        return false;

    char line[512];
    if (!read_line(client->socket_fd, line, sizeof(line)))
        return false;

    if (strncmp(line, "ERR", 3) == 0) {
        fprintf(stderr, "error: %s\n", line);
        return false;
    }

    return strncmp(line, "OK", 2) == 0;
}

char *client_list_ports(SRPClient *client) {
    if (!client || client->socket_fd < 0)
        return NULL;

    if (!write_line(client->socket_fd, "LIST"))
        return NULL;

    char line[512];
    if (!read_line(client->socket_fd, line, sizeof(line)))
        return NULL;

    return xstrdup(line);
}
