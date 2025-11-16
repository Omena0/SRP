#include "server.h"
#include "protocol.h"
#include "util.h"
#include "credentials.h"
#include "config.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <sys/select.h>
    #include <signal.h>
#endif

#define MAX_CLIENTS 1024
#define MAX_TUNNELS 4096
#define MAX_FORWARD_PORTS 256
#define BUFFER_SIZE 65536  /* 64KB for high throughput */
#define RELOAD_INTERVAL_SECS 5
#define KEEPALIVE_INTERVAL_SECS 30  /* Send PING every 30s */
#define KEEPALIVE_TIMEOUT_SECS 300  /* Close if no PONG after 5 minutes */

/* Tunnel: maps external client connection to agent via dedicated data socket */
typedef struct {
    uint32_t tunnel_id;
    socket_t client_sock;      /* External client connection */
    socket_t agent_data_sock;  /* Dedicated data socket to agent */
    uint16_t port;
    int agent_idx;       /* Index in clients array */
    uint8_t active;
    thread_t thread;     /* Dedicated thread for this tunnel */
    /* Write buffers for both directions */
    uint8_t* to_agent_buffer;
    size_t to_agent_buffer_size;
    size_t to_agent_buffer_capacity;
    uint8_t* to_client_buffer;
    size_t to_client_buffer_size;
    size_t to_client_buffer_capacity;
} tunnel_t;

/* Client: agent connection */
typedef struct {
    socket_t sock;
    char username[64];
    uint8_t authenticated;
    uint8_t active;
    buffer_t* recv_buffer;
    /* Write buffer for non-blocking sends to agent */
    uint8_t* write_buffer;
    size_t write_buffer_size;
    size_t write_buffer_capacity;
    /* Keepalive tracking */
    uint64_t last_activity;
    uint8_t ping_sent;
} client_t;

/* Forwarded port listener */
typedef struct {
    uint16_t port;
    socket_t listen_sock;
    char owner[64];      /* Username that claimed this port */
    uint8_t active;
} forward_port_t;

/* Server state */
typedef struct {
    server_config_t config;
    login_store_t* login_store;
    socket_t listen_sock;
    socket_t data_listen_sock;

    client_t clients[MAX_CLIENTS];
    tunnel_t tunnels[MAX_TUNNELS];
    forward_port_t forward_ports[MAX_FORWARD_PORTS];

    uint32_t next_tunnel_id;
    uint64_t last_reload;
    uint8_t running;
} server_state_t;

static server_state_t* g_server = NULL;

/* Forward declarations */
static void handle_auth(server_state_t* srv, int client_idx, const message_t* msg);
static void handle_claim(server_state_t* srv, int client_idx, const message_t* msg);
static void handle_unclaim(server_state_t* srv, int client_idx, const message_t* msg);
static void handle_list(server_state_t* srv, int client_idx, const message_t* msg);
static void handle_forward(server_state_t* srv, int client_idx, const message_t* msg);
static void handle_register(server_state_t* srv, int client_idx, const message_t* msg);

/* Signal handler */
#ifdef _WIN32
#include <signal.h>
static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    (void)ctrl_type;
    if (g_server) g_server->running = 0;
    return TRUE;
}
#else
static void signal_handler(int sig) {
    (void)sig;
    if (g_server) g_server->running = 0;
}
#endif

/* Find free slot */
static int find_free_client_slot(server_state_t* srv) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!srv->clients[i].active) return i;
    }
    return -1;
}

static int find_free_tunnel_slot(server_state_t* srv) {
    for (int i = 0; i < MAX_TUNNELS; i++) {
        if (!srv->tunnels[i].active) return i;
    }
    return -1;
}

static int find_free_forward_port_slot(server_state_t* srv) {
    for (int i = 0; i < MAX_FORWARD_PORTS; i++) {
        if (!srv->forward_ports[i].active) return i;
    }
    return -1;
}

/* Find client by username */
static int find_client_by_username(server_state_t* srv, const char* username) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (srv->clients[i].active && srv->clients[i].authenticated &&
            strcmp(srv->clients[i].username, username) == 0) {
            return i;
        }
    }
    return -1;
}

/* Find forward port */
static forward_port_t* find_forward_port(server_state_t* srv, uint16_t port) {
    for (int i = 0; i < MAX_FORWARD_PORTS; i++) {
        if (srv->forward_ports[i].active && srv->forward_ports[i].port == port) {
            return &srv->forward_ports[i];
        }
    }
    return NULL;
}

/* Close client */
static void close_client(server_state_t* srv, int idx) {
    client_t* client = &srv->clients[idx];
    if (!client->active) return;

    log_info("Closing client connection: %s", client->username);
    
    /* Mark inactive immediately to prevent re-entry */
    client->active = 0;

    /* Close all tunnels for this agent */
    for (int i = 0; i < MAX_TUNNELS; i++) {
        if (srv->tunnels[i].active && srv->tunnels[i].agent_idx == idx) {
            socket_close(srv->tunnels[i].client_sock);
            srv->tunnels[i].active = 0;
        }
    }

    /* Close all forwarded ports for this agent */
    for (int i = 0; i < MAX_FORWARD_PORTS; i++) {
        if (srv->forward_ports[i].active &&
            strcmp(srv->forward_ports[i].owner, client->username) == 0) {
            socket_close(srv->forward_ports[i].listen_sock);
            srv->forward_ports[i].active = 0;
            log_info("Closed forwarded port %u", srv->forward_ports[i].port);
        }
    }

    socket_close(client->sock);
    client->sock = INVALID_SOCKET_VALUE;
    /* recv_buffer not used anymore, set to NULL if still present */
    if (client->recv_buffer) {
        buffer_free(client->recv_buffer);
        client->recv_buffer = NULL;
    }
    if (client->write_buffer) {
        xfree(client->write_buffer);
        client->write_buffer = NULL;
    }
    memset(client->username, 0, sizeof(client->username));
    client->authenticated = 0;
}

/* Tunnel worker thread - handles bidirectional forwarding for one tunnel */
static void* tunnel_worker(void* arg) {
    tunnel_t* tunnel = (tunnel_t*)arg;
    uint8_t buffer_client[BUFFER_SIZE];  /* Client->Agent buffer */
    uint8_t buffer_agent[BUFFER_SIZE];   /* Agent->Client buffer */
    fd_set read_fds;
    struct timeval timeout;
    
    log_info("Tunnel %u worker thread started", tunnel->tunnel_id);
    
    /* Wait for agent data socket to be connected */
    int wait_count = 0;
    while (tunnel->active && tunnel->agent_data_sock == INVALID_SOCKET_VALUE) {
        if (++wait_count > 100) { /* 10 second timeout */
            log_error("Tunnel %u: Agent data socket not connected after 10s", tunnel->tunnel_id);
            tunnel->active = 0;
            goto cleanup;
        }
        
        /* Check if client socket is still alive */
        fd_set check_fds;
        FD_ZERO(&check_fds);
        FD_SET(tunnel->client_sock, &check_fds);
        struct timeval check_timeout = {0, 0};
        int check_ready = select(tunnel->client_sock + 1, &check_fds, NULL, NULL, &check_timeout);
        if (check_ready > 0) {
            /* Data available or socket closed - check by reading */
            char check_byte;
            int peek_result = recv(tunnel->client_sock, &check_byte, 1, MSG_PEEK);
            if (peek_result <= 0) {
                log_info("Tunnel %u: Client disconnected while waiting for agent data socket", tunnel->tunnel_id);
                tunnel->active = 0;
                goto cleanup;
            }
        }
        
#ifdef _WIN32
        Sleep(100);
#else
        usleep(100000);
#endif
    }
    
    if (!tunnel->active) goto cleanup;
    
    log_debug("Tunnel %u: Starting bidirectional forwarding", tunnel->tunnel_id);
    
    while (tunnel->active) {
        FD_ZERO(&read_fds);
        FD_SET(tunnel->client_sock, &read_fds);
        FD_SET(tunnel->agent_data_sock, &read_fds);
        
        timeout.tv_sec = 0;
        timeout.tv_usec = 1000; /* 1ms - low latency for data forwarding */
        
        socket_t max_fd = tunnel->client_sock > tunnel->agent_data_sock ? 
                         tunnel->client_sock : tunnel->agent_data_sock;
        int ready = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (ready < 0) {
            log_error("Tunnel %u: select() failed: %d", tunnel->tunnel_id, socket_errno);
            break;
        }
        
        if (ready == 0) continue;
        
        /* Forward client -> agent */
        if (FD_ISSET(tunnel->client_sock, &read_fds)) {
            int received = recv(tunnel->client_sock, (char*)buffer_client, sizeof(buffer_client), 0);
            if (received <= 0) {
                if (received == 0 || !socket_would_block(socket_errno)) {
                    log_info("Tunnel %u: Client disconnected", tunnel->tunnel_id);
                    break;
                }
            } else {
                /* Send all data to agent */
                size_t sent = 0;
                while (sent < (size_t)received) {
                    int s = send(tunnel->agent_data_sock, (const char*)buffer_client + sent,
                               received - sent, MSG_NOSIGNAL);
                    if (s < 0) {
                        if (!socket_would_block(socket_errno)) {
                            log_error("Tunnel %u: Failed to send to agent: %d", 
                                    tunnel->tunnel_id, socket_errno);
                            goto cleanup;
                        }
                        /* Wait for socket to be writable */
                        fd_set wfds;
                        FD_ZERO(&wfds);
                        FD_SET(tunnel->agent_data_sock, &wfds);
                        struct timeval tv = {5, 0};
                        if (select(tunnel->agent_data_sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
                            log_error("Tunnel %u: Send timeout", tunnel->tunnel_id);
                            goto cleanup;
                        }
                        continue;
                    }
                    sent += s;
                }
            }
        }
        
        /* Forward agent -> client */
        if (FD_ISSET(tunnel->agent_data_sock, &read_fds)) {
            int received = recv(tunnel->agent_data_sock, (char*)buffer_agent, sizeof(buffer_agent), 0);
            if (received <= 0) {
                if (received == 0 || !socket_would_block(socket_errno)) {
                    log_info("Tunnel %u: Agent disconnected", tunnel->tunnel_id);
                    break;
                }
            } else {
                /* Send all data to client */
                size_t sent = 0;
                while (sent < (size_t)received) {
                    int s = send(tunnel->client_sock, (const char*)buffer_agent + sent,
                               received - sent, MSG_NOSIGNAL);
                    if (s < 0) {
                        if (!socket_would_block(socket_errno)) {
                            log_error("Tunnel %u: Failed to send to client: %d", 
                                    tunnel->tunnel_id, socket_errno);
                            goto cleanup;
                        }
                        /* Wait for socket to be writable */
                        fd_set wfds;
                        FD_ZERO(&wfds);
                        FD_SET(tunnel->client_sock, &wfds);
                        struct timeval tv = {5, 0};
                        if (select(tunnel->client_sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
                            log_error("Tunnel %u: Send timeout", tunnel->tunnel_id);
                            goto cleanup;
                        }
                        continue;
                    }
                    sent += s;
                }
            }
        }
    }
    
cleanup:
    log_info("Tunnel %u worker thread cleaning up", tunnel->tunnel_id);
    
    /* Close sockets */
    socket_close(tunnel->client_sock);
    tunnel->client_sock = INVALID_SOCKET_VALUE;
    if (tunnel->agent_data_sock != INVALID_SOCKET_VALUE) {
        socket_close(tunnel->agent_data_sock);
        tunnel->agent_data_sock = INVALID_SOCKET_VALUE;
    }
    
    /* Free buffers if allocated */
    if (tunnel->to_agent_buffer) {
        xfree(tunnel->to_agent_buffer);
        tunnel->to_agent_buffer = NULL;
    }
    if (tunnel->to_client_buffer) {
        xfree(tunnel->to_client_buffer);
        tunnel->to_client_buffer = NULL;
    }
    
    tunnel->active = 0;
    log_info("Tunnel %u worker thread finished", tunnel->tunnel_id);
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

/* Close tunnel */
static void close_tunnel(server_state_t* srv, int idx) {
    tunnel_t* tunnel = &srv->tunnels[idx];
    if (!tunnel->active) return;

    /* Mark inactive to signal thread to stop */
    tunnel->active = 0;
    
    /* Thread is detached, so no need to join - resources freed automatically */
    /* Just give it a moment to exit gracefully */
    platform_sleep_ms(10);

    /* Notify agent of tunnel close via control socket */
    if (srv->clients[tunnel->agent_idx].active) {
        message_t* msg = message_create_tunnel_close(tunnel->tunnel_id);
        message_send(srv->clients[tunnel->agent_idx].sock, msg);
        message_free(msg);
    }

    /* Thread may have already closed sockets and freed buffers, check before cleanup */
    if (tunnel->client_sock != INVALID_SOCKET_VALUE) {
        socket_close(tunnel->client_sock);
    }
    if (tunnel->agent_data_sock != INVALID_SOCKET_VALUE) {
        socket_close(tunnel->agent_data_sock);
    }

    /* Free write buffers if still allocated */
    if (tunnel->to_agent_buffer) {
        xfree(tunnel->to_agent_buffer);
        tunnel->to_agent_buffer = NULL;
    }
    if (tunnel->to_client_buffer) {
        xfree(tunnel->to_client_buffer);
        tunnel->to_client_buffer = NULL;
    }
    tunnel->to_agent_buffer_size = 0;
    tunnel->to_agent_buffer_capacity = 0;
    tunnel->to_client_buffer_size = 0;
    tunnel->to_client_buffer_capacity = 0;

    tunnel->tunnel_id = 0;
    tunnel->agent_data_sock = INVALID_SOCKET_VALUE;
    tunnel->client_sock = INVALID_SOCKET_VALUE;
    tunnel->active = 0;
}

/* Create forwarded port listener */
static int create_forward_port(server_state_t* srv, uint16_t port, const char* owner) {
    int idx = find_free_forward_port_slot(srv);
    if (idx < 0) {
        log_error("No free forward port slots");
        return -1;
    }

    /* Create listening socket */
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET_VALUE) {
        log_error("Failed to create forward socket: %d", socket_errno);
        return -1;
    }

    socket_set_reuseaddr(sock);
    socket_set_nonblocking(sock);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Failed to bind forward port %u: %d", port, socket_errno);
        socket_close(sock);
        return -1;
    }

    if (listen(sock, 32) < 0) {
        log_error("Failed to listen on forward port %u: %d", port, socket_errno);
        socket_close(sock);
        return -1;
    }

    srv->forward_ports[idx].port = port;
    srv->forward_ports[idx].listen_sock = sock;
    strncpy(srv->forward_ports[idx].owner, owner, sizeof(srv->forward_ports[idx].owner) - 1);
    srv->forward_ports[idx].owner[sizeof(srv->forward_ports[idx].owner) - 1] = '\0';
    srv->forward_ports[idx].active = 1;

    log_info("Created forward port %u for user %s", port, owner);
    return 0;
}

/* Handle authentication */
static void handle_auth(server_state_t* srv, int client_idx, const message_t* msg) {
    client_t* client = &srv->clients[client_idx];
    auth_payload_t auth;

    if (message_parse_auth(msg, &auth) != 0) {
        log_error("Failed to parse AUTH message");
        message_t* err = message_create_error("Invalid AUTH message");
        message_send(client->sock, err);
        message_free(err);
        close_client(srv, client_idx);
        return;
    }

    /* Verify credentials */
    if (!login_store_verify_password(srv->login_store, auth.username, auth.password)) {
        log_warn("Authentication failed for user: %s", auth.username);
        message_t* err = message_create_error("Authentication failed");
        message_send(client->sock, err);
        message_free(err);
        close_client(srv, client_idx);
        return;
    }

    /* Check if user already connected - disconnect old session */
    int existing = find_client_by_username(srv, auth.username);
    if (existing >= 0) {
        log_info("User %s reconnecting, closing old session", auth.username);
        close_client(srv, existing);
    }

    strncpy(client->username, auth.username, sizeof(client->username) - 1);
    client->username[sizeof(client->username) - 1] = '\0';
    client->authenticated = 1;

    log_info("User authenticated: %s", client->username);

    /* Create forward listeners for any ports this user has claimed */
    user_t* user = login_store_find_user(srv->login_store, client->username);
    if (user) {
        for (int i = 0; i < user->claimed_count; i++) {
            uint16_t port = user->claimed_ports[i];
            if (!find_forward_port(srv, port)) {
                if (create_forward_port(srv, port, client->username) == 0) {
                    log_info("Created forward port %u for user %s", port, client->username);
                }
            }
        }
    }

    /* Send OK */
    message_t* ok = message_create_ok();
    message_send(client->sock, ok);
    message_free(ok);
}

/* Handle CLAIM */
static void handle_claim(server_state_t* srv, int client_idx, const message_t* msg) {
    client_t* client = &srv->clients[client_idx];

    if (!client->authenticated) {
        message_t* err = message_create_error("Not authenticated");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    port_payload_t payload;
    if (message_parse_port(msg, &payload) != 0) {
        message_t* err = message_create_error("Invalid CLAIM message");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    uint16_t port = payload.port;

    /* Validate port range */
    if (port < srv->config.min_port || port > srv->config.max_port) {
        message_t* err = message_create_error("Port out of allowed range");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    /* Check if port already claimed */
    const char* owner = login_store_port_owner(srv->login_store, port);
    if (owner && strcmp(owner, client->username) != 0) {
        message_t* err = message_create_error("Port already claimed by another user");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    /* Check user port limit */
    user_t* user = login_store_find_user(srv->login_store, client->username);
    if (user && user->claimed_count >= srv->config.ports_per_login) {
        message_t* err = message_create_error("Port limit reached");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    /* Claim port in database */
    if (login_store_claim_port(srv->login_store, client->username, port) != 0) {
        message_t* err = message_create_error("Failed to claim port");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    /* Create forward port listener if not exists */
    if (!find_forward_port(srv, port)) {
        if (create_forward_port(srv, port, client->username) != 0) {
            login_store_unclaim_port(srv->login_store, client->username, port);
            message_t* err = message_create_error("Failed to create forward listener");
            message_send(client->sock, err);
            message_free(err);
            return;
        }
    }

    log_info("User %s claimed port %u", client->username, port);

    message_t* ok = message_create_ok();
    message_send(client->sock, ok);
    message_free(ok);
}

/* Handle UNCLAIM */
static void handle_unclaim(server_state_t* srv, int client_idx, const message_t* msg) {
    client_t* client = &srv->clients[client_idx];

    if (!client->authenticated) {
        message_t* err = message_create_error("Not authenticated");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    port_payload_t payload;
    if (message_parse_port(msg, &payload) != 0) {
        message_t* err = message_create_error("Invalid UNCLAIM message");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    uint16_t port = payload.port;

    /* Verify ownership */
    if (!login_store_has_claimed(srv->login_store, client->username, port)) {
        message_t* err = message_create_error("Port not claimed by you");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    /* Close forward port */
    forward_port_t* fp = find_forward_port(srv, port);
    if (fp) {
        socket_close(fp->listen_sock);
        fp->active = 0;
    }

    /* Close all tunnels for this port */
    for (int i = 0; i < MAX_TUNNELS; i++) {
        if (srv->tunnels[i].active && srv->tunnels[i].port == port) {
            close_tunnel(srv, i);
        }
    }

    /* Unclaim from database */
    login_store_unclaim_port(srv->login_store, client->username, port);

    log_info("User %s unclaimed port %u", client->username, port);

    message_t* ok = message_create_ok();
    message_send(client->sock, ok);
    message_free(ok);
}

/* Handle LIST */
static void handle_list(server_state_t* srv, int client_idx, const message_t* msg) {
    (void)msg;
    client_t* client = &srv->clients[client_idx];

    if (!client->authenticated) {
        message_t* err = message_create_error("Not authenticated");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    user_t* user = login_store_find_user(srv->login_store, client->username);
    if (!user) {
        message_t* resp = message_create_list_response(NULL, 0);
        message_send(client->sock, resp);
        message_free(resp);
        return;
    }

    message_t* resp = message_create_list_response(user->claimed_ports, user->claimed_count);
    message_send(client->sock, resp);
    message_free(resp);
}

/* Handle FORWARD - agent requests a forward port without claiming */
static void handle_forward(server_state_t* srv, int client_idx, const message_t* msg) {
    client_t* client = &srv->clients[client_idx];

    if (!client->authenticated) {
        message_t* err = message_create_error("Not authenticated");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    port_payload_t payload;
    if (message_parse_port(msg, &payload) != 0) {
        message_t* err = message_create_error("Invalid FORWARD message");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    uint16_t port = payload.port;

    /* Validate port range */
    if (port < srv->config.min_port || port > srv->config.max_port) {
        message_t* err = message_create_error("Port out of allowed range");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    /* Check if port is already claimed by someone else */
    const char* owner = login_store_port_owner(srv->login_store, port);
    if (owner && strcmp(owner, client->username) != 0) {
        message_t* err = message_create_error("Port claimed by another user");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    /* Check if forward port already exists */
    forward_port_t* existing = find_forward_port(srv, port);
    if (existing) {
        /* If it's ours, that's fine */
        if (strcmp(existing->owner, client->username) == 0) {
            message_t* ok = message_create_ok();
            message_send(client->sock, ok);
            message_free(ok);
            return;
        }
        /* Someone else is forwarding it */
        message_t* err = message_create_error("Port already being forwarded");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    /* Create forward port listener */
    if (create_forward_port(srv, port, client->username) != 0) {
        message_t* err = message_create_error("Failed to create forward listener");
        message_send(client->sock, err);
        message_free(err);
        return;
    }

    log_info("User %s forwarding port %u", client->username, port);

    message_t* ok = message_create_ok();
    message_send(client->sock, ok);
    message_free(ok);
}

/* Handle REGISTER */
static void handle_register(server_state_t* srv, int client_idx, const message_t* msg) {
    client_t* client = &srv->clients[client_idx];
    
    auth_payload_t reg;
    if (message_parse_register(msg, &reg) != 0) {
        log_error("Failed to parse REGISTER message");
        message_t* err = message_create_error("Invalid REGISTER message");
        message_send(client->sock, err);
        message_free(err);
        close_client(srv, client_idx);
        return;
    }
    
    /* Validate username and password */
    if (strlen(reg.username) == 0 || strlen(reg.password) == 0) {
        log_warn("Registration failed: empty username or password");
        message_t* err = message_create_error("Username and password cannot be empty");
        message_send(client->sock, err);
        message_free(err);
        close_client(srv, client_idx);
        return;
    }
    
    /* Check if user already exists */
    if (login_store_find_user(srv->login_store, reg.username) != NULL) {
        log_warn("Registration failed: user %s already exists", reg.username);
        message_t* err = message_create_error("Username already exists");
        message_send(client->sock, err);
        message_free(err);
        close_client(srv, client_idx);
        return;
    }
    
    /* Add user to login store */
    if (login_store_add_user(srv->login_store, reg.username, reg.password) != 0) {
        log_error("Failed to register user: %s", reg.username);
        message_t* err = message_create_error("Failed to create user account");
        message_send(client->sock, err);
        message_free(err);
        close_client(srv, client_idx);
        return;
    }
    
    log_info("User registered: %s", reg.username);
    
    /* Send OK and close connection */
    message_t* ok = message_create_ok();
    message_send(client->sock, ok);
    message_free(ok);
    
    /* Close connection after registration */
    close_client(srv, client_idx);
}

/* Handle client message */
static void handle_client_message(server_state_t* srv, int client_idx) {
    client_t* client = &srv->clients[client_idx];

    /* Drain all pending messages from this client */
    while (1) {
        int would_block = 0;
        message_t* msg = message_receive_nonblocking(client->sock, &would_block);

        if (!msg) {
            if (!would_block) {
                log_info("Agent %s disconnected",
                         client->username[0] ? client->username : "(unauthenticated)");
                close_client(srv, client_idx);
            }
            return;
        }

        log_info("Received message type 0x%02x from client %s", msg->type, client->username[0] ? client->username : "(unauthenticated)");

        /* Update activity timestamp */
        client->last_activity = get_timestamp();
        client->ping_sent = 0;

        switch (msg->type) {
            case MSG_AUTH:
                handle_auth(srv, client_idx, msg);
                break;
            case MSG_CLAIM:
                handle_claim(srv, client_idx, msg);
                break;
            case MSG_UNCLAIM:
                handle_unclaim(srv, client_idx, msg);
                break;
            case MSG_LIST:
                handle_list(srv, client_idx, msg);
                break;
            case MSG_FORWARD:
                handle_forward(srv, client_idx, msg);
                break;
            case MSG_REGISTER:
                handle_register(srv, client_idx, msg);
                break;
            case MSG_TUNNEL_CLOSE:
                /* Agent is notifying us to close a tunnel (e.g., failed to connect data socket) */
                {
                    tunnel_close_payload_t payload;
                    if (message_parse_tunnel_close(msg, &payload) == 0) {
                        /* Find and close the tunnel */
                        for (int i = 0; i < MAX_TUNNELS; i++) {
                            if (srv->tunnels[i].active && srv->tunnels[i].tunnel_id == payload.tunnel_id) {
                                log_info("Agent requested close of tunnel %u", payload.tunnel_id);
                                close_tunnel(srv, i);
                                break;
                            }
                        }
                    }
                }
                break;
            case MSG_PING:
                /* Respond with PONG */
                {
                    message_t* pong = message_create_pong();
                    message_send(client->sock, pong);
                    message_free(pong);
                }
                break;
            case MSG_PONG:
                /* Just update activity timestamp (already done above) */
                log_debug("Received PONG from client %s", client->username);
                break;
            default:
                log_warn("Unknown message type from client: 0x%02x", msg->type);
                break;
        }

        message_free(msg);
    }
}

/* Handle new external client connection on forwarded port */
static void handle_forward_port_connection(server_state_t* srv, int fp_idx) {
    forward_port_t* fp = &srv->forward_ports[fp_idx];

    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    socket_t client_sock = accept(fp->listen_sock, (struct sockaddr*)&addr, &addrlen);

    if (client_sock == INVALID_SOCKET_VALUE) {
        int err = socket_errno;
        if (!socket_would_block(err)) {
            log_error("Failed to accept forward connection: %d", err);
        }
        return;
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, client_ip, sizeof(client_ip));
    log_info("New client connection on port %u from %s:%u", fp->port, client_ip, ntohs(addr.sin_port));

    socket_set_nonblocking(client_sock);
    socket_set_nodelay(client_sock);

    /* Set reasonable buffers for throughput without excessive memory */
    int bufsize = 512 * 1024; /* 512KB - good balance for Minecraft */
    setsockopt(client_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize, sizeof(bufsize));
    setsockopt(client_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&bufsize, sizeof(bufsize));

    /* Enable TCP keepalive */
    int keepalive = 1;
    setsockopt(client_sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));

#ifndef _WIN32
    /* Linux-specific: faster ACKs for lower latency */
    int quickack = 1;
    setsockopt(client_sock, IPPROTO_TCP, TCP_QUICKACK, &quickack, sizeof(quickack));

    /* Tune keepalive settings for faster dead connection detection */
    int keepidle = 30;  /* Start probes after 30s idle */
    int keepintvl = 5;  /* Probe every 5s */
    int keepcnt = 3;    /* Drop after 3 failed probes */
    setsockopt(client_sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(client_sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(client_sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
#endif

    /* Find agent for this port */
    int agent_idx = find_client_by_username(srv, fp->owner);
    if (agent_idx < 0) {
        log_warn("Agent not connected for port %u", fp->port);
        socket_close(client_sock);
        return;
    }

    /* Rate limiting: Count pending tunnels for this agent (no data socket yet) */
    int pending_count = 0;
    for (int i = 0; i < MAX_TUNNELS; i++) {
        if (srv->tunnels[i].active && 
            srv->tunnels[i].agent_idx == agent_idx &&
            srv->tunnels[i].agent_data_sock == INVALID_SOCKET_VALUE) {
            pending_count++;
        }
    }
    
    /* Limit to 100 pending tunnels per agent to prevent DoS while allowing burst connections */
    if (pending_count >= 100) {
        log_warn("Too many pending tunnels (%d) for agent on port %u, rejecting connection", 
                 pending_count, fp->port);
        socket_close(client_sock);
        return;
    }

    /* Create tunnel */
    int tunnel_idx = find_free_tunnel_slot(srv);
    if (tunnel_idx < 0) {
        log_error("No free tunnel slots");
        socket_close(client_sock);
        return;
    }

    tunnel_t* tunnel = &srv->tunnels[tunnel_idx];
    tunnel->tunnel_id = srv->next_tunnel_id++;
    tunnel->client_sock = client_sock;
    tunnel->agent_data_sock = INVALID_SOCKET_VALUE; /* Will be set when agent connects */
    tunnel->port = fp->port;
    tunnel->agent_idx = agent_idx;
    tunnel->to_agent_buffer = NULL;
    tunnel->to_agent_buffer_size = 0;
    tunnel->to_agent_buffer_capacity = 0;
    tunnel->to_client_buffer = NULL;
    tunnel->to_client_buffer_size = 0;
    tunnel->to_client_buffer_capacity = 0;
    tunnel->active = 1;
    tunnel->thread = 0;

    /* Notify agent to connect back on data port for this tunnel */
    message_t* msg = message_create_tunnel_open(tunnel->tunnel_id, fp->port, srv->config.data_port);
    if (message_send(srv->clients[agent_idx].sock, msg) != 0) {
        log_error("Failed to send TUNNEL_OPEN to agent");
        close_tunnel(srv, tunnel_idx);
        message_free(msg);
        return;
    }
    message_free(msg);

    log_info("Created tunnel %u for port %u, waiting for agent data connection", tunnel->tunnel_id, fp->port);
    
    /* Spawn worker thread with 256KB stack (instead of default 1-8MB) to reduce virtual memory per thread */
    if (thread_create_with_stack(&tunnel->thread, (thread_func_t)tunnel_worker, tunnel, 256 * 1024) != 0) {
        log_error("Failed to create worker thread for tunnel %u", tunnel->tunnel_id);
        close_tunnel(srv, tunnel_idx);
        return;
    }
    
    /* Detach thread so resources are freed automatically when it exits */
    thread_detach(tunnel->thread);
    tunnel->thread = 0; /* Mark as detached */
    
    log_debug("Tunnel %u worker thread spawned (detached)", tunnel->tunnel_id);
}

/* Handle data from external client - forward raw bytes to agent via data socket */
static void handle_tunnel_data(server_state_t* srv, int tunnel_idx) {
    tunnel_t* tunnel = &srv->tunnels[tunnel_idx];

    if (tunnel->agent_data_sock == INVALID_SOCKET_VALUE) {
        /* Data socket not connected yet - buffer data temporarily */
        uint8_t buffer[BUFFER_SIZE];
        int received = recv(tunnel->client_sock, (char*)buffer, sizeof(buffer), 0);
        if (received <= 0) {
            if (received == 0 || !socket_would_block(socket_errno)) {
                log_info("Tunnel %u client disconnected while waiting for data socket", tunnel->tunnel_id);
                close_tunnel(srv, tunnel_idx);
            }
            return;
        }

        /* Buffer the data */
        size_t new_size = tunnel->to_agent_buffer_size + received;
        if (new_size > tunnel->to_agent_buffer_capacity) {
            tunnel->to_agent_buffer_capacity = new_size * 2;
            if (tunnel->to_agent_buffer_capacity == 0) tunnel->to_agent_buffer_capacity = 65536;
            if (tunnel->to_agent_buffer_capacity > 2097152) { /* 2MB limit for buffering before data socket ready */
                log_error("Tunnel %u buffer overflow waiting for data socket, closing", tunnel->tunnel_id);
                close_tunnel(srv, tunnel_idx);
                return;
            }
            tunnel->to_agent_buffer = (uint8_t*)xrealloc(tunnel->to_agent_buffer, tunnel->to_agent_buffer_capacity);
        }
        memcpy(tunnel->to_agent_buffer + tunnel->to_agent_buffer_size, buffer, received);
        tunnel->to_agent_buffer_size += received;
        return;
    }

    uint8_t buffer[BUFFER_SIZE];
    int received = recv(tunnel->client_sock, (char*)buffer, sizeof(buffer), 0);

    if (received <= 0) {
        if (received < 0) {
            int err = socket_errno;
            if (!socket_would_block(err)) {
                log_info("Tunnel %u client disconnected: %d", tunnel->tunnel_id, err);
                close_tunnel(srv, tunnel_idx);
            }
        } else {
            log_info("Tunnel %u client closed connection", tunnel->tunnel_id);
            close_tunnel(srv, tunnel_idx);
        }
        return;
    }

    /* If buffer has data, append new data to maintain order */
    if (tunnel->to_agent_buffer_size > 0) {
        size_t new_size = tunnel->to_agent_buffer_size + received;
        if (new_size > tunnel->to_agent_buffer_capacity) {
            tunnel->to_agent_buffer_capacity = new_size * 2;
            if (tunnel->to_agent_buffer_capacity == 0) tunnel->to_agent_buffer_capacity = 65536;
            if (tunnel->to_agent_buffer_capacity > 134217728) {
                log_error("Tunnel %u to-agent buffer overflow", tunnel->tunnel_id);
                close_tunnel(srv, tunnel_idx);
                return;
            }
            tunnel->to_agent_buffer = (uint8_t*)xrealloc(tunnel->to_agent_buffer,
                                                         tunnel->to_agent_buffer_capacity);
        }
        memcpy(tunnel->to_agent_buffer + tunnel->to_agent_buffer_size, buffer, received);
        tunnel->to_agent_buffer_size += received;
        return;
    }

    /* Send raw bytes directly to agent data socket - ZERO OVERHEAD! */
    size_t total_sent = 0;
    while (total_sent < (size_t)received) {
        int sent = send(tunnel->agent_data_sock, (const char*)buffer + total_sent,
                       received - total_sent, MSG_NOSIGNAL);
        if (sent < 0) {
            int err = socket_errno;
            if (socket_would_block(err)) {
                /* Buffer remaining data */
                size_t remaining = received - total_sent;
                size_t new_size = tunnel->to_agent_buffer_size + remaining;
                if (new_size > tunnel->to_agent_buffer_capacity) {
                    tunnel->to_agent_buffer_capacity = new_size * 2;
                    if (tunnel->to_agent_buffer_capacity == 0) tunnel->to_agent_buffer_capacity = 65536;
                    if (tunnel->to_agent_buffer_capacity > 134217728) {
                        log_error("Tunnel %u to-agent buffer overflow", tunnel->tunnel_id);
                        close_tunnel(srv, tunnel_idx);
                        return;
                    }
                    tunnel->to_agent_buffer = (uint8_t*)xrealloc(tunnel->to_agent_buffer,
                                                                 tunnel->to_agent_buffer_capacity);
                }
                memcpy(tunnel->to_agent_buffer + tunnel->to_agent_buffer_size,
                       buffer + total_sent, remaining);
                tunnel->to_agent_buffer_size += remaining;
                return;
            }
            log_error("Failed to send to agent data socket: %d", err);
            close_tunnel(srv, tunnel_idx);
            return;
        }
        total_sent += sent;
    }
}

/* Handle data from agent - forward raw bytes to external client */
static void handle_agent_tunnel_data(server_state_t* srv, int tunnel_idx) {
    tunnel_t* tunnel = &srv->tunnels[tunnel_idx];

    uint8_t buffer[BUFFER_SIZE];
    int received = recv(tunnel->agent_data_sock, (char*)buffer, sizeof(buffer), 0);

    if (received <= 0) {
        if (received < 0) {
            int err = socket_errno;
            if (!socket_would_block(err)) {
                log_info("Tunnel %u agent disconnected: %d", tunnel->tunnel_id, err);
                close_tunnel(srv, tunnel_idx);
            }
        } else {
            log_info("Tunnel %u agent closed connection", tunnel->tunnel_id);
            close_tunnel(srv, tunnel_idx);
        }
        return;
    }

    /* If buffer has data, append new data to maintain order */
    if (tunnel->to_client_buffer_size > 0) {
        size_t new_size = tunnel->to_client_buffer_size + received;
        if (new_size > tunnel->to_client_buffer_capacity) {
            tunnel->to_client_buffer_capacity = new_size * 2;
            if (tunnel->to_client_buffer_capacity == 0) tunnel->to_client_buffer_capacity = 65536;
            if (tunnel->to_client_buffer_capacity > 134217728) {
                log_error("Tunnel %u to-client buffer overflow", tunnel->tunnel_id);
                close_tunnel(srv, tunnel_idx);
                return;
            }
            tunnel->to_client_buffer = (uint8_t*)xrealloc(tunnel->to_client_buffer,
                                                          tunnel->to_client_buffer_capacity);
        }
        memcpy(tunnel->to_client_buffer + tunnel->to_client_buffer_size, buffer, received);
        tunnel->to_client_buffer_size += received;
        return;
    }

    //log_debug("Received %d bytes from agent on tunnel %u", received, tunnel->tunnel_id);

    /* Send raw bytes directly to client - ZERO OVERHEAD! */
    size_t total_sent = 0;
    while (total_sent < (size_t)received) {
        int sent = send(tunnel->client_sock, (const char*)buffer + total_sent,
                       received - total_sent, MSG_NOSIGNAL);
        if (sent < 0) {
            int err = socket_errno;
            if (socket_would_block(err)) {
                /* Buffer remaining data */
                size_t remaining = received - total_sent;
                size_t new_size = tunnel->to_client_buffer_size + remaining;
                if (new_size > tunnel->to_client_buffer_capacity) {
                    tunnel->to_client_buffer_capacity = new_size * 2;
                    if (tunnel->to_client_buffer_capacity == 0) tunnel->to_client_buffer_capacity = 65536;
                    if (tunnel->to_client_buffer_capacity > 134217728) {
                        log_error("Tunnel %u to-client buffer overflow", tunnel->tunnel_id);
                        close_tunnel(srv, tunnel_idx);
                        return;
                    }
                    tunnel->to_client_buffer = (uint8_t*)xrealloc(tunnel->to_client_buffer,
                                                                  tunnel->to_client_buffer_capacity);
                }
                memcpy(tunnel->to_client_buffer + tunnel->to_client_buffer_size,
                       buffer + total_sent, remaining);
                tunnel->to_client_buffer_size += remaining;
                return;
            }
            log_error("Failed to send to client: %d", err);
            close_tunnel(srv, tunnel_idx);
            return;
        }
        total_sent += sent;
    }
}

/* Main server loop */
int server_run(const char* config_path) {
    server_state_t srv;
    memset(&srv, 0, sizeof(srv));
    g_server = &srv;

    /* Load configuration */
    if (config_load_server(config_path, &srv.config) != 0) {
        log_error("Failed to load server configuration");
        return -1;
    }

    /* Load login store */
    srv.login_store = login_store_create("logins.conf");
    login_store_load(srv.login_store);

    /* Create listening socket */
    srv.listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (srv.listen_sock == INVALID_SOCKET_VALUE) {
        log_error("Failed to create listening socket: %d", socket_errno);
        return -1;
    }

    socket_set_reuseaddr(srv.listen_sock);
    socket_set_nonblocking(srv.listen_sock);

    struct sockaddr_in addr;
    if (resolve_address(srv.config.host, srv.config.port, &addr) != 0) {
        log_error("Failed to resolve address: %s:%u", srv.config.host, srv.config.port);
        return -1;
    }

    if (bind(srv.listen_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Failed to bind: %d", socket_errno);
        return -1;
    }

    if (listen(srv.listen_sock, 32) < 0) {
        log_error("Failed to listen: %d", socket_errno);
        return -1;
    }

    /* Create dedicated data listener (agents connect here for raw tunnel bytes) */
    srv.data_listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (srv.data_listen_sock == INVALID_SOCKET_VALUE) {
        log_error("Failed to create data listening socket: %d", socket_errno);
        socket_close(srv.listen_sock);
        return -1;
    }
    socket_set_reuseaddr(srv.data_listen_sock);
    socket_set_nonblocking(srv.data_listen_sock);
    struct sockaddr_in data_addr;
    if (resolve_address(srv.config.host, srv.config.data_port, &data_addr) != 0) {
        log_error("Failed to resolve data listen address: %s:%u", srv.config.host, srv.config.data_port);
        socket_close(srv.listen_sock);
        socket_close(srv.data_listen_sock);
        return -1;
    }
    if (bind(srv.data_listen_sock, (struct sockaddr*)&data_addr, sizeof(data_addr)) < 0) {
        log_error("Failed to bind data socket: %d", socket_errno);
        socket_close(srv.listen_sock);
        socket_close(srv.data_listen_sock);
        return -1;
    }
    if (listen(srv.data_listen_sock, 32) < 0) {
        log_error("Failed to listen on data socket: %d", socket_errno);
        socket_close(srv.listen_sock);
        socket_close(srv.data_listen_sock);
        return -1;
    }

    log_info("Data listener on %s:%u", srv.config.host, srv.config.data_port);

    log_info("Server listening on %s:%u", srv.config.host, srv.config.port);

    log_info("Setting up event loop...");

#ifdef _WIN32
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif

    srv.running = 1;
    log_info("srv.running set to 1");

    srv.last_reload = get_timestamp();
    log_info("Timestamp obtained: %llu", (unsigned long long)srv.last_reload);

    srv.next_tunnel_id = 1;

    log_info("Entering main event loop, srv.running=%d", srv.running);

    uint64_t last_keepalive_check = get_timestamp();

    /* Main event loop */
    while (srv.running) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        socket_t max_fd = srv.listen_sock;
        FD_SET(srv.listen_sock, &read_fds);
        /* also monitor data listener */
        FD_SET(srv.data_listen_sock, &read_fds);
        if (srv.data_listen_sock > max_fd) max_fd = srv.data_listen_sock;

        /* Add client sockets - all active agents should be monitored */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (srv.clients[i].active) {
                FD_SET(srv.clients[i].sock, &read_fds);
                if (srv.clients[i].sock > max_fd) max_fd = srv.clients[i].sock;
            }
            /* Monitor for writeability if we have buffered data */
            if (srv.clients[i].active && srv.clients[i].write_buffer_size > 0) {
                FD_SET(srv.clients[i].sock, &write_fds);
            }
        }

        /* Add forward port sockets */
        for (int i = 0; i < MAX_FORWARD_PORTS; i++) {
            if (srv.forward_ports[i].active) {
                FD_SET(srv.forward_ports[i].listen_sock, &read_fds);
                if (srv.forward_ports[i].listen_sock > max_fd) max_fd = srv.forward_ports[i].listen_sock;
            }
        }

        /* Tunnel sockets are now handled by dedicated worker threads */

        struct timeval timeout = {0, 100000}; /* 100ms - responsive but low CPU */

        int ready = select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout);

        if (ready < 0) {
            int err = socket_errno;
#ifdef _WIN32
            if (err != WSAEINTR) {
#else
            if (err != EINTR) {
#endif
                log_error("select() failed: %d", err);
                break;
            }
            continue;
        }

        /* Accept new agent connections */
        if (FD_ISSET(srv.listen_sock, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);
            socket_t client_sock = accept(srv.listen_sock, (struct sockaddr*)&client_addr, &addrlen);

            if (client_sock != INVALID_SOCKET_VALUE) {
                int idx = find_free_client_slot(&srv);
                if (idx >= 0) {
                    socket_set_nonblocking(client_sock);
                    socket_set_nodelay(client_sock);

                    /* Set large buffers for maximum throughput */
                    int bufsize = 1024 * 1024; /* 1MB */
                    setsockopt(client_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize, sizeof(bufsize));
                    setsockopt(client_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&bufsize, sizeof(bufsize));

                    /* Enable TCP keepalive */
                    int keepalive = 1;
                    setsockopt(client_sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));

                    srv.clients[idx].sock = client_sock;
                    srv.clients[idx].authenticated = 0;
                    srv.clients[idx].active = 1;
                    /* recv_buffer not needed - message_receive_nonblocking doesn't use it */
                    srv.clients[idx].recv_buffer = NULL;
                    srv.clients[idx].write_buffer = NULL;
                    srv.clients[idx].write_buffer_size = 0;
                    srv.clients[idx].write_buffer_capacity = 0;
                    srv.clients[idx].last_activity = get_timestamp();
                    srv.clients[idx].ping_sent = 0;
                    memset(srv.clients[idx].username, 0, sizeof(srv.clients[idx].username));

                    log_info("New agent connection");
                } else {
                    log_error("No free client slots");
                    socket_close(client_sock);
                }
            }
        }

        /* Accept new agent DATA connections (dedicated data sockets) */
        if (FD_ISSET(srv.data_listen_sock, &read_fds)) {
            struct sockaddr_in client_addr;
            socklen_t addrlen = sizeof(client_addr);
            socket_t data_sock = accept(srv.data_listen_sock, (struct sockaddr*)&client_addr, &addrlen);
            if (data_sock != INVALID_SOCKET_VALUE) {
                /* Read 4-byte tunnel id handshake with timeout */
                /* Agent sends this immediately, but use select to wait for it */
                fd_set handshake_fds;
                struct timeval handshake_timeout = {2, 0}; /* 2 second timeout */
                FD_ZERO(&handshake_fds);
                FD_SET(data_sock, &handshake_fds);

                int sel = select(data_sock + 1, &handshake_fds, NULL, NULL, &handshake_timeout);
                if (sel <= 0) {
                    log_warn("Timeout waiting for tunnel id handshake, closing");
                    socket_close(data_sock);
                    goto next_accept;
                }

                uint32_t net_tid = 0;
                int total_read = 0;
                while (total_read < (int)sizeof(net_tid)) {
                    int r = recv(data_sock, (char*)&net_tid + total_read, sizeof(net_tid) - total_read, 0);
                    if (r <= 0) {
                        int err = socket_errno;
                        log_warn("Failed to read tunnel id from data connection (r=%d, err=%d), closing", r, err);
                        socket_close(data_sock);
                        goto next_accept;
                    }
                    total_read += r;
                }

                uint32_t tid = ntohl(net_tid);

                /* Find tunnel by id */
                int found = -1;
                for (int t = 0; t < MAX_TUNNELS; t++) {
                    if (srv.tunnels[t].active && srv.tunnels[t].tunnel_id == tid) {
                        found = t;
                        break;
                    }
                }

                if (found >= 0) {
                    /* Now set socket options and associate with tunnel */
                    socket_set_nonblocking(data_sock);
                    socket_set_nodelay(data_sock);

                    /* Set reasonable buffers for data path */
                    int bufsize = 512 * 1024; /* 512KB - good balance for Minecraft */
                    setsockopt(data_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize, sizeof(bufsize));
                    setsockopt(data_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&bufsize, sizeof(bufsize));

                    srv.tunnels[found].agent_data_sock = data_sock;
                    log_info("Associated data socket with tunnel %u (slot %d)", tid, found);
                } else {
                    log_warn("Received data connection for unknown tunnel %u, closing", tid);
                    socket_close(data_sock);
                }
                next_accept:;
            }
        }

        /* Handle client messages */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!srv.clients[i].active) continue;

            /* Flush write buffer if socket is writable */
            if (FD_ISSET(srv.clients[i].sock, &write_fds)) {
                if (srv.clients[i].write_buffer_size > 0) {
                    /* Try to flush as much as possible */
                    while (srv.clients[i].write_buffer_size > 0) {
                        int sent = send(srv.clients[i].sock,
                                      (const char*)srv.clients[i].write_buffer,
                                      srv.clients[i].write_buffer_size, MSG_NOSIGNAL);
                        if (sent > 0) {
                            memmove(srv.clients[i].write_buffer,
                                   srv.clients[i].write_buffer + sent,
                                   srv.clients[i].write_buffer_size - sent);
                            srv.clients[i].write_buffer_size -= sent;
                        } else if (sent < 0) {
                            int err = socket_errno;
                            if (socket_would_block(err)) {
                                break; /* Socket full, try again later */
                            } else {
                                log_error("Failed to write to agent %s: %d", srv.clients[i].username, err);
                                close_client(&srv, i);
                                break;
                            }
                        } else {
                            break;
                        }
                    }
                }
            }

            /* Handle incoming messages */
            if (srv.clients[i].active && FD_ISSET(srv.clients[i].sock, &read_fds)) {
                handle_client_message(&srv, i);
                /* Client may have been closed in handle_client_message, so don't access it after */
            }
        }

        /* Handle forward port connections */
        for (int i = 0; i < MAX_FORWARD_PORTS; i++) {
            if (srv.forward_ports[i].active && FD_ISSET(srv.forward_ports[i].listen_sock, &read_fds)) {
                handle_forward_port_connection(&srv, i);
            }
        }

        /* Tunnels are now handled by dedicated worker threads, no select() handling needed */

        /* Periodic operations - only check every 5 seconds to reduce CPU */
        uint64_t now = get_timestamp();
        if (now - last_keepalive_check < 5) {
            continue; /* Skip expensive checks if less than 5 seconds passed */
        }
        last_keepalive_check = now;

        /* Periodic login store reload */
        if (now - srv.last_reload > RELOAD_INTERVAL_SECS) {
            login_store_reload_if_modified(srv.login_store);
            srv.last_reload = now;
        }

        /* Check keepalive for all clients */
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!srv.clients[i].active || !srv.clients[i].authenticated) continue;

            /* Skip keepalive for agents with active tunnels - they're actively forwarding data */
            int has_active_tunnels = 0;
            for (int j = 0; j < MAX_TUNNELS; j++) {
                if (srv.tunnels[j].active && srv.tunnels[j].agent_idx == i) {
                    has_active_tunnels = 1;
                    break;
                }
            }
            if (has_active_tunnels) continue;

            uint64_t idle_time = now - srv.clients[i].last_activity;

            if (idle_time > KEEPALIVE_TIMEOUT_SECS && srv.clients[i].ping_sent) {
                /* No PONG received within timeout - close connection */
                log_warn("Client %s keepalive timeout (%llu seconds idle), closing",
                        srv.clients[i].username, (unsigned long long)idle_time);
                close_client(&srv, i);
            } else if (idle_time > KEEPALIVE_INTERVAL_SECS && !srv.clients[i].ping_sent) {
                /* Send PING to check if connection is alive */
                log_debug("Sending PING to client %s (idle for %llu seconds)",
                         srv.clients[i].username, (unsigned long long)idle_time);
                message_t* ping = message_create_ping();
                if (message_send(srv.clients[i].sock, ping) == 0) {
                    srv.clients[i].ping_sent = 1;
                } else {
                    log_warn("Failed to send PING to client %s, closing", srv.clients[i].username);
                    close_client(&srv, i);
                }
                message_free(ping);
            }
        }
    }

    /* Cleanup */
    log_info("Server shutting down, srv.running=%d", srv.running);

    /* Close all tunnels first - this will stop threads and free resources */
    for (int i = 0; i < MAX_TUNNELS; i++) {
        if (srv.tunnels[i].active) {
            close_tunnel(&srv, i);
        }
    }

    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (srv.clients[i].active) {
            close_client(&srv, i);
        }
    }

    for (int i = 0; i < MAX_FORWARD_PORTS; i++) {
        if (srv.forward_ports[i].active) {
            socket_close(srv.forward_ports[i].listen_sock);
        }
    }

    socket_close(srv.listen_sock);
    socket_close(srv.data_listen_sock);
    login_store_free(srv.login_store);
    config_free_server(&srv.config);

    return 0;
}
