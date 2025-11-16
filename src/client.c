#include "client.h"
#include "protocol.h"
#include "util.h"
#include "config.h"
#include "forward.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <signal.h>
#endif

#define MAX_TUNNELS 1024
#define KEEPALIVE_INTERVAL_SECS 30  /* Send PING every 30s */
#define KEEPALIVE_TIMEOUT_SECS 60   /* Reconnect if no response after 60s */

typedef struct {
    agent_config_t config;
    socket_t server_sock;
    mutex_t server_sock_mutex;
    tunnel_connection_t tunnels[MAX_TUNNELS];
    thread_t tunnel_threads[MAX_TUNNELS];
    uint8_t running;
    uint64_t last_activity;
    uint8_t ping_sent;
} agent_state_t;

static agent_state_t* g_agent = NULL;

/* Signal handler */
#ifndef _WIN32
static void signal_handler(int sig) {
    (void)sig;
    if (g_agent) g_agent->running = 0;
}
#endif

/* Connect to server */
static socket_t connect_to_server(const agent_config_t* config) {
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET_VALUE) {
        log_error("Failed to create socket: %d", socket_errno);
        return INVALID_SOCKET_VALUE;
    }
    
    socket_set_nodelay(sock);
    
    /* Enable TCP keepalive for server connection with aggressive timeouts */
    int keepalive = 1;
    setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));
    
#ifndef _WIN32
    /* Linux-specific keepalive tuning */
    int keepidle = 30;
    int keepintvl = 5;
    int keepcnt = 3;
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
    
    /* Enable quick ACK for lower latency */
    int quickack = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &quickack, sizeof(quickack));
#endif
    
    /* Set reasonable buffers */
    int bufsize = 256 * 1024; /* 256KB - plenty for control messages */
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize, sizeof(bufsize));
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char*)&bufsize, sizeof(bufsize));
    
    struct sockaddr_in addr;
    if (resolve_address(config->server_host, config->server_port, &addr) != 0) {
        log_error("Failed to resolve server address");
        socket_close(sock);
        return INVALID_SOCKET_VALUE;
    }
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Failed to connect to server: %d", socket_errno);
        socket_close(sock);
        return INVALID_SOCKET_VALUE;
    }
    
    log_info("Connected to server %s:%u", config->server_host, config->server_port);
    return sock;
}

/* Authenticate with server */
static int authenticate(socket_t sock, const agent_config_t* config) {
    /* Send AUTH message */
    message_t* auth_msg = message_create_auth(config->username, config->password);
    if (message_send(sock, auth_msg) != 0) {
        log_error("Failed to send AUTH message");
        message_free(auth_msg);
        return -1;
    }
    message_free(auth_msg);
    
    /* Receive response */
    message_t* resp = message_receive(sock);
    if (!resp) {
        log_error("Failed to receive AUTH response");
        return -1;
    }
    
    if (resp->type == MSG_OK) {
        log_info("Authentication successful");
        message_free(resp);
        return 0;
    } else if (resp->type == MSG_ERR) {
        error_payload_t err;
        message_parse_error(resp, &err);
        log_error("Authentication failed: %s", err.error);
        message_free(resp);
        return -1;
    }
    
    log_error("Unexpected response to AUTH");
    message_free(resp);
    return -1;
}

/* Reconnect to server with exponential backoff */
static socket_t reconnect_to_server(agent_state_t* agent) {
    int retry_delay = 1; /* Start with 1 second */
    int max_delay = 30;  /* Max 30 seconds between retries */
    
    while (agent->running) {
        log_info("Attempting to reconnect to server in %d seconds...", retry_delay);
        
#ifdef _WIN32
        Sleep(retry_delay * 1000);
#else
        sleep(retry_delay);
#endif
        
        if (!agent->running) break;
        
        socket_t sock = connect_to_server(&agent->config);
        if (sock == INVALID_SOCKET_VALUE) {
            retry_delay = (retry_delay * 2 > max_delay) ? max_delay : retry_delay * 2;
            continue;
        }
        
        /* Authenticate */
        if (authenticate(sock, &agent->config) != 0) {
            socket_close(sock);
            retry_delay = (retry_delay * 2 > max_delay) ? max_delay : retry_delay * 2;
            continue;
        }
        
        /* Re-register forward ports */
        int all_success = 1;
        for (int i = 0; i < agent->config.forward_count; i++) {
            uint16_t remote_port = agent->config.forwards[i].remote_port;
            log_info("Re-registering forward for port %u", remote_port);
            message_t* fwd_msg = message_create_port(MSG_FORWARD, remote_port);
            if (message_send(sock, fwd_msg) != 0) {
                log_error("Failed to send FORWARD request for port %u", remote_port);
                message_free(fwd_msg);
                all_success = 0;
                break;
            }
            message_free(fwd_msg);
            
            message_t* resp = message_receive(sock);
            if (!resp || resp->type != MSG_OK) {
                if (resp && resp->type == MSG_ERR) {
                    error_payload_t err;
                    message_parse_error(resp, &err);
                    log_error("Failed to forward port %u: %s", remote_port, err.error);
                } else {
                    log_error("Failed to forward port %u", remote_port);
                }
                if (resp) message_free(resp);
                all_success = 0;
                break;
            }
            message_free(resp);
            log_info("Re-forwarding port %u", remote_port);
        }
        
        if (!all_success) {
            socket_close(sock);
            retry_delay = (retry_delay * 2 > max_delay) ? max_delay : retry_delay * 2;
            continue;
        }
        
        log_info("Reconnected to server successfully");
        return sock;
    }
    
    return INVALID_SOCKET_VALUE;
}

/* Claim ports */
/* Find tunnel by ID */
static tunnel_connection_t* find_tunnel(agent_state_t* agent, uint32_t tunnel_id) {
    for (int i = 0; i < MAX_TUNNELS; i++) {
        if (agent->tunnels[i].active && agent->tunnels[i].tunnel_id == tunnel_id) {
            return &agent->tunnels[i];
        }
    }
    return NULL;
}

/* Find free tunnel slot */
static int find_free_tunnel_slot(agent_state_t* agent) {
    /* First pass: look for completely free slots */
    for (int i = 0; i < MAX_TUNNELS; i++) {
        if (agent->tunnels[i].local_sock == 0 && agent->tunnels[i].data_sock == 0) {
            return i;
        }
    }
    
    /* Second pass: look for inactive slots with finished threads */
    for (int i = 0; i < MAX_TUNNELS; i++) {
        if (!agent->tunnels[i].active) {
            return i;
        }
    }
    
    return -1;
}

/* Get local port for remote port */
static uint16_t get_local_port(const agent_config_t* config, uint16_t remote_port) {
    for (int i = 0; i < config->forward_count; i++) {
        if (config->forwards[i].remote_port == remote_port) {
            return config->forwards[i].local_port;
        }
    }
    return 0;
}

/* Handle TUNNEL_OPEN */
static void handle_tunnel_open(agent_state_t* agent, const message_t* msg) {
    tunnel_open_payload_t payload;
    if (message_parse_tunnel_open(msg, &payload) != 0) {
        log_error("Failed to parse TUNNEL_OPEN message");
        return;
    }
    
    uint32_t tunnel_id = payload.tunnel_id;
    uint16_t remote_port = payload.port;
    
    /* Get local port */
    uint16_t local_port = get_local_port(&agent->config, remote_port);
    if (local_port == 0) {
        log_error("No mapping for remote port %u", remote_port);
        return;
    }
    
    /* Connect to local service */
    socket_t local_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (local_sock == INVALID_SOCKET_VALUE) {
        log_error("Failed to create local socket: %d", socket_errno);
        return;
    }
    
    socket_set_nodelay(local_sock);
    socket_set_nonblocking(local_sock);
    
    /* Set reasonable socket buffers */
    int bufsize = 256 * 1024; /* 256KB - plenty for Minecraft */
    setsockopt(local_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize, sizeof(bufsize));
    setsockopt(local_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&bufsize, sizeof(bufsize));
    
    /* Disable Nagle's algorithm - critical for protocol packet boundaries! */
    int nodelay = 1;
    setsockopt(local_sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));
    
    /* Enable TCP keepalive to detect dead connections */
    int keepalive = 1;
    setsockopt(local_sock, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));
    
#ifndef _WIN32
    /* Enable quick ACK for lower latency */
    int quickack = 1;
    setsockopt(local_sock, IPPROTO_TCP, TCP_QUICKACK, &quickack, sizeof(quickack));
#endif
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(local_port);
    
    if (connect(local_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        int err = socket_errno;
        /* Nonblocking connect returns EINPROGRESS/WSAEWOULDBLOCK which is normal */
#ifdef _WIN32
        if (err != WSAEWOULDBLOCK) {
#else
        if (err != EINPROGRESS) {
#endif
            log_error("Tunnel %u: Failed to connect to local service on port %u: %d", tunnel_id, local_port, err);
            socket_close(local_sock);
            
            /* Send empty DATA to close tunnel */
            message_t* close_msg = message_create_data(tunnel_id, NULL, 0);
            message_send(agent->server_sock, close_msg);
            message_free(close_msg);
            return;
        }
        
        /* Wait for connection to complete */
        fd_set write_fds, error_fds;
        FD_ZERO(&write_fds);
        FD_ZERO(&error_fds);
        FD_SET(local_sock, &write_fds);
        FD_SET(local_sock, &error_fds);
        
        struct timeval timeout = {3, 0}; /* 3 second timeout - faster failure detection */
        int ready = select(local_sock + 1, NULL, &write_fds, &error_fds, &timeout);
        
        if (ready <= 0 || FD_ISSET(local_sock, &error_fds)) {
            log_error("Tunnel %u: Connection to local service timed out or failed: ready=%d, err=%d", tunnel_id, ready, socket_errno);
            socket_close(local_sock);
            
            message_t* close_msg = message_create_data(tunnel_id, NULL, 0);
            message_send(agent->server_sock, close_msg);
            message_free(close_msg);
            return;
        }
        
        /* Verify connection succeeded */
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        if (getsockopt(local_sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) < 0 || so_error != 0) {
            log_error("Tunnel %u: Connection to local service failed: getsockopt_err=%d, so_error=%d", tunnel_id, socket_errno, so_error);
            socket_close(local_sock);
            
            message_t* close_msg = message_create_data(tunnel_id, NULL, 0);
            message_send(agent->server_sock, close_msg);
            message_free(close_msg);
            return;
        }
    }
    
    log_info("Tunnel %u: Successfully connected to localhost:%u", tunnel_id, local_port);
    
    /* Find free tunnel slot */
    int idx = find_free_tunnel_slot(agent);
    if (idx < 0) {
        log_error("No free tunnel slots");
        socket_close(local_sock);
        return;
    }
    
    /* Create tunnel */
    tunnel_connection_t* tunnel = &agent->tunnels[idx];
    
    /* If slot is being reused and was previously active, ensure old thread is fully cleaned up */
    if (tunnel->local_sock != 0 || tunnel->data_sock != 0) {
        thread_join(agent->tunnel_threads[idx]);
        
        /* Clean up any remaining resources */
        if (tunnel->write_buffer) {
            xfree(tunnel->write_buffer);
            tunnel->write_buffer = NULL;
        }
        mutex_destroy(&tunnel->write_mutex);
    }
    
    /* Initialize tunnel structure */
    memset(tunnel, 0, sizeof(tunnel_connection_t));
    tunnel->tunnel_id = tunnel_id;
    tunnel->local_sock = local_sock;
    
    /* Connect dedicated data socket to server data port for zero-overhead forwarding */
    socket_t data_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (data_sock == INVALID_SOCKET_VALUE) {
        log_error("Failed to create data socket: %d", socket_errno);
        socket_close(local_sock);
        return;
    }

    socket_set_nodelay(data_sock);

    /* Set reasonable buffers for data path */
    int dbuf = 256 * 1024; /* 256KB - plenty for Minecraft */
    setsockopt(data_sock, SOL_SOCKET, SO_RCVBUF, (const char*)&dbuf, sizeof(dbuf));
    setsockopt(data_sock, SOL_SOCKET, SO_SNDBUF, (const char*)&dbuf, sizeof(dbuf));

    struct sockaddr_in data_addr;
    if (resolve_address(agent->config.server_host, payload.data_port, &data_addr) != 0) {
        log_error("Failed to resolve server data address");
        socket_close(local_sock);
        socket_close(data_sock);
        return;
    }

    log_info("Tunnel %u: Connecting data socket to %s:%u", tunnel_id, agent->config.server_host, payload.data_port);

    /* Set non-blocking for connection with timeout */
    socket_set_nonblocking(data_sock);

    /* Attempt connection */
    int conn_result = connect(data_sock, (struct sockaddr*)&data_addr, sizeof(data_addr));
    if (conn_result < 0) {
        int err = socket_errno;
        if (!socket_would_block(err) && err != IN_PROGRESS) {
            log_error("Failed to connect data socket to server: %d", err);
            socket_close(local_sock);
            socket_close(data_sock);
            /* Inform server to close tunnel */
            message_t* close_msg = message_create_tunnel_close(tunnel_id);
            message_send(agent->server_sock, close_msg);
            message_free(close_msg);
            return;
        }

        /* Connection in progress, wait for it with select */
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(data_sock, &write_fds);
        struct timeval timeout = {10, 0}; /* 10 second timeout */
        int sel = select(data_sock + 1, NULL, &write_fds, NULL, &timeout);

        if (sel <= 0) {
            log_error("Data socket connection timeout or error (tunnel %u)", tunnel_id);
            socket_close(local_sock);
            socket_close(data_sock);
            message_t* close_msg = message_create_tunnel_close(tunnel_id);
            message_send(agent->server_sock, close_msg);
            message_free(close_msg);
            return;
        }

        /* Check if connection succeeded */
        int so_error = 0;
        socklen_t len = sizeof(so_error);
        getsockopt(data_sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
        if (so_error != 0) {
            log_error("Data socket connection failed: %d (tunnel %u)", so_error, tunnel_id);
            socket_close(local_sock);
            socket_close(data_sock);
            message_t* close_msg = message_create_tunnel_close(tunnel_id);
            message_send(agent->server_sock, close_msg);
            message_free(close_msg);
            return;
        }
    }

    log_info("Tunnel %u: Data socket connected", tunnel_id);

    log_info("Tunnel %u: Data socket connected", tunnel_id);

    /* Send 4-byte tunnel id handshake (network byte order) */
    uint32_t net_tid = htonl(tunnel_id);
    
    /* Socket is non-blocking, but we need to send the handshake immediately */
    socket_set_blocking(data_sock);
    
    int total_sent = 0;
    while (total_sent < (int)sizeof(net_tid)) {
        int hs_sent = send(data_sock, (const char*)&net_tid + total_sent, sizeof(net_tid) - total_sent, 0);
        if (hs_sent <= 0) {
            int err = socket_errno;
            log_error("Failed to send data handshake for tunnel %u (err=%d)", tunnel_id, err);
            socket_close(local_sock);
            socket_close(data_sock);
            message_t* close_msg = message_create_data(tunnel_id, NULL, 0);
            message_send(agent->server_sock, close_msg);
            message_free(close_msg);
            return;
        }
        total_sent += hs_sent;
    }

    /* Set data socket non-blocking for worker thread */
    socket_set_nonblocking(data_sock);
    socket_set_nodelay(data_sock); /* Ensure no delay */
    tunnel->data_sock = data_sock;
    
    tunnel->local_port = local_port;
    tunnel->active = 1;
    tunnel->write_buffer = (uint8_t*)xmalloc(524288); /* 512KB initial buffer for heavy loads */
    tunnel->write_buffer_size = 0;
    tunnel->write_buffer_capacity = 524288;
    mutex_init(&tunnel->write_mutex);
    
    /* Start tunnel worker thread */
    if (thread_create(&agent->tunnel_threads[idx], (thread_func_t)tunnel_worker, tunnel) != 0) {
        log_error("Failed to create tunnel worker thread");
        socket_close(local_sock);
        tunnel->active = 0;
        return;
    }
    
    thread_detach(agent->tunnel_threads[idx]);
    
    log_info("Opened tunnel %u: remote_port=%u -> local_port=%u", tunnel_id, remote_port, local_port);
}

/* Handle TUNNEL_CLOSE */
static void handle_tunnel_close(agent_state_t* agent, const message_t* msg) {
    tunnel_close_payload_t payload;
    if (message_parse_tunnel_close(msg, &payload) != 0) {
        log_error("Failed to parse TUNNEL_CLOSE message");
        return;
    }
    
    tunnel_connection_t* tunnel = find_tunnel(agent, payload.tunnel_id);
    if (!tunnel) {
        /* Tunnel may have already been closed by worker thread */
        log_debug("Tunnel not found for CLOSE: %u", payload.tunnel_id);
        return;
    }
    
    log_info("Closing tunnel %u", payload.tunnel_id);
    socket_close(tunnel->local_sock);
    tunnel->active = 0;
}

/* Handle DATA from server */
static void handle_data_from_server(agent_state_t* agent, const message_t* msg) {
    data_payload_t data;
    if (message_parse_data(msg, &data) != 0) {
        log_error("Failed to parse DATA message");
        return;
    }
    log_debug("Parsed DATA: tunnel_id=%u, data_len=%u", data.tunnel_id, data.data_len);
    
    tunnel_connection_t* tunnel = find_tunnel(agent, data.tunnel_id);
    if (!tunnel) {
        log_warn("Tunnel not found for DATA: %u", data.tunnel_id);
        if (data.data) xfree(data.data);
        return;
    }
    
    log_debug("Found tunnel %u, active=%d, local_sock=%d", data.tunnel_id, tunnel->active, tunnel->local_sock);
    
    /* Try to acquire the mutex - if this fails, tunnel is being destroyed */
    if (mutex_trylock(&tunnel->write_mutex) != 0) {
        log_warn("Tunnel %u mutex busy (closing), discarding DATA", data.tunnel_id);
        if (data.data) xfree(data.data);
        return;
    }
    
    /* Double-check active flag while holding the mutex */
    if (!tunnel->active) {
        log_warn("Tunnel %u is closing, discarding DATA", data.tunnel_id);
        mutex_unlock(&tunnel->write_mutex);
        if (data.data) xfree(data.data);
        return;
    }
    
    /* Send data to local service */
    if (data.data_len > 0) {
        /* First, try to flush any existing buffered data */
        if (tunnel->write_buffer_size > 0) {
            int sent = send(tunnel->local_sock, (const char*)tunnel->write_buffer,
                          tunnel->write_buffer_size, MSG_NOSIGNAL);
            if (sent > 0) {
                log_debug("Flushed %d bytes from write buffer (tunnel %u)", sent, data.tunnel_id);
                memmove(tunnel->write_buffer, tunnel->write_buffer + sent,
                       tunnel->write_buffer_size - sent);
                tunnel->write_buffer_size -= sent;
            }
        }
        
        /* Try to send the new data directly */
        size_t total_sent = 0;
        while (total_sent < data.data_len) {
            int sent = send(tunnel->local_sock, (const char*)data.data + total_sent,
                          data.data_len - total_sent, MSG_NOSIGNAL);
            if (sent < 0) {
                int err = socket_errno;
                if (socket_would_block(err)) {
                    /* Buffer remaining data */
                    size_t remaining = data.data_len - total_sent;
                    size_t new_size = tunnel->write_buffer_size + remaining;
                    if (new_size > tunnel->write_buffer_capacity) {
                        tunnel->write_buffer_capacity = new_size * 2;
                        if (tunnel->write_buffer_capacity == 0) tunnel->write_buffer_capacity = 262144; /* 256KB */
                        if (tunnel->write_buffer_capacity > 134217728) { /* 128MB limit for heavy loads */
                            log_error("Write buffer overflow, closing tunnel %u", data.tunnel_id);
                            mutex_unlock(&tunnel->write_mutex);
                            socket_close(tunnel->local_sock);
                            tunnel->active = 0;
                            goto cleanup;
                        }
                        tunnel->write_buffer = (uint8_t*)xrealloc(tunnel->write_buffer, tunnel->write_buffer_capacity);
                    }
                    memcpy(tunnel->write_buffer + tunnel->write_buffer_size, 
                           data.data + total_sent, remaining);
                    tunnel->write_buffer_size = new_size;
                    log_debug("Buffered %zu bytes (would block) (tunnel %u)", remaining, data.tunnel_id);
                    break;
                }
                log_error("Failed to send data to local service: %d", err);
                mutex_unlock(&tunnel->write_mutex);
                socket_close(tunnel->local_sock);
                tunnel->active = 0;
                goto cleanup;
            }
            total_sent += sent;
        }
        
        mutex_unlock(&tunnel->write_mutex);
    } else {
        /* Empty data = close tunnel */
        socket_close(tunnel->local_sock);
        tunnel->active = 0;
    }
    
cleanup:
    if (data.data) xfree(data.data);
}

/* Main agent loop */
int client_run(const char* config_path) {
    agent_state_t agent;
    memset(&agent, 0, sizeof(agent));
    g_agent = &agent;
    mutex_init(&agent.server_sock_mutex);
    
    /* Load configuration */
    if (config_load_agent(config_path, &agent.config) != 0) {
        log_error("Failed to load agent configuration");
        return -1;
    }
    
    /* Connect to server */
    agent.server_sock = connect_to_server(&agent.config);
    if (agent.server_sock == INVALID_SOCKET_VALUE) {
        log_warn("Initial connection failed, will retry...");
        agent.running = 1; /* Set running flag so reconnect works */
        agent.server_sock = reconnect_to_server(&agent);
        if (agent.server_sock == INVALID_SOCKET_VALUE) {
            log_error("Failed to connect to server after retries");
            return -1;
        }
    } else {
        /* Authenticate */
        if (authenticate(agent.server_sock, &agent.config) != 0) {
            socket_close(agent.server_sock);
            return -1;
        }
        
        /* Request forward port listeners from server */
        for (int i = 0; i < agent.config.forward_count; i++) {
            uint16_t remote_port = agent.config.forwards[i].remote_port;
            log_info("Requesting forward for port %u", remote_port);
            message_t* fwd_msg = message_create_port(MSG_FORWARD, remote_port);
            if (message_send(agent.server_sock, fwd_msg) != 0) {
                log_error("Failed to send FORWARD request for port %u", remote_port);
                message_free(fwd_msg);
                socket_close(agent.server_sock);
                return -1;
            }
            message_free(fwd_msg);
            log_info("Waiting for FORWARD response for port %u", remote_port);
            
            message_t* resp = message_receive(agent.server_sock);
            if (!resp || resp->type != MSG_OK) {
                if (resp && resp->type == MSG_ERR) {
                    error_payload_t err;
                    message_parse_error(resp, &err);
                    log_error("Failed to forward port %u: %s", remote_port, err.error);
                } else {
                    log_error("Failed to forward port %u", remote_port);
                }
                if (resp) message_free(resp);
                socket_close(agent.server_sock);
                return -1;
            }
            message_free(resp);
            log_info("Forwarding port %u", remote_port);
        }
    }
    
    log_info("Agent started successfully");
    
#ifndef _WIN32
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif
    
    socket_set_nonblocking(agent.server_sock);
    agent.running = 1;
    agent.last_activity = get_timestamp();
    agent.ping_sent = 0;
    
    log_info("Entering agent event loop");
    
    int loop_count = 0;
    
    /* Main event loop */
    while (agent.running) {
        if (++loop_count % 1000 == 0) {
            log_debug("Agent heartbeat: %d iterations", loop_count);
        }
        
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(agent.server_sock, &read_fds);
        
        struct timeval timeout = {0, 100000}; /* 100ms - responsive but low CPU */
        int ready = select(agent.server_sock + 1, &read_fds, NULL, NULL, &timeout);
        
        if (ready > 0) {
        }
        
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
        
        if (ready == 0) continue; /* Timeout */
        
        /* Receive all pending messages from server (drain the socket buffer) */
        /* Collect messages with mutex held, then process without mutex */
        message_t* messages[64];
        int msg_count = 0;
        
        mutex_lock(&agent.server_sock_mutex);
        while (msg_count < 64) {
            int would_block = 0;
            message_t* msg = message_receive_nonblocking(agent.server_sock, &would_block);
            
            if (!msg) {
                if (!would_block) {
                    log_error("Server connection lost, attempting to reconnect...");
                    mutex_unlock(&agent.server_sock_mutex);
                    
                    /* Close old socket */
                    socket_close(agent.server_sock);
                    
                    /* Try to reconnect */
                    socket_t new_sock = reconnect_to_server(&agent);
                    if (new_sock == INVALID_SOCKET_VALUE) {
                        log_error("Failed to reconnect to server, shutting down");
                        agent.running = 0;
                        goto end_message_processing;
                    }
                    
                    /* Update socket and reset state */
                    mutex_lock(&agent.server_sock_mutex);
                    agent.server_sock = new_sock;
                    socket_set_nonblocking(agent.server_sock);
                    agent.last_activity = get_timestamp();
                    agent.ping_sent = 0;
                    mutex_unlock(&agent.server_sock_mutex);
                    
                    log_info("Reconnected successfully, continuing operation");
                    goto end_message_processing;
                }
                break;
            }
            
            messages[msg_count++] = msg;
        }
        mutex_unlock(&agent.server_sock_mutex);
        
end_message_processing:
        
        /* Process messages without holding mutex (allows tunnel workers to send) */
        if (msg_count > 0) {
            for (int i = 0; i < msg_count; i++) {
                message_t* msg = messages[i];
            log_info("Agent received message type 0x%02x", msg->type);
            
            /* Update activity timestamp on any message */
            agent.last_activity = get_timestamp();
            agent.ping_sent = 0;
            
            switch (msg->type) {
                case MSG_TUNNEL_OPEN:
                    handle_tunnel_open(&agent, msg);
                    break;
                case MSG_TUNNEL_CLOSE:
                    handle_tunnel_close(&agent, msg);
                    break;
                case MSG_DATA:
                    handle_data_from_server(&agent, msg);
                    break;
                case MSG_PING:
                    /* Respond with PONG */
                    {
                        message_t* pong = message_create_pong();
                        mutex_lock(&agent.server_sock_mutex);
                        message_send(agent.server_sock, pong);
                        mutex_unlock(&agent.server_sock_mutex);
                        message_free(pong);
                    }
                    break;
                case MSG_PONG:
                    /* Just update activity timestamp (already done above) */
                    log_debug("Received PONG from server");
                    break;
                case MSG_ERR:
                    {
                        error_payload_t err;
                        message_parse_error(msg, &err);
                        log_error("Server error: %s", err.error);
                    }
                    break;
                default:
                    log_warn("Unexpected message type: 0x%02x", msg->type);
                    break;
            }
            
            message_free(msg);
        }
        }
        
        /* Check keepalive - send PING if idle too long */
        uint64_t now = get_timestamp();
        uint64_t idle_time = now - agent.last_activity;
        
        if (idle_time > KEEPALIVE_TIMEOUT_SECS && agent.ping_sent) {
            /* No PONG received within timeout - connection may be dead */
            log_error("Server keepalive timeout (%llu seconds idle), reconnecting...",
                     (unsigned long long)idle_time);
            
            /* Close old socket */
            mutex_lock(&agent.server_sock_mutex);
            socket_close(agent.server_sock);
            mutex_unlock(&agent.server_sock_mutex);
            
            /* Try to reconnect */
            socket_t new_sock = reconnect_to_server(&agent);
            if (new_sock == INVALID_SOCKET_VALUE) {
                log_error("Failed to reconnect to server, shutting down");
                agent.running = 0;
                continue;
            }
            
            /* Update socket and reset state */
            mutex_lock(&agent.server_sock_mutex);
            agent.server_sock = new_sock;
            socket_set_nonblocking(agent.server_sock);
            agent.last_activity = get_timestamp();
            agent.ping_sent = 0;
            mutex_unlock(&agent.server_sock_mutex);
            
            log_info("Reconnected successfully after keepalive timeout");
        } else if (idle_time > KEEPALIVE_INTERVAL_SECS && !agent.ping_sent) {
            /* Send PING to keep connection alive */
            log_debug("Sending PING to server (idle for %llu seconds)",
                     (unsigned long long)idle_time);
            message_t* ping = message_create_ping();
            mutex_lock(&agent.server_sock_mutex);
            int send_result = message_send(agent.server_sock, ping);
            mutex_unlock(&agent.server_sock_mutex);
            if (send_result == 0) {
                agent.ping_sent = 1;
            } else {
                log_error("Failed to send PING to server, reconnecting...");
                
                /* Close old socket */
                mutex_lock(&agent.server_sock_mutex);
                socket_close(agent.server_sock);
                mutex_unlock(&agent.server_sock_mutex);
                
                /* Try to reconnect */
                socket_t new_sock = reconnect_to_server(&agent);
                if (new_sock == INVALID_SOCKET_VALUE) {
                    log_error("Failed to reconnect to server, shutting down");
                    agent.running = 0;
                    message_free(ping);
                    continue;
                }
                
                /* Update socket and reset state */
                mutex_lock(&agent.server_sock_mutex);
                agent.server_sock = new_sock;
                socket_set_nonblocking(agent.server_sock);
                agent.last_activity = get_timestamp();
                agent.ping_sent = 0;
                mutex_unlock(&agent.server_sock_mutex);
                
                log_info("Reconnected successfully after send failure");
            }
            message_free(ping);
        }
    }
    
    /* Cleanup */
    log_info("Agent shutting down");
    
    for (int i = 0; i < MAX_TUNNELS; i++) {
        if (agent.tunnels[i].active) {
            socket_close(agent.tunnels[i].local_sock);
            agent.tunnels[i].active = 0;
        }
    }
    
    socket_close(agent.server_sock);
    mutex_destroy(&agent.server_sock_mutex);
    config_free_agent(&agent.config);
    
    return 0;
}

/* Admin command: claim a port */
int client_claim_port(const char* config_path, uint16_t port) {
    agent_config_t config;
    if (config_load_agent(config_path, &config) != 0) {
        return -1;
    }
    
    socket_t sock = connect_to_server(&config);
    if (sock == INVALID_SOCKET_VALUE) {
        config_free_agent(&config);
        return -1;
    }
    
    if (authenticate(sock, &config) != 0) {
        socket_close(sock);
        config_free_agent(&config);
        return -1;
    }
    
    message_t* claim_msg = message_create_port(MSG_CLAIM, port);
    if (message_send(sock, claim_msg) != 0) {
        message_free(claim_msg);
        socket_close(sock);
        config_free_agent(&config);
        return -1;
    }
    message_free(claim_msg);
    
    message_t* resp = message_receive(sock);
    if (!resp) {
        socket_close(sock);
        config_free_agent(&config);
        return -1;
    }
    
    if (resp->type == MSG_OK) {
        printf("Successfully claimed port %u\n", port);
    } else if (resp->type == MSG_ERR) {
        error_payload_t err;
        message_parse_error(resp, &err);
        printf("Failed to claim port %u: %s\n", port, err.error);
    }
    
    message_free(resp);
    socket_close(sock);
    config_free_agent(&config);
    
    return 0;
}

/* Admin command: unclaim a port */
int client_unclaim_port(const char* config_path, uint16_t port) {
    agent_config_t config;
    if (config_load_agent(config_path, &config) != 0) {
        return -1;
    }
    
    socket_t sock = connect_to_server(&config);
    if (sock == INVALID_SOCKET_VALUE) {
        config_free_agent(&config);
        return -1;
    }
    
    if (authenticate(sock, &config) != 0) {
        socket_close(sock);
        config_free_agent(&config);
        return -1;
    }
    
    message_t* unclaim_msg = message_create_port(MSG_UNCLAIM, port);
    if (message_send(sock, unclaim_msg) != 0) {
        message_free(unclaim_msg);
        socket_close(sock);
        config_free_agent(&config);
        return -1;
    }
    message_free(unclaim_msg);
    
    message_t* resp = message_receive(sock);
    if (!resp) {
        socket_close(sock);
        config_free_agent(&config);
        return -1;
    }
    
    if (resp->type == MSG_OK) {
        printf("Successfully unclaimed port %u\n", port);
    } else if (resp->type == MSG_ERR) {
        error_payload_t err;
        message_parse_error(resp, &err);
        printf("Failed to unclaim port %u: %s\n", port, err.error);
    }
    
    message_free(resp);
    socket_close(sock);
    config_free_agent(&config);
    
    return 0;
}

/* Admin command: list claimed ports */
int client_list_ports(const char* config_path) {
    agent_config_t config;
    if (config_load_agent(config_path, &config) != 0) {
        return -1;
    }
    
    socket_t sock = connect_to_server(&config);
    if (sock == INVALID_SOCKET_VALUE) {
        config_free_agent(&config);
        return -1;
    }
    
    if (authenticate(sock, &config) != 0) {
        socket_close(sock);
        config_free_agent(&config);
        return -1;
    }
    
    message_t* list_msg = message_create_list_request();
    if (message_send(sock, list_msg) != 0) {
        message_free(list_msg);
        socket_close(sock);
        config_free_agent(&config);
        return -1;
    }
    message_free(list_msg);
    
    message_t* resp = message_receive(sock);
    if (!resp) {
        socket_close(sock);
        config_free_agent(&config);
        return -1;
    }
    
    if (resp->type == MSG_LIST) {
        list_payload_t list;
        if (message_parse_list(resp, &list) == 0) {
            printf("Claimed ports (%u):\n", list.count);
            for (int i = 0; i < list.count; i++) {
                printf("  %u\n", list.ports[i]);
            }
            if (list.ports) xfree(list.ports);
        }
    } else if (resp->type == MSG_ERR) {
        error_payload_t err;
        message_parse_error(resp, &err);
        printf("Failed to list ports: %s\n", err.error);
    }
    
    message_free(resp);
    socket_close(sock);
    config_free_agent(&config);
    
    return 0;
}
