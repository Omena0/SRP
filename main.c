/*
 * SRP - Small Reverse Proxy
 * High-performance reverse proxy for Minecraft servers with minimal latency
 * Cross-platform with optimized I/O for minimal latency
 */

#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#define close closesocket
typedef int socklen_t;
#else
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#endif

#define BUFFER_SIZE 8192
#define MAX_CONNECTIONS 256
#define AUTH_TIMEOUT 5
#define RATE_LIMIT_WINDOW 60
#define MAX_AUTH_ATTEMPTS 3
#define AUTH_RETRY_DELAY 1

#ifdef _WIN32
typedef SOCKET socket_t;
#define INVALID_SOCK INVALID_SOCKET
#define SOCK_ERR SOCKET_ERROR
#else
typedef int socket_t;
#define INVALID_SOCK -1
#define SOCK_ERR -1
#endif

typedef enum {
    CONN_STATE_AUTH,
    CONN_STATE_FORWARDING,
    CONN_STATE_TUNNEL_ESTABLISHED
} conn_state_t;

typedef struct {
    socket_t fd;
    socket_t peer_fd;
    conn_state_t state;
    time_t auth_start;
    char buffer[BUFFER_SIZE];
    int buffer_used;
} connection_t;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int attempts;
    time_t first_attempt;
    time_t last_attempt;
} rate_limit_entry_t;

static connection_t connections[MAX_CONNECTIONS];
static rate_limit_entry_t rate_limits[256];
static int rate_limit_count = 0;
static volatile int running = 1;
static char password[256];
static int total_connections = 0;
static int active_clients = 0;
static time_t start_time = 0;
static time_t last_update = 0;

// Traffic statistics (30 second window)
#define STATS_WINDOW 30
typedef struct {
    time_t timestamp;
    long long bytes_up;
    long long bytes_down;
    int packets_up;
    int packets_down;
} stats_sample_t;

static stats_sample_t stats_history[STATS_WINDOW];
static int stats_index = 0;
static long long total_bytes_up = 0;
static long long total_bytes_down = 0;
static int total_packets_up = 0;
static int total_packets_down = 0;

// Function prototypes
static void init_network(void);
static void cleanup_network(void);
static int set_nonblocking(socket_t fd);
static int set_tcp_nodelay(socket_t fd);
static void optimize_socket(socket_t fd);
static connection_t* get_connection(socket_t fd);
static void cleanup_connection(connection_t *conn);
static int check_rate_limit(const char *ip);
static void update_rate_limit(const char *ip, int success);
static int forward_mode(int local_port, const char *tunnel_addr, int tunnel_port);
static int serve_mode(const char *bind_addr, int bind_port, int tunnel_port);
static void print_status(const char *mode, int tunnel_active, int clients);
static void update_stats(int bytes_up, int bytes_down, int packets_up, int packets_down);
static void format_speed(long long bytes_per_sec, char *buf, size_t bufsize);

static void init_network(void) {
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

static void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

static int set_nonblocking(socket_t fd) {
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static int set_tcp_nodelay(socket_t fd) {
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&flag, sizeof(flag));
}

static void optimize_socket(socket_t fd) {
    // Disable Nagle's algorithm for minimum latency
    set_tcp_nodelay(fd);

    // Set socket buffer sizes for optimal throughput
    int bufsize = 262144; // 256KB
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&bufsize, sizeof(bufsize));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*)&bufsize, sizeof(bufsize));

    // Enable keep-alive
    int keepalive = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));
}

static connection_t* get_connection(socket_t fd) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (connections[i].fd == fd) {
            return &connections[i];
        }
    }
    return NULL;
}

static connection_t* alloc_connection(socket_t fd) {
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (connections[i].fd == INVALID_SOCK) {
            memset(&connections[i], 0, sizeof(connection_t));
            connections[i].fd = fd;
            connections[i].peer_fd = INVALID_SOCK;
            return &connections[i];
        }
    }
    return NULL;
}

static void cleanup_connection(connection_t *conn) {
    if (!conn || conn->fd == INVALID_SOCK) return;

    close(conn->fd);

    if (conn->peer_fd != INVALID_SOCK) {
        connection_t *peer = get_connection(conn->peer_fd);
        if (peer) {
            close(peer->fd);
            peer->fd = INVALID_SOCK;
            peer->peer_fd = INVALID_SOCK;
        }
    }

    conn->fd = INVALID_SOCK;
    conn->peer_fd = INVALID_SOCK;
}

static int check_rate_limit(const char *ip) {
    time_t now = time(NULL);

    for (int i = 0; i < rate_limit_count; i++) {
        if (strcmp(rate_limits[i].ip, ip) == 0) {
            // Check if rate limit window has expired
            if (now - rate_limits[i].first_attempt > RATE_LIMIT_WINDOW) {
                rate_limits[i].attempts = 0;
                rate_limits[i].first_attempt = now;
                return 1;
            }

            // Check if we've hit the limit
            if (rate_limits[i].attempts >= MAX_AUTH_ATTEMPTS) {
                return 0;
            }

            // Check retry delay
            if (now - rate_limits[i].last_attempt < AUTH_RETRY_DELAY) {
                return 0;
            }

            return 1;
        }
    }

    return 1; // Not in rate limit list
}

static void update_rate_limit(const char *ip, int success) {
    time_t now = time(NULL);

    for (int i = 0; i < rate_limit_count; i++) {
        if (strcmp(rate_limits[i].ip, ip) == 0) {
            if (success) {
                rate_limits[i].attempts = 0;
            } else {
                rate_limits[i].attempts++;
                rate_limits[i].last_attempt = now;
                if (rate_limits[i].attempts == 1) {
                    rate_limits[i].first_attempt = now;
                }
            }
            return;
        }
    }

    // Add new entry
    if (rate_limit_count < 256 && !success) {
        strncpy(rate_limits[rate_limit_count].ip, ip, INET_ADDRSTRLEN - 1);
        rate_limits[rate_limit_count].attempts = 1;
        rate_limits[rate_limit_count].first_attempt = now;
        rate_limits[rate_limit_count].last_attempt = now;
        rate_limit_count++;
    }
}

#ifdef _WIN32
static BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        running = 0;
        return TRUE;
    }
    return FALSE;
}
#else
static void signal_handler(int signum) {
    (void)signum;
    running = 0;
}
#endif

static void update_stats(int bytes_up, int bytes_down, int packets_up, int packets_down) {
    time_t now = time(NULL);

    // Update current second's stats
    if (stats_history[stats_index].timestamp != now) {
        stats_index = (stats_index + 1) % STATS_WINDOW;
        stats_history[stats_index].timestamp = now;
        stats_history[stats_index].bytes_up = 0;
        stats_history[stats_index].bytes_down = 0;
        stats_history[stats_index].packets_up = 0;
        stats_history[stats_index].packets_down = 0;
    }

    stats_history[stats_index].bytes_up += bytes_up;
    stats_history[stats_index].bytes_down += bytes_down;
    stats_history[stats_index].packets_up += packets_up;
    stats_history[stats_index].packets_down += packets_down;

    total_bytes_up += bytes_up;
    total_bytes_down += bytes_down;
    total_packets_up += packets_up;
    total_packets_down += packets_down;
}

static void format_speed(long long bytes_per_sec, char *buf, size_t bufsize) {
    double speed = (double)bytes_per_sec * 8.0; // Convert to bits

    if (speed < 1000.0) {
        snprintf(buf, bufsize, "%.0f bps", speed);
    } else if (speed < 1000000.0) {
        snprintf(buf, bufsize, "%.2f Kbps", speed / 1000.0);
    } else if (speed < 1000000000.0) {
        snprintf(buf, bufsize, "%.2f Mbps", speed / 1000000.0);
    } else {
        snprintf(buf, bufsize, "%.2f Gbps", speed / 1000000000.0);
    }
}

static void print_status(const char *mode, int tunnel_active, int clients) {
    time_t now = time(NULL);

    // Only update once per second to avoid spam
    if (now - last_update < 1) return;
    last_update = now;

    // Clear screen and move to top
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif

    // Calculate uptime
    int uptime = (int)(now - start_time);
    int hours = uptime / 3600;
    int mins = (uptime % 3600) / 60;
    int secs = uptime % 60;

    // Calculate traffic stats over last 30 seconds
    long long bytes_up_window = 0;
    long long bytes_down_window = 0;
    int packets_up_window = 0;
    int packets_down_window = 0;
    int valid_samples = 0;

    for (int i = 0; i < STATS_WINDOW; i++) {
        if (stats_history[i].timestamp > 0 && (now - stats_history[i].timestamp) < STATS_WINDOW) {
            bytes_up_window += stats_history[i].bytes_up;
            bytes_down_window += stats_history[i].bytes_down;
            packets_up_window += stats_history[i].packets_up;
            packets_down_window += stats_history[i].packets_down;
            valid_samples++;
        }
    }

    // Calculate average per second
    long long upload_speed = valid_samples > 0 ? bytes_up_window / valid_samples : 0;
    long long download_speed = valid_samples > 0 ? bytes_down_window / valid_samples : 0;
    int upload_pps = valid_samples > 0 ? packets_up_window / valid_samples : 0;
    int download_pps = valid_samples > 0 ? packets_down_window / valid_samples : 0;

    char upload_str[32], download_str[32];
    format_speed(upload_speed, upload_str, sizeof(upload_str));
    format_speed(download_speed, download_str, sizeof(download_str));

    // Print TUI header
    printf("+--------------------------------------------------------------+\n");
    printf("|                  SRP - Small Reverse Proxy                   |\n");
    printf("+--------------------------------------------------------------+\n");

    if (strcmp(mode, "forward") == 0) {
        printf("| Mode: Forward Agent                                          |\n");
        printf("+--------------------------------------------------------------+\n");
        printf("| Tunnel Status:   %-44s|\n", tunnel_active ? "CONNECTED" : "WAITING...");
        printf("| Active Client:   %-44d|\n", clients);
        printf("| Total Served:    %-44d|\n", total_connections);
        printf("+--------------------------------------------------------------+\n");
        printf("| Upload:          %-20s  %8d pps          |\n", upload_str, upload_pps);
        printf("| Download:        %-20s  %8d pps          |\n", download_str, download_pps);
    } else {
        printf("| Mode: Server                                                 |\n");
        printf("+--------------------------------------------------------------+\n");
        printf("| Forward Agents:  %-44d|\n", tunnel_active);
        printf("| Active Clients:  %-44d|\n", clients);
        printf("| Total Served:    %-44d|\n", total_connections);
        printf("+--------------------------------------------------------------+\n");
        printf("| Upload:          %-20s  %8d pps          |\n", upload_str, upload_pps);
        printf("| Download:        %-20s  %8d pps          |\n", download_str, download_pps);
    }

    printf("| Uptime:          %02d:%02d:%02d                                    |\n", hours, mins, secs);
    printf("+--------------------------------------------------------------+\n");
    printf("\nPress Ctrl+C to stop\n");

    fflush(stdout);
}

static int forward_mode(int local_port, const char *tunnel_addr, int tunnel_port) {
    printf("Connecting to tunnel at %s:%d...\n", tunnel_addr, tunnel_port);

    // Connect to tunnel server
    socket_t tunnel_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tunnel_fd == INVALID_SOCK) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in tunnel_sa;
    memset(&tunnel_sa, 0, sizeof(tunnel_sa));
    tunnel_sa.sin_family = AF_INET;
    tunnel_sa.sin_port = htons((u_short)tunnel_port);

    if (inet_pton(AF_INET, tunnel_addr, &tunnel_sa.sin_addr) <= 0) {
        perror("inet_pton");
        close(tunnel_fd);
        return -1;
    }

    if (connect(tunnel_fd, (struct sockaddr*)&tunnel_sa, sizeof(tunnel_sa)) < 0) {
        perror("connect to tunnel");
        close(tunnel_fd);
        return -1;
    }

    optimize_socket(tunnel_fd);

    // Send authentication
    char auth_msg[256];
    snprintf(auth_msg, sizeof(auth_msg), "AUTH:%s", password);
    if (send(tunnel_fd, auth_msg, (int)strlen(auth_msg), 0) < 0) {
        perror("send auth");
        close(tunnel_fd);
        return -1;
    }

    // Wait for auth response
    char response[16];
    int n = recv(tunnel_fd, response, sizeof(response) - 1, 0);
    if (n <= 0 || strncmp(response, "OK", 2) != 0) {
        fprintf(stderr, "Authentication failed\n");
        close(tunnel_fd);
        return -1;
    }

    start_time = time(NULL);
    last_update = 0;
    print_status("forward", 1, 0);

    set_nonblocking(tunnel_fd);    socket_t mc_fd = INVALID_SOCK;
    connection_t *tunnel_conn = alloc_connection(tunnel_fd);
    if (!tunnel_conn) {
        fprintf(stderr, "Failed to allocate connection\n");
        close(tunnel_fd);
        return -1;
    }
    tunnel_conn->state = CONN_STATE_TUNNEL_ESTABLISHED;
    tunnel_conn->peer_fd = INVALID_SOCK;

    // Main event loop - wait for data from tunnel, then connect to local server
    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tunnel_fd, &readfds);

        socket_t maxfd = tunnel_fd;

        if (mc_fd != INVALID_SOCK) {
            FD_SET(mc_fd, &readfds);
            if (mc_fd > maxfd) maxfd = mc_fd;
        }

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int activity = select((int)maxfd + 1, &readfds, NULL, NULL, &tv);

        if (activity < 0) {
            fprintf(stderr, "select error\n");
            break;
        }

        if (activity == 0) {
            print_status("forward", tunnel_fd != INVALID_SOCK, mc_fd != INVALID_SOCK ? 1 : 0);
            continue;
        }

        // Check tunnel socket
        if (FD_ISSET(tunnel_fd, &readfds)) {
            char buf[BUFFER_SIZE];
            n = recv(tunnel_fd, buf, sizeof(buf), 0);

            if (n <= 0) {
                fprintf(stderr, "Tunnel connection closed\n");
                if (mc_fd != INVALID_SOCK) close(mc_fd);
                cleanup_connection(tunnel_conn);
                return 1; // Signal reconnect needed
            }

            // First data received - connect to local server if not connected
            if (mc_fd == INVALID_SOCK) {
                total_connections++;
                active_clients = 1;

                mc_fd = socket(AF_INET, SOCK_STREAM, 0);
                if (mc_fd == INVALID_SOCK) {
                    fprintf(stderr, "Failed to create socket for local server\n");
                    close(tunnel_fd);
                    cleanup_connection(tunnel_conn);
                    return 1;
                }

                struct sockaddr_in mc_sa;
                memset(&mc_sa, 0, sizeof(mc_sa));
                mc_sa.sin_family = AF_INET;
                mc_sa.sin_addr.s_addr = inet_addr("127.0.0.1");
                mc_sa.sin_port = htons((u_short)local_port);

                if (connect(mc_fd, (struct sockaddr*)&mc_sa, sizeof(mc_sa)) < 0) {
                    fprintf(stderr, "Failed to connect to local server on localhost:%d\n", local_port);
                    fprintf(stderr, "Make sure your server is running on port %d\n", local_port);
                    close(mc_fd);
                    mc_fd = INVALID_SOCK;
                    close(tunnel_fd);
                    cleanup_connection(tunnel_conn);
                    return 1;
                }

                optimize_socket(mc_fd);
                set_nonblocking(mc_fd);

                connection_t *mc_conn = alloc_connection(mc_fd);
                if (mc_conn) {
                    mc_conn->state = CONN_STATE_FORWARDING;
                    mc_conn->peer_fd = tunnel_fd;
                    tunnel_conn->peer_fd = mc_fd;
                }

                printf("Connected to local server, forwarding traffic...\n");
            }

            // Forward to local server
            if (mc_fd != INVALID_SOCK) {
                if (send(mc_fd, buf, n, 0) < 0) {
                    fprintf(stderr, "Failed to send to local server\n");
                    close(mc_fd);
                    close(tunnel_fd);
                    cleanup_connection(tunnel_conn);
                    return 1;
                }
                update_stats(0, n, 0, 1);  // Download from tunnel
            }
        }

        // Check local server socket
        if (mc_fd != INVALID_SOCK && FD_ISSET(mc_fd, &readfds)) {
            char buf[BUFFER_SIZE];
            n = recv(mc_fd, buf, sizeof(buf), 0);

            if (n <= 0) {
                // Close local server connection but keep tunnel open
                connection_t *mc_conn = get_connection(mc_fd);
                if (mc_conn) {
                    close(mc_fd);
                    mc_conn->fd = INVALID_SOCK;
                    mc_conn->peer_fd = INVALID_SOCK;
                }
                tunnel_conn->peer_fd = INVALID_SOCK;
                mc_fd = INVALID_SOCK;
                active_clients = 0;
                print_status("forward", 1, 0);
                continue; // Keep looping, wait for next client
            }

            // Forward to tunnel
            if (send(tunnel_fd, buf, n, 0) < 0) {
                fprintf(stderr, "Failed to send to tunnel\n");
                close(mc_fd);
                close(tunnel_fd);
                cleanup_connection(tunnel_conn);
                return 1;
            }
            update_stats(n, 0, 1, 0);  // Upload to tunnel
        }
    }

    if (mc_fd != INVALID_SOCK) close(mc_fd);
    cleanup_connection(tunnel_conn);
    printf("\n");
    return 0;
}

static int serve_mode(const char *bind_addr, int bind_port, int tunnel_port) {
    // Create listening socket for CLIENTS
    socket_t listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == INVALID_SOCK) {
        perror("socket");
        return -1;
    }

    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    struct sockaddr_in bind_sa;
    memset(&bind_sa, 0, sizeof(bind_sa));
    bind_sa.sin_family = AF_INET;
    bind_sa.sin_port = htons((u_short)bind_port);

    if (inet_pton(AF_INET, bind_addr, &bind_sa.sin_addr) <= 0) {
        perror("inet_pton");
        close(listen_fd);
        return -1;
    }

    if (bind(listen_fd, (struct sockaddr*)&bind_sa, sizeof(bind_sa)) < 0) {
        perror("bind client port");
        close(listen_fd);
        return -1;
    }

    if (listen(listen_fd, SOMAXCONN) < 0) {
        perror("listen");
        close(listen_fd);
        return -1;
    }

    // Create listening socket for TUNNEL
    socket_t tunnel_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tunnel_listen_fd == INVALID_SOCK) {
        perror("socket");
        close(listen_fd);
        return -1;
    }

    setsockopt(tunnel_listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    struct sockaddr_in tunnel_sa;
    memset(&tunnel_sa, 0, sizeof(tunnel_sa));
    tunnel_sa.sin_family = AF_INET;
    tunnel_sa.sin_port = htons((u_short)tunnel_port);

    if (inet_pton(AF_INET, bind_addr, &tunnel_sa.sin_addr) <= 0) {
        perror("inet_pton");
        close(listen_fd);
        close(tunnel_listen_fd);
        return -1;
    }

    if (bind(tunnel_listen_fd, (struct sockaddr*)&tunnel_sa, sizeof(tunnel_sa)) < 0) {
        perror("bind tunnel port");
        close(listen_fd);
        close(tunnel_listen_fd);
        return -1;
    }

    if (listen(tunnel_listen_fd, SOMAXCONN) < 0) {
        perror("listen");
        close(listen_fd);
        close(tunnel_listen_fd);
        return -1;
    }

    set_nonblocking(listen_fd);
    set_nonblocking(tunnel_listen_fd);

    start_time = time(NULL);
    last_update = 0;
    print_status("serve", 0, 0);    socket_t tunnel_fd = INVALID_SOCK;
    socket_t client_fd = INVALID_SOCK;

    // Main event loop
    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(listen_fd, &readfds);
        FD_SET(tunnel_listen_fd, &readfds);

        socket_t maxfd = (listen_fd > tunnel_listen_fd) ? listen_fd : tunnel_listen_fd;

        if (tunnel_fd != INVALID_SOCK) {
            FD_SET(tunnel_fd, &readfds);
            if (tunnel_fd > maxfd) maxfd = tunnel_fd;
        }

        if (client_fd != INVALID_SOCK) {
            FD_SET(client_fd, &readfds);
            if (client_fd > maxfd) maxfd = client_fd;
        }

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int activity = select((int)maxfd + 1, &readfds, NULL, NULL, &tv);

        if (activity < 0) {
            break;
        }

        if (activity == 0) {
            print_status("serve", tunnel_fd != INVALID_SOCK ? 1 : 0, client_fd != INVALID_SOCK ? 1 : 0);
            // Timeout - check auth timeouts
            time_t now = time(NULL);
            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                connection_t *conn = &connections[i];
                if (conn->fd != INVALID_SOCK && conn->state == CONN_STATE_AUTH) {
                    if (now - conn->auth_start > AUTH_TIMEOUT) {
                        printf("Authentication timeout\n");
                        cleanup_connection(conn);
                        if (tunnel_fd == conn->fd) tunnel_fd = INVALID_SOCK;
                    }
                }
            }
            continue;
        }

        // Check for new TUNNEL connections
        if (FD_ISSET(tunnel_listen_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            socket_t new_fd = accept(tunnel_listen_fd, (struct sockaddr*)&client_addr, &client_len);

            if (new_fd != INVALID_SOCK) {
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

                if (tunnel_fd == INVALID_SOCK) {
                    optimize_socket(new_fd);
                    set_nonblocking(new_fd);

                    connection_t *conn = alloc_connection(new_fd);
                    if (conn) {
                        conn->state = CONN_STATE_AUTH;
                        conn->auth_start = time(NULL);
                        tunnel_fd = new_fd;
                    }
                } else {
                    close(new_fd);
                }
            }
        }

        // Check for new CLIENT connections
        if (FD_ISSET(listen_fd, &readfds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            socket_t new_fd = accept(listen_fd, (struct sockaddr*)&client_addr, &client_len);

            if (new_fd != INVALID_SOCK) {
                char client_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

                if (tunnel_fd == INVALID_SOCK) {
                    printf("Client from %s rejected (no tunnel connected)\n", client_ip);
                    close(new_fd);
                } else if (client_fd == INVALID_SOCK) {
                    connection_t *tunnel = get_connection(tunnel_fd);
                    if (tunnel && tunnel->state == CONN_STATE_TUNNEL_ESTABLISHED) {
                        optimize_socket(new_fd);
                        set_nonblocking(new_fd);
                        client_fd = new_fd;

                        connection_t *conn = alloc_connection(new_fd);
                        if (conn && tunnel) {
                            conn->state = CONN_STATE_FORWARDING;
                            conn->peer_fd = tunnel_fd;
                            tunnel->peer_fd = new_fd;
                        }
                    } else {
                        printf("Client from %s rejected (tunnel not authenticated)\n", client_ip);
                        close(new_fd);
                    }
                } else {
                    printf("Client from %s rejected (already have a client)\n", client_ip);
                    close(new_fd);
                }
            }
        }

        // Handle tunnel data
        if (tunnel_fd != INVALID_SOCK && FD_ISSET(tunnel_fd, &readfds)) {
            connection_t *conn = get_connection(tunnel_fd);

            if (conn && conn->state == CONN_STATE_AUTH) {
                // Handle authentication
                char buf[256];
                int n = recv(tunnel_fd, buf, sizeof(buf) - 1, 0);

                if (n <= 0) {
                    cleanup_connection(conn);
                    tunnel_fd = INVALID_SOCK;
                } else {
                    buf[n] = '\0';

                    struct sockaddr_in addr;
                    socklen_t addr_len = sizeof(addr);
                    getpeername(tunnel_fd, (struct sockaddr*)&addr, &addr_len);
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));

                    if (!check_rate_limit(ip)) {
                        printf("Rate limited: %s\n", ip);
                        cleanup_connection(conn);
                        tunnel_fd = INVALID_SOCK;
                    } else if (strncmp(buf, "AUTH:", 5) == 0) {
                        const char *recv_pass = buf + 5;

                        if (strcmp(recv_pass, password) == 0) {
                            send(tunnel_fd, "OK", 2, 0);
                            conn->state = CONN_STATE_TUNNEL_ESTABLISHED;
                            update_rate_limit(ip, 1);
                            print_status("serve", 1, 0);
                        } else {
                            send(tunnel_fd, "FAIL", 4, 0);
                            update_rate_limit(ip, 0);
#ifdef _WIN32
                            Sleep(1000);
#else
                            sleep(1);
#endif
                            cleanup_connection(conn);
                            tunnel_fd = INVALID_SOCK;
                        }
                    } else {
                        send(tunnel_fd, "FAIL", 4, 0);
                        update_rate_limit(ip, 0);
#ifdef _WIN32
                        Sleep(1000);
#else
                        sleep(1);
#endif
                        cleanup_connection(conn);
                        tunnel_fd = INVALID_SOCK;
                    }
                }
            } else if (conn && conn->peer_fd != INVALID_SOCK) {
                // Forward data to client
                char buf[BUFFER_SIZE];
                int n = recv(tunnel_fd, buf, sizeof(buf), 0);

                if (n <= 0) {
                    // Tunnel died - close client too
                    if (client_fd != INVALID_SOCK) {
                        connection_t *client_conn = get_connection(client_fd);
                        if (client_conn) {
                            close(client_fd);
                            client_conn->fd = INVALID_SOCK;
                            client_conn->peer_fd = INVALID_SOCK;
                        }
                    }
                    cleanup_connection(conn);
                    tunnel_fd = INVALID_SOCK;
                    client_fd = INVALID_SOCK;
                    active_clients = 0;
                    print_status("serve", 0, 0);
                } else {
                    send(conn->peer_fd, buf, n, 0);
                    update_stats(0, n, 0, 1);  // Download from tunnel to client
                }
            }
        }

        // Handle client data
        if (client_fd != INVALID_SOCK && FD_ISSET(client_fd, &readfds)) {
            connection_t *conn = get_connection(client_fd);

            if (conn && conn->peer_fd != INVALID_SOCK) {
                char buf[BUFFER_SIZE];
                int n = recv(client_fd, buf, sizeof(buf), 0);

                if (n <= 0) {
                    // Only close client, keep tunnel connected
                    connection_t *tunnel = get_connection(tunnel_fd);
                    if (tunnel) {
                        tunnel->peer_fd = INVALID_SOCK;
                    }
                    close(client_fd);
                    conn->fd = INVALID_SOCK;
                    conn->peer_fd = INVALID_SOCK;
                    client_fd = INVALID_SOCK;
                    active_clients = 0;
                    print_status("serve", 1, 0);
                } else {
                    send(conn->peer_fd, buf, n, 0);
                    update_stats(n, 0, 1, 0);  // Upload from client to tunnel
                }
            }
        }
    }

    close(listen_fd);
    close(tunnel_listen_fd);
    printf("\n");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage:\n");
        fprintf(stderr, "  Forward mode: %s forward <local-port> <tunnel-ip:port> <password>\n", argv[0]);
        fprintf(stderr, "  Serve mode:   %s serve <client-addr:port> <tunnel-addr:port> <password>\n", argv[0]);
        fprintf(stderr, "\nExample:\n");
        fprintf(stderr, "  VPS:  %s serve 0.0.0.0:25565 0.0.0.0:7777 mypass\n", argv[0]);
        fprintf(stderr, "  Home: %s forward 25565 vps-ip:7777 mypass\n", argv[0]);
        return 1;
    }

    init_network();

#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);
#endif

    // Initialize connection table
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        connections[i].fd = INVALID_SOCK;
        connections[i].peer_fd = INVALID_SOCK;
    }

    if (strcmp(argv[1], "forward") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s forward <local-port> <tunnel-ip:port> <password>\n", argv[0]);
            cleanup_network();
            return 1;
        }

        int local_port = atoi(argv[2]);
        char tunnel_addr[256];
        int tunnel_port;

        char *colon = strchr(argv[3], ':');
        if (!colon) {
            fprintf(stderr, "Invalid tunnel address format. Use IP:PORT\n");
            cleanup_network();
            return 1;
        }

        strncpy(tunnel_addr, argv[3], colon - argv[3]);
        tunnel_addr[colon - argv[3]] = '\0';
        tunnel_port = atoi(colon + 1);

        strncpy(password, argv[4], sizeof(password) - 1);

        // Auto-reconnect loop
        while (running) {
            int ret = forward_mode(local_port, tunnel_addr, tunnel_port);
            if (ret == 0 || !running) break;

            printf("Reconnecting in 5 seconds...\n");
#ifdef _WIN32
            Sleep(5000);
#else
            sleep(5);
#endif
        }

    } else if (strcmp(argv[1], "serve") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage: %s serve <client-addr:port> <tunnel-addr:port> <password>\n", argv[0]);
            fprintf(stderr, "\nExample: %s serve 0.0.0.0:25565 0.0.0.0:7777 mypass\n", argv[0]);
            fprintf(stderr, "  - Clients connect to port 25565\n");
            fprintf(stderr, "  - Forward agent connects to port 7777\n");
            cleanup_network();
            return 1;
        }

        char client_addr[256];
        int client_port;
        char tunnel_addr[256];
        int tunnel_port;

        char *colon = strchr(argv[2], ':');
        if (!colon) {
            fprintf(stderr, "Invalid client address format. Use IP:PORT\n");
            cleanup_network();
            return 1;
        }

        strncpy(client_addr, argv[2], colon - argv[2]);
        client_addr[colon - argv[2]] = '\0';
        client_port = atoi(colon + 1);

        colon = strchr(argv[3], ':');
        if (!colon) {
            fprintf(stderr, "Invalid tunnel address format. Use IP:PORT\n");
            cleanup_network();
            return 1;
        }

        strncpy(tunnel_addr, argv[3], colon - argv[3]);
        tunnel_addr[colon - argv[3]] = '\0';
        tunnel_port = atoi(colon + 1);

        // Use same bind address for both
        if (strcmp(client_addr, tunnel_addr) != 0) {
            fprintf(stderr, "Warning: Client and tunnel addresses must be the same\n");
            fprintf(stderr, "Using: %s for both ports\n", client_addr);
        }

        strncpy(password, argv[4], sizeof(password) - 1);

        serve_mode(client_addr, client_port, tunnel_port);
    } else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        fprintf(stderr, "Use 'forward' or 'serve'\n");
        cleanup_network();
        return 1;
    }

    cleanup_network();
    printf("\nShutdown complete\n");
    return 0;
}


