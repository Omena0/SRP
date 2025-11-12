/*
 * SRP - Small Reverse Proxy
 * High-performance reverse proxy with session multiplexing
 * Supports multiple clients per agent with full concurrency
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
#include <sys/ioctl.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#endif

#define BUFFER_SIZE 32767
#define MAX_CONNECTIONS 256
#define MAX_FORWARDED_PORTS 256
#define AUTH_TIMEOUT 5
#define RATE_LIMIT_WINDOW 60
#define MAX_AUTH_ATTEMPTS 3
#define AUTH_RETRY_DELAY 1

#ifdef _WIN32
typedef SOCKET socket_t;
#define INVALID_SOCK INVALID_SOCKET
#define SOCK_ERR SOCKET_ERROR
#define SEND_FLAGS 0
#else
typedef int socket_t;
#define INVALID_SOCK -1
#define SOCK_ERR -1
#define SEND_FLAGS MSG_NOSIGNAL
#include <pthread.h>
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
    int forwarded_port;
    int is_tunnel;
    unsigned short session_id;  // Session ID for multiplexing
} connection_t;

typedef struct {
    char ip[INET_ADDRSTRLEN];
    int attempts;
    time_t first_attempt;
    time_t last_attempt;
} rate_limit_entry_t;

typedef struct {
    int port;
    socket_t listen_fd;
    socket_t tunnel_fd;
    char bind_addr[256];
} forwarded_port_t;

typedef struct {
    int local_port;
    int remote_port;
} forward_config_t;

// Packet protocol for session multiplexing
#define SESSION_ID_HEARTBEAT 0xFFFF  // Special session ID for heartbeat packets

#pragma pack(push, 1)
typedef struct {
    unsigned short session_id;
    unsigned short length;
} packet_header_t;
#pragma pack(pop)

static connection_t connections[MAX_CONNECTIONS];
static forwarded_port_t forwarded_ports[MAX_FORWARDED_PORTS];
static int forwarded_port_count = 0;
static forward_config_t forward_configs[MAX_FORWARDED_PORTS];
static int forward_config_count = 0;
static rate_limit_entry_t rate_limits[256];
static int rate_limit_count = 0;
static volatile int running = 1;
static char password[256];
static volatile unsigned long long total_connections = 0;
static volatile int active_clients = 0;
static volatile int tunnel_connected = 0;  // Track tunnel connection status
static volatile double ping_ms = 0.0;  // Current ping in milliseconds
static time_t start_time = 0;
static unsigned long long last_update_us = 0;  // Last update time in microseconds
static time_t last_heartbeat = 0;

#define STATS_WINDOW 5
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

#ifndef _WIN32
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

typedef struct {
    int local_port;
    int server_port;
    char tunnel_addr[256];
    int tunnel_port;
} forward_thread_args_t;

typedef struct {
    char bind_addr[256];
    int tunnel_port;
} serve_thread_args_t;

static void init_network(void);
static void cleanup_network(void);
static int set_nonblocking(socket_t fd);
static int set_tcp_nodelay(socket_t fd);
static void optimize_socket(socket_t fd);
static connection_t* get_connection(socket_t fd);
static connection_t* alloc_connection(socket_t fd);
static void cleanup_connection(connection_t *conn);
static forwarded_port_t* get_forwarded_port(int port);
static int add_forwarded_port(int port, socket_t listen_fd, socket_t tunnel_fd, const char *bind_addr);
static void remove_forwarded_port(int port);
static void remove_forwarded_ports_for_tunnel(socket_t tunnel_fd);
static int check_rate_limit(const char *ip);
static void update_rate_limit(const char *ip, int success);
static int send_packet(socket_t fd, unsigned short session_id, const char *data, unsigned short length);
static int forward_mode(int local_port, int server_port, const char *tunnel_addr, int tunnel_port);
static int serve_mode(const char *bind_addr, int tunnel_port);
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
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static int set_tcp_nodelay(socket_t fd) {
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&flag, sizeof(flag));
}

static void optimize_socket(socket_t fd) {
    set_tcp_nodelay(fd);
    int sndbuf = BUFFER_SIZE * 8;  // Larger send buffer
    int rcvbuf = BUFFER_SIZE * 8;  // Larger receive buffer
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(sndbuf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char*)&rcvbuf, sizeof(rcvbuf));
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
            connections[i].state = CONN_STATE_AUTH;
            connections[i].auth_start = time(NULL);
            return &connections[i];
        }
    }
    return NULL;
}

static void cleanup_connection(connection_t *conn) {
    if (conn->fd != INVALID_SOCK) {
        close(conn->fd);
        conn->fd = INVALID_SOCK;
    }
    conn->peer_fd = INVALID_SOCK;
    conn->state = CONN_STATE_AUTH;
    conn->buffer_used = 0;
}

static forwarded_port_t* get_forwarded_port(int port) {
    for (int i = 0; i < forwarded_port_count; i++) {
        if (forwarded_ports[i].port == port) {
            return &forwarded_ports[i];
        }
    }
    return NULL;
}

static int add_forwarded_port(int port, socket_t listen_fd, socket_t tunnel_fd, const char *bind_addr) {
    if (forwarded_port_count >= MAX_FORWARDED_PORTS) {
        return -1;
    }
    forwarded_ports[forwarded_port_count].port = port;
    forwarded_ports[forwarded_port_count].listen_fd = listen_fd;
    forwarded_ports[forwarded_port_count].tunnel_fd = tunnel_fd;
    strncpy(forwarded_ports[forwarded_port_count].bind_addr, bind_addr, sizeof(forwarded_ports[forwarded_port_count].bind_addr) - 1);
    forwarded_port_count++;
    return 0;
}

static void remove_forwarded_port(int port) {
    for (int i = 0; i < forwarded_port_count; i++) {
        if (forwarded_ports[i].port == port) {
            if (forwarded_ports[i].listen_fd != INVALID_SOCK) {
                close(forwarded_ports[i].listen_fd);
            }
            for (int j = i; j < forwarded_port_count - 1; j++) {
                forwarded_ports[j] = forwarded_ports[j + 1];
            }
            forwarded_port_count--;
            break;
        }
    }
}

static void remove_forwarded_ports_for_tunnel(socket_t tunnel_fd) {
    for (int i = forwarded_port_count - 1; i >= 0; i--) {
        if (forwarded_ports[i].tunnel_fd == tunnel_fd) {
            remove_forwarded_port(forwarded_ports[i].port);
        }
    }
}

static int check_rate_limit(const char *ip) {
    time_t now = time(NULL);
    for (int i = 0; i < rate_limit_count; i++) {
        if (strcmp(rate_limits[i].ip, ip) == 0) {
            if (now - rate_limits[i].first_attempt >= RATE_LIMIT_WINDOW) {
                rate_limits[i].attempts = 0;
                rate_limits[i].first_attempt = now;
                return 1;
            }
            if (rate_limits[i].attempts >= MAX_AUTH_ATTEMPTS) {
                return 0;
            }
            if (now - rate_limits[i].last_attempt < AUTH_RETRY_DELAY) {
                return 0;
            }
            return 1;
        }
    }
    return 1;
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
    if (rate_limit_count < 256 && !success) {
        strncpy(rate_limits[rate_limit_count].ip, ip, INET_ADDRSTRLEN - 1);
        rate_limits[rate_limit_count].attempts = 1;
        rate_limits[rate_limit_count].first_attempt = now;
        rate_limits[rate_limit_count].last_attempt = now;
        rate_limit_count++;
    }
}

static int send_packet(socket_t fd, unsigned short session_id, const char *data, unsigned short length) {
    packet_header_t header;
    header.session_id = htons(session_id);
    header.length = htons(length);

#ifdef _WIN32
    int flags = SEND_FLAGS;
#else
    int flags = SEND_FLAGS;
#endif

    // Send header
    int sent = send(fd, (const char*)&header, sizeof(header), flags);
    if (sent < 0) {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) return 0;  // Would block, try again later
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;  // Would block, try again later
#endif
        return -1;  // Real error
    }
    if (sent != sizeof(header)) {
        return -1;  // Partial header send is an error
    }

    // Send data
    if (length > 0) {
        sent = send(fd, data, length, flags);
        if (sent < 0) {
#ifdef _WIN32
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) return 0;  // Would block, try again later
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;  // Would block, try again later
#endif
            return -1;  // Real error
        }
        if (sent != length) {
            return -1;  // Partial data send is an error
        }
    }
    return 1;  // Success
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
static void signal_handler(int sig) {
    (void)sig;
    running = 0;
}
#endif

static void update_stats(int bytes_up, int bytes_down, int packets_up, int packets_down) {
#ifndef _WIN32
    pthread_mutex_lock(&stats_mutex);
#endif
    time_t now = time(NULL);
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
#ifndef _WIN32
    pthread_mutex_unlock(&stats_mutex);
#endif
}

static void format_speed(long long bytes_per_sec, char *buf, size_t bufsize) {
    if (bytes_per_sec >= 1024 * 1024) {
        snprintf(buf, bufsize, "%.2f MB/s", bytes_per_sec / (1024.0 * 1024.0));
    } else if (bytes_per_sec >= 1024) {
        snprintf(buf, bufsize, "%.2f KB/s", bytes_per_sec / 1024.0);
    } else {
        snprintf(buf, bufsize, "%lld B/s", bytes_per_sec);
    }
}

static void print_status(const char *mode, int tunnel_active, int clients) {
    // Get current time in microseconds
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    unsigned long long now_us = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    now_us = now_us / 10;  // Convert to microseconds
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long now_us = (unsigned long long)tv.tv_sec * 1000000ULL + tv.tv_usec;
#endif

    // Update every 250ms
    if (now_us - last_update_us < 250000) return;
    last_update_us = now_us;

    time_t now = time(NULL);

#ifndef _WIN32
    pthread_mutex_lock(&stats_mutex);
#endif

    long long bytes_up = 0, bytes_down = 0;
    int packets_up = 0, packets_down = 0;
    time_t oldest = now - STATS_WINDOW;
    for (int i = 0; i < STATS_WINDOW; i++) {
        if (stats_history[i].timestamp >= oldest) {
            bytes_up += stats_history[i].bytes_up;
            bytes_down += stats_history[i].bytes_down;
            packets_up += stats_history[i].packets_up;
            packets_down += stats_history[i].packets_down;
        }
    }

    long long upload_bps = bytes_up / STATS_WINDOW;
    long long download_bps = bytes_down / STATS_WINDOW;
    int upload_pps = packets_up / STATS_WINDOW;
    int download_pps = packets_down / STATS_WINDOW;

    unsigned long long total_conns = total_connections;
    double current_ping = ping_ms;

#ifndef _WIN32
    pthread_mutex_unlock(&stats_mutex);
#endif

    char upload_str[32], download_str[32];
    format_speed(upload_bps, upload_str, sizeof(upload_str));
    format_speed(download_bps, download_str, sizeof(download_str));

    int uptime = (start_time > 0) ? (int)(now - start_time) : 0;
    int hours = uptime / 3600;
    int mins = (uptime % 3600) / 60;
    int secs = uptime % 60;

    // Get terminal size
    int term_width = 80, term_height = 24;
#ifndef _WIN32
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) {
        term_width = w.ws_col;
        term_height = w.ws_row;
    }
#endif
    if (term_width < 50) term_width = 50;  // Minimum width

    int box_width = term_width - 2;  // Account for borders

    // Clear screen properly for both Unix and Windows
    printf("\033[2J");       // Clear entire screen
    printf("\033[3J");       // Clear scrollback buffer
    printf("\033[H");        // Move cursor to home position
    fflush(stdout);

    // Dynamic box drawing
    printf("+");
    for (int i = 0; i < box_width; i++) printf("-");
    printf("+\n");

    // Center the title
    const char *title = "SRP - Small Reverse Proxy";
    int title_len = strlen(title);
    int padding = (box_width - title_len) / 2;
    printf("|%*s%s%*s|\n", padding, "", title, box_width - padding - title_len, "");

    printf("+");
    for (int i = 0; i < box_width; i++) printf("-");
    printf("+\n");

    if (strcmp(mode, "serve") == 0) {
        char line[512];
        snprintf(line, sizeof(line), "%-20s %d", "Mode:", 0);
        sprintf(line, "%-20s Server", "Mode:");
        printf("| %-*s |\n", box_width - 2, line);

        sprintf(line, "%-20s %02d:%02d:%02d", "Uptime:", hours, mins, secs);
        printf("| %-*s |\n", box_width - 2, line);

        // Separator
        printf("+");
        for (int i = 0; i < box_width; i++) printf("-");
        printf("+\n");

        sprintf(line, "%-20s %d", "Active Tunnels:", tunnel_active);
        printf("| %-*s |\n", box_width - 2, line);

        sprintf(line, "%-20s %d", "Active Clients:", clients);
        printf("| %-*s |\n", box_width - 2, line);

        sprintf(line, "%-20s %llu", "Total Served:", total_conns);
        printf("| %-*s |\n", box_width - 2, line);

        // Separator
        printf("+");
        for (int i = 0; i < box_width; i++) printf("-");
        printf("+\n");

        sprintf(line, "%-20s %s (%d pps)", "Upload:", upload_str, upload_pps);
        printf("| %-*s |\n", box_width - 2, line);

        sprintf(line, "%-20s %s (%d pps)", "Download:", download_str, download_pps);
        printf("| %-*s |\n", box_width - 2, line);

        // Bottom border
        printf("+");
        for (int i = 0; i < box_width; i++) printf("-");
        printf("+\n");
    } else {
        // Forward agent - show forwards table and stats side by side
        int left_width = box_width / 2 - 1;
        int right_width = box_width - left_width - 3;

        // Header line - calculate padding for each section
        int left_text_len = 9;  // "Forwards" length
        int right_text_len = 11; // "Statistics" length
        int left_equals = (left_width - left_text_len - 2) / 2;
        int right_equals = (right_width - right_text_len - 2) / 2;
        
        printf("|");
        for (int i = 0; i < left_equals+1; i++) printf("=");
        printf(" Forwards ");
        for (int i = 0; i < left_width - left_equals - left_text_len - 2; i++) printf("=");
        printf("|");
        for (int i = 0; i < right_equals; i++) printf("=");
        printf(" Statistics ");
        for (int i = 0; i < right_width - right_equals - right_text_len + 1; i++) printf("=");
        printf("|\n");

        // Content - show forwards and stats
        int max_lines = (forward_config_count > 7) ? forward_config_count : 7;
        for (int i = 0; i < max_lines; i++) {
            char left_content[256] = "";
            char right_content[256] = "";

            if (i < forward_config_count) {
                snprintf(left_content, sizeof(left_content), "%5d --> %-5d",
                         forward_configs[i].local_port, forward_configs[i].remote_port);
            }

            if (i == 0) {
                snprintf(right_content, sizeof(right_content), "Tunnel: %s",
                         tunnel_active ? "Connected" : "Disconnected");
            } else if (i == 1) {
                snprintf(right_content, sizeof(right_content), "Uptime: %02d:%02d:%02d", hours, mins, secs);
            } else if (i == 2) {
                snprintf(right_content, sizeof(right_content), "Ping: %.2f ms", current_ping);
            } else if (i == 3) {
                snprintf(right_content, sizeof(right_content), "Active Sessions: %d", clients);
            } else if (i == 4) {
                snprintf(right_content, sizeof(right_content), "Total Served: %llu", total_conns);
            } else if (i == 5) {
                snprintf(right_content, sizeof(right_content), "Upload:   %s (%d pps)", upload_str, upload_pps);
            } else if (i == 6) {
                snprintf(right_content, sizeof(right_content), "Download: %s (%d pps)", download_str, download_pps);
            }

            printf("| %-*s| %-*s|\n", left_width-1, left_content, right_width+1, right_content);
        }

        // Bottom line
        printf("\\");
        for (int i = 0; i < left_width; i++) printf("=");
        printf("|");
        for (int i = 0; i < right_width+2; i++) printf("=");
        printf("/\n");
    }
    fflush(stdout);
}

static int forward_mode(int local_port, int server_port, const char *tunnel_addr, int tunnel_port) {
    socket_t tunnel_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tunnel_fd == INVALID_SOCK) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in tunnel_sa;
    memset(&tunnel_sa, 0, sizeof(tunnel_sa));
    tunnel_sa.sin_family = AF_INET;
    tunnel_sa.sin_port = htons((unsigned short)tunnel_port);

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

    char auth_msg[256];
    snprintf(auth_msg, sizeof(auth_msg), "AUTH:%s:%d", password, server_port);
    if (send(tunnel_fd, auth_msg, (int)strlen(auth_msg), SEND_FLAGS) < 0) {
        perror("send auth");
        close(tunnel_fd);
        return -1;
    }

    char response[16];
    int n = recv(tunnel_fd, response, sizeof(response) - 1, 0);
    if (n <= 0 || strncmp(response, "OK", 2) != 0) {
        fprintf(stderr, "Authentication failed\n");
        close(tunnel_fd);
        return -1;
    }

    start_time = time(NULL);
    last_update_us = 0;

    set_nonblocking(tunnel_fd);

    tunnel_connected = 1;  // Mark tunnel as connected

    connection_t *tunnel_conn = alloc_connection(tunnel_fd);
    if (!tunnel_conn) {
        fprintf(stderr, "Failed to allocate connection\n");
        close(tunnel_fd);
        return -1;
    }
    tunnel_conn->state = CONN_STATE_TUNNEL_ESTABLISHED;
    tunnel_conn->peer_fd = INVALID_SOCK;
    tunnel_conn->is_tunnel = 1;

    typedef struct {
        unsigned short session_id;
        socket_t fd;
        int active;
    } session_t;

    session_t sessions[MAX_CONNECTIONS];
    memset(sessions, 0, sizeof(sessions));
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        sessions[i].fd = INVALID_SOCK;
    }

    char packet_buf[BUFFER_SIZE];  // Larger buffer for multiple packets
    int packet_buf_used = 0;

    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tunnel_fd, &readfds);

        socket_t maxfd = tunnel_fd;
        int active_session_count = 0;
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (sessions[i].active && sessions[i].fd != INVALID_SOCK) {
                FD_SET(sessions[i].fd, &readfds);
                if (sessions[i].fd > maxfd) maxfd = sessions[i].fd;
                active_session_count++;
            }
        }
        active_clients = active_session_count;  // Update global counter

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        // Send heartbeat every second
        time_t now = time(NULL);
        if (now - last_heartbeat >= 1) {
            last_heartbeat = now;
#ifdef _WIN32
            FILETIME ft;
            GetSystemTimePreciseAsFileTime(&ft);
            unsigned long long timestamp = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            timestamp = timestamp / 10;  // Convert to microseconds
#else
            struct timeval tv;
            gettimeofday(&tv, NULL);
            unsigned long long timestamp = (unsigned long long)tv.tv_sec * 1000000ULL + tv.tv_usec;
#endif
            send_packet(tunnel_fd, SESSION_ID_HEARTBEAT, (char*)&timestamp, sizeof(timestamp));
        }

        int activity = select((int)maxfd + 1, &readfds, NULL, NULL, &tv);

        if (activity < 0) {
            fprintf(stderr, "select error\n");
            break;
        }

        if (activity == 0) {
            continue;
        }

        if (FD_ISSET(tunnel_fd, &readfds)) {
            char temp_buf[BUFFER_SIZE];
            n = recv(tunnel_fd, temp_buf, sizeof(temp_buf), 0);

            if (n < 0) {
#ifdef _WIN32
                int err = WSAGetLastError();
                if (err != WSAEWOULDBLOCK) {
#else
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
#endif
                    fprintf(stderr, "Tunnel connection error\n");
                    for (int i = 0; i < MAX_CONNECTIONS; i++) {
                        if (sessions[i].active && sessions[i].fd != INVALID_SOCK) {
                            close(sessions[i].fd);
                            sessions[i].active = 0;
                            sessions[i].fd = INVALID_SOCK;
                        }
                    }
                    cleanup_connection(tunnel_conn);
                    tunnel_connected = 0;
                    return 1;
#ifdef _WIN32
                }
#else
                }
#endif
            } else if (n == 0) {
                fprintf(stderr, "Tunnel connection closed\n");
                for (int i = 0; i < MAX_CONNECTIONS; i++) {
                    if (sessions[i].active && sessions[i].fd != INVALID_SOCK) {
                        close(sessions[i].fd);
                        sessions[i].active = 0;
                        sessions[i].fd = INVALID_SOCK;
                    }
                }
                cleanup_connection(tunnel_conn);
                tunnel_connected = 0;  // Mark tunnel as disconnected
                return 1;
            } else if (n > 0) {

            if (packet_buf_used + n > (int)sizeof(packet_buf)) {
                fprintf(stderr, "Packet buffer overflow\n");
                break;
            }
            memcpy(packet_buf + packet_buf_used, temp_buf, n);
            packet_buf_used += n;

            while (packet_buf_used >= (int)sizeof(packet_header_t)) {
                packet_header_t *header = (packet_header_t*)packet_buf;
                unsigned short session_id = ntohs(header->session_id);
                unsigned short length = ntohs(header->length);

                if (packet_buf_used < (int)(sizeof(packet_header_t) + length)) {
                    break;
                }

                // Handle heartbeat response
                if (session_id == SESSION_ID_HEARTBEAT && length == sizeof(unsigned long long)) {
                    unsigned long long sent_timestamp;
                    memcpy(&sent_timestamp, packet_buf + sizeof(packet_header_t), sizeof(sent_timestamp));

#ifdef _WIN32
                    FILETIME ft;
                    GetSystemTimePreciseAsFileTime(&ft);
                    unsigned long long now_timestamp = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
                    now_timestamp = now_timestamp / 10;  // Convert to microseconds
#else
                    struct timeval tv;
                    gettimeofday(&tv, NULL);
                    unsigned long long now_timestamp = (unsigned long long)tv.tv_sec * 1000000ULL + tv.tv_usec;
#endif
                    // Sanity check: if timestamp is in the future or too old (>10 seconds), ignore it
                    if (now_timestamp > sent_timestamp && (now_timestamp - sent_timestamp) < 10000000ULL) {
                        ping_ms = (now_timestamp - sent_timestamp) / 1000.0;  // Convert microseconds to milliseconds
                    }

                    // Remove heartbeat packet from buffer
                    int packet_size = sizeof(packet_header_t) + length;
                    memmove(packet_buf, packet_buf + packet_size, packet_buf_used - packet_size);
                    packet_buf_used -= packet_size;
                    continue;
                }

                session_t *session = NULL;
                for (int i = 0; i < MAX_CONNECTIONS; i++) {
                    if (sessions[i].active && sessions[i].session_id == session_id) {
                        session = &sessions[i];
                        break;
                    }
                }

                if (!session && length > 0) {
                    for (int i = 0; i < MAX_CONNECTIONS; i++) {
                        if (!sessions[i].active) {
                            socket_t mc_fd = socket(AF_INET, SOCK_STREAM, 0);
                            if (mc_fd == INVALID_SOCK) {
                                fprintf(stderr, "Failed to create socket for local server\n");
                                break;
                            }

                            struct sockaddr_in mc_sa;
                            memset(&mc_sa, 0, sizeof(mc_sa));
                            mc_sa.sin_family = AF_INET;
                            mc_sa.sin_addr.s_addr = inet_addr("127.0.0.1");
                            mc_sa.sin_port = htons((unsigned short)local_port);

                            optimize_socket(mc_fd);

                            if (connect(mc_fd, (struct sockaddr*)&mc_sa, sizeof(mc_sa)) < 0) {
                                fprintf(stderr, "Failed to connect to local server on localhost:%d\n", local_port);
                                close(mc_fd);
                                break;
                            }

                            set_nonblocking(mc_fd);

                            sessions[i].session_id = session_id;
                            sessions[i].fd = mc_fd;
                            sessions[i].active = 1;
                            session = &sessions[i];
                            total_connections++;
                            break;
                        }
                    }
                }

                if (session && session->fd != INVALID_SOCK) {
                    if (length == 0) {
                        close(session->fd);
                        session->active = 0;
                        session->fd = INVALID_SOCK;
                    } else {
                        char *data = packet_buf + sizeof(packet_header_t);
                        int sent = send(session->fd, data, length, SEND_FLAGS);
                        if (sent < 0) {
#ifdef _WIN32
                            int err = WSAGetLastError();
                            if (err != WSAEWOULDBLOCK) {
#else
                            if (errno != EAGAIN && errno != EWOULDBLOCK) {
#endif
                                close(session->fd);
                                session->active = 0;
                                session->fd = INVALID_SOCK;
                                send_packet(tunnel_fd, session_id, NULL, 0);
#ifdef _WIN32
                            }
#else
                            }
#endif
                        } else if (sent > 0) {
                            update_stats(0, sent, 0, 1);
                        }
                    }
                }

                int packet_size = sizeof(packet_header_t) + length;
                memmove(packet_buf, packet_buf + packet_size, packet_buf_used - packet_size);
                packet_buf_used -= packet_size;
            }
            }
        }

        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (sessions[i].active && sessions[i].fd != INVALID_SOCK && FD_ISSET(sessions[i].fd, &readfds)) {
                char buf[BUFFER_SIZE];
                n = recv(sessions[i].fd, buf, sizeof(buf), 0);

                if (n < 0) {
#ifdef _WIN32
                    int err = WSAGetLastError();
                    if (err != WSAEWOULDBLOCK) {
#else
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
#endif
                        close(sessions[i].fd);
                        sessions[i].active = 0;
                        sessions[i].fd = INVALID_SOCK;
                        send_packet(tunnel_fd, sessions[i].session_id, NULL, 0);
#ifdef _WIN32
                    }
#else
                    }
#endif
                } else if (n == 0) {
                    close(sessions[i].fd);
                    sessions[i].active = 0;
                    sessions[i].fd = INVALID_SOCK;
                    send_packet(tunnel_fd, sessions[i].session_id, NULL, 0);
                } else {
                    int ret = send_packet(tunnel_fd, sessions[i].session_id, buf, n);
                    if (ret < 0) {
                        close(sessions[i].fd);
                        close(tunnel_fd);
                        cleanup_connection(tunnel_conn);
                        tunnel_connected = 0;  // Mark tunnel as disconnected
                        return 1;
                    } else if (ret > 0) {
                        update_stats(n, 0, 1, 0);
                    }
                    // If ret == 0 (would block), just skip this iteration
                }
            }
        }
    }

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (sessions[i].active && sessions[i].fd != INVALID_SOCK) {
            close(sessions[i].fd);
        }
    }
    cleanup_connection(tunnel_conn);
    tunnel_connected = 0;  // Mark tunnel as disconnected
    printf("\n");
    return 0;
}

static int serve_mode(const char *bind_addr, int tunnel_port) {
    socket_t tunnel_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tunnel_listen_fd == INVALID_SOCK) {
        perror("socket");
        return -1;
    }

    int reuse = 1;
    setsockopt(tunnel_listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    struct sockaddr_in tunnel_sa;
    memset(&tunnel_sa, 0, sizeof(tunnel_sa));
    tunnel_sa.sin_family = AF_INET;
    tunnel_sa.sin_port = htons((unsigned short)tunnel_port);

    if (inet_pton(AF_INET, bind_addr, &tunnel_sa.sin_addr) <= 0) {
        perror("inet_pton");
        close(tunnel_listen_fd);
        return -1;
    }

    if (bind(tunnel_listen_fd, (struct sockaddr*)&tunnel_sa, sizeof(tunnel_sa)) < 0) {
        perror("bind tunnel port");
        close(tunnel_listen_fd);
        return -1;
    }

    if (listen(tunnel_listen_fd, SOMAXCONN) < 0) {
        perror("listen");
        close(tunnel_listen_fd);
        return -1;
    }

    set_nonblocking(tunnel_listen_fd);

    start_time = time(NULL);
    last_update_us = 0;

    while (running) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tunnel_listen_fd, &readfds);
        socket_t maxfd = tunnel_listen_fd;

        for (int i = 0; i < forwarded_port_count; i++) {
            if (forwarded_ports[i].listen_fd != INVALID_SOCK) {
                FD_SET(forwarded_ports[i].listen_fd, &readfds);
                if (forwarded_ports[i].listen_fd > maxfd) {
                    maxfd = forwarded_ports[i].listen_fd;
                }
            }
        }

        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            if (connections[i].fd != INVALID_SOCK) {
                FD_SET(connections[i].fd, &readfds);
                if (connections[i].fd > maxfd) {
                    maxfd = connections[i].fd;
                }
            }
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
            int tunnel_count = 0;
            for (int i = 0; i < MAX_CONNECTIONS; i++) {
                if (connections[i].fd != INVALID_SOCK && connections[i].is_tunnel) {
                    tunnel_count++;
                }
            }
            continue;
        }

        if (FD_ISSET(tunnel_listen_fd, &readfds)) {
            struct sockaddr_in addr;
            socklen_t addr_len = sizeof(addr);
            socket_t new_fd = accept(tunnel_listen_fd, (struct sockaddr*)&addr, &addr_len);

            if (new_fd != INVALID_SOCK) {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));

                if (!check_rate_limit(ip)) {
                    close(new_fd);
                } else {
                    optimize_socket(new_fd);
                    set_nonblocking(new_fd);

                    connection_t *conn = alloc_connection(new_fd);
                    if (conn) {
                        conn->is_tunnel = 1;
                    } else {
                        close(new_fd);
                    }
                }
            }
        }

        for (int i = 0; i < forwarded_port_count; i++) {
            if (forwarded_ports[i].listen_fd != INVALID_SOCK && FD_ISSET(forwarded_ports[i].listen_fd, &readfds)) {
                struct sockaddr_in addr;
                socklen_t addr_len = sizeof(addr);
                socket_t new_fd = accept(forwarded_ports[i].listen_fd, (struct sockaddr*)&addr, &addr_len);

                if (new_fd != INVALID_SOCK) {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));

                    socket_t tunnel_fd = forwarded_ports[i].tunnel_fd;
                    connection_t *tunnel = get_connection(tunnel_fd);

                    if (tunnel && tunnel->state == CONN_STATE_TUNNEL_ESTABLISHED) {
                        optimize_socket(new_fd);
                        set_nonblocking(new_fd);

                        connection_t *client_conn = alloc_connection(new_fd);
                        if (client_conn) {
                            client_conn->session_id = (unsigned short)(new_fd & 0xFFFF);
                            client_conn->state = CONN_STATE_FORWARDING;
                            client_conn->peer_fd = tunnel_fd;
                            client_conn->is_tunnel = 0;
                            total_connections++;
                            active_clients++;
                        } else {
                            close(new_fd);
                        }
                    } else {
                        close(new_fd);
                    }
                }
            }
        }

        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            connection_t *conn = &connections[i];
            if (conn->fd == INVALID_SOCK || !FD_ISSET(conn->fd, &readfds)) {
                continue;
            }

            if (conn->state == CONN_STATE_AUTH) {
                char buf[512];
                int n = recv(conn->fd, buf, sizeof(buf) - 1, 0);

                if (n < 0) {
#ifdef _WIN32
                    int err = WSAGetLastError();
                    if (err != WSAEWOULDBLOCK) {
#else
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
#endif
                        cleanup_connection(conn);
                        continue;
#ifdef _WIN32
                    }
#else
                    }
#endif
                } else if (n == 0) {
                    cleanup_connection(conn);
                    continue;
                } else {

                buf[n] = '\0';

                if (strncmp(buf, "AUTH:", 5) == 0) {
                    char *pass_start = buf + 5;
                    char *port_str = strchr(pass_start, ':');

                    if (port_str) {
                        *port_str = '\0';
                        port_str++;
                        int requested_port = atoi(port_str);

                        if (strcmp(pass_start, password) == 0 && requested_port > 0) {
                            struct sockaddr_in peer_addr;
                            socklen_t peer_len = sizeof(peer_addr);
                            getpeername(conn->fd, (struct sockaddr*)&peer_addr, &peer_len);
                            char ip[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &peer_addr.sin_addr, ip, sizeof(ip));

                            send(conn->fd, "OK", 2, SEND_FLAGS);
                            conn->state = CONN_STATE_TUNNEL_ESTABLISHED;
                            conn->forwarded_port = requested_port;
                            update_rate_limit(ip, 1);

                            socket_t listen_fd = socket(AF_INET, SOCK_STREAM, 0);
                            if (listen_fd != INVALID_SOCK) {
                                int reuse_opt = 1;
                                setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse_opt, sizeof(reuse_opt));

                                struct sockaddr_in bind_sa;
                                memset(&bind_sa, 0, sizeof(bind_sa));
                                bind_sa.sin_family = AF_INET;
                                bind_sa.sin_port = htons((unsigned short)requested_port);

                                if (inet_pton(AF_INET, bind_addr, &bind_sa.sin_addr) <= 0) {
                                    perror("inet_pton for client port");
                                    close(listen_fd);
                                } else if (bind(listen_fd, (struct sockaddr*)&bind_sa, sizeof(bind_sa)) < 0) {
                                    close(listen_fd);
                                } else if (listen(listen_fd, SOMAXCONN) < 0) {
                                    close(listen_fd);
                                } else {
                                    set_nonblocking(listen_fd);
                                    add_forwarded_port(requested_port, listen_fd, conn->fd, bind_addr);
                                }
                            }
                        } else {
                            send(conn->fd, "FAIL", 4, SEND_FLAGS);
                            struct sockaddr_in peer_addr;
                            socklen_t peer_len = sizeof(peer_addr);
                            getpeername(conn->fd, (struct sockaddr*)&peer_addr, &peer_len);
                            char ip[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &peer_addr.sin_addr, ip, sizeof(ip));
                            update_rate_limit(ip, 0);
#ifdef _WIN32
                            Sleep(1000);
#else
                            sleep(1);
#endif
                            cleanup_connection(conn);
                        }
                    } else {
                        send(conn->fd, "FAIL", 4, SEND_FLAGS);
                        cleanup_connection(conn);
                    }
                } else {
                    cleanup_connection(conn);
                }
                }
                continue;
            }

            if (!conn->is_tunnel && conn->state == CONN_STATE_FORWARDING && conn->peer_fd != INVALID_SOCK) {
                char buf[BUFFER_SIZE];
                int n = recv(conn->fd, buf, sizeof(buf), 0);

                if (n < 0) {
#ifdef _WIN32
                    int err = WSAGetLastError();
                    if (err != WSAEWOULDBLOCK) {
#else
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
#endif
                        connection_t *tunnel = get_connection(conn->peer_fd);
                        if (tunnel && tunnel->fd != INVALID_SOCK) {
                            send_packet(tunnel->fd, conn->session_id, NULL, 0);
                        }
                        active_clients--;
                        cleanup_connection(conn);
                        continue;
#ifdef _WIN32
                    }
#else
                    }
#endif
                } else if (n == 0) {
                    connection_t *tunnel = get_connection(conn->peer_fd);
                    if (tunnel && tunnel->fd != INVALID_SOCK) {
                        send_packet(tunnel->fd, conn->session_id, NULL, 0);
                    }
                    active_clients--;
                    cleanup_connection(conn);
                    continue;
                } else {

                connection_t *tunnel = get_connection(conn->peer_fd);
                if (tunnel && tunnel->fd != INVALID_SOCK) {
                    int ret = send_packet(tunnel->fd, conn->session_id, buf, n);
                    if (ret < 0) {
                        cleanup_connection(conn);
                    } else if (ret > 0) {
                        update_stats(n, 0, 1, 0);
                    }
                    // If ret == 0 (would block), just skip this iteration
                } else {
                    cleanup_connection(conn);
                }
                }
                continue;
            }

            if (conn->is_tunnel && conn->state == CONN_STATE_TUNNEL_ESTABLISHED) {
                packet_header_t header;
                int n = recv(conn->fd, (char*)&header, sizeof(header), MSG_PEEK);

                if (n < 0) {
#ifdef _WIN32
                    int err = WSAGetLastError();
                    if (err != WSAEWOULDBLOCK) {
#else
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
#endif
                        remove_forwarded_ports_for_tunnel(conn->fd);

                        for (int j = 0; j < MAX_CONNECTIONS; j++) {
                            if (connections[j].fd != INVALID_SOCK &&
                                !connections[j].is_tunnel &&
                                connections[j].peer_fd == conn->fd) {
                                cleanup_connection(&connections[j]);
                                active_clients--;
                            }
                        }

                        cleanup_connection(conn);
                        continue;
#ifdef _WIN32
                    }
#else
                    }
#endif
                } else if (n == 0) {
                    remove_forwarded_ports_for_tunnel(conn->fd);

                    for (int j = 0; j < MAX_CONNECTIONS; j++) {
                        if (connections[j].fd != INVALID_SOCK &&
                            !connections[j].is_tunnel &&
                            connections[j].peer_fd == conn->fd) {
                            cleanup_connection(&connections[j]);
                            active_clients--;
                        }
                    }

                    cleanup_connection(conn);
                    continue;
                }

                if (n < (int)sizeof(header)) {
                    continue;
                }

                unsigned short session_id = ntohs(header.session_id);
                unsigned short length = ntohs(header.length);

                // Handle heartbeat - echo it back
                if (session_id == SESSION_ID_HEARTBEAT) {
                    char heartbeat_data[sizeof(unsigned long long)];
                    recv(conn->fd, (char*)&header, sizeof(header), 0);
                    if (length == sizeof(unsigned long long)) {
                        recv(conn->fd, heartbeat_data, length, 0);
                        send_packet(conn->fd, SESSION_ID_HEARTBEAT, heartbeat_data, length);
                    }
                    continue;
                }

                char peek_buf[sizeof(packet_header_t) + BUFFER_SIZE];
                int peek_size = recv(conn->fd, peek_buf, sizeof(header) + length, MSG_PEEK);
                if (peek_size < (int)(sizeof(header) + length)) {
                    continue;
                }

                recv(conn->fd, (char*)&header, sizeof(header), 0);

                char buf[BUFFER_SIZE];
                if (length > 0) {
                    int data_received = recv(conn->fd, buf, length, 0);
                    if (data_received != length) {
                        cleanup_connection(conn);
                        continue;
                    }
                }

                connection_t *target_client = NULL;
                for (int j = 0; j < MAX_CONNECTIONS; j++) {
                    if (connections[j].fd != INVALID_SOCK &&
                        !connections[j].is_tunnel &&
                        connections[j].peer_fd == conn->fd &&
                        connections[j].session_id == session_id) {
                        target_client = &connections[j];
                        break;
                    }
                }

                if (target_client) {
                    if (length == 0) {
                        cleanup_connection(target_client);
                        active_clients--;
                    } else {
                        if (send(target_client->fd, buf, length, SEND_FLAGS) < 0) {
                            cleanup_connection(target_client);
                            active_clients--;
                        } else {
                            update_stats(0, length, 0, 1);
                        }
                    }
                }

                continue;
            }
        }
    }

    for (int i = 0; i < forwarded_port_count; i++) {
        if (forwarded_ports[i].listen_fd != INVALID_SOCK) {
            close(forwarded_ports[i].listen_fd);
        }
    }

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        if (connections[i].fd != INVALID_SOCK) {
            cleanup_connection(&connections[i]);
        }
    }

    close(tunnel_listen_fd);
    return 0;
}

#ifndef _WIN32
static void* forward_thread_func(void* arg) {
    forward_thread_args_t* args = (forward_thread_args_t*)arg;
    while (running) {
        int ret = forward_mode(args->local_port, args->server_port, args->tunnel_addr, args->tunnel_port);
        if (ret != 1 || !running) break;
        sleep(5);
    }
    free(args);
    return NULL;
}

static void* serve_thread_func(void* arg) {
    serve_thread_args_t* args = (serve_thread_args_t*)arg;
    serve_mode(args->bind_addr, args->tunnel_port);
    free(args);
    return NULL;
}
#endif

// Load forward config from file (simple format: local_port:remote_port per line)
static int load_forward_config(const char *filename, char *server_addr, int *server_port, char *passwd) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;

    char line[256];
    forward_config_count = 0;
    int in_forwards_section = 0;
    server_addr[0] = '\0';
    *server_port = 0;
    passwd[0] = '\0';

    while (fgets(line, sizeof(line), f)) {
        // Remove trailing newline
        line[strcspn(line, "\r\n")] = 0;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '/' || line[0] == '\0') continue;

        // Check for section markers
        if (strstr(line, "forwards=[") || strstr(line, "forwards= [")) {
            in_forwards_section = 1;
            continue;
        }
        if (in_forwards_section && strchr(line, ']')) {
            in_forwards_section = 0;
            continue;
        }

        // Parse server= line
        if (strncmp(line, "server=", 7) == 0) {
            char *value = line + 7;
            char *colon = strchr(value, ':');
            if (colon) {
                *colon = '\0';
                strncpy(server_addr, value, 255);
                *server_port = atoi(colon + 1);
            }
            continue;
        }

        // Parse passwd= line
        if (strncmp(line, "passwd=", 7) == 0) {
            strncpy(passwd, line + 7, 255);
            continue;
        }

        // Parse forward entries in forwards section
        if (in_forwards_section && forward_config_count < MAX_FORWARDED_PORTS) {
            int local, remote;
            // Support both "8000 -> 3000" and "8000:3000" formats
            if (sscanf(line, "%d -> %d", &local, &remote) == 2 ||
                sscanf(line, "%d->%d", &local, &remote) == 2 ||
                sscanf(line, "%d:%d", &local, &remote) == 2) {
                forward_configs[forward_config_count].local_port = local;
                forward_configs[forward_config_count].remote_port = remote;
                forward_config_count++;
            }
        }
    }

    fclose(f);
    return (server_addr[0] != '\0' && *server_port > 0 && passwd[0] != '\0') ? forward_config_count : 0;
}

static int load_server_config(const char *filename, char *bind_addr, int *bind_port, char *passwd) {
    FILE *f = fopen(filename, "r");
    if (!f) return 0;

    char line[256];
    bind_addr[0] = '\0';
    *bind_port = 0;
    passwd[0] = '\0';

    while (fgets(line, sizeof(line), f)) {
        // Remove trailing newline
        line[strcspn(line, "\r\n")] = 0;
        
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '/' || line[0] == '\0') continue;

        // Parse host= line
        if (strncmp(line, "host=", 5) == 0) {
            char *value = line + 5;
            char *colon = strchr(value, ':');
            if (colon) {
                *colon = '\0';
                strncpy(bind_addr, value, 255);
                *bind_port = atoi(colon + 1);
            }
            continue;
        }

        // Parse passwd= line
        if (strncmp(line, "passwd=", 7) == 0) {
            strncpy(passwd, line + 7, 255);
            continue;
        }
    }

    fclose(f);
    return (bind_addr[0] != '\0' && *bind_port > 0 && passwd[0] != '\0') ? 1 : 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage:\n");
        printf("  Server: %s serve <bind_addr>:<tunnel_port> <password>\n", argv[0]);
        printf("  Agent:  %s forward [<local_port>:<server_port>] [<tunnel_addr>:<tunnel_port>] [<password>]\n", argv[0]);
        printf("          %s forward  (uses forwards.conf)\n", argv[0]);
        return 1;
    }

    init_network();
    memset(connections, 0, sizeof(connections));
    memset(forwarded_ports, 0, sizeof(forwarded_ports));
    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        connections[i].fd = INVALID_SOCK;
    }

#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);  // Ignore SIGPIPE to prevent crashes on broken pipes
#endif

    if (strcmp(argv[1], "serve") == 0) {
        char bind_addr[256] = "";
        int tunnel_port = 0;

        if (argc >= 4) {
            // Full command line: serve bind_addr:port password
            char *colon = strchr(argv[2], ':');
            if (!colon) {
                fprintf(stderr, "Invalid bind address format\n");
                return 1;
            }
            *colon = '\0';
            strncpy(bind_addr, argv[2], sizeof(bind_addr) - 1);
            tunnel_port = atoi(colon + 1);
            strncpy(password, argv[3], sizeof(password) - 1);
        } else if (argc == 2) {
            // Try to load from config file: serve (no args)
            if (load_server_config("srps.conf", bind_addr, &tunnel_port, password) == 0) {
                fprintf(stderr, "No config file found or invalid format\n");
                fprintf(stderr, "Usage: %s serve <bind_addr>:<tunnel_port> <password>\n", argv[0]);
                fprintf(stderr, "   Or create srps.conf with:\n");
                fprintf(stderr, "   host=<addr>:<port>\n");
                fprintf(stderr, "   passwd=<password>\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Usage: %s serve <bind_addr>:<tunnel_port> <password>\n", argv[0]);
            return 1;
        }

#ifndef _WIN32
        serve_thread_args_t* args = malloc(sizeof(serve_thread_args_t));
        strncpy(args->bind_addr, bind_addr, sizeof(args->bind_addr) - 1);
        args->tunnel_port = tunnel_port;

        pthread_t thread;
        pthread_create(&thread, NULL, serve_thread_func, args);
        pthread_detach(thread);

        // Status update loop
        while (running) {
            usleep(250000);  // 250ms = 250,000 microseconds
            print_status("serve", forwarded_port_count, active_clients);
        }
#else
        serve_mode(bind_addr, tunnel_port);
#endif
    } else if (strcmp(argv[1], "forward") == 0) {
        // Parse command line arguments
        int local_port = 0, server_port = 0, tunnel_port = 0;
        char tunnel_addr[256] = "";
        char config_server[256] = "";
        int config_port = 0;
        char config_passwd[256] = "";

        if (argc >= 5) {
            // Full command line: forward local:server tunnel_addr:port password
            char *colon1 = strchr(argv[2], ':');
            char *colon2 = strchr(argv[3], ':');
            if (!colon1 || !colon2) {
                fprintf(stderr, "Invalid address format\n");
                return 1;
            }
            *colon1 = '\0';
            *colon2 = '\0';
            local_port = atoi(argv[2]);
            server_port = atoi(colon1 + 1);
            strncpy(tunnel_addr, argv[3], sizeof(tunnel_addr) - 1);
            tunnel_port = atoi(colon2 + 1);
            strncpy(password, argv[4], sizeof(password) - 1);

            // Add to config for display
            if (forward_config_count < MAX_FORWARDED_PORTS) {
                forward_configs[forward_config_count].local_port = local_port;
                forward_configs[forward_config_count].remote_port = server_port;
                forward_config_count++;
            }
        } else if (argc == 2) {
            // Try to load from config file: forward (no args)
            if (load_forward_config("forwards.conf", config_server, &config_port, config_passwd) == 0) {
                fprintf(stderr, "No config file found or invalid format\n");
                fprintf(stderr, "Usage: %s forward <local_port>:<server_port> <tunnel_addr>:<tunnel_port> <password>\n", argv[0]);
                fprintf(stderr, "   Or create forwards.conf with:\n");
                fprintf(stderr, "   server=<addr>:<port>\n");
                fprintf(stderr, "   passwd=<password>\n");
                fprintf(stderr, "   forwards=[\n");
                fprintf(stderr, "       <local> -> <remote>\n");
                fprintf(stderr, "   ]\n");
                return 1;
            }
            // Use config file values
            strncpy(tunnel_addr, config_server, sizeof(tunnel_addr) - 1);
            tunnel_port = config_port;
            strncpy(password, config_passwd, sizeof(password) - 1);

            // Use first config entry for single forward mode
            if (forward_config_count > 0) {
                local_port = forward_configs[0].local_port;
                server_port = forward_configs[0].remote_port;
            }
        } else if (argc >= 4) {
            // Using config file for forwards, but override server/pass: forward tunnel_addr:port password
            if (load_forward_config("forwards.conf", config_server, &config_port, config_passwd) > 0) {
                // Config loaded, use it for forwards but allow CLI override
                char *colon = strchr(argv[2], ':');
                if (colon) {
                    *colon = '\0';
                    strncpy(tunnel_addr, argv[2], sizeof(tunnel_addr) - 1);
                    tunnel_port = atoi(colon + 1);
                } else {
                    strncpy(tunnel_addr, config_server, sizeof(tunnel_addr) - 1);
                    tunnel_port = config_port;
                }
                strncpy(password, argv[3], sizeof(password) - 1);

                // Use first config entry
                if (forward_config_count > 0) {
                    local_port = forward_configs[0].local_port;
                    server_port = forward_configs[0].remote_port;
                }
            } else {
                fprintf(stderr, "Invalid arguments for forward mode\n");
                return 1;
            }
        } else {
            fprintf(stderr, "Invalid arguments for forward mode\n");
            return 1;
        }

#ifndef _WIN32
        forward_thread_args_t* args = malloc(sizeof(forward_thread_args_t));
        args->local_port = local_port;
        args->server_port = server_port;
        strncpy(args->tunnel_addr, tunnel_addr, sizeof(args->tunnel_addr) - 1);
        args->tunnel_port = tunnel_port;

        pthread_t thread;
        pthread_create(&thread, NULL, forward_thread_func, args);
        pthread_detach(thread);

        // Status update loop
        while (running) {
            usleep(250000);  // 250ms = 250,000 microseconds
            print_status("forward", tunnel_connected, active_clients);
        }
#else
        while (running) {
            int ret = forward_mode(local_port, server_port, tunnel_addr, tunnel_port);
            if (ret != 1 || !running) break;
            printf("Reconnecting in 5 seconds...\n");
            Sleep(5000);
        }
#endif
    } else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        return 1;
    }

    cleanup_network();
    return 0;
}
