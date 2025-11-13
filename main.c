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
#include <math.h>
#include <ctype.h>

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
#define MAX_CONNECTIONS 65536     // Now dynamically allocated, no memory waste
#define MAX_FORWARDED_PORTS 65536 // Now dynamically allocated, no memory waste
#define AUTH_TIMEOUT 5
#define RATE_LIMIT_WINDOW 60
#define MAX_AUTH_ATTEMPTS 3
#define AUTH_RETRY_DELAY 1

#define DEBUG_LOG(fmt, ...)                                  \
    do                                                       \
    {                                                        \
        fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr);                                      \
    } while (0)
#define INFO_LOG(fmt, ...)                                  \
    do                                                      \
    {                                                       \
        fprintf(stderr, "[INFO] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr);                                     \
    } while (0)
#define ERROR_LOG(fmt, ...)                                  \
    do                                                       \
    {                                                        \
        fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); \
        fflush(stderr);                                      \
    } while (0)

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

typedef enum
{
    CONN_STATE_AUTH,
    CONN_STATE_FORWARDING,
    CONN_STATE_TUNNEL_ESTABLISHED
} conn_state_t;

typedef struct
{
    socket_t fd;
    socket_t peer_fd;
    conn_state_t state;
    time_t auth_start;
    char buffer[BUFFER_SIZE];
    int buffer_used;
    int forwarded_port;
    int is_tunnel;
    unsigned short session_id; // Session ID for multiplexing
} connection_t;

typedef struct
{
    char ip[INET_ADDRSTRLEN];
    int attempts;
    time_t first_attempt;
    time_t last_attempt;
} rate_limit_entry_t;

typedef struct
{
    int port;
    socket_t listen_fd;
    socket_t tunnel_fd;
    char bind_addr[256];
    char login_used[256]; // Track which login/password was used to forward this port
    int is_claimed;       // Whether this port is claimed (permanent until unclaimed)
} forwarded_port_t;

typedef struct
{
    int local_port;
    int remote_port;
} forward_config_t;

// Packet protocol for session multiplexing
#define SESSION_ID_HEARTBEAT 0xFFFF // Special session ID for heartbeat packets

#pragma pack(push, 1)
typedef struct
{
    unsigned short session_id;
    unsigned short length;
} packet_header_t;
#pragma pack(pop)

static connection_t *connections = NULL;
static forwarded_port_t *forwarded_ports = NULL;
static int forwarded_port_count = 0;
static forward_config_t *forward_configs = NULL;
static int forward_config_count = 0;
static rate_limit_entry_t *rate_limits = NULL; // Dynamically allocated for 64K entries
static int rate_limit_count = 0;
static volatile int running = 1;
static char password[256];
static char logins_file[64] = "logins.conf"; // Path to dynamic logins file

// Server configuration limits
static int min_port = 1024;          // Minimum allowed port to forward
static int max_port = 65535;         // Maximum allowed port to forward
static int ports_per_login = 10;     // Maximum claimed ports per login
static int logins_per_ip = 5;        // Maximum logins per IP address
static int *restricted_ports = NULL; // Dynamically allocated restricted ports list
static int restricted_port_count = 0;
static int max_restricted_ports = 1024; // Initial capacity

static volatile unsigned long long total_connections = 0;
static volatile int active_clients = 0;
static volatile int tunnel_connected = 0; // Track tunnel connection status
static volatile double ping_ms = 0.0;     // Current ping in milliseconds
static time_t start_time = 0;
static unsigned long long last_update_us = 0; // Last update time in microseconds
static time_t last_heartbeat = 0;

#define STATS_WINDOW 5
typedef struct
{
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

typedef struct
{
    int local_port;
    int server_port;
    char tunnel_addr[256];
    int tunnel_port;
} forward_thread_args_t;

typedef struct
{
    char bind_addr[256];
    int tunnel_port;
} serve_thread_args_t;

static void init_network(void);
static void cleanup_network(void);
static int set_nonblocking(socket_t fd);
static int set_tcp_nodelay(socket_t fd);
static void optimize_socket(socket_t fd);
static connection_t *get_connection(socket_t fd);
static connection_t *alloc_connection(socket_t fd);
static void cleanup_connection(connection_t *conn);
static forwarded_port_t *get_forwarded_port(int port);
static int add_forwarded_port(int port, socket_t listen_fd, socket_t tunnel_fd, const char *bind_addr, const char *login);
static void remove_forwarded_port(int port);
static int count_ports_for_login(const char *login);
static void remove_forwarded_ports_for_tunnel(socket_t tunnel_fd);
static int check_rate_limit(const char *ip);
static void update_rate_limit(const char *ip, int success);
static int check_password(const char *pass);
static unsigned int simple_hash(const char *str);
static double calculate_entropy(const char *password);
static int validate_password(const char *password, char *error_msg, size_t error_size);
static int count_logins_for_ip(const char *ip);
static int is_port_restricted(int port);
static int get_claimed_ports_for_login(const char *login, int *ports, int max_ports);
static int is_port_claimed_by_anyone(int port);
static int save_claimed_port(const char *login, int port);
static int remove_claimed_port(const char *login, int port);
static int register_user(const char *username, const char *password);
static int delete_user(const char *username, const char *password);
static int load_client_config(char *server_addr, int *server_port, char *username, char *password);
static int send_packet(socket_t fd, unsigned short session_id, const char *data, unsigned short length);
static int forward_mode(int local_port, int server_port, const char *tunnel_addr, int tunnel_port);
static int serve_mode(const char *bind_addr, int tunnel_port);
static void print_status(const char *mode, int tunnel_active, int clients);
static void update_stats(int bytes_up, int bytes_down, int packets_up, int packets_down);
static void format_speed(long long bytes_per_sec, char *buf, size_t bufsize);

static void init_network(void)
{
#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
}

static void cleanup_network(void)
{
#ifdef _WIN32
    WSACleanup();
#endif
}

static int set_nonblocking(socket_t fd)
{
#ifdef _WIN32
    u_long mode = 1;
    return ioctlsocket(fd, FIONBIO, &mode);
#else
    int flags = fcntl(fd, F_GETFL, 0);
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
}

static int set_tcp_nodelay(socket_t fd)
{
    int flag = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&flag, sizeof(flag));
}

static void optimize_socket(socket_t fd)
{
    set_tcp_nodelay(fd);
    int sndbuf = BUFFER_SIZE * 8; // Larger send buffer
    int rcvbuf = BUFFER_SIZE * 8; // Larger receive buffer
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&sndbuf, sizeof(sndbuf));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof(rcvbuf));
}

static connection_t *get_connection(socket_t fd)
{
    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (connections[i].fd == fd)
        {
            return &connections[i];
        }
    }
    return NULL;
}

static connection_t *alloc_connection(socket_t fd)
{
    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (connections[i].fd == INVALID_SOCK)
        {
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

static void cleanup_connection(connection_t *conn)
{
    if (conn->fd != INVALID_SOCK)
    {
        close(conn->fd);
        conn->fd = INVALID_SOCK;
    }
    conn->peer_fd = INVALID_SOCK;
    conn->state = CONN_STATE_AUTH;
    conn->buffer_used = 0;
}

static forwarded_port_t *get_forwarded_port(int port)
{
    for (int i = 0; i < forwarded_port_count; i++)
    {
        if (forwarded_ports[i].port == port)
        {
            return &forwarded_ports[i];
        }
    }
    return NULL;
}

static int add_forwarded_port(int port, socket_t listen_fd, socket_t tunnel_fd, const char *bind_addr, const char *login)
{
    if (forwarded_port_count >= MAX_FORWARDED_PORTS)
    {
        return -1;
    }
    forwarded_ports[forwarded_port_count].port = port;
    forwarded_ports[forwarded_port_count].listen_fd = listen_fd;
    forwarded_ports[forwarded_port_count].tunnel_fd = tunnel_fd;
    forwarded_ports[forwarded_port_count].is_claimed = 0;
    strncpy(forwarded_ports[forwarded_port_count].bind_addr, bind_addr, sizeof(forwarded_ports[forwarded_port_count].bind_addr) - 1);
    strncpy(forwarded_ports[forwarded_port_count].login_used, login, sizeof(forwarded_ports[forwarded_port_count].login_used) - 1);
    forwarded_port_count++;
    return 0;
}

static int count_ports_for_login(const char *login)
{
    // Count only claimed ports
    int claimed_ports[MAX_FORWARDED_PORTS];
    return get_claimed_ports_for_login(login, claimed_ports, MAX_FORWARDED_PORTS);
}

static void remove_forwarded_port(int port)
{
    for (int i = 0; i < forwarded_port_count; i++)
    {
        if (forwarded_ports[i].port == port)
        {
            if (forwarded_ports[i].listen_fd != INVALID_SOCK)
            {
                close(forwarded_ports[i].listen_fd);
            }
            for (int j = i; j < forwarded_port_count - 1; j++)
            {
                forwarded_ports[j] = forwarded_ports[j + 1];
            }
            forwarded_port_count--;
            break;
        }
    }
}

static void remove_forwarded_ports_for_tunnel(socket_t tunnel_fd)
{
    for (int i = forwarded_port_count - 1; i >= 0; i--)
    {
        if (forwarded_ports[i].tunnel_fd == tunnel_fd)
        {
            remove_forwarded_port(forwarded_ports[i].port);
        }
    }
}

static int check_rate_limit(const char *ip)
{
    time_t now = time(NULL);
    for (int i = 0; i < rate_limit_count; i++)
    {
        if (strcmp(rate_limits[i].ip, ip) == 0)
        {
            if (now - rate_limits[i].first_attempt >= RATE_LIMIT_WINDOW)
            {
                rate_limits[i].attempts = 0;
                rate_limits[i].first_attempt = now;
                return 1;
            }
            if (rate_limits[i].attempts >= MAX_AUTH_ATTEMPTS)
            {
                return 0;
            }
            if (now - rate_limits[i].last_attempt < AUTH_RETRY_DELAY)
            {
                return 0;
            }
            return 1;
        }
    }
    return 1;
}

static void update_rate_limit(const char *ip, int success)
{
    time_t now = time(NULL);
    for (int i = 0; i < rate_limit_count; i++)
    {
        if (strcmp(rate_limits[i].ip, ip) == 0)
        {
            if (success)
            {
                rate_limits[i].attempts = 0;
            }
            else
            {
                rate_limits[i].attempts++;
                rate_limits[i].last_attempt = now;
                if (rate_limits[i].attempts == 1)
                {
                    rate_limits[i].first_attempt = now;
                }
            }
            return;
        }
    }
    if (rate_limit_count < 65536 && !success)
    {
        strncpy(rate_limits[rate_limit_count].ip, ip, INET_ADDRSTRLEN - 1);
        rate_limits[rate_limit_count].attempts = 1;
        rate_limits[rate_limit_count].first_attempt = now;
        rate_limits[rate_limit_count].last_attempt = now;
        rate_limit_count++;
    }
}

// Simple hash function for passwords (using djb2 algorithm)
static unsigned int simple_hash(const char *str)
{
    unsigned int hash = 5381;
    int c;
    while ((c = *str++))
    {
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

// Calculate Shannon entropy in bits
static double calculate_entropy(const char *password)
{
    int freq[256] = {0};
    int len = strlen(password);
    if (len == 0)
        return 0.0;

    for (int i = 0; i < len; i++)
    {
        freq[(unsigned char)password[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++)
    {
        if (freq[i] > 0)
        {
            double p = (double)freq[i] / len;
            entropy -= p * (log(p) / log(2));
        }
    }

    return entropy * len; // Total entropy in bits
}

// Validate password meets requirements
static int validate_password(const char *password, char *error_msg, size_t error_size)
{
    int len = strlen(password);

    // Check minimum length
    if (len < 6)
    {
        snprintf(error_msg, error_size, "Password must be at least 6 characters");
        return 0;
    }

    // Check for invalid characters (no | allowed)
    for (int i = 0; i < len; i++)
    {
        if (password[i] == '|')
        {
            snprintf(error_msg, error_size, "Password cannot contain '|' character");
            return 0;
        }
        if (!isprint((unsigned char)password[i]))
        {
            snprintf(error_msg, error_size, "Password must contain only printable characters");
            return 0;
        }
    }

    // Check entropy
    double entropy = calculate_entropy(password);
    if (entropy < 32.0)
    {
        snprintf(error_msg, error_size, "Password entropy too low (%.1f bits, need 32+)", entropy);
        return 0;
    }

    return 1;
}

// Count active logins from a specific IP
static int count_logins_for_ip(const char *ip)
{
    int count = 0;
    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (connections[i].fd != INVALID_SOCK && connections[i].is_tunnel)
        {
            struct sockaddr_in peer_addr;
            socklen_t peer_len = sizeof(peer_addr);
            if (getpeername(connections[i].fd, (struct sockaddr *)&peer_addr, &peer_len) == 0)
            {
                char conn_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &peer_addr.sin_addr, conn_ip, sizeof(conn_ip));
                if (strcmp(conn_ip, ip) == 0)
                {
                    count++;
                }
            }
        }
    }
    return count;
}

// Check if port is in restricted list
static int is_port_restricted(int port)
{
    for (int i = 0; i < restricted_port_count; i++)
    {
        if (restricted_ports[i] == port)
        {
            return 1;
        }
    }
    return 0;
}

// Get claimed ports for a login from logins.conf
static int get_claimed_ports_for_login(const char *login, int *ports, int max_ports)
{
    FILE *f = fopen(logins_file, "r");
    if (!f)
        return 0;

    char line[512];
    int count = 0;

    while (fgets(line, sizeof(line), f))
    {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == '/' || line[0] == '\0')
            continue;

        // Extract username from line (format: username:hash|port1,port2 or username:hash)
        char temp[512];
        strncpy(temp, line, sizeof(temp) - 1);
        temp[sizeof(temp) - 1] = '\0';

        char *pipe = strchr(temp, '|');
        char *ports_str = NULL;

        if (pipe)
        {
            *pipe = '\0';
            ports_str = pipe + 1;
        }

        char *colon = strchr(temp, ':');
        if (colon)
            *colon = '\0';

        // temp now contains just the username
        if (strcmp(temp, login) == 0)
        {
            // Parse ports if they exist
            if (ports_str)
            {
                char ports_copy[256];
                strncpy(ports_copy, ports_str, sizeof(ports_copy) - 1);
                ports_copy[sizeof(ports_copy) - 1] = '\0';

                char *token = strtok(ports_copy, ",");
                while (token && count < max_ports)
                {
                    ports[count++] = atoi(token);
                    token = strtok(NULL, ",");
                }
            }
            break;
        }
    }

    fclose(f);
    return count;
}

// Check if a port is claimed by any user
static int is_port_claimed_by_anyone(int port)
{
    FILE *f = fopen(logins_file, "r");
    if (!f)
        return 0;

    char line[512];

    while (fgets(line, sizeof(line), f))
    {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == '#' || line[0] == '/' || line[0] == '\0')
            continue;

        // Check if this line has claimed ports
        char *pipe = strchr(line, '|');
        if (pipe)
        {
            char ports_str[256];
            strncpy(ports_str, pipe + 1, sizeof(ports_str) - 1);
            ports_str[sizeof(ports_str) - 1] = '\0';

            // Parse ports
            char *token = strtok(ports_str, ",");
            while (token)
            {
                if (atoi(token) == port)
                {
                    fclose(f);
                    return 1; // Port is claimed
                }
                token = strtok(NULL, ",");
            }
        }
    }

    fclose(f);
    return 0; // Port is not claimed
}

// Save a claimed port for a login
static int save_claimed_port(const char *login, int port)
{
    FILE *f = fopen(logins_file, "r");
    if (!f)
        return 0;

    char lines[1024][512];
    int line_count = 0;
    int found_index = -1;

    // Read ALL lines first
    while (fgets(lines[line_count], sizeof(lines[line_count]), f) && line_count < 1024)
    {
        lines[line_count][strcspn(lines[line_count], "\r\n")] = 0;
        line_count++;
    }
    fclose(f);

    // Now find and modify the target line
    for (int i = 0; i < line_count; i++)
    {
        if (lines[i][0] == '#' || lines[i][0] == '/' || lines[i][0] == '\0')
            continue;

        // Extract username from line
        char temp[512];
        strncpy(temp, lines[i], sizeof(temp) - 1);
        temp[sizeof(temp) - 1] = '\0';

        char *pipe = strchr(temp, '|');
        if (pipe)
            *pipe = '\0';

        char *colon = strchr(temp, ':');
        if (colon)
            *colon = '\0';

        // temp now contains just the username
        if (strcmp(temp, login) == 0)
        {
            // Found the login, now modify the line
            char *orig_pipe = strchr(lines[i], '|');
            char new_line[512];

            if (orig_pipe)
            {
                // Already has claimed ports, append new one
                int prefix_len = orig_pipe - lines[i];
                char prefix[512];
                strncpy(prefix, lines[i], prefix_len);
                prefix[prefix_len] = '\0';

                snprintf(new_line, sizeof(new_line), "%s|%s,%d", prefix, orig_pipe + 1, port);
            }
            else
            {
                // No ports yet, add the pipe and port
                snprintf(new_line, sizeof(new_line), "%s|%d", lines[i], port);
            }

            strncpy(lines[i], new_line, sizeof(lines[i]) - 1);
            lines[i][sizeof(lines[i]) - 1] = '\0';

            found_index = i;
            break;
        }
    }

    if (found_index == -1)
        return 0;

    // Write back all lines
    f = fopen(logins_file, "w");
    if (!f)
        return 0;

    for (int i = 0; i < line_count; i++)
    {
        fprintf(f, "%s\n", lines[i]);
    }
    fclose(f);
    return 1;
}

// Remove a claimed port from a login
static int remove_claimed_port(const char *login, int port)
{
    FILE *f = fopen(logins_file, "r");
    if (!f)
        return 0;

    char lines[1024][512];
    int line_count = 0;
    int found = 0;

    while (fgets(lines[line_count], sizeof(lines[line_count]), f) && line_count < 1024)
    {
        lines[line_count][strcspn(lines[line_count], "\r\n")] = 0;

        if (lines[line_count][0] != '#' && lines[line_count][0] != '/' && lines[line_count][0] != '\0')
        {
            // Extract username from line (username:hash|ports or username:hash)
            char temp[512];
            strncpy(temp, lines[line_count], sizeof(temp) - 1);
            temp[sizeof(temp) - 1] = '\0';

            char *pipe_pos = strchr(temp, '|');
            if (pipe_pos)
                *pipe_pos = '\0';

            char *colon = strchr(temp, ':');
            if (colon)
                *colon = '\0';

            // temp now contains just the username
            if (strcmp(temp, login) == 0)
            {
                // Found the login, now modify the original line
                char *orig_pipe = strchr(lines[line_count], '|');

                if (orig_pipe)
                {
                    // Has claimed ports, remove the specified one
                    char username_hash[512];
                    strncpy(username_hash, lines[line_count], orig_pipe - lines[line_count]);
                    username_hash[orig_pipe - lines[line_count]] = '\0';

                    char *ports_str = orig_pipe + 1;
                    char ports_copy[256];
                    strncpy(ports_copy, ports_str, sizeof(ports_copy) - 1);
                    ports_copy[sizeof(ports_copy) - 1] = '\0';

                    char new_ports[256] = "";
                    char *token = strtok(ports_copy, ",");
                    int first = 1;

                    while (token)
                    {
                        int p = atoi(token);
                        if (p != port)
                        {
                            if (!first)
                                strcat(new_ports, ",");
                            char port_str[16];
                            snprintf(port_str, sizeof(port_str), "%d", p);
                            strcat(new_ports, port_str);
                            first = 0;
                        }
                        token = strtok(NULL, ",");
                    }

                    if (strlen(new_ports) > 0)
                    {
                        snprintf(lines[line_count], sizeof(lines[line_count]), "%s|%s", username_hash, new_ports);
                    }
                    else
                    {
                        snprintf(lines[line_count], sizeof(lines[line_count]), "%s", username_hash);
                    }
                    found = 1;
                }
                break;
            }
        }
        line_count++;
    }
    fclose(f);

    if (!found)
        return 0;

    // Write back
    f = fopen(logins_file, "w");
    if (!f)
        return 0;

    for (int i = 0; i < line_count; i++)
    {
        fprintf(f, "%s\n", lines[i]);
    }
    fclose(f);
    return 1;
}

// Register a new user
static int register_user(const char *username, const char *password)
{
    char error_msg[256];

    // Validate username (no colons or pipes)
    if (strchr(username, ':') || strchr(username, '|'))
    {
        fprintf(stderr, "Username cannot contain ':' or '|'\n");
        return 0;
    }

    // Validate password
    if (!validate_password(password, error_msg, sizeof(error_msg)))
    {
        fprintf(stderr, "Password validation failed: %s\n", error_msg);
        return 0;
    }

    // Hash password
    unsigned int hash = simple_hash(password);

    // Check if user already exists
    FILE *f = fopen(logins_file, "r");
    if (f)
    {
        char line[512];
        while (fgets(line, sizeof(line), f))
        {
            line[strcspn(line, "\r\n")] = 0;
            if (line[0] == '#' || line[0] == '/' || line[0] == '\0')
                continue;

            char *colon = strchr(line, ':');
            char *pipe = strchr(line, '|');
            if (pipe && (!colon || pipe < colon))
            {
                // Handle case where there's a pipe before colon
                continue;
            }
            if (colon)
            {
                *colon = '\0';
                if (strcmp(line, username) == 0)
                {
                    fclose(f);
                    fprintf(stderr, "User already exists\n");
                    return 0;
                }
            }
        }
        fclose(f);
    }

    // Append new user
    f = fopen(logins_file, "a");
    if (!f)
    {
        perror("Failed to open logins.conf");
        return 0;
    }

    fprintf(f, "%s:%u\n", username, hash);
    fclose(f);

    printf("User '%s' registered successfully\n", username);
    return 1;
}

// Delete a user account
static int delete_user(const char *username, const char *password)
{
    unsigned int hash = simple_hash(password);

    FILE *f = fopen(logins_file, "r");
    if (!f)
        return 0;

    char lines[1024][512];
    int line_count = 0;
    int found = 0;
    int deleted_index = -1;

    while (fgets(lines[line_count], sizeof(lines[line_count]), f) && line_count < 1024)
    {
        lines[line_count][strcspn(lines[line_count], "\r\n")] = 0;

        if (lines[line_count][0] != '#' && lines[line_count][0] != '/' && lines[line_count][0] != '\0')
        {
            char temp[512];
            strncpy(temp, lines[line_count], sizeof(temp) - 1);

            char *colon = strchr(temp, ':');
            char *pipe = strchr(temp, '|');

            if (pipe && (!colon || pipe < colon))
            {
                // Skip malformed lines
                line_count++;
                continue;
            }

            if (colon)
            {
                *colon = '\0';
                unsigned int stored_hash = (unsigned int)strtoul(colon + 1, NULL, 10);

                if (strcmp(temp, username) == 0 && stored_hash == hash)
                {
                    found = 1;
                    deleted_index = line_count;
                }
            }
        }
        line_count++;
    }
    fclose(f);

    if (!found)
    {
        fprintf(stderr, "User not found or password incorrect\n");
        return 0;
    }

    // Write back without deleted user
    f = fopen(logins_file, "w");
    if (!f)
        return 0;

    for (int i = 0; i < line_count; i++)
    {
        if (i != deleted_index)
        {
            fprintf(f, "%s\n", lines[i]);
        }
    }
    fclose(f);

    printf("User '%s' deleted successfully\n", username);
    return 1;
}

static int check_password(const char *pass)
{
    fprintf(stderr, pass);
    fprintf(stderr, "\n");
    fprintf(stderr, password);
    fprintf(stderr, "\n");
    // First check the main password
    if (strcmp(pass, password) == 0)
    {
        return 1;
    }

    // Try to load passwords from logins.conf
    // Format: username:hashed_password or username:hashed_password|port1,port2
    FILE *f = fopen(logins_file, "r");
    if (!f)
    {
        return 0; // File doesn't exist, password not found
    }

    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f))
    {
        // Remove trailing newline/whitespace
        line[strcspn(line, "\r\n")] = 0;

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '/' || line[0] == '\0')
            continue;

        // Trim leading whitespace
        char *trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t')
            trimmed++;

        // Split by pipe first to remove port data
        char *pipe = strchr(trimmed, '|');
        if (pipe)
            *pipe = '\0';

        // Now check username:hash format
        char *colon = strchr(trimmed, ':');
        if (colon)
        {
            // Split into username and hash
            *colon = '\0';
            char *username = trimmed;
            char *hash_str = colon + 1;
            unsigned int stored_hash = (unsigned int)strtoul(hash_str, NULL, 10);

            // Pass format is username:password, we need to split and verify
            char pass_copy[256];
            strncpy(pass_copy, pass, sizeof(pass_copy) - 1);
            pass_copy[sizeof(pass_copy) - 1] = '\0';

            char *pass_colon = strchr(pass_copy, ':');
            if (pass_colon)
            {
                *pass_colon = '\0';
                char *pass_username = pass_copy;
                char *pass_password = pass_colon + 1;

                if (strcmp(username, pass_username) == 0)
                {
                    unsigned int pass_hash = simple_hash(pass_password);
                    if (pass_hash == stored_hash)
                    {
                        found = 1;
                        break;
                    }
                }
            }
        }
        else
        {
            // Old format compatibility - direct password match
            if (strcmp(trimmed, pass) == 0)
            {
                found = 1;
                break;
            }
        }
    }

    fclose(f);
    return found;
}

static int send_packet(socket_t fd, unsigned short session_id, const char *data, unsigned short length)
{
    packet_header_t header;
    header.session_id = htons(session_id);
    header.length = htons(length);

    DEBUG_LOG("send_packet: session_id=%u, length=%u, data=%p", session_id, length, data);

    // Create a buffer with header + data for atomic send
    int total_size = sizeof(header) + length;
    char *buf = malloc(total_size);
    if (!buf)
    {
        ERROR_LOG("send_packet: malloc failed");
        return -1;
    }

    memcpy(buf, &header, sizeof(header));
    if (length > 0)
    {
        memcpy(buf + sizeof(header), data, length);
    }

#ifdef _WIN32
    int flags = SEND_FLAGS;
#else
    int flags = SEND_FLAGS;
#endif

    // Send entire packet atomically
    int sent = send(fd, buf, total_size, flags);
    DEBUG_LOG("send_packet: sent %d bytes total", sent);

    free(buf);

    if (sent < 0)
    {
#ifdef _WIN32
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK)
            return 0; // Would block, try again later
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return 0; // Would block, try again later
#endif
        return -1; // Real error
    }
    if (sent != total_size)
    {
        ERROR_LOG("send_packet: partial send! sent=%d, expected=%d", sent, total_size);
        return -1; // Partial packet send is an error
    }

    return 1; // Success
}

#ifdef _WIN32
static BOOL WINAPI console_handler(DWORD signal)
{
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT)
    {
        running = 0;
        return TRUE;
    }
    return FALSE;
}
#else
static void signal_handler(int sig)
{
    (void)sig;
    running = 0;
}
#endif

static void update_stats(int bytes_up, int bytes_down, int packets_up, int packets_down)
{
#ifndef _WIN32
    pthread_mutex_lock(&stats_mutex);
#endif
    time_t now = time(NULL);
    if (stats_history[stats_index].timestamp != now)
    {
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

static void format_speed(long long bytes_per_sec, char *buf, size_t bufsize)
{
    if (bytes_per_sec >= 1024 * 1024)
    {
        snprintf(buf, bufsize, "%.2f MB/s", bytes_per_sec / (1024.0 * 1024.0));
    }
    else if (bytes_per_sec >= 1024)
    {
        snprintf(buf, bufsize, "%.2f KB/s", bytes_per_sec / 1024.0);
    }
    else
    {
        snprintf(buf, bufsize, "%lld B/s", bytes_per_sec);
    }
}

static void print_status(const char *mode, int tunnel_active, int clients)
{
    // Get current time in microseconds
#ifdef _WIN32
    FILETIME ft;
    GetSystemTimePreciseAsFileTime(&ft);
    unsigned long long now_us = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    now_us = now_us / 10; // Convert to microseconds
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    unsigned long long now_us = (unsigned long long)tv.tv_sec * 1000000ULL + tv.tv_usec;
#endif

    // Update every 250ms
    if (now_us - last_update_us < 250000)
        return;
    last_update_us = now_us;

    time_t now = time(NULL);

#ifndef _WIN32
    pthread_mutex_lock(&stats_mutex);
#endif

    long long bytes_up = 0, bytes_down = 0;
    int packets_up = 0, packets_down = 0;
    time_t oldest = now - STATS_WINDOW;
    for (int i = 0; i < STATS_WINDOW; i++)
    {
        if (stats_history[i].timestamp >= oldest)
        {
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
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0)
    {
        term_width = w.ws_col;
        term_height = w.ws_row;
    }
#endif
    if (term_width < 40)
        term_width = 40; // Minimum width

    int box_width = term_width - 2; // Account for borders

    // Clear screen properly for both Unix and Windows
    printf("\033[2J"); // Clear entire screen
    printf("\033[3J"); // Clear scrollback buffer
    printf("\033[H");  // Move cursor to home position
    fflush(stdout);

    // Dynamic box drawing
    printf("+");
    for (int i = 0; i < box_width; i++)
        printf("-");
    printf("+\n");

    // Center the title
    const char *title = "SRP - Small Reverse Proxy";
    int title_len = strlen(title);
    int padding = (box_width - title_len) / 2;
    printf("|%*s%s%*s|\n", padding, "", title, box_width - padding - title_len, "");

    printf("+");
    for (int i = 0; i < box_width; i++)
        printf("-");
    printf("+\n");

    if (strcmp(mode, "serve") == 0)
    {
        char line[512];
        snprintf(line, sizeof(line), "%-20s %d", "Mode:", 0);
        sprintf(line, "%-20s Server", "Mode:");
        printf("| %-*s |\n", box_width - 2, line);

        sprintf(line, "%-20s %02d:%02d:%02d", "Uptime:", hours, mins, secs);
        printf("| %-*s |\n", box_width - 2, line);

        // Separator
        printf("+");
        for (int i = 0; i < box_width; i++)
            printf("-");
        printf("+\n");

        sprintf(line, "%-20s %d", "Active Tunnels:", tunnel_active);
        printf("| %-*s |\n", box_width - 2, line);

        sprintf(line, "%-20s %d", "Active Clients:", clients);
        printf("| %-*s |\n", box_width - 2, line);

        sprintf(line, "%-20s %llu", "Total Served:", total_conns);
        printf("| %-*s |\n", box_width - 2, line);

        // Separator
        printf("+");
        for (int i = 0; i < box_width; i++)
            printf("-");
        printf("+\n");

        sprintf(line, "%-20s %s (%d pps)", "Upload:", upload_str, upload_pps);
        printf("| %-*s |\n", box_width - 2, line);

        sprintf(line, "%-20s %s (%d pps)", "Download:", download_str, download_pps);
        printf("| %-*s |\n", box_width - 2, line);

        // Bottom border
        printf("+");
        for (int i = 0; i < box_width; i++)
            printf("-");
        printf("+\n");
    }
    else
    {
        // Forward agent - show forwards table and stats side by side
        int left_width = box_width / 2 - 1;
        int right_width = box_width - left_width - 3;

        // Header line - calculate padding for each section
        int left_text_len = 9;   // "Forwards" length
        int right_text_len = 11; // "Statistics" length
        int left_equals = (left_width - left_text_len - 2) / 2;
        int right_equals = (right_width - right_text_len - 2) / 2;

        printf("|");
        for (int i = 0; i < left_equals + 1; i++)
            printf("=");
        printf(" Forwards ");
        for (int i = 0; i < left_width - left_equals - left_text_len - 2; i++)
            printf("=");
        printf("|");
        for (int i = 0; i < right_equals; i++)
            printf("=");
        printf(" Statistics ");
        for (int i = 0; i < right_width - right_equals - right_text_len + 1; i++)
            printf("=");
        printf("|\n");

        // Content - show forwards and stats
        int max_lines = (forward_config_count > 7) ? forward_config_count : 7;
        for (int i = 0; i < max_lines; i++)
        {
            char left_content[256] = "";
            char right_content[256] = "";

            if (i < forward_config_count)
            {
                snprintf(left_content, sizeof(left_content), "%5d --> %-5d",
                         forward_configs[i].local_port, forward_configs[i].remote_port);
            }

            if (i == 0)
            {
                snprintf(right_content, sizeof(right_content), "Tunnel: %s",
                         tunnel_active ? "Connected" : "Disconnected");
            }
            else if (i == 1)
            {
                snprintf(right_content, sizeof(right_content), "Uptime: %02d:%02d:%02d", hours, mins, secs);
            }
            else if (i == 2)
            {
                snprintf(right_content, sizeof(right_content), "Ping: %.2f ms", current_ping);
            }
            else if (i == 3)
            {
                snprintf(right_content, sizeof(right_content), "Active Sessions: %d", clients);
            }
            else if (i == 4)
            {
                snprintf(right_content, sizeof(right_content), "Total Served: %llu", total_conns);
            }
            else if (i == 5)
            {
                snprintf(right_content, sizeof(right_content), "Upload:   %s (%d pps)", upload_str, upload_pps);
            }
            else if (i == 6)
            {
                snprintf(right_content, sizeof(right_content), "Download: %s (%d pps)", download_str, download_pps);
            }

            printf("| %-*s| %-*s|\n", left_width - 1, left_content, right_width + 1, right_content);
        }

        // Bottom line
        printf("\\");
        for (int i = 0; i < left_width; i++)
            printf("=");
        printf("|");
        for (int i = 0; i < right_width + 2; i++)
            printf("=");
        printf("/\n");
    }
    fflush(stdout);
}

static int forward_mode(int local_port, int server_port, const char *tunnel_addr, int tunnel_port)
{
    socket_t tunnel_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tunnel_fd == INVALID_SOCK)
    {
        perror("socket");
        return -1;
    }

    struct sockaddr_in tunnel_sa;
    memset(&tunnel_sa, 0, sizeof(tunnel_sa));
    tunnel_sa.sin_family = AF_INET;
    tunnel_sa.sin_port = htons((unsigned short)tunnel_port);

    if (inet_pton(AF_INET, tunnel_addr, &tunnel_sa.sin_addr) <= 0)
    {
        perror("inet_pton");
        close(tunnel_fd);
        return -1;
    }

    if (connect(tunnel_fd, (struct sockaddr *)&tunnel_sa, sizeof(tunnel_sa)) < 0)
    {
        perror("connect to tunnel");
        close(tunnel_fd);
        return -1;
    }

    optimize_socket(tunnel_fd);

    char auth_msg[256];

    // Extract the plaintext password and hash it
    char *colon = strchr(password, ':');
    if (colon)
    {
        char username[256];
        char plaintext_password[256];
        size_t username_len = colon - password;
        if (username_len >= sizeof(username))
            username_len = sizeof(username) - 1;
        memcpy(username, password, username_len);
        username[username_len] = '\0';

        strncpy(plaintext_password, colon + 1, sizeof(plaintext_password) - 1);
        plaintext_password[sizeof(plaintext_password) - 1] = '\0';

        // Hash the password
        unsigned int hash = simple_hash(plaintext_password);

        // Send AUTH with username and hash
        snprintf(auth_msg, sizeof(auth_msg), "AUTH:%s:%u:%d", username, hash, server_port);
        fprintf(stderr, "Agent: sending AUTH message: %s\n", auth_msg);
    }
    else
    {
        // Fallback if password format is wrong
        snprintf(auth_msg, sizeof(auth_msg), "AUTH:%s:%d", password, server_port);
        fprintf(stderr, "Agent: sending AUTH message (fallback): %s\n", auth_msg);
    }

    if (send(tunnel_fd, auth_msg, (int)strlen(auth_msg), SEND_FLAGS) < 0)
    {
        perror("send auth");
        close(tunnel_fd);
        return -1;
    }

    char response[16];
    int n = recv(tunnel_fd, response, sizeof(response) - 1, 0);
    if (n > 0)
    {
        response[n] = '\0'; // Null-terminate
    }
    if (n <= 0 || strncmp(response, "OK", 2) != 0)
    {
        fprintf(stderr, "Authentication failed\n");
        fprintf(stderr, "Response: %s\n", response);
        close(tunnel_fd);
        return -1;
    }

    start_time = time(NULL);
    last_update_us = 0;

    set_nonblocking(tunnel_fd);

    tunnel_connected = 1; // Mark tunnel as connected

    connection_t *tunnel_conn = alloc_connection(tunnel_fd);
    if (!tunnel_conn)
    {
        fprintf(stderr, "Failed to allocate connection\n");
        close(tunnel_fd);
        return -1;
    }
    tunnel_conn->state = CONN_STATE_TUNNEL_ESTABLISHED;
    tunnel_conn->peer_fd = INVALID_SOCK;
    tunnel_conn->is_tunnel = 1;

    typedef struct
    {
        unsigned short session_id;
        socket_t fd;
        int active;
    } session_t;

    // Initialize
    session_t sessions[MAX_CONNECTIONS];
    memset(sessions, 0, sizeof(sessions));
    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        sessions[i].fd = INVALID_SOCK;
    }

    char packet_buf[BUFFER_SIZE]; // Larger buffer for multiple packets
    int packet_buf_used = 0;

    while (running)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tunnel_fd, &readfds);

        socket_t maxfd = tunnel_fd;
        int active_session_count = 0;
        for (int i = 0; i < MAX_CONNECTIONS; i++)
        {
            if (sessions[i].active && sessions[i].fd != INVALID_SOCK)
            {
                FD_SET(sessions[i].fd, &readfds);
                if (sessions[i].fd > maxfd)
                    maxfd = sessions[i].fd;
                active_session_count++;
                fprintf(stderr, "Agent: monitoring session %u (fd=%d)\n", sessions[i].session_id, (int)sessions[i].fd);
            }
        }
        active_clients = active_session_count; // Update global counter

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        // Send heartbeat every second
        time_t now = time(NULL);
        if (now - last_heartbeat >= 1)
        {
            last_heartbeat = now;
#ifdef _WIN32
            FILETIME ft;
            GetSystemTimePreciseAsFileTime(&ft);
            unsigned long long timestamp = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            timestamp = timestamp / 10; // Convert to microseconds
#else
            struct timeval tv;
            gettimeofday(&tv, NULL);
            unsigned long long timestamp = (unsigned long long)tv.tv_sec * 1000000ULL + tv.tv_usec;
#endif
            send_packet(tunnel_fd, SESSION_ID_HEARTBEAT, (char *)&timestamp, sizeof(timestamp));
        }

        int activity = select((int)maxfd + 1, &readfds, NULL, NULL, &tv);

        if (activity < 0)
        {
            fprintf(stderr, "select error\n");
            break;
        }

        if (activity == 0)
        {
            continue;
        }

        if (FD_ISSET(tunnel_fd, &readfds))
        {
            char temp_buf[BUFFER_SIZE];
            n = recv(tunnel_fd, temp_buf, sizeof(temp_buf), 0);
            fprintf(stderr, "Agent: recv from tunnel returned %d bytes\n", n);
            DEBUG_LOG("Agent: recv from tunnel returned %d bytes", n);

            if (n < 0)
            {
#ifdef _WIN32
                int err = WSAGetLastError();
                if (err != WSAEWOULDBLOCK)
                {
#else
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
#endif
                    fprintf(stderr, "Tunnel connection error\n");
                    for (int i = 0; i < MAX_CONNECTIONS; i++)
                    {
                        if (sessions[i].active && sessions[i].fd != INVALID_SOCK)
                        {
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
            }
            else if (n == 0)
            {
                fprintf(stderr, "Tunnel connection closed\n");
                for (int i = 0; i < MAX_CONNECTIONS; i++)
                {
                    if (sessions[i].active && sessions[i].fd != INVALID_SOCK)
                    {
                        close(sessions[i].fd);
                        sessions[i].active = 0;
                        sessions[i].fd = INVALID_SOCK;
                    }
                }
                cleanup_connection(tunnel_conn);
                tunnel_connected = 0; // Mark tunnel as disconnected
                return 1;
            }
            else if (n > 0)
            {

                if (packet_buf_used + n > (int)sizeof(packet_buf))
                {
                    fprintf(stderr, "Packet buffer overflow\n");
                    break;
                }
                memcpy(packet_buf + packet_buf_used, temp_buf, n);
                packet_buf_used += n;

                while (packet_buf_used >= (int)sizeof(packet_header_t))
                {
                    packet_header_t *header = (packet_header_t *)packet_buf;
                    unsigned short session_id = ntohs(header->session_id);
                    unsigned short length = ntohs(header->length);

                    if (packet_buf_used < (int)(sizeof(packet_header_t) + length))
                    {
                        break;
                    }

                    // Handle heartbeat response
                    if (session_id == SESSION_ID_HEARTBEAT && length == sizeof(unsigned long long))
                    {
                        unsigned long long sent_timestamp;
                        memcpy(&sent_timestamp, packet_buf + sizeof(packet_header_t), sizeof(sent_timestamp));

#ifdef _WIN32
                        FILETIME ft;
                        GetSystemTimePreciseAsFileTime(&ft);
                        unsigned long long now_timestamp = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
                        now_timestamp = now_timestamp / 10; // Convert to microseconds
#else
                        struct timeval tv;
                        gettimeofday(&tv, NULL);
                        unsigned long long now_timestamp = (unsigned long long)tv.tv_sec * 1000000ULL + tv.tv_usec;
#endif
                        // Sanity check: if timestamp is in the future or too old (>10 seconds), ignore it
                        if (now_timestamp > sent_timestamp && (now_timestamp - sent_timestamp) < 10000000ULL)
                        {
                            ping_ms = (now_timestamp - sent_timestamp) / 1000.0; // Convert microseconds to milliseconds
                        }

                        // Remove heartbeat packet from buffer
                        int packet_size = sizeof(packet_header_t) + length;
                        memmove(packet_buf, packet_buf + packet_size, packet_buf_used - packet_size);
                        packet_buf_used -= packet_size;
                        continue;
                    }

                    session_t *session = NULL;
                    for (int i = 0; i < MAX_CONNECTIONS; i++)
                    {
                        if (sessions[i].active && sessions[i].session_id == session_id)
                        {
                            session = &sessions[i];
                            break;
                        }
                    }

                    if (!session && length > 0)
                    {
                        for (int i = 0; i < MAX_CONNECTIONS; i++)
                        {
                            if (!sessions[i].active)
                            {
                                socket_t mc_fd = socket(AF_INET, SOCK_STREAM, 0);
                                if (mc_fd == INVALID_SOCK)
                                {
                                    fprintf(stderr, "Failed to create socket for local server\n");
                                    break;
                                }

                                struct sockaddr_in mc_sa;
                                memset(&mc_sa, 0, sizeof(mc_sa));
                                mc_sa.sin_family = AF_INET;
                                mc_sa.sin_addr.s_addr = inet_addr("127.0.0.1");
                                mc_sa.sin_port = htons((unsigned short)local_port);

                                optimize_socket(mc_fd);

                                if (connect(mc_fd, (struct sockaddr *)&mc_sa, sizeof(mc_sa)) < 0)
                                {
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
                                fprintf(stderr, "Agent: Created new session %u (fd=%d) for incoming request\n", session_id, (int)mc_fd);
                                break;
                            }
                        }
                    }

                    if (session && session->fd != INVALID_SOCK)
                    {
                        if (length == 0)
                        {
                            close(session->fd);
                            session->active = 0;
                            session->fd = INVALID_SOCK;
                        }
                        else
                        {
                            char *data = packet_buf + sizeof(packet_header_t);
                            int sent = send(session->fd, data, length, SEND_FLAGS);
                            fprintf(stderr, "Agent: Sent %d bytes to local server (session %u)\n", sent, session_id);
                            if (sent < 0)
                            {
#ifdef _WIN32
                                int err = WSAGetLastError();
                                if (err != WSAEWOULDBLOCK)
                                {
#else
                                if (errno != EAGAIN && errno != EWOULDBLOCK)
                                {
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
                            }
                            else if (sent > 0)
                            {
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

        for (int i = 0; i < MAX_CONNECTIONS; i++)
        {
            if (sessions[i].active && sessions[i].fd != INVALID_SOCK && FD_ISSET(sessions[i].fd, &readfds))
            {
                char buf[BUFFER_SIZE];
                n = recv(sessions[i].fd, buf, sizeof(buf), 0);
                fprintf(stderr, "Agent: recv from local server (session %u) returned %d bytes\n", sessions[i].session_id, n);

                if (n < 0)
                {
#ifdef _WIN32
                    int err = WSAGetLastError();
                    if (err != WSAEWOULDBLOCK)
                    {
#else
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                    {
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
                }
                else if (n == 0)
                {
                    close(sessions[i].fd);
                    sessions[i].active = 0;
                    sessions[i].fd = INVALID_SOCK;
                    send_packet(tunnel_fd, sessions[i].session_id, NULL, 0);
                }
                else
                {
                    int ret = send_packet(tunnel_fd, sessions[i].session_id, buf, n);
                    fprintf(stderr, "Agent: send_packet returned %d (session %u, %d bytes)\n", ret, sessions[i].session_id, n);
                    if (ret < 0)
                    {
                        close(sessions[i].fd);
                        close(tunnel_fd);
                        cleanup_connection(tunnel_conn);
                        tunnel_connected = 0; // Mark tunnel as disconnected
                        return 1;
                    }
                    else if (ret > 0)
                    {
                        update_stats(n, 0, 1, 0);
                    }
                    // If ret == 0 (would block), just skip this iteration
                }
            }
        }
    }

    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (sessions[i].active && sessions[i].fd != INVALID_SOCK)
        {
            close(sessions[i].fd);
        }
    }
    cleanup_connection(tunnel_conn);
    tunnel_connected = 0; // Mark tunnel as disconnected
    printf("\n");
    return 0;
}

static int serve_mode(const char *bind_addr, int tunnel_port)
{
    // Open debug log file
    FILE *debug_log = fopen("server.log", "w");
    if (debug_log)
    {
        fprintf(debug_log, "serve_mode starting\n");
        fflush(debug_log);
    }

    socket_t tunnel_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tunnel_listen_fd == INVALID_SOCK)
    {
        perror("socket");
        return -1;
    }

    int reuse = 1;
    setsockopt(tunnel_listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in tunnel_sa;
    memset(&tunnel_sa, 0, sizeof(tunnel_sa));
    tunnel_sa.sin_family = AF_INET;
    tunnel_sa.sin_port = htons((unsigned short)tunnel_port);

    if (inet_pton(AF_INET, bind_addr, &tunnel_sa.sin_addr) <= 0)
    {
        perror("inet_pton");
        close(tunnel_listen_fd);
        return -1;
    }

    if (bind(tunnel_listen_fd, (struct sockaddr *)&tunnel_sa, sizeof(tunnel_sa)) < 0)
    {
        perror("bind tunnel port");
        close(tunnel_listen_fd);
        return -1;
    }

    if (listen(tunnel_listen_fd, SOMAXCONN) < 0)
    {
        perror("listen");
        close(tunnel_listen_fd);
        return -1;
    }

    set_nonblocking(tunnel_listen_fd);

    start_time = time(NULL);
    last_update_us = 0;

    while (running)
    {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(tunnel_listen_fd, &readfds);
        socket_t maxfd = tunnel_listen_fd;

        for (int i = 0; i < forwarded_port_count; i++)
        {
            if (forwarded_ports[i].listen_fd != INVALID_SOCK)
            {
                FD_SET(forwarded_ports[i].listen_fd, &readfds);
                if (forwarded_ports[i].listen_fd > maxfd)
                {
                    maxfd = forwarded_ports[i].listen_fd;
                }
            }
        }

        for (int i = 0; i < MAX_CONNECTIONS; i++)
        {
            if (connections[i].fd != INVALID_SOCK)
            {
                FD_SET(connections[i].fd, &readfds);
                if (connections[i].fd > maxfd)
                {
                    maxfd = connections[i].fd;
                }
            }
        }

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int activity = select((int)maxfd + 1, &readfds, NULL, NULL, &tv);

        if (activity < 0)
        {
            fprintf(stderr, "select error\n");
            break;
        }

        if (activity == 0)
        {
            int tunnel_count = 0;
            for (int i = 0; i < MAX_CONNECTIONS; i++)
            {
                if (connections[i].fd != INVALID_SOCK && connections[i].is_tunnel)
                {
                    tunnel_count++;
                }
            }
            continue;
        }

        if (FD_ISSET(tunnel_listen_fd, &readfds))
        {
            struct sockaddr_in addr;
            socklen_t addr_len = sizeof(addr);
            socket_t new_fd = accept(tunnel_listen_fd, (struct sockaddr *)&addr, &addr_len);

            if (new_fd != INVALID_SOCK)
            {
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));

                if (!check_rate_limit(ip))
                {
                    close(new_fd);
                }
                else
                {
                    optimize_socket(new_fd);
                    set_nonblocking(new_fd);

                    connection_t *conn = alloc_connection(new_fd);
                    if (conn)
                    {
                        conn->is_tunnel = 1;
                    }
                    else
                    {
                        close(new_fd);
                    }
                }
            }
        }

        for (int i = 0; i < forwarded_port_count; i++)
        {
            if (forwarded_ports[i].listen_fd != INVALID_SOCK && FD_ISSET(forwarded_ports[i].listen_fd, &readfds))
            {
                fprintf(stderr, "Server: Accepting connection on forwarded port %d (listen_fd=%d)\n", forwarded_ports[i].port, (int)forwarded_ports[i].listen_fd);
                struct sockaddr_in addr;
                socklen_t addr_len = sizeof(addr);
                socket_t new_fd = accept(forwarded_ports[i].listen_fd, (struct sockaddr *)&addr, &addr_len);

                if (new_fd != INVALID_SOCK)
                {
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));

                    socket_t tunnel_fd = forwarded_ports[i].tunnel_fd;
                    connection_t *tunnel = get_connection(tunnel_fd);

                    if (tunnel && tunnel->state == CONN_STATE_TUNNEL_ESTABLISHED)
                    {
                        optimize_socket(new_fd);
                        set_nonblocking(new_fd);

                        connection_t *client_conn = alloc_connection(new_fd);
                        if (client_conn)
                        {
                            client_conn->session_id = (unsigned short)(new_fd & 0xFFFF);
                            client_conn->state = CONN_STATE_FORWARDING;
                            client_conn->peer_fd = tunnel_fd;
                            client_conn->is_tunnel = 0;
                            total_connections++;
                            active_clients++;
                            fprintf(stderr, "Server: Accepted client connection on port %d (fd=%d, session_id=%u)\n", forwarded_ports[i].port, (int)new_fd, client_conn->session_id);
                        }
                        else
                        {
                            close(new_fd);
                        }
                    }
                    else
                    {
                        close(new_fd);
                    }
                }
            }
        }

        for (int i = 0; i < MAX_CONNECTIONS; i++)
        {
            connection_t *conn = &connections[i];
            if (conn->fd == INVALID_SOCK || !FD_ISSET(conn->fd, &readfds))
            {
                continue;
            }

            if (conn->state == CONN_STATE_AUTH)
            {
                char buf[512];
                int n = recv(conn->fd, buf, sizeof(buf) - 1, 0);

                if (n < 0)
                {
#ifdef _WIN32
                    int err = WSAGetLastError();
                    if (err != WSAEWOULDBLOCK)
                    {
#else
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                    {
#endif
                        cleanup_connection(conn);
                        continue;
#ifdef _WIN32
                    }
#else
                    }
#endif
                }
                else if (n == 0)
                {
                    cleanup_connection(conn);
                    continue;
                }
                else
                {

                    buf[n] = '\0';

                    // Handle CLAIM command: CLAIM:username:hashed_password:port
                    if (strncmp(buf, "CLAIM:", 6) == 0)
                    {
                        char *username_start = buf + 6;
                        char *hash_str = strchr(username_start, ':');
                        if (!hash_str)
                        {
                            send(conn->fd, "ERROR:Invalid claim format", 27, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }
                        *hash_str = '\0';
                        hash_str++;

                        char *port_str = strchr(hash_str, ':');
                        if (!port_str)
                        {
                            send(conn->fd, "ERROR:Invalid claim format", 27, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }
                        *port_str = '\0';
                        port_str++;

                        int claim_port = atoi(port_str);
                        unsigned int hash = (unsigned int)strtoul(hash_str, NULL, 10);

                        // Verify credentials
                        char login[512];
                        snprintf(login, sizeof(login), "%s:%u", username_start, hash);

                        // For claim, we need to manually verify the hash
                        FILE *f = fopen(logins_file, "r");
                        int valid = 0;
                        if (f)
                        {
                            char line[512];
                            while (fgets(line, sizeof(line), f))
                            {
                                line[strcspn(line, "\r\n")] = 0;
                                if (line[0] == '#' || line[0] == '/' || line[0] == '\0')
                                    continue;

                                char *pipe = strchr(line, '|');
                                if (pipe)
                                    *pipe = '\0';

                                char *colon = strchr(line, ':');
                                if (colon)
                                {
                                    *colon = '\0';
                                    unsigned int stored_hash = (unsigned int)strtoul(colon + 1, NULL, 10);
                                    if (strcmp(line, username_start) == 0 && stored_hash == hash)
                                    {
                                        valid = 1;
                                        break;
                                    }
                                }
                            }
                            fclose(f);
                        }

                        if (!valid)
                        {
                            send(conn->fd, "ERROR:Invalid credentials", 25, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        // Check port restrictions
                        if (is_port_restricted(claim_port))
                        {
                            send(conn->fd, "ERROR:Port is restricted", 24, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        // Check if port is claimed by anyone
                        if (is_port_claimed_by_anyone(claim_port))
                        {
                            send(conn->fd, "ERROR:Port already claimed", 26, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        // Check if already claimed
                        int claimed_ports[MAX_FORWARDED_PORTS];
                        int num_claimed = get_claimed_ports_for_login(username_start, claimed_ports, MAX_FORWARDED_PORTS);
                        int already_claimed = 0;
                        for (int i = 0; i < num_claimed; i++)
                        {
                            if (claimed_ports[i] == claim_port)
                            {
                                already_claimed = 1;
                                break;
                            }
                        }

                        if (already_claimed)
                        {
                            send(conn->fd, "ERROR:Port already claimed by you", 33, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        // Check port limit
                        if (num_claimed >= ports_per_login)
                        {
                            char error_msg[128];
                            snprintf(error_msg, sizeof(error_msg), "ERROR:Maximum claimed ports reached (%d/%d)",
                                     num_claimed, ports_per_login);
                            send(conn->fd, error_msg, (int)strlen(error_msg), SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        // Save claim
                        if (save_claimed_port(username_start, claim_port))
                        {
                            send(conn->fd, "OK:Port claimed successfully", 28, SEND_FLAGS);
                        }
                        else
                        {
                            send(conn->fd, "ERROR:Failed to save claim", 26, SEND_FLAGS);
                        }
                        cleanup_connection(conn);
                        continue;
                    }

                    // Handle UNCLAIM command: UNCLAIM:username:hashed_password:port
                    if (strncmp(buf, "UNCLAIM:", 8) == 0)
                    {
                        char *username_start = buf + 8;
                        char *hash_str = strchr(username_start, ':');
                        if (!hash_str)
                        {
                            send(conn->fd, "ERROR:Invalid unclaim format", 28, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }
                        *hash_str = '\0';
                        hash_str++;

                        char *port_str = strchr(hash_str, ':');
                        if (!port_str)
                        {
                            send(conn->fd, "ERROR:Invalid unclaim format", 28, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }
                        *port_str = '\0';
                        port_str++;

                        int unclaim_port = atoi(port_str);
                        unsigned int hash = (unsigned int)strtoul(hash_str, NULL, 10);

                        // Verify credentials
                        FILE *f = fopen(logins_file, "r");
                        int valid = 0;
                        if (f)
                        {
                            char line[512];
                            while (fgets(line, sizeof(line), f))
                            {
                                line[strcspn(line, "\r\n")] = 0;
                                if (line[0] == '#' || line[0] == '/' || line[0] == '\0')
                                    continue;

                                char *pipe = strchr(line, '|');
                                if (pipe)
                                    *pipe = '\0';

                                char *colon = strchr(line, ':');
                                if (colon)
                                {
                                    *colon = '\0';
                                    unsigned int stored_hash = (unsigned int)strtoul(colon + 1, NULL, 10);
                                    if (strcmp(line, username_start) == 0 && stored_hash == hash)
                                    {
                                        valid = 1;
                                        break;
                                    }
                                }
                            }
                            fclose(f);
                        }

                        if (!valid)
                        {
                            send(conn->fd, "ERROR:Invalid credentials", 25, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        // Remove claim
                        if (remove_claimed_port(username_start, unclaim_port))
                        {
                            send(conn->fd, "OK:Port unclaimed successfully", 30, SEND_FLAGS);
                        }
                        else
                        {
                            send(conn->fd, "ERROR:Port not claimed by you", 29, SEND_FLAGS);
                        }
                        cleanup_connection(conn);
                        continue;
                    }

                    // Handle REGISTER command: REGISTER:username:hashed_password
                    if (strncmp(buf, "REGISTER:", 9) == 0)
                    {
                        char *username_start = buf + 9;
                        char *hash_str = strchr(username_start, ':');
                        if (!hash_str)
                        {
                            send(conn->fd, "ERROR:Invalid register format", 29, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }
                        *hash_str = '\0';
                        hash_str++;

                        unsigned int hash = (unsigned int)strtoul(hash_str, NULL, 10);

                        // Validate username (no colons or pipes)
                        if (strchr(username_start, ':') || strchr(username_start, '|'))
                        {
                            send(conn->fd, "ERROR:Username cannot contain ':' or '|'", 40, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        // Check if user already exists
                        FILE *f = fopen(logins_file, "r");
                        int exists = 0;
                        if (f)
                        {
                            char line[512];
                            while (fgets(line, sizeof(line), f))
                            {
                                line[strcspn(line, "\r\n")] = 0;
                                if (line[0] == '#' || line[0] == '/' || line[0] == '\0')
                                    continue;

                                char *pipe = strchr(line, '|');
                                if (pipe)
                                    *pipe = '\0';

                                char *colon = strchr(line, ':');
                                if (colon)
                                {
                                    *colon = '\0';
                                    if (strcmp(line, username_start) == 0)
                                    {
                                        exists = 1;
                                        break;
                                    }
                                }
                            }
                            fclose(f);
                        }

                        if (exists)
                        {
                            send(conn->fd, "ERROR:User already exists", 25, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        // Append new user
                        f = fopen(logins_file, "a");
                        if (!f)
                        {
                            send(conn->fd, "ERROR:Failed to create user", 27, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        fprintf(f, "%s:%u\n", username_start, hash);
                        fclose(f);

                        send(conn->fd, "OK:User registered successfully", 31, SEND_FLAGS);
                        cleanup_connection(conn);
                        continue;
                    }

                    // Handle DELETEACC command: DELETEACC:username:hashed_password
                    if (strncmp(buf, "DELETEACC:", 10) == 0)
                    {
                        char *username_start = buf + 10;
                        char *hash_str = strchr(username_start, ':');
                        if (!hash_str)
                        {
                            send(conn->fd, "ERROR:Invalid deleteacc format", 30, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }
                        *hash_str = '\0';
                        hash_str++;

                        unsigned int hash = (unsigned int)strtoul(hash_str, NULL, 10);

                        // Verify credentials and delete
                        FILE *f = fopen(logins_file, "r");
                        if (!f)
                        {
                            send(conn->fd, "ERROR:Failed to access users", 28, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        char lines[1024][512];
                        int line_count = 0;
                        int found = 0;
                        int deleted_index = -1;

                        while (fgets(lines[line_count], sizeof(lines[line_count]), f) && line_count < 1024)
                        {
                            lines[line_count][strcspn(lines[line_count], "\r\n")] = 0;

                            if (lines[line_count][0] != '#' && lines[line_count][0] != '/' && lines[line_count][0] != '\0')
                            {
                                char temp[512];
                                strncpy(temp, lines[line_count], sizeof(temp) - 1);

                                char *pipe = strchr(temp, '|');
                                if (pipe)
                                    *pipe = '\0';

                                char *colon = strchr(temp, ':');
                                if (colon)
                                {
                                    *colon = '\0';
                                    unsigned int stored_hash = (unsigned int)strtoul(colon + 1, NULL, 10);

                                    if (strcmp(temp, username_start) == 0 && stored_hash == hash)
                                    {
                                        found = 1;
                                        deleted_index = line_count;
                                    }
                                }
                            }
                            line_count++;
                        }
                        fclose(f);

                        if (!found)
                        {
                            send(conn->fd, "ERROR:User not found or password incorrect", 42, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        // Write back without deleted user
                        f = fopen(logins_file, "w");
                        if (!f)
                        {
                            send(conn->fd, "ERROR:Failed to delete user", 27, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        for (int i = 0; i < line_count; i++)
                        {
                            if (i != deleted_index)
                            {
                                fprintf(f, "%s\n", lines[i]);
                            }
                        }
                        fclose(f);

                        send(conn->fd, "OK:User deleted successfully", 28, SEND_FLAGS);
                        cleanup_connection(conn);
                        continue;
                    }

                    if (strncmp(buf, "AUTH:", 5) == 0)
                    {
                        if (debug_log)
                        {
                            fprintf(debug_log, "Received AUTH message: %s\n", buf);
                            fflush(debug_log);
                        }
                        char *username_start = buf + 5;
                        char *pass_str = strchr(username_start, ':');

                        if (!pass_str)
                        {
                            if (debug_log) fprintf(debug_log, "ERROR: No first colon found\n");
                            send(conn->fd, "ERROR:Invalid auth format", 25, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        *pass_str = '\0';
                        pass_str++;

                        char *port_str = strchr(pass_str, ':');
                        if (!port_str)
                        {
                            if (debug_log) fprintf(debug_log, "ERROR: No second colon found\n");
                            send(conn->fd, "ERROR:Invalid auth format", 25, SEND_FLAGS);
                            cleanup_connection(conn);
                            continue;
                        }

                        *port_str = '\0';
                        port_str++;
                        int requested_port = atoi(port_str);

                        // Verify credentials
                        unsigned int hash = (unsigned int)strtoul(pass_str, NULL, 10);
                        FILE *f = fopen(logins_file, "r");
                        int valid = 0;
                        if (f)
                        {
                            char line[512];
                            while (fgets(line, sizeof(line), f))
                            {
                                line[strcspn(line, "\r\n")] = 0;
                                if (line[0] == '#' || line[0] == '/' || line[0] == '\0')
                                    continue;

                                char *pipe = strchr(line, '|');
                                if (pipe)
                                    *pipe = '\0';

                                char *colon = strchr(line, ':');
                                if (colon)
                                {
                                    *colon = '\0';
                                    unsigned int stored_hash = (unsigned int)strtoul(colon + 1, NULL, 10);
                                    if (strcmp(line, username_start) == 0 && stored_hash == hash)
                                    {
                                        valid = 1;
                                        break;
                                    }
                                }
                            }
                            fclose(f);
                        }
                        if (valid && requested_port > 0)
                        {
                            struct sockaddr_in peer_addr;
                            socklen_t peer_len = sizeof(peer_addr);
                            getpeername(conn->fd, (struct sockaddr *)&peer_addr, &peer_len);
                            char ip[INET_ADDRSTRLEN];
                            inet_ntop(AF_INET, &peer_addr.sin_addr, ip, sizeof(ip));

                            // Check logins per IP limit
                            int ip_logins = count_logins_for_ip(ip);
                            if (ip_logins >= logins_per_ip)
                            {
                                char error_msg[128];
                                snprintf(error_msg, sizeof(error_msg), "ERROR:Too many logins from this IP (%d/%d)",
                                         ip_logins, logins_per_ip);
                                send(conn->fd, error_msg, (int)strlen(error_msg), SEND_FLAGS);
                                update_rate_limit(ip, 0);
#ifdef _WIN32
                                Sleep(1000);
#else
                                sleep(1);
#endif
                                cleanup_connection(conn);
                                continue;
                            }

                            // Check if port is restricted
                            if (is_port_restricted(requested_port))
                            {
                                char error_msg[128];
                                snprintf(error_msg, sizeof(error_msg), "ERROR:Port %d is restricted", requested_port);
                                send(conn->fd, error_msg, (int)strlen(error_msg), SEND_FLAGS);
                                update_rate_limit(ip, 0);
#ifdef _WIN32
                                Sleep(1000);
#else
                                sleep(1);
#endif
                                cleanup_connection(conn);
                                continue;
                            }

                            // Check port range
                            if (requested_port < min_port || requested_port > max_port)
                            {
                                char error_msg[128];
                                snprintf(error_msg, sizeof(error_msg), "ERROR:Port %d outside allowed range (%d-%d)",
                                         requested_port, min_port, max_port);
                                send(conn->fd, error_msg, (int)strlen(error_msg), SEND_FLAGS);
                                update_rate_limit(ip, 0);
#ifdef _WIN32
                                Sleep(1000);
#else
                                sleep(1);
#endif
                                cleanup_connection(conn);
                                continue;
                            }

                            // Check if port is already forwarded
                            forwarded_port_t *existing = get_forwarded_port(requested_port);
                            if (existing)
                            {
                                char error_msg[128];
                                snprintf(error_msg, sizeof(error_msg), "ERROR:Port %d already forwarded by another login",
                                         requested_port);
                                send(conn->fd, error_msg, (int)strlen(error_msg), SEND_FLAGS);
                                update_rate_limit(ip, 0);
#ifdef _WIN32
                                Sleep(1000);
#else
                                sleep(1);
#endif
                                cleanup_connection(conn);
                                continue;
                            }

                            // Check ports per login limit
                            int current_ports = count_ports_for_login(username_start);
                            if (current_ports >= ports_per_login)
                            {
                                char error_msg[128];
                                snprintf(error_msg, sizeof(error_msg), "ERROR:Login has reached maximum ports (%d/%d)",
                                         current_ports, ports_per_login);
                                send(conn->fd, error_msg, (int)strlen(error_msg), SEND_FLAGS);
                                update_rate_limit(ip, 0);
#ifdef _WIN32
                                Sleep(1000);
#else
                                sleep(1);
#endif
                                cleanup_connection(conn);
                                continue;
                            }

                            send(conn->fd, "OK", 2, SEND_FLAGS);
                            conn->state = CONN_STATE_TUNNEL_ESTABLISHED;
                            conn->forwarded_port = requested_port;
                            update_rate_limit(ip, 1);
                            fprintf(stderr, "Server: Tunnel authenticated, setting up forwarded port %d\n", requested_port);

                            socket_t listen_fd = socket(AF_INET, SOCK_STREAM, 0);
                            if (listen_fd != INVALID_SOCK)
                            {
                                int reuse_opt = 1;
                                setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse_opt, sizeof(reuse_opt));

                                struct sockaddr_in bind_sa;
                                memset(&bind_sa, 0, sizeof(bind_sa));
                                bind_sa.sin_family = AF_INET;
                                bind_sa.sin_port = htons((unsigned short)requested_port);

                                if (inet_pton(AF_INET, bind_addr, &bind_sa.sin_addr) <= 0)
                                {
                                    perror("inet_pton for client port");
                                    close(listen_fd);
                                }
                                else if (bind(listen_fd, (struct sockaddr *)&bind_sa, sizeof(bind_sa)) < 0)
                                {
                                    close(listen_fd);
                                }
                                else if (listen(listen_fd, SOMAXCONN) < 0)
                                {
                                    close(listen_fd);
                                }
                                else
                                {
                                    set_nonblocking(listen_fd);
                                    fprintf(stderr, "Server: Forwarded port %d listening (listen_fd=%d)\n", requested_port, (int)listen_fd);
                                    add_forwarded_port(requested_port, listen_fd, conn->fd, bind_addr, username_start);
                                }
                            }
                        }
                        else
                        {
                            send(conn->fd, "FAIL", 4, SEND_FLAGS);
                            struct sockaddr_in peer_addr;
                            socklen_t peer_len = sizeof(peer_addr);
                            getpeername(conn->fd, (struct sockaddr *)&peer_addr, &peer_len);
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
                    }
                    else
                    {
                        cleanup_connection(conn);
                    }
                    continue;
                }

                // DEBUG: Check conditions before forwarding
                if (!conn->is_tunnel)
                {
                    fprintf(stderr, "Server: Non-tunnel connection fd=%d, state=%d, peer_fd=%d, checking conditions...\n", 
                            (int)conn->fd, conn->state, (int)conn->peer_fd);
                }

                if (!conn->is_tunnel && conn->state == CONN_STATE_FORWARDING && conn->peer_fd != INVALID_SOCK)
                {
                    char buf[BUFFER_SIZE];
                    int n = recv(conn->fd, buf, sizeof(buf), 0);
                    fprintf(stderr, "Server: recv from client (session %u) returned %d bytes\n", conn->session_id, n);

                    if (n < 0)
                    {
#ifdef _WIN32
                        int err = WSAGetLastError();
                        if (err != WSAEWOULDBLOCK)
                        {
#else
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
#endif
                            connection_t *tunnel = get_connection(conn->peer_fd);
                            if (tunnel && tunnel->fd != INVALID_SOCK)
                            {
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
                    }
                    else if (n == 0)
                    {
                        connection_t *tunnel = get_connection(conn->peer_fd);
                        if (tunnel && tunnel->fd != INVALID_SOCK)
                        {
                            send_packet(tunnel->fd, conn->session_id, NULL, 0);
                        }
                        active_clients--;
                        cleanup_connection(conn);
                        continue;
                    }
                    else
                    {

                        connection_t *tunnel = get_connection(conn->peer_fd);
                        if (tunnel && tunnel->fd != INVALID_SOCK)
                        {
                            fprintf(stderr, "Server: Forwarding %d bytes from client (session %u) to tunnel (tunnel_fd=%d)\n", n, conn->session_id, (int)tunnel->fd);
                            if (debug_log) fprintf(debug_log, "Forwarding %d bytes from client (session %u) to tunnel\n", n, conn->session_id);
                            int ret = send_packet(tunnel->fd, conn->session_id, buf, n);
                            if (ret < 0)
                            {
                                cleanup_connection(conn);
                            }
                            else if (ret > 0)
                            {
                                update_stats(n, 0, 1, 0);
                            }
                            // If ret == 0 (would block), just skip this iteration
                        }
                        else
                        {
                            cleanup_connection(conn);
                        }
                    }
                    continue;
                }

                if (conn->is_tunnel && conn->state == CONN_STATE_TUNNEL_ESTABLISHED)
                {
                    fprintf(stderr, "Server: Processing tunnel packet (fd=%d)\n", (int)conn->fd);
                    packet_header_t header;
                    int n = recv(conn->fd, (char *)&header, sizeof(header), MSG_PEEK);

                    if (n < 0)
                    {
#ifdef _WIN32
                        int err = WSAGetLastError();
                        if (err != WSAEWOULDBLOCK)
                        {
#else
                        if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
#endif
                            remove_forwarded_ports_for_tunnel(conn->fd);

                            for (int j = 0; j < MAX_CONNECTIONS; j++)
                            {
                                if (connections[j].fd != INVALID_SOCK &&
                                    !connections[j].is_tunnel &&
                                    connections[j].peer_fd == conn->fd)
                                {
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
                    }
                    else if (n == 0)
                    {
                        remove_forwarded_ports_for_tunnel(conn->fd);

                        for (int j = 0; j < MAX_CONNECTIONS; j++)
                        {
                            if (connections[j].fd != INVALID_SOCK &&
                                !connections[j].is_tunnel &&
                                connections[j].peer_fd == conn->fd)
                            {
                                cleanup_connection(&connections[j]);
                                active_clients--;
                            }
                        }

                        cleanup_connection(conn);
                        continue;
                    }

                    if (n < (int)sizeof(header))
                    {
                        continue;
                    }

                    unsigned short session_id = ntohs(header.session_id);
                    unsigned short length = ntohs(header.length);

                    if (debug_log) fprintf(debug_log, "Tunnel received packet: session_id=%u, length=%u\n", session_id, length);

                    // Handle heartbeat - echo it back
                    if (session_id == SESSION_ID_HEARTBEAT)
                    {
                        char heartbeat_data[sizeof(unsigned long long)];
                        recv(conn->fd, (char *)&header, sizeof(header), 0);
                        if (length == sizeof(unsigned long long))
                        {
                            recv(conn->fd, heartbeat_data, length, 0);
                            send_packet(conn->fd, SESSION_ID_HEARTBEAT, heartbeat_data, length);
                        }
                        continue;
                    }

                    char peek_buf[sizeof(packet_header_t) + BUFFER_SIZE];
                    int peek_size = recv(conn->fd, peek_buf, sizeof(header) + length, MSG_PEEK);
                    if (peek_size < (int)(sizeof(header) + length))
                    {
                        continue;
                    }

                    recv(conn->fd, (char *)&header, sizeof(header), 0);

                    char buf[BUFFER_SIZE];
                    if (length > 0)
                    {
                        int data_received = recv(conn->fd, buf, length, 0);
                        if (data_received != length)
                        {
                            cleanup_connection(conn);
                            continue;
                        }
                    }

                    connection_t *target_client = NULL;
                    for (int j = 0; j < MAX_CONNECTIONS; j++)
                    {
                        if (connections[j].fd != INVALID_SOCK &&
                            !connections[j].is_tunnel &&
                            connections[j].peer_fd == conn->fd &&
                            connections[j].session_id == session_id)
                        {
                            target_client = &connections[j];
                            break;
                        }
                    }

                    if (target_client)
                    {
                        if (debug_log) fprintf(debug_log, "Found target client for session %u\n", session_id);
                        fprintf(stderr, "Server: Found target client for session %u, length=%u\n", session_id, length);
                        if (length == 0)
                        {
                            cleanup_connection(target_client);
                            active_clients--;
                        }
                        else
                        {
                            if (debug_log) fprintf(debug_log, "Sending %u bytes to client\n", length);
                            if (send(target_client->fd, buf, length, SEND_FLAGS) < 0)
                            {
                                cleanup_connection(target_client);
                                active_clients--;
                            }
                            else
                            {
                                update_stats(0, length, 0, 1);
                            }
                        }
                    }
                    else
                    {
                        if (debug_log) fprintf(debug_log, "No target client found for session %u\n", session_id);
                        fprintf(stderr, "Server: No target client found for session %u\n", session_id);
                    }

                    continue;
                }
            }
        }
    }

    // Close forwarded ports
    for (int i = 0; i < forwarded_port_count; i++)
    {
        if (forwarded_ports[i].listen_fd != INVALID_SOCK)
        {
            close(forwarded_ports[i].listen_fd);
        }
    }

    // Close connections
    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        if (connections[i].fd != INVALID_SOCK)
        {
            cleanup_connection(&connections[i]);
        }
    }

    // Stop listening
    close(tunnel_listen_fd);

    // Log stop message
    if (debug_log)
    {
        fprintf(debug_log, "Serve mode ending\n");
        fclose(debug_log);
    }

    return 0;
}

#ifndef _WIN32
static void *forward_thread_func(void *arg)
{
    forward_thread_args_t *args = (forward_thread_args_t *)arg;
    while (running)
    {
        int ret = forward_mode(args->local_port, args->server_port, args->tunnel_addr, args->tunnel_port);
        if (ret != 1 || !running)
            break;
        sleep(5);
    }
    free(args);
    return NULL;
}

static void *serve_thread_func(void *arg)
{
    serve_thread_args_t *args = (serve_thread_args_t *)arg;
    serve_mode(args->bind_addr, args->tunnel_port);
    free(args);
    return NULL;
}
#endif

// Load forward config from file (simple format: local_port:remote_port per line)
static int load_forward_config(const char *filename, char *server_addr, int *server_port, char *passwd)
{
    FILE *f = fopen(filename, "r");
    if (!f)
        return 0;

    char line[256];
    forward_config_count = 0;
    int in_forwards_section = 0;
    server_addr[0] = '\0';
    *server_port = 0;
    passwd[0] = '\0';

    while (fgets(line, sizeof(line), f))
    {
        // Remove trailing newline
        line[strcspn(line, "\r\n")] = 0;

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '/' || line[0] == '\0')
            continue;

        // Check for section markers
        if (strstr(line, "forwards=[") || strstr(line, "forwards= ["))
        {
            in_forwards_section = 1;
            continue;
        }
        if (in_forwards_section && strchr(line, ']'))
        {
            in_forwards_section = 0;
            continue;
        }

        // Parse server= line
        if (strncmp(line, "server=", 7) == 0)
        {
            char *value = line + 7;
            char *colon = strchr(value, ':');
            if (colon)
            {
                *colon = '\0';
                strncpy(server_addr, value, 255);
                *server_port = atoi(colon + 1);
            }
            continue;
        }

        // Parse passwd= line
        if (strncmp(line, "passwd=", 7) == 0)
        {
            strncpy(passwd, line + 7, 255);
            continue;
        }

        // Parse forward entries in forwards section
        if (in_forwards_section && forward_config_count < MAX_FORWARDED_PORTS)
        {
            int local, remote;
            // Support both "8000 -> 3000" and "8000:3000" formats
            if (sscanf(line, "%d -> %d", &local, &remote) == 2 ||
                sscanf(line, "%d->%d", &local, &remote) == 2 ||
                sscanf(line, "%d:%d", &local, &remote) == 2)
            {
                forward_configs[forward_config_count].local_port = local;
                forward_configs[forward_config_count].remote_port = remote;
                forward_config_count++;
            }
        }
    }

    fclose(f);
    return (server_addr[0] != '\0' && *server_port > 0 && passwd[0] != '\0') ? forward_config_count : 0;
}

static int load_server_config(const char *filename, char *bind_addr, int *bind_port, char *passwd)
{
    FILE *f = fopen(filename, "r");
    if (!f)
        return 0;

    char line[256];
    bind_addr[0] = '\0';
    *bind_port = 0;
    passwd[0] = '\0';

    while (fgets(line, sizeof(line), f))
    {
        // Remove trailing newline
        line[strcspn(line, "\r\n")] = 0;

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '/' || line[0] == '\0')
            continue;

        // Parse host= line
        if (strncmp(line, "host=", 5) == 0)
        {
            char *value = line + 5;
            char *colon = strchr(value, ':');
            if (colon)
            {
                *colon = '\0';
                strncpy(bind_addr, value, 255);
                *bind_port = atoi(colon + 1);
            }
            continue;
        }

        // Parse passwd= line
        if (strncmp(line, "passwd=", 7) == 0)
        {
            strncpy(passwd, line + 7, 255);
            continue;
        }

        // Parse min_port= line
        if (strncmp(line, "min_port=", 9) == 0)
        {
            min_port = atoi(line + 9);
            if (min_port < 1)
                min_port = 1;
            continue;
        }

        // Parse max_port= line
        if (strncmp(line, "max_port=", 9) == 0)
        {
            max_port = atoi(line + 9);
            if (max_port > 65535)
                max_port = 65535;
            continue;
        }

        // Parse ports_per_login= line
        if (strncmp(line, "ports_per_login=", 16) == 0)
        {
            ports_per_login = atoi(line + 16);
            if (ports_per_login < 1)
                ports_per_login = 1;
            if (ports_per_login > MAX_FORWARDED_PORTS)
                ports_per_login = MAX_FORWARDED_PORTS;
            continue;
        }

        // Parse logins_per_ip= line
        if (strncmp(line, "logins_per_ip=", 14) == 0)
        {
            logins_per_ip = atoi(line + 14);
            if (logins_per_ip < 1)
                logins_per_ip = 1;
            continue;
        }

        // Parse restricted_ports= line
        if (strncmp(line, "restricted_ports=", 17) == 0)
        {
            char *ports_str = line + 17;
            restricted_port_count = 0;
            char *token = strtok(ports_str, ",");
            while (token && restricted_port_count < 256)
            {
                restricted_ports[restricted_port_count++] = atoi(token);
                token = strtok(NULL, ",");
            }
            continue;
        }
    }

    fclose(f);
    return (bind_addr[0] != '\0' && *bind_port > 0 && passwd[0] != '\0') ? 1 : 0;
}

// Helper function to load client config from forwards.conf (tries current dir and parent dir)
static int load_client_config(char *server_addr, int *server_port, char *username, char *password)
{
    char config_server[256];
    int config_port = 0;
    char config_passwd[256];
    config_passwd[0] = '\0';

    // Try current directory first, then parent directory
    if (load_forward_config("forwards.conf", config_server, &config_port, config_passwd) <= 0)
    {
        if (load_forward_config("../forwards.conf", config_server, &config_port, config_passwd) <= 0)
        {
            // Try srps.conf as fallback for server address only
            char bind_addr[256];
            int bind_port;
            char passwd[256];
            if (load_server_config("srps.conf", bind_addr, &bind_port, passwd))
            {
                strncpy(server_addr, bind_addr, 255);
                *server_port = bind_port;
                return 0; // No credentials but server found
            }
            else if (load_server_config("../srps.conf", bind_addr, &bind_port, passwd))
            {
                strncpy(server_addr, bind_addr, 255);
                *server_port = bind_port;
                return 0; // No credentials but server found
            }
            return -1; // Nothing found
        }
    }

    // Found forwards.conf
    strncpy(server_addr, config_server, 255);
    *server_port = config_port;

    if (config_passwd[0] != '\0')
    {
        char *colon = strchr(config_passwd, ':');
        if (colon)
        {
            *colon = '\0';
            strncpy(username, config_passwd, 255);
            strncpy(password, colon + 1, 255);
            return 1; // Found both server and credentials
        }
    }

    return 0; // Found server but no credentials
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage:\n");
        printf("  Server:     %s serve <bind_addr>:<tunnel_port> <password>\n", argv[0]);
        printf("  Agent:      %s forward [<local_port>:<server_port>] [<tunnel_addr>:<tunnel_port>] [<password>]\n", argv[0]);
        printf("              %s forward  (uses forwards.conf)\n", argv[0]);
        printf("  Claim:      %s claim <port> [<server_addr>:<port>] [<username>:<password>]\n", argv[0]);
        printf("  Unclaim:    %s unclaim <port> [<server_addr>:<port>] [<username>:<password>]\n", argv[0]);
        printf("  Register:   %s register <username> <password> [<server_addr>:<port>]\n", argv[0]);
        printf("  Delete:     %s deleteacc <username> <password> [<server_addr>:<port>]\n", argv[0]);
        return 1;
    }

    init_network();

    // Allocate dynamic arrays
    connections = calloc(MAX_CONNECTIONS, sizeof(connection_t));
    forwarded_ports = calloc(MAX_FORWARDED_PORTS, sizeof(forwarded_port_t));
    forward_configs = calloc(MAX_FORWARDED_PORTS, sizeof(forward_config_t));
    rate_limits = calloc(65536, sizeof(rate_limit_entry_t));
    restricted_ports = calloc(max_restricted_ports, sizeof(int));

    if (!connections || !forwarded_ports || !forward_configs || !rate_limits || !restricted_ports)
    {
        fprintf(stderr, "Failed to allocate memory\n");
        return 1;
    }
    for (int i = 0; i < MAX_CONNECTIONS; i++)
    {
        connections[i].fd = INVALID_SOCK;
    }

#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN); // Ignore SIGPIPE to prevent crashes on broken pipes
#endif

    if (strcmp(argv[1], "serve") == 0)
    {
        char bind_addr[256] = "";
        int tunnel_port = 0;

        if (argc >= 4)
        {
            // Full command line: serve bind_addr:port password
            char *colon = strchr(argv[2], ':');
            if (!colon)
            {
                fprintf(stderr, "Invalid bind address format\n");
                return 1;
            }
            *colon = '\0';
            strncpy(bind_addr, argv[2], sizeof(bind_addr) - 1);
            tunnel_port = atoi(colon + 1);
            strncpy(password, argv[3], sizeof(password) - 1);
        }
        else if (argc == 2)
        {
            // Try to load from config file: serve (no args)
            if (load_server_config("srps.conf", bind_addr, &tunnel_port, password) == 0)
            {
                fprintf(stderr, "No config file found or invalid format\n");
                fprintf(stderr, "Usage: %s serve <bind_addr>:<tunnel_port> <password>\n", argv[0]);
                fprintf(stderr, "   Or create srps.conf with:\n");
                fprintf(stderr, "   host=<addr>:<port>\n");
                fprintf(stderr, "   passwd=<password>\n");
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "Usage: %s serve <bind_addr>:<tunnel_port> <password>\n", argv[0]);
            return 1;
        }

#ifndef _WIN32
        serve_thread_args_t *args = malloc(sizeof(serve_thread_args_t));
        strncpy(args->bind_addr, bind_addr, sizeof(args->bind_addr) - 1);
        args->tunnel_port = tunnel_port;

        pthread_t thread;
        pthread_create(&thread, NULL, serve_thread_func, args);
        pthread_detach(thread);

        // Status update loop
        while (running)
        {
            usleep(250000); // 250ms = 250,000 microseconds
            print_status("serve", forwarded_port_count, active_clients);
        }
#else
        serve_mode(bind_addr, tunnel_port);
#endif
    }
    else if (strcmp(argv[1], "forward") == 0)
    {
        // Parse command line arguments
        int local_port = 0, server_port = 0, tunnel_port = 0;
        char tunnel_addr[256] = "";
        char config_server[256] = "";
        int config_port = 0;
        char config_passwd[256] = "";

        if (argc >= 5)
        {
            // Full command line: forward local:server tunnel_addr:port password
            char *colon1 = strchr(argv[2], ':');
            char *colon2 = strchr(argv[3], ':');
            if (!colon1 || !colon2)
            {
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
            if (forward_config_count < MAX_FORWARDED_PORTS)
            {
                forward_configs[forward_config_count].local_port = local_port;
                forward_configs[forward_config_count].remote_port = server_port;
                forward_config_count++;
            }
        }
        else if (argc == 2)
        {
            // Try to load from config file: forward (no args)
            if (load_forward_config("forwards.conf", config_server, &config_port, config_passwd) == 0)
            {
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
            if (forward_config_count > 0)
            {
                local_port = forward_configs[0].remote_port;   // Backend port
                server_port = forward_configs[0].local_port;   // Tunnel server port
            }
        }
        else if (argc >= 4)
        {
            // Using config file for forwards, but override server/pass: forward tunnel_addr:port password
            if (load_forward_config("forwards.conf", config_server, &config_port, config_passwd) > 0)
            {
                // Config loaded, use it for forwards but allow CLI override
                char *colon = strchr(argv[2], ':');
                if (colon)
                {
                    *colon = '\0';
                    strncpy(tunnel_addr, argv[2], sizeof(tunnel_addr) - 1);
                    tunnel_port = atoi(colon + 1);
                }
                else
                {
                    strncpy(tunnel_addr, config_server, sizeof(tunnel_addr) - 1);
                    tunnel_port = config_port;
                }
                strncpy(password, argv[3], sizeof(password) - 1);

                // Use first config entry
                // Note: in forwards.conf "20001 -> 8000" means:
                // local_port (20001) = the tunnel server's listening port
                // remote_port (8000) = the backend service port on agent
                if (forward_config_count > 0)
                {
                    local_port = forward_configs[0].remote_port;   // Backend port (8000)
                    server_port = forward_configs[0].local_port;   // Tunnel server port (20001)
                }
            }
            else
            {
                fprintf(stderr, "Invalid arguments for forward mode\n");
                return 1;
            }
        }
        else
        {
            fprintf(stderr, "Invalid arguments for forward mode\n");
            return 1;
        }

#ifndef _WIN32
        forward_thread_args_t *args = malloc(sizeof(forward_thread_args_t));
        args->local_port = local_port;
        args->server_port = server_port;
        strncpy(args->tunnel_addr, tunnel_addr, sizeof(args->tunnel_addr) - 1);
        args->tunnel_port = tunnel_port;

        pthread_t thread;
        pthread_create(&thread, NULL, forward_thread_func, args);
        pthread_detach(thread);

        // Status update loop
        while (running)
        {
            usleep(250000); // 250ms = 250,000 microseconds
            print_status("forward", tunnel_connected, active_clients);
        }
#else
        while (running)
        {
            int ret = forward_mode(local_port, server_port, tunnel_addr, tunnel_port);
            if (ret != 1 || !running)
                break;
            printf("Reconnecting in 5 seconds...\n");
            Sleep(5000);
        }
#endif
    }
    else if (strcmp(argv[1], "register") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Usage: %s register <username> <password> [<server_addr>:<port>]\n", argv[0]);
            fprintf(stderr, "  If credentials/server not provided, reads from forwards.conf\n");
            return 1;
        }

        char server_addr[256] = "127.0.0.1";
        int server_port = 6969;
        char username[256] = "";
        char user_password[256] = "";

        // Check if we have username and password from args
        int has_creds = (argc >= 4);

        if (has_creds)
        {
            strncpy(username, argv[2], sizeof(username) - 1);
            strncpy(user_password, argv[3], sizeof(user_password) - 1);
        }

        // Parse optional server address from args
        if (argc >= 5)
        {
            char *colon = strchr(argv[4], ':');
            if (colon)
            {
                *colon = '\0';
                strncpy(server_addr, argv[4], sizeof(server_addr) - 1);
                server_port = atoi(colon + 1);
            }
        }
        else
        {
            // Try to load from forwards.conf
            char config_server[256];
            int config_port;
            char config_passwd[256];
            if (load_forward_config("forwards.conf", config_server, &config_port, config_passwd) > 0)
            {
                strncpy(server_addr, config_server, sizeof(server_addr) - 1);
                server_port = config_port;

                // If no credentials from args, use from config
                if (!has_creds && config_passwd[0] != '\0')
                {
                    char *colon = strchr(config_passwd, ':');
                    if (colon)
                    {
                        *colon = '\0';
                        strncpy(username, config_passwd, sizeof(username) - 1);
                        strncpy(user_password, colon + 1, sizeof(user_password) - 1);
                        has_creds = 1;
                    }
                }
            }
            else
            {
                // Fallback to srps.conf for server address only
                char bind_addr[256];
                int bind_port;
                char passwd[256];
                if (load_server_config("srps.conf", bind_addr, &bind_port, passwd))
                {
                    strncpy(server_addr, bind_addr, sizeof(server_addr) - 1);
                    server_port = bind_port;
                }
            }
        }

        if (!has_creds)
        {
            fprintf(stderr, "Username and password required (provide as args or in forwards.conf)\n");
            return 1;
        }

        // Validate password before sending to server
        char error_msg[256];
        if (!validate_password(user_password, error_msg, sizeof(error_msg)))
        {
            fprintf(stderr, "Password validation failed: %s\n", error_msg);
            return 1;
        }

        // Validate username (no colons or pipes)
        if (strchr(username, ':') || strchr(username, '|'))
        {
            fprintf(stderr, "Username cannot contain ':' or '|'\n");
            return 1;
        }

        // Connect to server
        socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCK)
        {
            perror("socket");
            return 1;
        }

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((unsigned short)server_port);
        inet_pton(AF_INET, server_addr, &sa.sin_addr);

        if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        {
            perror("connect");
            close(sock);
            return 1;
        }

        // Hash password
        unsigned int hash = simple_hash(user_password);

        // Send REGISTER command: REGISTER:username:hashed_password
        char register_msg[512];
        snprintf(register_msg, sizeof(register_msg), "REGISTER:%s:%u", username, hash);

        if (send(sock, register_msg, (int)strlen(register_msg), SEND_FLAGS) < 0)
        {
            perror("send");
            close(sock);
            return 1;
        }

        char response[256];
        int n = recv(sock, response, sizeof(response) - 1, 0);
        if (n > 0)
        {
            response[n] = '\0';
            printf("%s\n", response);
            close(sock);
            return (strncmp(response, "OK", 2) == 0) ? 0 : 1;
        }

        close(sock);
        return 1;
    }
    else if (strcmp(argv[1], "deleteacc") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Usage: %s deleteacc <username> <password> [<server_addr>:<port>]\n", argv[0]);
            fprintf(stderr, "  If credentials/server not provided, reads from forwards.conf\n");
            return 1;
        }

        char server_addr[256] = "127.0.0.1";
        int server_port = 6969;
        char username[256] = "";
        char user_password[256] = "";

        // Check if we have username and password from args
        int has_creds = (argc >= 4);

        if (has_creds)
        {
            strncpy(username, argv[2], sizeof(username) - 1);
            strncpy(user_password, argv[3], sizeof(user_password) - 1);
        }

        // Parse optional server address from args
        if (argc >= 5)
        {
            char *colon = strchr(argv[4], ':');
            if (colon)
            {
                *colon = '\0';
                strncpy(server_addr, argv[4], sizeof(server_addr) - 1);
                server_port = atoi(colon + 1);
            }
        }
        else
        {
            // Try to load from forwards.conf
            char config_server[256];
            int config_port;
            char config_passwd[256];
            if (load_forward_config("forwards.conf", config_server, &config_port, config_passwd) > 0)
            {
                strncpy(server_addr, config_server, sizeof(server_addr) - 1);
                server_port = config_port;

                // If no credentials from args, use from config
                if (!has_creds && config_passwd[0] != '\0')
                {
                    char *colon = strchr(config_passwd, ':');
                    if (colon)
                    {
                        *colon = '\0';
                        strncpy(username, config_passwd, sizeof(username) - 1);
                        strncpy(user_password, colon + 1, sizeof(user_password) - 1);
                        has_creds = 1;
                    }
                }
            }
            else
            {
                // Fallback to srps.conf for server address only
                char bind_addr[256];
                int bind_port;
                char passwd[256];
                if (load_server_config("srps.conf", bind_addr, &bind_port, passwd))
                {
                    strncpy(server_addr, bind_addr, sizeof(server_addr) - 1);
                    server_port = bind_port;
                }
            }
        }

        if (!has_creds)
        {
            fprintf(stderr, "Username and password required (provide as args or in forwards.conf)\n");
            return 1;
        }

        // Connect to server
        socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCK)
        {
            perror("socket");
            return 1;
        }

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((unsigned short)server_port);
        inet_pton(AF_INET, server_addr, &sa.sin_addr);

        if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        {
            perror("connect");
            close(sock);
            return 1;
        }

        // Hash password
        unsigned int hash = simple_hash(user_password);

        // Send DELETEACC command: DELETEACC:username:hashed_password
        char delete_msg[512];
        snprintf(delete_msg, sizeof(delete_msg), "DELETEACC:%s:%u", username, hash);

        if (send(sock, delete_msg, (int)strlen(delete_msg), SEND_FLAGS) < 0)
        {
            perror("send");
            close(sock);
            return 1;
        }

        char response[256];
        int n = recv(sock, response, sizeof(response) - 1, 0);
        if (n > 0)
        {
            response[n] = '\0';
            printf("%s\n", response);
            close(sock);
            return (strncmp(response, "OK", 2) == 0) ? 0 : 1;
        }

        close(sock);
        return 1;
    }
    else if (strcmp(argv[1], "claim") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Usage: %s claim <port> [<server_addr>:<port>] [<username>:<password>]\n", argv[0]);
            fprintf(stderr, "  If credentials/server not provided, reads from forwards.conf\n");
            return 1;
        }

        int claim_port = atoi(argv[2]);
        char server_addr[256] = "127.0.0.1";
        int server_port = 6969;
        char username[256] = "";
        char passwd[256] = "";
        int has_creds = 0;

        // Parse optional server address
        if (argc >= 4)
        {
            char *colon = strchr(argv[3], ':');
            if (colon)
            {
                *colon = '\0';
                strncpy(server_addr, argv[3], sizeof(server_addr) - 1);
                server_port = atoi(colon + 1);
            }
        }

        // Parse optional credentials
        if (argc >= 5)
        {
            char temp_passwd[256];
            strncpy(temp_passwd, argv[4], sizeof(temp_passwd) - 1);
            char *colon = strchr(temp_passwd, ':');
            if (colon)
            {
                *colon = '\0';
                strncpy(username, temp_passwd, sizeof(username) - 1);
                strncpy(passwd, colon + 1, sizeof(passwd) - 1);
                has_creds = 1;
            }
        }

        // If no credentials or server provided, try to load from forwards.conf
        if (!has_creds || argc < 4)
        {
            char config_user[256] = "";
            char config_pass[256] = "";
            int result = load_client_config(server_addr, &server_port, config_user, config_pass);

            // Use config credentials if not provided in args
            if (!has_creds && result > 0)
            {
                strncpy(username, config_user, sizeof(username) - 1);
                strncpy(passwd, config_pass, sizeof(passwd) - 1);
                has_creds = 1;
            }
        }

        if (!has_creds)
        {
            fprintf(stderr, "Username:password required (provide as arg or in forwards.conf)\n");
            return 1;
        }

        // Connect to server and send claim request
        socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCK)
        {
            perror("socket");
            return 1;
        }

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((unsigned short)server_port);
        inet_pton(AF_INET, server_addr, &sa.sin_addr);

        if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        {
            perror("connect");
            close(sock);
            return 1;
        }

        // Send claim command: CLAIM:username:hashed_password:port
        unsigned int hash = simple_hash(passwd);
        char claim_msg[512];
        snprintf(claim_msg, sizeof(claim_msg), "CLAIM:%s:%u:%d", username, hash, claim_port);

        if (send(sock, claim_msg, (int)strlen(claim_msg), SEND_FLAGS) < 0)
        {
            perror("send");
            close(sock);
            return 1;
        }

        char response[256];
        int n = recv(sock, response, sizeof(response) - 1, 0);
        if (n > 0)
        {
            response[n] = '\0';
            printf("%s\n", response);
            close(sock);
            return (strncmp(response, "OK", 2) == 0) ? 0 : 1;
        }

        close(sock);
        return 1;
    }
    else if (strcmp(argv[1], "unclaim") == 0)
    {
        if (argc < 3)
        {
            fprintf(stderr, "Usage: %s unclaim <port> [<server_addr>:<port>] [<username>:<password>]\n", argv[0]);
            fprintf(stderr, "  If credentials/server not provided, reads from forwards.conf\n");
            return 1;
        }

        int unclaim_port = atoi(argv[2]);
        char server_addr[256] = "127.0.0.1";
        int server_port = 6969;
        char username[256] = "";
        char passwd[256] = "";
        int has_creds = 0;

        if (argc >= 4)
        {
            char *colon = strchr(argv[3], ':');
            if (colon)
            {
                *colon = '\0';
                strncpy(server_addr, argv[3], sizeof(server_addr) - 1);
                server_port = atoi(colon + 1);
            }
        }

        if (argc >= 5)
        {
            char temp_passwd[256];
            strncpy(temp_passwd, argv[4], sizeof(temp_passwd) - 1);
            char *colon = strchr(temp_passwd, ':');
            if (colon)
            {
                *colon = '\0';
                strncpy(username, temp_passwd, sizeof(username) - 1);
                strncpy(passwd, colon + 1, sizeof(passwd) - 1);
                has_creds = 1;
            }
        }

        // If no credentials or server provided, try to load from forwards.conf
        if (!has_creds || argc < 4)
        {
            char config_server[256];
            int config_port;
            char config_passwd[256];
            if (load_forward_config("forwards.conf", config_server, &config_port, config_passwd) > 0)
            {
                if (argc < 4)
                {
                    strncpy(server_addr, config_server, sizeof(server_addr) - 1);
                    server_port = config_port;
                }

                if (!has_creds && config_passwd[0] != '\0')
                {
                    char *colon = strchr(config_passwd, ':');
                    if (colon)
                    {
                        *colon = '\0';
                        strncpy(username, config_passwd, sizeof(username) - 1);
                        strncpy(passwd, colon + 1, sizeof(passwd) - 1);
                        has_creds = 1;
                    }
                }
            }
        }

        if (!has_creds)
        {
            fprintf(stderr, "Username:password required (provide as arg or in forwards.conf)\n");
            return 1;
        }

        socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCK)
        {
            perror("socket");
            return 1;
        }

        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((unsigned short)server_port);
        inet_pton(AF_INET, server_addr, &sa.sin_addr);

        if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        {
            perror("connect");
            close(sock);
            return 1;
        }

        unsigned int hash = simple_hash(passwd);
        char unclaim_msg[512];
        snprintf(unclaim_msg, sizeof(unclaim_msg), "UNCLAIM:%s:%u:%d", username, hash, unclaim_port);

        if (send(sock, unclaim_msg, (int)strlen(unclaim_msg), SEND_FLAGS) < 0)
        {
            perror("send");
            close(sock);
            return 1;
        }

        char response[256];
        int n = recv(sock, response, sizeof(response) - 1, 0);
        if (n > 0)
        {
            response[n] = '\0';
            printf("%s\n", response);
            close(sock);
            return (strncmp(response, "OK", 2) == 0) ? 0 : 1;
        }

        close(sock);
        return 1;
    }
    else
    {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        return 1;
    }

    cleanup_network();

    // Free dynamic arrays
    free(connections);
    free(forwarded_ports);
    free(forward_configs);
    free(rate_limits);
    free(restricted_ports);

    return 0;
}
