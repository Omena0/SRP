#include "forward.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>

#define BUFFER_SIZE 4096
#define MAX_CONNECTIONS 256

typedef struct {
    int client_fd;
    int server_fd;
    char client_buf[BUFFER_SIZE];
    size_t client_buf_len;
    char server_buf[BUFFER_SIZE];
    size_t server_buf_len;
} Connection;

typedef struct {
    Connection connections[MAX_CONNECTIONS];
    int conn_count;
} ConnectionPool;

static int socket_connect(const char *host, uint16_t port) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    
    char port_str[16];
    sprintf(port_str, "%u", port);
    
    struct addrinfo *result;
    if (getaddrinfo(host, port_str, &hints, &result) != 0)
        return -1;
    
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
    return fd;
}

static int socket_listen(const char *bind_host, uint16_t bind_port) {
    struct addrinfo hints = {0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    char port_str[16];
    sprintf(port_str, "%u", bind_port);
    
    struct addrinfo *result;
    if (getaddrinfo(bind_host, port_str, &hints, &result) != 0)
        return -1;
    
    int fd = -1;
    for (struct addrinfo *rp = result; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == -1)
            continue;
        
        int opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
            close(fd);
            continue;
        }
        
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;
        
        close(fd);
        fd = -1;
    }
    
    freeaddrinfo(result);
    
    if (fd == -1)
        return -1;
    
    if (listen(fd, 128) == -1) {
        close(fd);
        return -1;
    }
    
    return fd;
}

static void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static bool relay_data(int from, int to, char *buf, size_t *buf_len) {
    (void)from;
    if (*buf_len == 0)
        return true;
    
    ssize_t written = send(to, buf, *buf_len, MSG_NOSIGNAL);
    if (written < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            return false;
        return true;
    }
    
    if (written < (ssize_t)*buf_len) {
        memmove(buf, buf + written, *buf_len - written);
        *buf_len -= written;
        return true;
    }
    
    *buf_len = 0;
    return true;
}

bool proxy_ports(const char *bind_addr, uint16_t bind_port,
                 const char *dest_host, uint16_t dest_port) {
    if (!bind_addr || !dest_host)
        return false;
    
    int listen_fd = socket_listen(bind_addr, bind_port);
    if (listen_fd == -1) {
        perror("socket_listen");
        return false;
    }
    
    set_nonblocking(listen_fd);
    ConnectionPool pool = {0};
    
    fprintf(stderr, "Forwarding %s:%u -> %s:%u\n", bind_addr, bind_port,
            dest_host, dest_port);
    
    while (1) {
        fd_set readfds, writefds;
        int max_fd = listen_fd;
        
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_SET(listen_fd, &readfds);
        
        for (int i = 0; i < pool.conn_count; i++) {
            Connection *conn = &pool.connections[i];
            if (conn->client_fd != -1) {
                FD_SET(conn->client_fd, &readfds);
                max_fd = (conn->client_fd > max_fd) ? conn->client_fd : max_fd;
            }
            
            if (conn->server_fd != -1) {
                if (conn->client_buf_len > 0)
                    FD_SET(conn->server_fd, &writefds);
                else
                    FD_SET(conn->server_fd, &readfds);
                
                max_fd = (conn->server_fd > max_fd) ? conn->server_fd : max_fd;
            }
        }
        
        struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
        int select_res = select(max_fd + 1, &readfds, &writefds, NULL, &tv);
        
        if (select_res == -1) {
            perror("select");
            break;
        }
        
        /* Accept new connections */
        if (FD_ISSET(listen_fd, &readfds)) {
            int client_fd = accept(listen_fd, NULL, NULL);
            if (client_fd != -1) {
                if (pool.conn_count >= MAX_CONNECTIONS) {
                    close(client_fd);
                } else {
                    int server_fd = socket_connect(dest_host, dest_port);
                    if (server_fd != -1) {
                        set_nonblocking(client_fd);
                        set_nonblocking(server_fd);
                        
                        Connection *conn = &pool.connections[pool.conn_count++];
                        conn->client_fd = client_fd;
                        conn->server_fd = server_fd;
                        conn->client_buf_len = 0;
                        conn->server_buf_len = 0;
                    } else {
                        close(client_fd);
                    }
                }
            }
        }
        
        /* Process existing connections */
        for (int i = 0; i < pool.conn_count; ) {
            Connection *conn = &pool.connections[i];
            bool close_conn = false;
            
            if (FD_ISSET(conn->client_fd, &readfds)) {
                ssize_t n = recv(conn->client_fd, conn->client_buf + conn->client_buf_len,
                                BUFFER_SIZE - conn->client_buf_len, 0);
                if (n <= 0) {
                    close_conn = true;
                } else {
                    conn->client_buf_len += n;
                }
            }
            
            if (FD_ISSET(conn->server_fd, &readfds)) {
                ssize_t n = recv(conn->server_fd, conn->server_buf + conn->server_buf_len,
                                BUFFER_SIZE - conn->server_buf_len, 0);
                if (n <= 0) {
                    close_conn = true;
                } else {
                    conn->server_buf_len += n;
                }
            }
            
            if (FD_ISSET(conn->server_fd, &writefds)) {
                if (!relay_data(conn->client_fd, conn->server_fd,
                               conn->client_buf, &conn->client_buf_len)) {
                    close_conn = true;
                }
            }
            
            /* Send buffered server data to client */
            if (conn->server_buf_len > 0) {
                ssize_t written = send(conn->client_fd, conn->server_buf,
                                      conn->server_buf_len, MSG_NOSIGNAL);
                if (written < 0) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        close_conn = true;
                } else {
                    if (written < (ssize_t)conn->server_buf_len) {
                        memmove(conn->server_buf, conn->server_buf + written,
                               conn->server_buf_len - written);
                    }
                    conn->server_buf_len -= written;
                }
            }
            
            if (close_conn) {
                if (conn->client_fd != -1)
                    close(conn->client_fd);
                if (conn->server_fd != -1)
                    close(conn->server_fd);
                
                if (i < pool.conn_count - 1) {
                    memmove(conn, conn + 1,
                           (pool.conn_count - i - 1) * sizeof(Connection));
                }
                pool.conn_count--;
            } else {
                i++;
            }
        }
    }
    
    close(listen_fd);
    return true;
}
