#include "forward.h"
#include "protocol.h"
#include "util.h"
#include "platform.h"
#include <stdlib.h>
#include <string.h>

/* ZERO overhead - dedicated data socket sends raw bytes! */
#define FORWARD_BUFFER_SIZE (64 * 1024)  /* 64KB for maximum throughput */

/* Forward data bidirectionally between server data socket and local service */
void* tunnel_worker(void* arg) {
    tunnel_connection_t* conn = (tunnel_connection_t*)arg;
    
    uint8_t buffer_local[FORWARD_BUFFER_SIZE];  /* Local->Server buffer */
    uint8_t buffer_server[FORWARD_BUFFER_SIZE]; /* Server->Local buffer */
    fd_set read_fds, write_fds;
    struct timeval timeout;
    
    log_info("Tunnel worker %u started with dedicated data socket", conn->tunnel_id);
    
    while (conn->active) {
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(conn->local_sock, &read_fds);
        FD_SET(conn->data_sock, &read_fds);
        
        /* Monitor for write if we have buffered data */
        mutex_lock(&conn->write_mutex);
        if (conn->write_buffer_size > 0) {
            FD_SET(conn->local_sock, &write_fds);
        }
        mutex_unlock(&conn->write_mutex);
        
        timeout.tv_sec = 0;
        timeout.tv_usec = 1000; /* 1ms - low latency without excessive CPU */
        
        socket_t max_fd = conn->local_sock > conn->data_sock ? conn->local_sock : conn->data_sock;
        int ready = select(max_fd + 1, &read_fds, &write_fds, NULL, &timeout);
        
        if (ready < 0) {
            log_error("select() failed in tunnel worker: %d", socket_errno);
            break;
        }
        
        if (ready == 0) continue; /* Timeout */
        
        /* Flush write buffer to local service if writable */
        if (FD_ISSET(conn->local_sock, &write_fds)) {
            mutex_lock(&conn->write_mutex);
            if (conn->write_buffer_size > 0) {
                int sent = send(conn->local_sock, (const char*)conn->write_buffer,
                              conn->write_buffer_size, MSG_NOSIGNAL);
                if (sent > 0) {
                    log_debug("Tunnel %u: Flushed %d/%zu buffered bytes", conn->tunnel_id, sent, conn->write_buffer_size);
                    memmove(conn->write_buffer, conn->write_buffer + sent,
                           conn->write_buffer_size - sent);
                    conn->write_buffer_size -= sent;
                } else if (sent < 0 && !socket_would_block(socket_errno)) {
                    log_error("Failed to write to local service: %d", socket_errno);
                    mutex_unlock(&conn->write_mutex);
                    break;
                }
            }
            mutex_unlock(&conn->write_mutex);
        }
        
        /* Data from local service -> send to server data socket (ZERO OVERHEAD!) */
        if (FD_ISSET(conn->local_sock, &read_fds)) {
            int received = recv(conn->local_sock, (char*)buffer_local, sizeof(buffer_local), 0);
            
            if (received < 0) {
                int err = socket_errno;
                if (!socket_would_block(err)) {
                    log_error("Local connection error: %d", err);
                    goto cleanup;
                }
            } else if (received == 0) {
                log_info("Local connection closed (tunnel %u)", conn->tunnel_id);
                goto cleanup;
            } else {
                log_debug("Tunnel %u: Forwarding %d bytes local->server", conn->tunnel_id, received);
                /* Send raw bytes directly - NO protocol overhead! */
                size_t sent = 0;
                while (sent < (size_t)received) {
                    int s = send(conn->data_sock, (const char*)buffer_local + sent,
                               received - sent, MSG_NOSIGNAL);
                    if (s < 0) {
                        if (!socket_would_block(socket_errno)) {
                            log_error("Failed to send to server: %d", socket_errno);
                            goto cleanup;
                        }
                        /* Wait briefly for socket to be writable */
                        fd_set wfds;
                        FD_ZERO(&wfds);
                        FD_SET(conn->data_sock, &wfds);
                        struct timeval tv = {5, 0};
                        if (select(conn->data_sock + 1, NULL, &wfds, NULL, &tv) <= 0) {
                            log_error("Send timeout");
                            goto cleanup;
                        }
                        continue;
                    }
                    sent += s;
                }
                log_debug("Tunnel %u: Sent all %d bytes local->server", conn->tunnel_id, received);
            }
        }
        
        /* Data from server data socket -> send to local service (ZERO OVERHEAD!) */
        if (FD_ISSET(conn->data_sock, &read_fds)) {
            int received = recv(conn->data_sock, (char*)buffer_server, sizeof(buffer_server), 0);
            
            if (received < 0) {
                int err = socket_errno;
                if (!socket_would_block(err)) {
                    log_error("Server data socket error: %d", err);
                    break;
                }
            } else if (received == 0) {
                log_info("Server closed data socket (tunnel %u)", conn->tunnel_id);
                break;
            } else {
                log_debug("Tunnel %u: Forwarding %d bytes server->local", conn->tunnel_id, received);
                /* Send raw bytes to local service */
                mutex_lock(&conn->write_mutex);
                
                /* Try direct send first */
                if (conn->write_buffer_size == 0) {
                    int sent = send(conn->local_sock, (const char*)buffer_server, received, MSG_NOSIGNAL);
                    if (sent > 0) {
                        log_debug("Tunnel %u: Direct sent %d/%d bytes server->local", conn->tunnel_id, sent, received);
                        if (sent < received) {
                            /* Buffer remainder */
                            size_t remaining = received - sent;
                            log_debug("Tunnel %u: Buffering %zu remaining bytes", conn->tunnel_id, remaining);
                            if (remaining > conn->write_buffer_capacity) {
                                conn->write_buffer_capacity = remaining * 2;
                                conn->write_buffer = (uint8_t*)xrealloc(conn->write_buffer,
                                                                       conn->write_buffer_capacity);
                            }
                            memcpy(conn->write_buffer, buffer_server + sent, remaining);
                            conn->write_buffer_size = remaining;
                        }
                        mutex_unlock(&conn->write_mutex);
                    } else {
                        log_debug("Tunnel %u: Direct send failed, buffering all %d bytes", conn->tunnel_id, received);
                        /* Buffer all data if direct send failed */
                        size_t new_size = conn->write_buffer_size + received;
                        if (new_size > conn->write_buffer_capacity) {
                            conn->write_buffer_capacity = new_size * 2;
                            if (conn->write_buffer_capacity > 134217728) {
                                log_error("Write buffer overflow (tunnel %u)", conn->tunnel_id);
                                mutex_unlock(&conn->write_mutex);
                                break;
                            }
                            conn->write_buffer = (uint8_t*)xrealloc(conn->write_buffer,
                                                                   conn->write_buffer_capacity);
                        }
                        memcpy(conn->write_buffer + conn->write_buffer_size, buffer_server, received);
                        conn->write_buffer_size += received;
                        mutex_unlock(&conn->write_mutex);
                    }
                } else {
                    log_debug("Tunnel %u: Buffer has %zu bytes, appending %d bytes", conn->tunnel_id, conn->write_buffer_size, received);
                    /* Buffer all data if write buffer already has data */
                    size_t new_size = conn->write_buffer_size + received;
                    if (new_size > conn->write_buffer_capacity) {
                        conn->write_buffer_capacity = new_size * 2;
                        if (conn->write_buffer_capacity > 134217728) {
                            log_error("Write buffer overflow (tunnel %u)", conn->tunnel_id);
                            mutex_unlock(&conn->write_mutex);
                            break;
                        }
                        conn->write_buffer = (uint8_t*)xrealloc(conn->write_buffer,
                                                               conn->write_buffer_capacity);
                    }
                    memcpy(conn->write_buffer + conn->write_buffer_size, buffer_server, received);
                    conn->write_buffer_size += received;
                    mutex_unlock(&conn->write_mutex);
                }
            }
        }
    }
    
cleanup:
    socket_close(conn->local_sock);
    socket_close(conn->data_sock);
    conn->active = 0;
    
    /* Free write buffer */
    mutex_lock(&conn->write_mutex);
    if (conn->write_buffer) {
        xfree(conn->write_buffer);
        conn->write_buffer = NULL;
    }
    conn->write_buffer_size = 0;
    conn->write_buffer_capacity = 0;
    mutex_unlock(&conn->write_mutex);
    
    log_info("Tunnel worker finished for tunnel %u", conn->tunnel_id);
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}
