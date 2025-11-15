#ifndef FORWARD_H
#define FORWARD_H

#include "platform.h"
#include <stdint.h>

/* Tunnel connection info - dedicated data socket per tunnel */
typedef struct {
    uint32_t tunnel_id;
    socket_t local_sock;       /* Connection to local service */
    socket_t data_sock;        /* Dedicated data socket to server */
    uint16_t local_port;
    int active;
    uint8_t* write_buffer;
    size_t write_buffer_size;
    size_t write_buffer_capacity;
    mutex_t write_mutex;
} tunnel_connection_t;

/* Forward data between server and local service */
void* tunnel_worker(void* arg);

#endif /* FORWARD_H */
