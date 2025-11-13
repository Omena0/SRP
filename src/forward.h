#ifndef FORWARD_H
#define FORWARD_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint16_t remote_port;
    uint16_t local_port;
} PortMapping;

/* Bidirectional proxy between remote and local ports */
bool proxy_ports(const char *bind_addr, uint16_t bind_port,
                 const char *dest_host, uint16_t dest_port);

#endif
