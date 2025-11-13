#ifndef CLIENT_H
#define CLIENT_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    int socket_fd;
    char *username;
    char *password;
    char *server_host;
    uint16_t server_port;
} SRPClient;

/* Connect and authenticate to SRP server */
SRPClient *client_connect(const char *host, uint16_t port,
                          const char *username, const char *password);

/* Disconnect from server */
void client_disconnect(SRPClient *client);

/* Claim a port on the server */
bool client_claim_port(SRPClient *client, uint16_t port);

/* Unclaim a port */
bool client_unclaim_port(SRPClient *client, uint16_t port);

/* List all claimed ports */
char *client_list_ports(SRPClient *client);

#endif
