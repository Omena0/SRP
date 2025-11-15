#ifndef CLIENT_H
#define CLIENT_H

#include "config.h"

/* Start the agent/client */
int client_run(const char* config_path);

/* Admin commands */
int client_claim_port(const char* config_path, uint16_t port);
int client_unclaim_port(const char* config_path, uint16_t port);
int client_list_ports(const char* config_path);

#endif /* CLIENT_H */
