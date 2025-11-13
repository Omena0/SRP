#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct {
    char *host;
    uint16_t port;
    uint16_t min_port;
    uint16_t max_port;
    uint16_t ports_per_login;
    uint16_t logins_per_ip;
    char *restricted_ports; /* comma-separated */
} ServerConfig;

typedef struct {
    char *server_host;
    uint16_t server_port;
    char *username;
    char *password;
    struct {
        uint16_t remote;
        uint16_t local;
    } *forwards;
    size_t forward_count;
    size_t forward_cap;
} ClientConfig;

/* Parse server config from file */
ServerConfig *config_parse_server(const char *path);

/* Parse client config from file */
ClientConfig *config_parse_client(const char *path);

/* Free server config */
void config_free_server(ServerConfig *cfg);

/* Free client config */
void config_free_client(ClientConfig *cfg);

/* Check if port is restricted */
bool config_port_restricted(ServerConfig *cfg, uint16_t port);

#endif
