#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

/* Server configuration */
typedef struct {
    char host[256];
    uint16_t port;
    /* Dedicated data port for agent data socket connections (optional). If 0, uses port+1 */
    uint16_t data_port;
    uint16_t min_port;
    uint16_t max_port;
    int ports_per_login;
    int logins_per_ip;
    uint16_t* restricted_ports;
    int restricted_count;
} server_config_t;

/* Forward mapping */
typedef struct {
    uint16_t remote_port;
    uint16_t local_port;
} forward_mapping_t;

/* Agent configuration */
typedef struct {
    char server_host[256];
    uint16_t server_port;
    char username[64];
    char password[128];
    forward_mapping_t* forwards;
    int forward_count;
} agent_config_t;

/* Configuration loading */
int config_load_server(const char* path, server_config_t* config);
int config_load_agent(const char* path, agent_config_t* config);

/* Configuration cleanup */
void config_free_server(server_config_t* config);
void config_free_agent(agent_config_t* config);

/* Default configuration paths */
#define DEFAULT_SERVER_CONFIG "srps.conf"
#define DEFAULT_AGENT_CONFIG "forwards.conf"

#endif /* CONFIG_H */
