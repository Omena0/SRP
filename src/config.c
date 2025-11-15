#include "config.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* Parse a key=value line */
static int parse_line(char* line, char** key, char** value) {
    if (!line || !key || !value) return -1;
    
    /* Skip comments and empty lines */
    line = str_trim(line);
    if (line[0] == '#' || line[0] == '\0') return 1;
    
    /* Find '=' */
    char* eq = strchr(line, '=');
    if (!eq) return -1;
    
    *eq = '\0';
    *key = str_trim(line);
    *value = str_trim(eq + 1);
    
    return 0;
}

/* Parse forward list in format: forwards=[\n    20001 -> 8000\n    20002 -> 8001\n] */
static int parse_forward_list(FILE* f, forward_mapping_t** forwards, int* count) {
    if (!f || !forwards || !count) return -1;
    
    char line[512];
    int capacity = 16;
    *forwards = (forward_mapping_t*)xmalloc(capacity * sizeof(forward_mapping_t));
    *count = 0;
    
    while (fgets(line, sizeof(line), f)) {
        char* trimmed = str_trim(line);
        
        /* End of forward list */
        if (strchr(trimmed, ']')) break;
        
        /* Skip empty lines and comments */
        if (trimmed[0] == '\0' || trimmed[0] == '#') continue;
        
        /* Parse: remote_port -> local_port */
        char* arrow = strstr(trimmed, "->");
        if (!arrow) continue;
        
        *arrow = '\0';
        char* remote_str = str_trim(trimmed);
        char* local_str = str_trim(arrow + 2);
        
        uint16_t remote_port, local_port;
        if (str_to_uint16(remote_str, &remote_port) != 0) continue;
        if (str_to_uint16(local_str, &local_port) != 0) continue;
        
        /* Expand capacity if needed */
        if (*count >= capacity) {
            capacity *= 2;
            *forwards = (forward_mapping_t*)xrealloc(*forwards, capacity * sizeof(forward_mapping_t));
        }
        
        (*forwards)[*count].remote_port = remote_port;
        (*forwards)[*count].local_port = local_port;
        (*count)++;
    }
    
    return 0;
}

int config_load_server(const char* path, server_config_t* config) {
    if (!path || !config) return -1;
    
    FILE* f = fopen(path, "r");
    if (!f) {
        log_error("Failed to open server config: %s", path);
        return -1;
    }
    
    /* Set defaults */
    memset(config, 0, sizeof(*config));
    strcpy(config->host, "127.0.0.1");
    config->port = 6969;
    config->data_port = 0; /* default: 0 => use port+1 */
    config->min_port = 20000;
    config->max_port = 21000;
    config->ports_per_login = 10;
    config->logins_per_ip = 3;
    config->restricted_ports = NULL;
    config->restricted_count = 0;
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* key;
        char* value;
        int ret = parse_line(line, &key, &value);
        if (ret != 0) continue;
        
        if (strcmp(key, "host") == 0) {
            /* Parse host:port */
            if (parse_address(value, config->host, sizeof(config->host), &config->port) != 0) {
                /* Try just host */
                strncpy(config->host, value, sizeof(config->host) - 1);
            }
        }
        else if (strcmp(key, "min_port") == 0) {
            str_to_uint16(value, &config->min_port);
        }
        else if (strcmp(key, "max_port") == 0) {
            str_to_uint16(value, &config->max_port);
        }
        else if (strcmp(key, "ports_per_login") == 0) {
            str_to_int(value, &config->ports_per_login);
        }
        else if (strcmp(key, "logins_per_ip") == 0) {
            str_to_int(value, &config->logins_per_ip);
        }
        else if (strcmp(key, "restricted_ports") == 0) {
            parse_port_list(value, &config->restricted_ports, &config->restricted_count);
        }
        else if (strcmp(key, "data_port") == 0) {
            str_to_uint16(value, &config->data_port);
        }
    }
    
    fclose(f);
    /* If data_port not specified, use port+1 by default */
    if (config->data_port == 0) config->data_port = config->port + 1;
    log_info("Loaded server config: %s:%d (data=%d)", config->host, config->port, config->data_port);
    return 0;
}

int config_load_agent(const char* path, agent_config_t* config) {
    if (!path || !config) return -1;
    
    FILE* f = fopen(path, "r");
    if (!f) {
        log_error("Failed to open agent config: %s", path);
        return -1;
    }
    
    /* Set defaults */
    memset(config, 0, sizeof(*config));
    strcpy(config->server_host, "127.0.0.1");
    config->server_port = 6969;
    config->forwards = NULL;
    config->forward_count = 0;
    
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* key;
        char* value;
        int ret = parse_line(line, &key, &value);
        if (ret != 0) continue;
        
        if (strcmp(key, "server") == 0) {
            parse_address(value, config->server_host, sizeof(config->server_host), &config->server_port);
        }
        else if (strcmp(key, "passwd") == 0) {
            /* Format: username:password */
            char* colon = strchr(value, ':');
            if (colon) {
                *colon = '\0';
                strncpy(config->username, value, sizeof(config->username) - 1);
                strncpy(config->password, colon + 1, sizeof(config->password) - 1);
            }
        }
        else if (strcmp(key, "forwards") == 0) {
            /* Check if it starts with '[' */
            if (strchr(value, '[')) {
                parse_forward_list(f, &config->forwards, &config->forward_count);
            }
        }
    }
    
    fclose(f);
    log_info("Loaded agent config: server=%s:%d, user=%s, forwards=%d",
             config->server_host, config->server_port, config->username, config->forward_count);
    return 0;
}

void config_free_server(server_config_t* config) {
    if (!config) return;
    if (config->restricted_ports) {
        xfree(config->restricted_ports);
        config->restricted_ports = NULL;
    }
}

void config_free_agent(agent_config_t* config) {
    if (!config) return;
    if (config->forwards) {
        xfree(config->forwards);
        config->forwards = NULL;
    }
}
