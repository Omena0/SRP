#include "config.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static char *parse_value(const char *line) {
    const char *eq = strchr(line, '=');
    if (!eq)
        return NULL;
    
    const char *val = eq + 1;
    while (isspace((unsigned char)*val))
        val++;
    
    char *trimmed = trim_string(val);
    return trimmed;
}

ServerConfig *config_parse_server(const char *path) {
    if (!path)
        return NULL;
    
    size_t len = 0;
    char *content = read_file(path, &len);
    if (!content)
        return NULL;
    
    ServerConfig *cfg = xcalloc(1, sizeof(ServerConfig));
    cfg->host = xstrdup("127.0.0.1");
    cfg->port = 6969;
    cfg->min_port = 20000;
    cfg->max_port = 21000;
    cfg->ports_per_login = 10;
    cfg->logins_per_ip = 3;
    cfg->restricted_ports = xstrdup("");
    
    size_t line_count = 0;
    char **lines = split_string(content, '\n', &line_count);
    free(content);
    
    if (!lines) {
        return cfg;
    }
    
    for (size_t i = 0; i < line_count; i++) {
        char *line = lines[i];
        if (!line || line[0] == '\0' || line[0] == '#')
            continue;
        
        char *trimmed = trim_string(line);
        if (strlen(trimmed) == 0) {
            free(trimmed);
            continue;
        }
        
        if (strncmp(trimmed, "host=", 5) == 0) {
            char *val = parse_value(trimmed);
            if (val) {
                free(cfg->host);
                cfg->host = val;
            }
        } else if (strncmp(trimmed, "min_port=", 9) == 0) {
            char *val = parse_value(trimmed);
            if (val) {
                cfg->min_port = parse_port(val);
                free(val);
            }
        } else if (strncmp(trimmed, "max_port=", 9) == 0) {
            char *val = parse_value(trimmed);
            if (val) {
                cfg->max_port = parse_port(val);
                free(val);
            }
        } else if (strncmp(trimmed, "ports_per_login=", 16) == 0) {
            char *val = parse_value(trimmed);
            if (val) {
                cfg->ports_per_login = parse_port(val);
                free(val);
            }
        } else if (strncmp(trimmed, "logins_per_ip=", 14) == 0) {
            char *val = parse_value(trimmed);
            if (val) {
                cfg->logins_per_ip = parse_port(val);
                free(val);
            }
        } else if (strncmp(trimmed, "restricted_ports=", 17) == 0) {
            char *val = parse_value(trimmed);
            if (val) {
                free(cfg->restricted_ports);
                cfg->restricted_ports = val;
            }
        }
        
        free(trimmed);
    }
    
    free_split_string(lines, line_count);
    return cfg;
}

ClientConfig *config_parse_client(const char *path) {
    if (!path)
        return NULL;
    
    size_t len = 0;
    char *content = read_file(path, &len);
    if (!content)
        return NULL;
    
    ClientConfig *cfg = xcalloc(1, sizeof(ClientConfig));
    cfg->server_host = xstrdup("127.0.0.1");
    cfg->server_port = 6969;
    cfg->forwards = xcalloc(10, sizeof(cfg->forwards[0]));
    cfg->forward_cap = 10;
    cfg->forward_count = 0;
    
    size_t line_count = 0;
    char **lines = split_string(content, '\n', &line_count);
    free(content);
    
    if (!lines)
        return cfg;
    
    bool in_forwards = false;
    
    for (size_t i = 0; i < line_count; i++) {
        char *line = lines[i];
        if (!line || line[0] == '\0' || line[0] == '#')
            continue;
        
        char *trimmed = trim_string(line);
        if (strlen(trimmed) == 0) {
            free(trimmed);
            continue;
        }
        
        if (strcmp(trimmed, "forwards=[") == 0) {
            in_forwards = true;
            free(trimmed);
            continue;
        }
        
        if (strcmp(trimmed, "]") == 0) {
            in_forwards = false;
            free(trimmed);
            continue;
        }
        
        if (in_forwards) {
            /* Parse: "remote -> local" */
            char *arrow = strstr(trimmed, "->");
            if (arrow) {
                *arrow = '\0';
                uint16_t remote = parse_port(trim_string(trimmed));
                uint16_t local = parse_port(trim_string(arrow + 2));
                
                if (remote > 0 && local > 0) {
                    if (cfg->forward_count >= cfg->forward_cap) {
                        cfg->forward_cap *= 2;
                        cfg->forwards = xrealloc(cfg->forwards,
                                                 cfg->forward_cap * sizeof(cfg->forwards[0]));
                    }
                    cfg->forwards[cfg->forward_count].remote = remote;
                    cfg->forwards[cfg->forward_count].local = local;
                    cfg->forward_count++;
                }
                free(arrow);
            }
            free(trimmed);
            continue;
        }
        
        if (strncmp(trimmed, "server=", 7) == 0) {
            char *val = parse_value(trimmed);
            if (val) {
                char host[256];
                uint16_t port = 0;
                if (parse_addr(val, host, sizeof(host), &port)) {
                    free(cfg->server_host);
                    cfg->server_host = xstrdup(host);
                    cfg->server_port = port;
                }
                free(val);
            }
        } else if (strncmp(trimmed, "passwd=", 7) == 0) {
            char *val = parse_value(trimmed);
            if (val) {
                size_t colon_count = 0;
                char **parts = split_string(val, ':', &colon_count);
                if (parts && colon_count == 2) {
                    cfg->username = xstrdup(parts[0]);
                    cfg->password = xstrdup(parts[1]);
                }
                if (parts)
                    free_split_string(parts, colon_count);
                free(val);
            }
        }
        
        free(trimmed);
    }
    
    free_split_string(lines, line_count);
    return cfg;
}

void config_free_server(ServerConfig *cfg) {
    if (!cfg)
        return;
    
    free(cfg->host);
    free(cfg->restricted_ports);
    free(cfg);
}

void config_free_client(ClientConfig *cfg) {
    if (!cfg)
        return;
    
    free(cfg->server_host);
    free(cfg->username);
    free(cfg->password);
    free(cfg->forwards);
    free(cfg);
}

bool config_port_restricted(ServerConfig *cfg, uint16_t port) {
    if (!cfg || !cfg->restricted_ports || cfg->restricted_ports[0] == '\0')
        return false;
    
    size_t port_count = 0;
    char **ports = split_string(cfg->restricted_ports, ',', &port_count);
    
    if (!ports)
        return false;
    
    bool restricted = false;
    for (size_t i = 0; i < port_count; i++) {
        if (parse_port(ports[i]) == port) {
            restricted = true;
            break;
        }
    }
    
    free_split_string(ports, port_count);
    return restricted;
}
