#include "credentials.h"
#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

LoginStore *loginstore_new(void) {
    LoginStore *store = xmalloc(sizeof(LoginStore));
    store->logins = xcalloc(10, sizeof(Login));
    store->count = 0;
    store->cap = 10;
    return store;
}

void loginstore_free(LoginStore *store) {
    if (!store)
        return;
    
    for (size_t i = 0; i < store->count; i++) {
        free(store->logins[i].username);
        free(store->logins[i].passwd_hash);
        free(store->logins[i].claimed_ports);
    }
    
    free(store->logins);
    free(store);
}

void loginstore_add(LoginStore *store, const char *username, const char *passwd_hash) {
    if (!store || !username || !passwd_hash)
        return;
    
    /* Don't add duplicates */
    if (loginstore_get(store, username))
        return;
    
    if (store->count >= store->cap) {
        store->cap *= 2;
        store->logins = xrealloc(store->logins, store->cap * sizeof(Login));
    }
    
    Login *login = &store->logins[store->count++];
    login->username = xstrdup(username);
    login->passwd_hash = xstrdup(passwd_hash);
    login->created_at = time(NULL);
    login->claimed_ports = xcalloc(10, sizeof(uint16_t));
    login->claimed_count = 0;
    login->claimed_cap = 10;
}

Login *loginstore_get(LoginStore *store, const char *username) {
    if (!store || !username)
        return NULL;
    
    for (size_t i = 0; i < store->count; i++) {
        if (strcmp(store->logins[i].username, username) == 0)
            return &store->logins[i];
    }
    
    return NULL;
}

bool loginstore_remove(LoginStore *store, const char *username) {
    if (!store || !username)
        return false;
    
    for (size_t i = 0; i < store->count; i++) {
        if (strcmp(store->logins[i].username, username) == 0) {
            free(store->logins[i].username);
            free(store->logins[i].passwd_hash);
            free(store->logins[i].claimed_ports);
            
            if (i < store->count - 1) {
                memmove(&store->logins[i], &store->logins[i + 1],
                        (store->count - i - 1) * sizeof(Login));
            }
            store->count--;
            return true;
        }
    }
    
    return false;
}

bool loginstore_claim_port(LoginStore *store, const char *username, uint16_t port) {
    if (!store || !username || port == 0)
        return false;
    
    Login *login = loginstore_get(store, username);
    if (!login)
        return false;
    
    /* Don't add duplicates */
    if (loginstore_has_port(store, username, port))
        return false;
    
    if (login->claimed_count >= login->claimed_cap) {
        login->claimed_cap *= 2;
        login->claimed_ports = xrealloc(login->claimed_ports,
                                        login->claimed_cap * sizeof(uint16_t));
    }
    
    login->claimed_ports[login->claimed_count++] = port;
    return true;
}

bool loginstore_unclaim_port(LoginStore *store, const char *username, uint16_t port) {
    if (!store || !username || port == 0)
        return false;
    
    Login *login = loginstore_get(store, username);
    if (!login)
        return false;
    
    for (size_t i = 0; i < login->claimed_count; i++) {
        if (login->claimed_ports[i] == port) {
            if (i < login->claimed_count - 1) {
                memmove(&login->claimed_ports[i], &login->claimed_ports[i + 1],
                        (login->claimed_count - i - 1) * sizeof(uint16_t));
            }
            login->claimed_count--;
            return true;
        }
    }
    
    return false;
}

bool loginstore_has_port(LoginStore *store, const char *username, uint16_t port) {
    if (!store || !username || port == 0)
        return false;
    
    Login *login = loginstore_get(store, username);
    if (!login)
        return false;
    
    for (size_t i = 0; i < login->claimed_count; i++) {
        if (login->claimed_ports[i] == port)
            return true;
    }
    
    return false;
}

bool loginstore_load(LoginStore *store, const char *path) {
    if (!store || !path)
        return false;
    
    size_t file_len = 0;
    char *content = read_file(path, &file_len);
    if (!content)
        return false;
    
    size_t line_count = 0;
    char **lines = split_string(content, '\n', &line_count);
    free(content);
    
    if (!lines)
        return true; /* Empty file is OK */
    
    for (size_t i = 0; i < line_count; i++) {
        char *line = lines[i];
        if (!line || line[0] == '\0')
            continue;
        
        /* Parse: username:hash:created_at[|port1,port2,...] */
        char *p = line;
        char *colon1 = strchr(p, ':');
        if (!colon1)
            continue;
        
        size_t username_len = colon1 - p;
        char *username = xmalloc(username_len + 1);
        memcpy(username, p, username_len);
        username[username_len] = '\0';
        
        p = colon1 + 1;
        char *colon2 = strchr(p, ':');
        if (!colon2) {
            free(username);
            continue;
        }
        
        size_t hash_len = colon2 - p;
        char *hash = xmalloc(hash_len + 1);
        memcpy(hash, p, hash_len);
        hash[hash_len] = '\0';
        
        p = colon2 + 1;
        char *pipe = strchr(p, '|');
        
        uint64_t created_at = 0;
        if (pipe) {
            size_t timestamp_len = pipe - p;
            char *ts_str = xmalloc(timestamp_len + 1);
            memcpy(ts_str, p, timestamp_len);
            ts_str[timestamp_len] = '\0';
            created_at = strtoull(ts_str, NULL, 10);
            free(ts_str);
            p = pipe + 1;
        } else {
            created_at = strtoull(p, NULL, 10);
            p = NULL;
        }
        
        loginstore_add(store, username, hash);
        Login *login = loginstore_get(store, username);
        if (login)
            login->created_at = created_at;
        
        /* Parse ports */
        if (p) {
            size_t port_count = 0;
            char **ports = split_string(p, ',', &port_count);
            if (ports) {
                for (size_t j = 0; j < port_count; j++) {
                    uint16_t port = parse_port(ports[j]);
                    if (port > 0)
                        loginstore_claim_port(store, username, port);
                }
                free_split_string(ports, port_count);
            }
        }
        
        free(username);
        free(hash);
    }
    
    free_split_string(lines, line_count);
    return true;
}

bool loginstore_save(LoginStore *store, const char *path) {
    if (!store || !path)
        return false;
    
    String content = string_new(256);
    
    for (size_t i = 0; i < store->count; i++) {
        Login *login = &store->logins[i];
        
        string_append_cstr(&content, login->username);
        string_append_cstr(&content, ":");
        string_append_cstr(&content, login->passwd_hash);
        string_append_cstr(&content, ":");
        
        char timestamp[32];
        sprintf(timestamp, "%lu", (unsigned long)login->created_at);
        string_append_cstr(&content, timestamp);
        
        if (login->claimed_count > 0) {
            string_append_cstr(&content, "|");
            
            for (size_t j = 0; j < login->claimed_count; j++) {
                if (j > 0)
                    string_append_cstr(&content, ",");
                
                char port_str[16];
                sprintf(port_str, "%u", login->claimed_ports[j]);
                string_append_cstr(&content, port_str);
            }
        }
        
        string_append_cstr(&content, "\n");
    }
    
    size_t len = content.len;
    char *cstr = xmalloc(len);
    memcpy(cstr, content.data, len);
    bool result = write_file(path, cstr, len);
    free(cstr);
    string_free(&content);
    
    return result;
}
