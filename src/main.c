#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util.h"
#include "auth.h"
#include "credentials.h"
#include "config.h"
#include "forward.h"
#include "server.h"
#include "client.h"

#define LOGINS_FILE "logins.conf"
#define SERVER_CONFIG_FILE "srps.conf"
#define CLIENT_CONFIG_FILE "forwards.conf"

/* ============== Command handlers ============== */

static int cmd_register(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: srp register <username> <password>\n");
        return 1;
    }
    
    const char *username = argv[2];
    const char *password = argv[3];
    
    if (strlen(username) == 0 || strlen(password) == 0) {
        fprintf(stderr, "error: username and password cannot be empty\n");
        return 1;
    }
    
    LoginStore *store = loginstore_new();
    if (!loginstore_load(store, LOGINS_FILE)) {
        fprintf(stderr, "note: creating new logins file\n");
    }
    
    if (loginstore_get(store, username)) {
        fprintf(stderr, "error: user already exists\n");
        loginstore_free(store);
        return 1;
    }
    
    char *hash = hash_password(password);
    if (!hash) {
        fprintf(stderr, "error: failed to hash password\n");
        loginstore_free(store);
        return 1;
    }
    
    loginstore_add(store, username, hash);
    free(hash);
    
    if (!loginstore_save(store, LOGINS_FILE)) {
        fprintf(stderr, "error: failed to save logins\n");
        loginstore_free(store);
        return 1;
    }
    
    printf("registered: %s\n", username);
    loginstore_free(store);
    return 0;
}

static int cmd_deletelogin(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: srp deletelogin <username> <password>\n");
        return 1;
    }
    
    const char *username = argv[2];
    const char *password = argv[3];
    
    LoginStore *store = loginstore_new();
    if (!loginstore_load(store, LOGINS_FILE)) {
        fprintf(stderr, "error: failed to load logins\n");
        loginstore_free(store);
        return 1;
    }
    
    Login *login = loginstore_get(store, username);
    if (!login) {
        fprintf(stderr, "error: user not found\n");
        loginstore_free(store);
        return 1;
    }
    
    if (!verify_password(password, login->passwd_hash)) {
        fprintf(stderr, "error: invalid password\n");
        loginstore_free(store);
        return 1;
    }
    
    if (!loginstore_remove(store, username)) {
        fprintf(stderr, "error: failed to remove user\n");
        loginstore_free(store);
        return 1;
    }
    
    if (!loginstore_save(store, LOGINS_FILE)) {
        fprintf(stderr, "error: failed to save logins\n");
        loginstore_free(store);
        return 1;
    }
    
    printf("deleted: %s\n", username);
    loginstore_free(store);
    return 0;
}

static int cmd_claim(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: srp claim <port>\n");
        return 1;
    }
    
    uint16_t port = parse_port(argv[2]);
    if (port == 0) {
        fprintf(stderr, "error: invalid port\n");
        return 1;
    }
    
    ServerConfig *cfg = config_parse_server(SERVER_CONFIG_FILE);
    if (!cfg) {
        fprintf(stderr, "error: failed to load server config\n");
        return 1;
    }
    
    if (port < cfg->min_port || port > cfg->max_port) {
        fprintf(stderr, "error: port out of range [%u, %u]\n", cfg->min_port, cfg->max_port);
        config_free_server(cfg);
        return 1;
    }
    
    if (config_port_restricted(cfg, port)) {
        fprintf(stderr, "error: port is restricted\n");
        config_free_server(cfg);
        return 1;
    }
    
    /* Check if port is already claimed by loading logins */
    LoginStore *store = loginstore_new();
    loginstore_load(store, LOGINS_FILE);
    
    for (size_t i = 0; i < store->count; i++) {
        if (loginstore_has_port(store, store->logins[i].username, port)) {
            fprintf(stderr, "error: port already claimed by %s\n", store->logins[i].username);
            loginstore_free(store);
            config_free_server(cfg);
            return 1;
        }
    }
    
    loginstore_free(store);
    config_free_server(cfg);
    
    printf("port can be claimed: %u\n", port);
    return 0;
}

static int cmd_unclaim(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: srp unclaim <username> <password>\n");
        return 1;
    }
    
    const char *username = argv[2];
    const char *password = argv[3];
    
    LoginStore *store = loginstore_new();
    if (!loginstore_load(store, LOGINS_FILE)) {
        fprintf(stderr, "error: failed to load logins\n");
        loginstore_free(store);
        return 1;
    }
    
    Login *login = loginstore_get(store, username);
    if (!login) {
        fprintf(stderr, "error: user not found\n");
        loginstore_free(store);
        return 1;
    }
    
    if (!verify_password(password, login->passwd_hash)) {
        fprintf(stderr, "error: invalid password\n");
        loginstore_free(store);
        return 1;
    }
    
    if (login->claimed_count == 0) {
        fprintf(stderr, "note: no ports claimed\n");
        loginstore_free(store);
        return 0;
    }
    
    /* Unclaim all ports */
    for (size_t i = 0; i < login->claimed_count; i++) {
        printf("unclaimed: %u\n", login->claimed_ports[i]);
    }
    login->claimed_count = 0;
    
    if (!loginstore_save(store, LOGINS_FILE)) {
        fprintf(stderr, "error: failed to save logins\n");
        loginstore_free(store);
        return 1;
    }
    
    loginstore_free(store);
    return 0;
}

static int cmd_forward(int argc, char **argv) {
    (void)argc;
    (void)argv;
    ClientConfig *cfg = config_parse_client(CLIENT_CONFIG_FILE);
    if (!cfg) {
        fprintf(stderr, "error: failed to load client config\n");
        return 1;
    }
    
    if (!cfg->username || !cfg->password) {
        fprintf(stderr, "error: username/password not configured\n");
        config_free_client(cfg);
        return 1;
    }
    
    if (cfg->forward_count == 0) {
        fprintf(stderr, "error: no forwards configured\n");
        config_free_client(cfg);
        return 1;
    }
    
    /* Connect to server */
    SRPClient *client = client_connect(cfg->server_host, cfg->server_port,
                                       cfg->username, cfg->password);
    if (!client) {
        config_free_client(cfg);
        return 1;
    }
    
    printf("Connected to %s:%u\n", cfg->server_host, cfg->server_port);
    
    /* Claim all ports */
    for (size_t i = 0; i < cfg->forward_count; i++) {
        uint16_t remote_port = cfg->forwards[i].remote;
        uint16_t local_port = cfg->forwards[i].local;
        
        if (!client_claim_port(client, remote_port)) {
            fprintf(stderr, "error: failed to claim port %u\n", remote_port);
            client_disconnect(client);
            config_free_client(cfg);
            return 1;
        }
        printf("claimed: %u -> %u\n", remote_port, local_port);
    }
    
    printf("\nPort claims successful!\n");
    printf("Note: Run server in another terminal to handle forwarding:\n");
    printf("  ./build/srp serve &\n");
    
    client_disconnect(client);
    config_free_client(cfg);
    return 0;
}

static int cmd_serve(int argc, char **argv) {
    (void)argc;
    (void)argv;
    
    ServerConfig *cfg = config_parse_server(SERVER_CONFIG_FILE);
    if (!cfg) {
        fprintf(stderr, "error: failed to load server config\n");
        return 1;
    }
    
    LoginStore *store = loginstore_new();
    if (!loginstore_load(store, LOGINS_FILE)) {
        fprintf(stderr, "note: creating new logins file\n");
    }
    
    int result = server_run(cfg, store);
    
    loginstore_free(store);
    config_free_server(cfg);
    return result;
}

static void print_usage(const char *progname) {
    printf("SRP - Small Reverse Proxy\n\n");
    printf("Usage:\n");
    printf("  %s register <username> <password>\n", progname);
    printf("  %s deletelogin <username> <password>\n", progname);
    printf("  %s claim <port>\n", progname);
    printf("  %s unclaim <username> <password>\n", progname);
    printf("  %s forward\n", progname);
    printf("  %s serve\n", progname);
    printf("\n");
    printf("Config files:\n");
    printf("  srps.conf     - Server configuration\n");
    printf("  forwards.conf - Client port forwarding configuration\n");
    printf("  logins.conf   - User credentials (auto-managed)\n");
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *cmd = argv[1];
    
    if (strcmp(cmd, "register") == 0) {
        return cmd_register(argc, argv);
    } else if (strcmp(cmd, "deletelogin") == 0) {
        return cmd_deletelogin(argc, argv);
    } else if (strcmp(cmd, "claim") == 0) {
        return cmd_claim(argc, argv);
    } else if (strcmp(cmd, "unclaim") == 0) {
        return cmd_unclaim(argc, argv);
    } else if (strcmp(cmd, "forward") == 0) {
        return cmd_forward(argc, argv);
    } else if (strcmp(cmd, "serve") == 0) {
        return cmd_serve(argc, argv);
    } else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0) {
        print_usage(argv[0]);
        return 0;
    } else {
        fprintf(stderr, "error: unknown command '%s'\n", cmd);
        print_usage(argv[0]);
        return 1;
    }
}
