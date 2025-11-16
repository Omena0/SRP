#include "platform.h"
#include "util.h"
#include "config.h"
#include "credentials.h"
#include "protocol.h"
#include "server.h"
#include "client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <malloc.h>  /* For mallopt */
#endif

static void print_usage(const char* prog) {
    printf("SRP - Small Reverse Proxy\n\n");
    printf("Usage:\n");
    printf("  %s serve [config]              Start server (default: srps.conf)\n", prog);
    printf("  %s forward [config]            Start agent (default: forwards.conf)\n", prog);
    printf("  %s register <username> <password>\n", prog);
    printf("  %s deletelogin <username>\n", prog);
    printf("  %s claim <port> [config]       Claim a port\n", prog);
    printf("  %s unclaim <port> [config]     Unclaim a port\n", prog);
    printf("  %s list [config]               List claimed ports\n", prog);
    printf("\n");
}

static int cmd_register(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: register <username> <password>\n");
        return 1;
    }
    
    const char* username = argv[0];
    const char* password = argv[1];
    
    if (strlen(username) == 0 || strlen(username) >= MAX_USERNAME_LEN) {
        fprintf(stderr, "Invalid username length\n");
        return 1;
    }
    
    if (strlen(password) == 0 || strlen(password) >= MAX_PASSWORD_LEN) {
        fprintf(stderr, "Invalid password length\n");
        return 1;
    }
    
    /* Load agent config to get server address */
    agent_config_t config;
    if (config_load_agent(DEFAULT_AGENT_CONFIG, &config) != 0) {
        fprintf(stderr, "Failed to load agent config (%s)\n", DEFAULT_AGENT_CONFIG);
        return 1;
    }
    
    /* Connect to server */
    socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET_VALUE) {
        fprintf(stderr, "Failed to create socket: %d\n", socket_errno);
        config_free_agent(&config);
        return 1;
    }
    
    struct sockaddr_in addr;
    if (resolve_address(config.server_host, config.server_port, &addr) != 0) {
        fprintf(stderr, "Failed to resolve server address: %s:%u\n", config.server_host, config.server_port);
        socket_close(sock);
        config_free_agent(&config);
        return 1;
    }
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to connect to server: %d\n", socket_errno);
        socket_close(sock);
        config_free_agent(&config);
        return 1;
    }
    
    printf("Connected to server %s:%u\n", config.server_host, config.server_port);
    config_free_agent(&config);
    
    /* Send REGISTER message */
    message_t* reg_msg = message_create_register(username, password);
    if (!reg_msg) {
        fprintf(stderr, "Failed to create REGISTER message\n");
        socket_close(sock);
        return 1;
    }
    
    if (message_send(sock, reg_msg) != 0) {
        fprintf(stderr, "Failed to send REGISTER message\n");
        message_free(reg_msg);
        socket_close(sock);
        return 1;
    }
    message_free(reg_msg);
    
    /* Receive response */
    message_t* resp = message_receive(sock);
    if (!resp) {
        fprintf(stderr, "Failed to receive response from server\n");
        socket_close(sock);
        return 1;
    }
    
    if (resp->type == MSG_OK) {
        printf("User registered successfully: %s\n", username);
        message_free(resp);
        socket_close(sock);
        return 0;
    } else if (resp->type == MSG_ERR) {
        error_payload_t err;
        message_parse_error(resp, &err);
        fprintf(stderr, "Registration failed: %s\n", err.error);
        message_free(resp);
        socket_close(sock);
        return 1;
    } else {
        fprintf(stderr, "Unexpected response from server: 0x%02x\n", resp->type);
        message_free(resp);
        socket_close(sock);
        return 1;
    }
}

static int cmd_deletelogin(int argc, char** argv) {
    if (argc < 1) {
        fprintf(stderr, "Usage: deletelogin <username>\n");
        return 1;
    }
    
    const char* username = argv[0];
    
    login_store_t* store = login_store_create("logins.conf");
    login_store_load(store);
    
    if (login_store_remove_user(store, username) == 0) {
        printf("User deleted successfully: %s\n", username);
        login_store_free(store);
        return 0;
    } else {
        fprintf(stderr, "Failed to delete user\n");
        login_store_free(store);
        return 1;
    }
}

static int cmd_serve(int argc, char** argv) {
    const char* config_path = argc > 0 ? argv[0] : DEFAULT_SERVER_CONFIG;
    
    log_info("Starting server with config: %s", config_path);
    return server_run(config_path);
}

static int cmd_forward(int argc, char** argv) {
    const char* config_path = argc > 0 ? argv[0] : DEFAULT_AGENT_CONFIG;
    
    log_info("Starting agent with config: %s", config_path);
    return client_run(config_path);
}

static int cmd_claim(int argc, char** argv) {
    if (argc < 1) {
        fprintf(stderr, "Usage: claim <port> [config]\n");
        return 1;
    }
    
    uint16_t port;
    if (str_to_uint16(argv[0], &port) != 0) {
        fprintf(stderr, "Invalid port number\n");
        return 1;
    }
    
    const char* config_path = argc > 1 ? argv[1] : DEFAULT_AGENT_CONFIG;
    
    return client_claim_port(config_path, port);
}

static int cmd_unclaim(int argc, char** argv) {
    if (argc < 1) {
        fprintf(stderr, "Usage: unclaim <port> [config]\n");
        return 1;
    }
    
    uint16_t port;
    if (str_to_uint16(argv[0], &port) != 0) {
        fprintf(stderr, "Invalid port number\n");
        return 1;
    }
    
    const char* config_path = argc > 1 ? argv[1] : DEFAULT_AGENT_CONFIG;
    
    return client_unclaim_port(config_path, port);
}

static int cmd_list(int argc, char** argv) {
    const char* config_path = argc > 0 ? argv[0] : DEFAULT_AGENT_CONFIG;
    
    return client_list_ports(config_path);
}

int main(int argc, char** argv) {
#ifndef _WIN32
    /* Tune malloc BEFORE any allocations to minimize virtual memory usage */
    mallopt(M_ARENA_MAX, 1);           /* Only 1 arena - we don't need per-thread arenas */
    mallopt(M_MMAP_THRESHOLD, 64*1024); /* Use mmap for allocations >64KB */
    mallopt(M_TRIM_THRESHOLD, 128*1024); /* Return memory to OS when >128KB is free */
    mallopt(M_TOP_PAD, 64*1024);        /* Reduce heap padding */
#endif

    /* Initialize platform */
    if (platform_init() != 0) {
        fprintf(stderr, "Failed to initialize platform\n");
        return 1;
    }
    
    /* Initialize logging */
    log_init(NULL); /* Log to stderr by default */
    
    if (argc < 2) {
        print_usage(argv[0]);
        platform_cleanup();
        return 1;
    }
    
    const char* cmd = argv[1];
    int ret = 0;
    
    if (strcmp(cmd, "serve") == 0) {
        ret = cmd_serve(argc - 2, argv + 2);
    }
    else if (strcmp(cmd, "forward") == 0) {
        ret = cmd_forward(argc - 2, argv + 2);
    }
    else if (strcmp(cmd, "register") == 0) {
        ret = cmd_register(argc - 2, argv + 2);
    }
    else if (strcmp(cmd, "deletelogin") == 0) {
        ret = cmd_deletelogin(argc - 2, argv + 2);
    }
    else if (strcmp(cmd, "claim") == 0) {
        ret = cmd_claim(argc - 2, argv + 2);
    }
    else if (strcmp(cmd, "unclaim") == 0) {
        ret = cmd_unclaim(argc - 2, argv + 2);
    }
    else if (strcmp(cmd, "list") == 0) {
        ret = cmd_list(argc - 2, argv + 2);
    }
    else {
        fprintf(stderr, "Unknown command: %s\n\n", cmd);
        print_usage(argv[0]);
        ret = 1;
    }
    
    log_close();
    platform_cleanup();
    
    return ret;
}
