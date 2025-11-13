#ifndef SERVER_H
#define SERVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include "credentials.h"
#include "config.h"

typedef struct {
    int socket_fd;
    char username[256];
    bool authenticated;
} ServerClient;

/* Protocol commands (newline-delimited) */
#define CMD_AUTH "AUTH"
#define CMD_CLAIM "CLAIM"
#define CMD_UNCLAIM "UNCLAIM"
#define CMD_LIST "LIST"
#define CMD_QUIT "QUIT"

/* Response codes */
#define RESP_OK "OK"
#define RESP_ERR "ERR"

int server_run(ServerConfig *cfg, LoginStore *store);

#endif
