#ifndef SERVER_H
#define SERVER_H

#include "platform.h"
#include "config.h"
#include "credentials.h"
#include <stdint.h>

/* Start the server */
int server_run(const char* config_path);

#endif /* SERVER_H */
