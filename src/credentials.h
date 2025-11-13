#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#include "util.h"
#include <stdint.h>

typedef struct {
    char *username;
    char *passwd_hash;
    uint64_t created_at;
    uint16_t *claimed_ports;
    size_t claimed_count;
    size_t claimed_cap;
} Login;

typedef struct {
    Login *logins;
    size_t count;
    size_t cap;
} LoginStore;

/* Initialize empty login store */
LoginStore *loginstore_new(void);

/* Free all logins and the store */
void loginstore_free(LoginStore *store);

/* Add a new login */
void loginstore_add(LoginStore *store, const char *username, const char *passwd_hash);

/* Get login by username, returns NULL if not found */
Login *loginstore_get(LoginStore *store, const char *username);

/* Remove login by username */
bool loginstore_remove(LoginStore *store, const char *username);

/* Add claimed port to login */
bool loginstore_claim_port(LoginStore *store, const char *username, uint16_t port);

/* Remove claimed port from login */
bool loginstore_unclaim_port(LoginStore *store, const char *username, uint16_t port);

/* Check if login has claimed port */
bool loginstore_has_port(LoginStore *store, const char *username, uint16_t port);

/* Load logins from file */
bool loginstore_load(LoginStore *store, const char *path);

/* Save logins to file */
bool loginstore_save(LoginStore *store, const char *path);

#endif
