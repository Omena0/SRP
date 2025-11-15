#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#include <stdint.h>

/* User account */
typedef struct {
    char username[64];
    char password_hash[65]; /* SHA-256 hex string */
    uint64_t created_at;
    uint16_t* claimed_ports;
    int claimed_count;
} user_t;

/* Login store */
typedef struct {
    user_t* users;
    int user_count;
    int capacity;
    char* file_path;
    uint64_t last_modified;
} login_store_t;

/* Store management */
login_store_t* login_store_create(const char* file_path);
void login_store_free(login_store_t* store);
int login_store_load(login_store_t* store);
int login_store_save(login_store_t* store);
int login_store_reload_if_modified(login_store_t* store);

/* User operations */
user_t* login_store_find_user(login_store_t* store, const char* username);
int login_store_add_user(login_store_t* store, const char* username, const char* password);
int login_store_remove_user(login_store_t* store, const char* username);
int login_store_verify_password(login_store_t* store, const char* username, const char* password);

/* Port claims */
int login_store_claim_port(login_store_t* store, const char* username, uint16_t port);
int login_store_unclaim_port(login_store_t* store, const char* username, uint16_t port);
int login_store_has_claimed(login_store_t* store, const char* username, uint16_t port);
const char* login_store_port_owner(login_store_t* store, uint16_t port);

/* Password hashing */
void sha256_hash(const char* input, char* output);

#endif /* CREDENTIALS_H */
