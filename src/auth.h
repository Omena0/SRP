#ifndef AUTH_H
#define AUTH_H

#include <stdbool.h>

/* Simple password hashing using SHA256 - returns hex string (malloc'd) */
char *hash_password(const char *password);

/* Verify password against hash */
bool verify_password(const char *password, const char *hash);

#endif
