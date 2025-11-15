#include "credentials.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Simple SHA-256 implementation */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_hash(const char* input, char* output) {
    uint32_t h[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    size_t len = strlen(input);
    size_t total_len = len + 1 + 8; /* +1 for 0x80, +8 for length */
    size_t padded_len = ((total_len + 63) / 64) * 64;
    
    uint8_t* padded = (uint8_t*)xcalloc(padded_len, 1);
    memcpy(padded, input, len);
    padded[len] = 0x80;
    
    uint64_t bit_len = len * 8;
    for (int i = 0; i < 8; i++) {
        padded[padded_len - 1 - i] = (bit_len >> (i * 8)) & 0xFF;
    }
    
    /* Process chunks */
    for (size_t chunk = 0; chunk < padded_len; chunk += 64) {
        uint32_t w[64];
        
        /* Prepare message schedule */
        for (int i = 0; i < 16; i++) {
            w[i] = (padded[chunk + i * 4] << 24) |
                   (padded[chunk + i * 4 + 1] << 16) |
                   (padded[chunk + i * 4 + 2] << 8) |
                   (padded[chunk + i * 4 + 3]);
        }
        for (int i = 16; i < 64; i++) {
            w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
        }
        
        /* Working variables */
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];
        
        /* Main loop */
        for (int i = 0; i < 64; i++) {
            uint32_t t1 = h_val + EP1(e) + CH(e, f, g) + k[i] + w[i];
            uint32_t t2 = EP0(a) + MAJ(a, b, c);
            h_val = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        
        /* Update hash */
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
    }
    
    xfree(padded);
    
    /* Convert to hex string */
    for (int i = 0; i < 8; i++) {
        sprintf(output + i * 8, "%08x", h[i]);
    }
    output[64] = '\0';
}

/* ========== Login Store ========== */

login_store_t* login_store_create(const char* file_path) {
    login_store_t* store = (login_store_t*)xmalloc(sizeof(login_store_t));
    store->users = NULL;
    store->user_count = 0;
    store->capacity = 0;
    store->file_path = str_dup(file_path);
    store->last_modified = 0;
    return store;
}

void login_store_free(login_store_t* store) {
    if (!store) return;
    
    for (int i = 0; i < store->user_count; i++) {
        if (store->users[i].claimed_ports) {
            xfree(store->users[i].claimed_ports);
        }
    }
    
    xfree(store->users);
    xfree(store->file_path);
    xfree(store);
}

static uint64_t get_file_mtime(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
#ifdef _WIN32
    return (uint64_t)st.st_mtime;
#else
    return (uint64_t)st.st_mtime;
#endif
}

int login_store_load(login_store_t* store) {
    if (!store) return -1;
    
    /* Clear existing users */
    for (int i = 0; i < store->user_count; i++) {
        if (store->users[i].claimed_ports) {
            xfree(store->users[i].claimed_ports);
        }
    }
    store->user_count = 0;
    
    FILE* f = fopen(store->file_path, "r");
    if (!f) {
        log_warn("Login store file not found, creating new: %s", store->file_path);
        return 0; /* Empty store */
    }
    
    store->last_modified = get_file_mtime(store->file_path);
    
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        char* trimmed = str_trim(line);
        if (trimmed[0] == '\0' || trimmed[0] == '#') continue;
        
        /* Format: username:password_hash:timestamp|port1,port2,port3 */
        char* colon1 = strchr(trimmed, ':');
        if (!colon1) continue;
        *colon1 = '\0';
        
        char* colon2 = strchr(colon1 + 1, ':');
        if (!colon2) continue;
        *colon2 = '\0';
        
        char* pipe = strchr(colon2 + 1, '|');
        
        /* Expand capacity */
        if (store->user_count >= store->capacity) {
            store->capacity = store->capacity == 0 ? 16 : store->capacity * 2;
            store->users = (user_t*)xrealloc(store->users, store->capacity * sizeof(user_t));
        }
        
        user_t* user = &store->users[store->user_count];
        strncpy(user->username, trimmed, sizeof(user->username) - 1);
        strncpy(user->password_hash, colon1 + 1, sizeof(user->password_hash) - 1);
        
        uint64_t ts;
        if (sscanf(colon2 + 1, "%llu", (unsigned long long*)&ts) == 1) {
            user->created_at = ts;
        } else {
            user->created_at = get_timestamp();
        }
        
        /* Parse claimed ports */
        user->claimed_ports = NULL;
        user->claimed_count = 0;
        
        if (pipe) {
            parse_port_list(pipe + 1, &user->claimed_ports, &user->claimed_count);
        }
        
        store->user_count++;
    }
    
    fclose(f);
    log_info("Loaded %d users from login store", store->user_count);
    return 0;
}

int login_store_save(login_store_t* store) {
    if (!store) return -1;
    
    FILE* f = fopen(store->file_path, "w");
    if (!f) {
        log_error("Failed to save login store: %s", store->file_path);
        return -1;
    }
    
    for (int i = 0; i < store->user_count; i++) {
        user_t* user = &store->users[i];
        fprintf(f, "%s:%s:%llu", user->username, user->password_hash,
                (unsigned long long)user->created_at);
        
        if (user->claimed_count > 0) {
            fprintf(f, "|");
            for (int j = 0; j < user->claimed_count; j++) {
                fprintf(f, "%u", user->claimed_ports[j]);
                if (j < user->claimed_count - 1) fprintf(f, ",");
            }
        }
        
        fprintf(f, "\n");
    }
    
    fclose(f);
    store->last_modified = get_file_mtime(store->file_path);
    return 0;
}

int login_store_reload_if_modified(login_store_t* store) {
    if (!store) return -1;
    
    uint64_t mtime = get_file_mtime(store->file_path);
    if (mtime > store->last_modified) {
        log_info("Login store modified, reloading");
        return login_store_load(store);
    }
    
    return 0;
}

user_t* login_store_find_user(login_store_t* store, const char* username) {
    if (!store || !username) return NULL;
    
    for (int i = 0; i < store->user_count; i++) {
        if (strcmp(store->users[i].username, username) == 0) {
            return &store->users[i];
        }
    }
    
    return NULL;
}

int login_store_add_user(login_store_t* store, const char* username, const char* password) {
    if (!store || !username || !password) return -1;
    
    /* Check if user exists */
    if (login_store_find_user(store, username)) {
        log_error("User already exists: %s", username);
        return -1;
    }
    
    /* Expand capacity */
    if (store->user_count >= store->capacity) {
        store->capacity = store->capacity == 0 ? 16 : store->capacity * 2;
        store->users = (user_t*)xrealloc(store->users, store->capacity * sizeof(user_t));
    }
    
    user_t* user = &store->users[store->user_count];
    strncpy(user->username, username, sizeof(user->username) - 1);
    sha256_hash(password, user->password_hash);
    user->created_at = get_timestamp();
    user->claimed_ports = NULL;
    user->claimed_count = 0;
    
    store->user_count++;
    return login_store_save(store);
}

int login_store_remove_user(login_store_t* store, const char* username) {
    if (!store || !username) return -1;
    
    for (int i = 0; i < store->user_count; i++) {
        if (strcmp(store->users[i].username, username) == 0) {
            if (store->users[i].claimed_ports) {
                xfree(store->users[i].claimed_ports);
            }
            
            /* Shift remaining users */
            memmove(&store->users[i], &store->users[i + 1],
                    (store->user_count - i - 1) * sizeof(user_t));
            store->user_count--;
            
            return login_store_save(store);
        }
    }
    
    log_error("User not found: %s", username);
    return -1;
}

int login_store_verify_password(login_store_t* store, const char* username, const char* password) {
    if (!store || !username || !password) return 0;
    
    user_t* user = login_store_find_user(store, username);
    if (!user) return 0;
    
    char hash[65];
    sha256_hash(password, hash);
    return strcmp(user->password_hash, hash) == 0;
}

int login_store_claim_port(login_store_t* store, const char* username, uint16_t port) {
    if (!store || !username) return -1;
    
    user_t* user = login_store_find_user(store, username);
    if (!user) return -1;
    
    /* Check if already claimed */
    for (int i = 0; i < user->claimed_count; i++) {
        if (user->claimed_ports[i] == port) return 0; /* Already claimed */
    }
    
    /* Add port */
    user->claimed_ports = (uint16_t*)xrealloc(user->claimed_ports,
                                               (user->claimed_count + 1) * sizeof(uint16_t));
    user->claimed_ports[user->claimed_count] = port;
    user->claimed_count++;
    
    return login_store_save(store);
}

int login_store_unclaim_port(login_store_t* store, const char* username, uint16_t port) {
    if (!store || !username) return -1;
    
    user_t* user = login_store_find_user(store, username);
    if (!user) return -1;
    
    /* Find and remove port */
    for (int i = 0; i < user->claimed_count; i++) {
        if (user->claimed_ports[i] == port) {
            memmove(&user->claimed_ports[i], &user->claimed_ports[i + 1],
                    (user->claimed_count - i - 1) * sizeof(uint16_t));
            user->claimed_count--;
            return login_store_save(store);
        }
    }
    
    return -1; /* Port not claimed */
}

int login_store_has_claimed(login_store_t* store, const char* username, uint16_t port) {
    if (!store || !username) return 0;
    
    user_t* user = login_store_find_user(store, username);
    if (!user) return 0;
    
    for (int i = 0; i < user->claimed_count; i++) {
        if (user->claimed_ports[i] == port) return 1;
    }
    
    return 0;
}

const char* login_store_port_owner(login_store_t* store, uint16_t port) {
    if (!store) return NULL;
    
    for (int i = 0; i < store->user_count; i++) {
        user_t* user = &store->users[i];
        for (int j = 0; j < user->claimed_count; j++) {
            if (user->claimed_ports[j] == port) {
                return user->username;
            }
        }
    }
    
    return NULL;
}
