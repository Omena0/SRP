#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} String;

typedef struct {
    const char *key;
    void *value;
} HashEntry;

typedef struct {
    HashEntry *entries;
    size_t cap;
    size_t len;
} HashMap;

/* String utilities */
String string_new(size_t cap);
void string_free(String *s);
void string_append(String *s, const char *data, size_t len);
void string_append_cstr(String *s, const char *cstr);
char *string_cstr(String *s);
String string_from_cstr(const char *cstr);

/* HashMap utilities */
HashMap *hashmap_new(size_t cap);
void hashmap_free(HashMap *map);
void hashmap_set(HashMap *map, const char *key, void *value);
void *hashmap_get(HashMap *map, const char *key);
bool hashmap_contains(HashMap *map, const char *key);
void hashmap_remove(HashMap *map, const char *key);

/* File utilities */
char *read_file(const char *path, size_t *out_len);
bool write_file(const char *path, const char *data, size_t len);
bool file_exists(const char *path);

/* String parsing */
char **split_string(const char *str, char delim, size_t *out_count);
void free_split_string(char **parts, size_t count);
char *trim_string(const char *str);
bool parse_addr(const char *addr, char *out_host, size_t host_len, uint16_t *out_port);
uint16_t parse_port(const char *str);

/* Memory utilities */
void *xmalloc(size_t size);
void *xcalloc(size_t count, size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *str);

#endif
