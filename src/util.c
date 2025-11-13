#include "util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

/* ============== Memory utilities ============== */

void *xmalloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr && size > 0) {
        fprintf(stderr, "fatal: malloc failed\n");
        exit(1);
    }
    return ptr;
}

void *xcalloc(size_t count, size_t size) {
    void *ptr = calloc(count, size);
    if (!ptr && (count * size) > 0) {
        fprintf(stderr, "fatal: calloc failed\n");
        exit(1);
    }
    return ptr;
}

void *xrealloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size > 0) {
        fprintf(stderr, "fatal: realloc failed\n");
        exit(1);
    }
    return new_ptr;
}

char *xstrdup(const char *str) {
    if (!str)
        return NULL;
    size_t len = strlen(str) + 1;
    char *dup = xmalloc(len);
    memcpy(dup, str, len);
    return dup;
}

/* ============== String utilities ============== */

String string_new(size_t cap) {
    if (cap == 0)
        cap = 32;
    return (String){
        .data = xmalloc(cap),
        .len = 0,
        .cap = cap,
    };
}

void string_free(String *s) {
    if (s && s->data) {
        free(s->data);
        s->data = NULL;
        s->len = 0;
        s->cap = 0;
    }
}

void string_append(String *s, const char *data, size_t len) {
    if (!s || !data || len == 0)
        return;
    
    while (s->len + len >= s->cap) {
        s->cap *= 2;
        s->data = xrealloc(s->data, s->cap);
    }
    
    memcpy(s->data + s->len, data, len);
    s->len += len;
}

void string_append_cstr(String *s, const char *cstr) {
    if (cstr)
        string_append(s, cstr, strlen(cstr));
}

char *string_cstr(String *s) {
    if (!s || !s->data)
        return NULL;
    
    if (s->len >= s->cap) {
        s->cap = s->len + 1;
        s->data = xrealloc(s->data, s->cap);
    }
    
    s->data[s->len] = '\0';
    return s->data;
}

String string_from_cstr(const char *cstr) {
    if (!cstr)
        return string_new(0);
    
    String s = string_new(strlen(cstr) + 1);
    string_append_cstr(&s, cstr);
    return s;
}

/* ============== HashMap utilities ============== */

static size_t hash_djb2(const char *str) {
    size_t hash = 5381;
    int c;
    while ((c = (unsigned char)*str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

HashMap *hashmap_new(size_t cap) {
    if (cap == 0)
        cap = 16;
    
    HashMap *map = xmalloc(sizeof(HashMap));
    map->entries = xcalloc(cap, sizeof(HashEntry));
    map->cap = cap;
    map->len = 0;
    return map;
}

void hashmap_free(HashMap *map) {
    if (!map)
        return;
    
    for (size_t i = 0; i < map->cap; i++) {
        if (map->entries[i].key) {
            free((void *)map->entries[i].key);
        }
    }
    free(map->entries);
    free(map);
}

void hashmap_set(HashMap *map, const char *key, void *value) {
    if (!map || !key)
        return;
    
    /* Simple linear probing hash table */
    size_t idx = hash_djb2(key) % map->cap;
    
    for (size_t i = 0; i < map->cap; i++) {
        size_t pos = (idx + i) % map->cap;
        
        if (!map->entries[pos].key) {
            map->entries[pos].key = xstrdup(key);
            map->entries[pos].value = value;
            map->len++;
            return;
        }
        
        if (strcmp(map->entries[pos].key, key) == 0) {
            map->entries[pos].value = value;
            return;
        }
    }
    
    /* Rehash if no space found (shouldn't happen) */
    fprintf(stderr, "warning: hashmap full, cannot insert\n");
}

void *hashmap_get(HashMap *map, const char *key) {
    if (!map || !key)
        return NULL;
    
    size_t idx = hash_djb2(key) % map->cap;
    
    for (size_t i = 0; i < map->cap; i++) {
        size_t pos = (idx + i) % map->cap;
        
        if (!map->entries[pos].key)
            return NULL;
        
        if (strcmp(map->entries[pos].key, key) == 0)
            return map->entries[pos].value;
    }
    
    return NULL;
}

bool hashmap_contains(HashMap *map, const char *key) {
    return hashmap_get(map, key) != NULL;
}

void hashmap_remove(HashMap *map, const char *key) {
    if (!map || !key)
        return;
    
    size_t idx = hash_djb2(key) % map->cap;
    
    for (size_t i = 0; i < map->cap; i++) {
        size_t pos = (idx + i) % map->cap;
        
        if (!map->entries[pos].key)
            return;
        
        if (strcmp(map->entries[pos].key, key) == 0) {
            free((void *)map->entries[pos].key);
            map->entries[pos].key = NULL;
            map->entries[pos].value = NULL;
            map->len--;
            return;
        }
    }
}

/* ============== File utilities ============== */

char *read_file(const char *path, size_t *out_len) {
    if (!path)
        return NULL;
    
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    
    char *data = xmalloc(size + 1);
    size_t read = fread(data, 1, size, f);
    fclose(f);
    
    if ((long)read != size) {
        free(data);
        return NULL;
    }
    
    data[size] = '\0';
    if (out_len)
        *out_len = size;
    
    return data;
}

bool write_file(const char *path, const char *data, size_t len) {
    if (!path || !data)
        return false;
    
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    
    size_t written = fwrite(data, 1, len, f);
    fclose(f);
    
    return written == len;
}

bool file_exists(const char *path) {
    if (!path)
        return false;
    
    FILE *f = fopen(path, "r");
    if (f) {
        fclose(f);
        return true;
    }
    return false;
}

/* ============== String parsing ============== */

char **split_string(const char *str, char delim, size_t *out_count) {
    if (!str) {
        if (out_count) *out_count = 0;
        return NULL;
    }
    
    size_t cap = 10;
    size_t len = 0;
    char **parts = xmalloc(cap * sizeof(char *));
    
    const char *start = str;
    const char *end = str;
    
    while (*end) {
        if (*end == delim) {
            size_t part_len = end - start;
            char *part = xmalloc(part_len + 1);
            memcpy(part, start, part_len);
            part[part_len] = '\0';
            
            if (len >= cap) {
                cap *= 2;
                parts = xrealloc(parts, cap * sizeof(char *));
            }
            parts[len++] = part;
            
            start = end + 1;
        }
        end++;
    }
    
    /* Last part */
    size_t part_len = end - start;
    if (part_len > 0) {
        char *part = xmalloc(part_len + 1);
        memcpy(part, start, part_len);
        part[part_len] = '\0';
        
        if (len >= cap) {
            cap *= 2;
            parts = xrealloc(parts, cap * sizeof(char *));
        }
        parts[len++] = part;
    }
    
    if (out_count)
        *out_count = len;
    
    return parts;
}

void free_split_string(char **parts, size_t count) {
    if (!parts)
        return;
    
    for (size_t i = 0; i < count; i++)
        free(parts[i]);
    
    free(parts);
}

char *trim_string(const char *str) {
    if (!str)
        return xstrdup("");
    
    while (isspace((unsigned char)*str))
        str++;
    
    const char *end = str + strlen(str);
    while (end > str && isspace((unsigned char)*(end - 1)))
        end--;
    
    size_t len = end - str;
    char *trimmed = xmalloc(len + 1);
    memcpy(trimmed, str, len);
    trimmed[len] = '\0';
    
    return trimmed;
}

bool parse_addr(const char *addr, char *out_host, size_t host_len, uint16_t *out_port) {
    if (!addr || !out_host || !out_port)
        return false;
    
    const char *colon = strrchr(addr, ':');
    if (!colon)
        return false;
    
    size_t host_size = colon - addr;
    if (host_size == 0 || host_size >= host_len)
        return false;
    
    memcpy(out_host, addr, host_size);
    out_host[host_size] = '\0';
    
    *out_port = parse_port(colon + 1);
    return *out_port > 0;
}

uint16_t parse_port(const char *str) {
    if (!str)
        return 0;
    
    char *end;
    long port = strtol(str, &end, 10);
    
    if (*end != '\0' || port < 1 || port > 65535)
        return 0;
    
    return (uint16_t)port;
}
