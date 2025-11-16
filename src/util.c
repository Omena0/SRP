#include "util.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdarg.h>

#ifdef _WIN32
    #include <sys/stat.h>
#else
    #include <sys/stat.h>
    #include <sys/time.h>
#endif

/* ========== String Utilities ========== */

char* str_trim(char* str) {
    if (!str) return NULL;
    
    /* Trim leading space */
    while (isspace((unsigned char)*str)) str++;
    
    if (*str == 0) return str;
    
    /* Trim trailing space */
    char* end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    
    return str;
}

char* str_dup(const char* str) {
    if (!str) return NULL;
    size_t len = strlen(str);
    char* dup = (char*)xmalloc(len + 1);
    memcpy(dup, str, len + 1);
    return dup;
}

int str_split(const char* str, char delim, char*** out, int* count) {
    if (!str || !out || !count) return -1;
    
    /* Count delimiters */
    int n = 1;
    for (const char* p = str; *p; p++) {
        if (*p == delim) n++;
    }
    
    *out = (char**)xmalloc(n * sizeof(char*));
    *count = 0;
    
    const char* start = str;
    const char* end;
    
    while ((end = strchr(start, delim)) != NULL) {
        size_t len = end - start;
        (*out)[*count] = (char*)xmalloc(len + 1);
        memcpy((*out)[*count], start, len);
        (*out)[*count][len] = '\0';
        (*count)++;
        start = end + 1;
    }
    
    /* Last segment */
    (*out)[*count] = str_dup(start);
    (*count)++;
    
    return 0;
}

void str_free_split(char** arr, int count) {
    if (!arr) return;
    for (int i = 0; i < count; i++) {
        xfree(arr[i]);
    }
    xfree(arr);
}

int str_to_int(const char* str, int* out) {
    if (!str || !out) return -1;
    char* endptr;
    long val = strtol(str, &endptr, 10);
    if (*endptr != '\0') return -1;
    *out = (int)val;
    return 0;
}

int str_to_uint16(const char* str, uint16_t* out) {
    if (!str || !out) return -1;
    char* endptr;
    long val = strtol(str, &endptr, 10);
    if (*endptr != '\0' || val < 0 || val > 65535) return -1;
    *out = (uint16_t)val;
    return 0;
}

/* Parse comma-separated list of ports */
int parse_port_list(const char* str, uint16_t** ports, int* count) {
    if (!str || !ports || !count) return -1;
    
    /* Empty list */
    if (strlen(str) == 0) {
        *ports = NULL;
        *count = 0;
        return 0;
    }
    
    char** parts;
    int n;
    if (str_split(str, ',', &parts, &n) != 0) return -1;
    
    *ports = (uint16_t*)xmalloc(n * sizeof(uint16_t));
    *count = 0;
    
    for (int i = 0; i < n; i++) {
        uint16_t port;
        if (str_to_uint16(str_trim(parts[i]), &port) == 0) {
            (*ports)[*count] = port;
            (*count)++;
        }
    }
    
    str_free_split(parts, n);
    return 0;
}

/* ========== Memory Utilities ========== */

void* xmalloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr && size != 0) {
        log_error("Out of memory (malloc %zu bytes)", size);
        exit(1);
    }
    return ptr;
}

void* xcalloc(size_t nmemb, size_t size) {
    void* ptr = calloc(nmemb, size);
    if (!ptr && nmemb != 0 && size != 0) {
        log_error("Out of memory (calloc %zu * %zu bytes)", nmemb, size);
        exit(1);
    }
    return ptr;
}

void* xrealloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr && size != 0) {
        log_error("Out of memory (realloc %zu bytes)", size);
        exit(1);
    }
    return new_ptr;
}

void xfree(void* ptr) {
    free(ptr);
}

/* ========== Logging ========== */

static FILE* log_file = NULL;
static mutex_t log_mutex;
static int log_initialized = 0;

void log_init(const char* filename) {
    if (log_initialized) return;
    
    mutex_init(&log_mutex);
    
    if (filename) {
        log_file = fopen(filename, "a");
        if (!log_file) {
            fprintf(stderr, "Warning: Could not open log file %s\n", filename);
            log_file = stderr;
        }
    } else {
        log_file = stderr;
    }
    
    log_initialized = 1;
}

void log_close(void) {
    if (!log_initialized) return;
    
    if (log_file && log_file != stderr) {
        fclose(log_file);
    }
    
    mutex_destroy(&log_mutex);
    log_initialized = 0;
}

static void log_write(const char* level, const char* fmt, va_list args) {
    if (!log_initialized) log_init(NULL);
    
    mutex_lock(&log_mutex);
    
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    fprintf(log_file, "[%s] [%s] ", time_buf, level);
    vfprintf(log_file, fmt, args);
    fprintf(log_file, "\n");
    fflush(log_file);
    
    mutex_unlock(&log_mutex);
}

void log_info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_write("INFO", fmt, args);
    va_end(args);
}

void log_warn(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_write("WARN", fmt, args);
    va_end(args);
}

void log_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log_write("ERROR", fmt, args);
    va_end(args);
}

void log_debug(const char* fmt, ...) {
#ifdef DEBUG
    va_list args;
    va_start(args, fmt);
    log_write("DEBUG", fmt, args);
    va_end(args);
#else
    (void)fmt; /* Suppress unused parameter warning */
#endif
}

/* ========== Time Utilities ========== */

uint64_t get_timestamp(void) {
#ifdef _WIN32
    return (uint64_t)time(NULL);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec;
#endif
}

void format_timestamp(uint64_t ts, char* buf, size_t size) {
    time_t t = (time_t)ts;
    struct tm* tm_info = localtime(&t);
    strftime(buf, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/* ========== File Utilities ========== */

int file_exists(const char* path) {
    struct stat st;
    return stat(path, &st) == 0;
}

long file_size(const char* path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return (long)st.st_size;
}

char* file_read_all(const char* path, size_t* size) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (fsize < 0) {
        fclose(f);
        return NULL;
    }
    
    char* content = (char*)xmalloc(fsize + 1);
    size_t read = fread(content, 1, fsize, f);
    fclose(f);
    
    content[read] = '\0';
    if (size) *size = read;
    
    return content;
}

/* ========== Buffer Utilities ========== */

void buffer_free(buffer_t* buf) {
    if (!buf) return;
    xfree(buf->data);
    xfree(buf);
}

int buffer_write(buffer_t* buf, const uint8_t* data, size_t len) {
    if (!buf || !data) return -1;
    
    /* Ensure capacity */
    while (buf->size + len > buf->capacity) {
        buf->capacity *= 2;
        buf->data = (uint8_t*)xrealloc(buf->data, buf->capacity);
    }
    
    memcpy(buf->data + buf->size, data, len);
    buf->size += len;
    return 0;
}

int buffer_read(buffer_t* buf, uint8_t* data, size_t len) {
    if (!buf || !data) return -1;
    
    size_t available = buf->size - buf->read_pos;
    if (len > available) len = available;
    
    memcpy(data, buf->data + buf->read_pos, len);
    buf->read_pos += len;
    return (int)len;
}

size_t buffer_available(const buffer_t* buf) {
    if (!buf) return 0;
    return buf->size - buf->read_pos;
}

void buffer_compact(buffer_t* buf) {
    if (!buf || buf->read_pos == 0) return;
    
    size_t available = buf->size - buf->read_pos;
    if (available > 0) {
        memmove(buf->data, buf->data + buf->read_pos, available);
    }
    buf->size = available;
    buf->read_pos = 0;
}

void buffer_clear(buffer_t* buf) {
    if (!buf) return;
    buf->size = 0;
    buf->read_pos = 0;
}

/* ========== Network Utilities ========== */

int parse_address(const char* addr, char* host, size_t host_len, uint16_t* port) {
    if (!addr || !host || !port) return -1;
    
    /* Find colon */
    const char* colon = strchr(addr, ':');
    if (!colon) return -1;
    
    /* Extract host */
    size_t host_size = colon - addr;
    if (host_size >= host_len) return -1;
    memcpy(host, addr, host_size);
    host[host_size] = '\0';
    
    /* Extract port */
    return str_to_uint16(colon + 1, port);
}

int resolve_address(const char* host, uint16_t port, struct sockaddr_in* addr) {
    if (!host || !addr) return -1;
    
    memset(addr, 0, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    
    /* Try as IP address first */
    if (inet_pton(AF_INET, host, &addr->sin_addr) == 1) {
        return 0;
    }
    
    /* Resolve hostname */
    struct hostent* he = gethostbyname(host);
    if (!he) return -1;
    
    memcpy(&addr->sin_addr, he->h_addr_list[0], he->h_length);
    return 0;
}
