#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>
#include <stdint.h>

/* Forward declarations */
struct sockaddr_in;

/* String utilities */
char* str_trim(char* str);
char* str_dup(const char* str);
int str_split(const char* str, char delim, char*** out, int* count);
void str_free_split(char** arr, int count);
int str_to_int(const char* str, int* out);
int str_to_uint16(const char* str, uint16_t* out);
int parse_port_list(const char* str, uint16_t** ports, int* count);

/* Memory utilities */
void* xmalloc(size_t size);
void* xcalloc(size_t nmemb, size_t size);
void* xrealloc(void* ptr, size_t size);
void xfree(void* ptr);

/* Logging */
void log_init(const char* filename);
void log_close(void);
void log_info(const char* fmt, ...);
void log_warn(const char* fmt, ...);
void log_error(const char* fmt, ...);
void log_debug(const char* fmt, ...);

/* Time utilities */
uint64_t get_timestamp(void);
void format_timestamp(uint64_t ts, char* buf, size_t size);

/* File utilities */
int file_exists(const char* path);
long file_size(const char* path);
char* file_read_all(const char* path, size_t* size);

/* Buffer utilities */
typedef struct {
    uint8_t* data;
    size_t size;
    size_t capacity;
    size_t read_pos;
} buffer_t;

buffer_t* buffer_create(size_t initial_capacity);
void buffer_free(buffer_t* buf);
int buffer_write(buffer_t* buf, const uint8_t* data, size_t len);
int buffer_read(buffer_t* buf, uint8_t* data, size_t len);
size_t buffer_available(const buffer_t* buf);
void buffer_compact(buffer_t* buf);
void buffer_clear(buffer_t* buf);

/* Network utilities */
int parse_address(const char* addr, char* host, size_t host_len, uint16_t* port);
int resolve_address(const char* host, uint16_t port, struct sockaddr_in* addr);

#endif /* UTIL_H */
