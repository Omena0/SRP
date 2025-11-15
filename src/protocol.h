#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

/* Binary protocol for SRP
 * 
 * All messages have the format:
 *   [type:1byte][length:4bytes][payload:N bytes]
 * 
 * Length is payload length in bytes (big-endian uint32_t)
 */

/* Message types */
#define MSG_AUTH        0x01
#define MSG_CLAIM       0x02
#define MSG_UNCLAIM     0x03
#define MSG_LIST        0x04
#define MSG_DATA        0x05
#define MSG_OK          0x06
#define MSG_ERR         0x07
#define MSG_TUNNEL_OPEN 0x08
#define MSG_TUNNEL_CLOSE 0x09
#define MSG_FORWARD     0x0A
#define MSG_PING        0x0B
#define MSG_PONG        0x0C

/* Message header size: type(1) + length(4) */
#define MSG_HEADER_SIZE 5

/* Maximum message sizes */
#define MAX_USERNAME_LEN 64
#define MAX_PASSWORD_LEN 128
#define MAX_ERROR_MSG_LEN 256
#define MAX_PAYLOAD_SIZE (512 * 1024) /* 512KB max payload for chunksending heavy loads */

/* Protocol version */
#define PROTOCOL_VERSION 1

/* Message structures */

typedef struct {
    uint8_t type;
    uint32_t length;
    uint8_t* payload;
} message_t;

/* AUTH message payload: <username>\0<password> */
typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} auth_payload_t;

/* CLAIM/UNCLAIM message payload: <port:uint16_t> */
typedef struct {
    uint16_t port;
} port_payload_t;

/* LIST response payload: <count:uint16_t><port1:uint16_t><port2:uint16_t>... */
typedef struct {
    uint16_t count;
    uint16_t* ports;
} list_payload_t;

/* DATA message payload: <tunnel_id:uint32_t><data> */
typedef struct {
    uint32_t tunnel_id;
    uint32_t data_len;
    uint8_t* data;
} data_payload_t;

/* TUNNEL_OPEN message payload: <tunnel_id:uint32_t><port:uint16_t><data_port:uint16_t> */
typedef struct {
    uint32_t tunnel_id;
    uint16_t port;
    uint16_t data_port;
} tunnel_open_payload_t;

/* TUNNEL_CLOSE message payload: <tunnel_id:uint32_t> */
typedef struct {
    uint32_t tunnel_id;
} tunnel_close_payload_t;

/* ERR message payload: <error_message> (null-terminated string) */
typedef struct {
    char error[MAX_ERROR_MSG_LEN];
} error_payload_t;

/* Protocol functions */

/* Message creation */
message_t* message_create(uint8_t type, uint32_t length);
void message_free(message_t* msg);

/* AUTH */
message_t* message_create_auth(const char* username, const char* password);
int message_parse_auth(const message_t* msg, auth_payload_t* auth);

/* CLAIM/UNCLAIM */
message_t* message_create_port(uint8_t type, uint16_t port);
int message_parse_port(const message_t* msg, port_payload_t* payload);

/* LIST */
message_t* message_create_list_request(void);
message_t* message_create_list_response(uint16_t* ports, uint16_t count);
int message_parse_list(const message_t* msg, list_payload_t* list);

/* DATA */
message_t* message_create_data(uint32_t tunnel_id, const uint8_t* data, uint32_t data_len);
int message_parse_data(const message_t* msg, data_payload_t* data);

/* TUNNEL_OPEN */
message_t* message_create_tunnel_open(uint32_t tunnel_id, uint16_t port, uint16_t data_port);
int message_parse_tunnel_open(const message_t* msg, tunnel_open_payload_t* payload);

/* TUNNEL_CLOSE */
message_t* message_create_tunnel_close(uint32_t tunnel_id);
int message_parse_tunnel_close(const message_t* msg, tunnel_close_payload_t* payload);

/* OK */
message_t* message_create_ok(void);

/* ERR */
message_t* message_create_error(const char* error);
int message_parse_error(const message_t* msg, error_payload_t* error);

/* PING/PONG - application-level keepalive */
message_t* message_create_ping(void);
message_t* message_create_pong(void);

/* Send/Receive */
int message_send(int sock, const message_t* msg);
message_t* message_receive(int sock);
message_t* message_receive_nonblocking(int sock, int* would_block);

/* Utility */
void message_print(const message_t* msg); /* For debugging */

/* Endianness conversion - use system functions if available, otherwise implement */
#ifdef _WIN32
    /* Windows already includes htonl/ntohl in winsock2.h */
    #define htons_portable(x) htons(x)
    #define ntohs_portable(x) ntohs(x)
    #define htonl_portable(x) htonl(x)
    #define ntohl_portable(x) ntohl(x)
#else
    /* POSIX systems also have these in netinet/in.h or arpa/inet.h */
    #include <arpa/inet.h>
    #define htons_portable(x) htons(x)
    #define ntohs_portable(x) ntohs(x)
    #define htonl_portable(x) htonl(x)
    #define ntohl_portable(x) ntohl(x)
#endif

#endif /* PROTOCOL_H */
