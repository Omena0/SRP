#include "protocol.h"
#include "util.h"
#include "platform.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========== Message Management ========== */

message_t* message_create(uint8_t type, uint32_t length) {
    message_t* msg = (message_t*)xmalloc(sizeof(message_t));
    msg->type = type;
    msg->length = length;
    msg->payload = length > 0 ? (uint8_t*)xmalloc(length) : NULL;
    return msg;
}

void message_free(message_t* msg) {
    if (!msg) return;
    if (msg->payload) xfree(msg->payload);
    xfree(msg);
}

/* ========== Message Creation ========== */

message_t* message_create_auth(const char* username, const char* password) {
    if (!username || !password) return NULL;
    
    size_t username_len = strlen(username);
    size_t password_len = strlen(password);
    
    if (username_len >= MAX_USERNAME_LEN || password_len >= MAX_PASSWORD_LEN) {
        log_error("Username or password too long");
        return NULL;
    }
    
    uint32_t length = username_len + 1 + password_len + 1;
    message_t* msg = message_create(MSG_AUTH, length);
    
    memcpy(msg->payload, username, username_len + 1);
    memcpy(msg->payload + username_len + 1, password, password_len + 1);
    
    return msg;
}

message_t* message_create_port(uint8_t type, uint16_t port) {
    message_t* msg = message_create(type, sizeof(uint16_t));
    uint16_t net_port = htons_portable(port);
    memcpy(msg->payload, &net_port, sizeof(uint16_t));
    return msg;
}

message_t* message_create_list_request(void) {
    return message_create(MSG_LIST, 0);
}

message_t* message_create_list_response(uint16_t* ports, uint16_t count) {
    uint32_t length = sizeof(uint16_t) + count * sizeof(uint16_t);
    message_t* msg = message_create(MSG_LIST, length);
    
    uint16_t net_count = htons_portable(count);
    memcpy(msg->payload, &net_count, sizeof(uint16_t));
    
    for (int i = 0; i < count; i++) {
        uint16_t net_port = htons_portable(ports[i]);
        memcpy(msg->payload + sizeof(uint16_t) + i * sizeof(uint16_t), &net_port, sizeof(uint16_t));
    }
    
    return msg;
}

message_t* message_create_data(uint32_t tunnel_id, const uint8_t* data, uint32_t data_len) {
    if (!data && data_len > 0) return NULL;
    
    uint32_t length = sizeof(uint32_t) + data_len;
    if (length > MAX_PAYLOAD_SIZE) {
        log_error("Data payload too large: %u bytes", data_len);
        return NULL;
    }
    
    message_t* msg = message_create(MSG_DATA, length);
    
    uint32_t net_tunnel_id = htonl_portable(tunnel_id);
    memcpy(msg->payload, &net_tunnel_id, sizeof(uint32_t));
    
    if (data_len > 0) {
        memcpy(msg->payload + sizeof(uint32_t), data, data_len);
    }
    
    return msg;
}

message_t* message_create_tunnel_open(uint32_t tunnel_id, uint16_t port, uint16_t data_port) {
    message_t* msg = message_create(MSG_TUNNEL_OPEN, sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t));

    uint32_t net_tunnel_id = htonl_portable(tunnel_id);
    uint16_t net_port = htons_portable(port);
    uint16_t net_data = htons_portable(data_port);

    memcpy(msg->payload, &net_tunnel_id, sizeof(uint32_t));
    memcpy(msg->payload + sizeof(uint32_t), &net_port, sizeof(uint16_t));
    memcpy(msg->payload + sizeof(uint32_t) + sizeof(uint16_t), &net_data, sizeof(uint16_t));

    return msg;
}

message_t* message_create_tunnel_close(uint32_t tunnel_id) {
    message_t* msg = message_create(MSG_TUNNEL_CLOSE, sizeof(uint32_t));
    
    uint32_t net_tunnel_id = htonl_portable(tunnel_id);
    memcpy(msg->payload, &net_tunnel_id, sizeof(uint32_t));
    
    return msg;
}

message_t* message_create_ok(void) {
    return message_create(MSG_OK, 0);
}

message_t* message_create_error(const char* error) {
    if (!error) return NULL;
    
    size_t len = strlen(error);
    if (len >= MAX_ERROR_MSG_LEN) len = MAX_ERROR_MSG_LEN - 1;
    
    message_t* msg = message_create(MSG_ERR, len + 1);
    memcpy(msg->payload, error, len);
    msg->payload[len] = '\0';
    
    return msg;
}

message_t* message_create_ping(void) {
    return message_create(MSG_PING, 0);
}

message_t* message_create_pong(void) {
    return message_create(MSG_PONG, 0);
}

message_t* message_create_register(const char* username, const char* password) {
    /* REGISTER uses same format as AUTH: <username>\0<password> */
    if (!username || !password) return NULL;
    
    size_t username_len = strlen(username);
    size_t password_len = strlen(password);
    
    if (username_len >= MAX_USERNAME_LEN || password_len >= MAX_PASSWORD_LEN) {
        log_error("Username or password too long");
        return NULL;
    }
    
    uint32_t length = username_len + 1 + password_len + 1;
    message_t* msg = message_create(MSG_REGISTER, length);
    
    memcpy(msg->payload, username, username_len + 1);
    memcpy(msg->payload + username_len + 1, password, password_len + 1);
    
    return msg;
}

/* ========== Message Parsing ========== */

int message_parse_auth(const message_t* msg, auth_payload_t* auth) {
    if (!msg || !auth || msg->type != MSG_AUTH) return -1;
    
    const char* username = (const char*)msg->payload;
    size_t username_len = strnlen(username, msg->length);
    
    if (username_len >= msg->length || username_len >= MAX_USERNAME_LEN) return -1;
    
    const char* password = username + username_len + 1;
    size_t password_len = strnlen(password, msg->length - username_len - 1);
    
    if (password_len >= MAX_PASSWORD_LEN) return -1;
    
    strncpy(auth->username, username, MAX_USERNAME_LEN - 1);
    strncpy(auth->password, password, MAX_PASSWORD_LEN - 1);
    auth->username[MAX_USERNAME_LEN - 1] = '\0';
    auth->password[MAX_PASSWORD_LEN - 1] = '\0';
    
    return 0;
}

int message_parse_register(const message_t* msg, auth_payload_t* payload) {
    /* REGISTER uses same format as AUTH */
    if (!msg || !payload || msg->type != MSG_REGISTER) return -1;
    
    const char* username = (const char*)msg->payload;
    size_t username_len = strnlen(username, msg->length);
    
    if (username_len >= msg->length || username_len >= MAX_USERNAME_LEN) return -1;
    
    const char* password = username + username_len + 1;
    size_t password_len = strnlen(password, msg->length - username_len - 1);
    
    if (password_len >= MAX_PASSWORD_LEN) return -1;
    
    strncpy(payload->username, username, MAX_USERNAME_LEN - 1);
    strncpy(payload->password, password, MAX_PASSWORD_LEN - 1);
    payload->username[MAX_USERNAME_LEN - 1] = '\0';
    payload->password[MAX_PASSWORD_LEN - 1] = '\0';
    
    return 0;
}

int message_parse_port(const message_t* msg, port_payload_t* payload) {
    if (!msg || !payload) return -1;
    if (msg->length != sizeof(uint16_t)) return -1;
    
    uint16_t net_port;
    memcpy(&net_port, msg->payload, sizeof(uint16_t));
    payload->port = ntohs_portable(net_port);
    
    return 0;
}

int message_parse_list(const message_t* msg, list_payload_t* list) {
    if (!msg || !list || msg->type != MSG_LIST) return -1;
    
    if (msg->length < sizeof(uint16_t)) return -1;
    
    uint16_t net_count;
    memcpy(&net_count, msg->payload, sizeof(uint16_t));
    list->count = ntohs_portable(net_count);
    
    if (list->count == 0) {
        list->ports = NULL;
        return 0;
    }
    
    if (msg->length != sizeof(uint16_t) + list->count * sizeof(uint16_t)) return -1;
    
    list->ports = (uint16_t*)xmalloc(list->count * sizeof(uint16_t));
    
    for (int i = 0; i < list->count; i++) {
        uint16_t net_port;
        memcpy(&net_port, msg->payload + sizeof(uint16_t) + i * sizeof(uint16_t), sizeof(uint16_t));
        list->ports[i] = ntohs_portable(net_port);
    }
    
    return 0;
}

int message_parse_data(const message_t* msg, data_payload_t* data) {
    if (!msg || !data || msg->type != MSG_DATA) return -1;
    if (msg->length < sizeof(uint32_t)) return -1;
    
    uint32_t net_tunnel_id;
    memcpy(&net_tunnel_id, msg->payload, sizeof(uint32_t));
    data->tunnel_id = ntohl_portable(net_tunnel_id);
    
    data->data_len = msg->length - sizeof(uint32_t);
    
    if (data->data_len > 0) {
        data->data = (uint8_t*)xmalloc(data->data_len);
        memcpy(data->data, msg->payload + sizeof(uint32_t), data->data_len);
    } else {
        data->data = NULL;
    }
    
    return 0;
}

int message_parse_tunnel_open(const message_t* msg, tunnel_open_payload_t* payload) {
    if (!msg || !payload || msg->type != MSG_TUNNEL_OPEN) return -1;
    if (msg->length != sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t)) return -1;

    uint32_t net_tunnel_id;
    uint16_t net_port;
    uint16_t net_data;

    memcpy(&net_tunnel_id, msg->payload, sizeof(uint32_t));
    memcpy(&net_port, msg->payload + sizeof(uint32_t), sizeof(uint16_t));
    memcpy(&net_data, msg->payload + sizeof(uint32_t) + sizeof(uint16_t), sizeof(uint16_t));

    payload->tunnel_id = ntohl_portable(net_tunnel_id);
    payload->port = ntohs_portable(net_port);
    payload->data_port = ntohs_portable(net_data);

    return 0;
}

int message_parse_tunnel_close(const message_t* msg, tunnel_close_payload_t* payload) {
    if (!msg || !payload || msg->type != MSG_TUNNEL_CLOSE) return -1;
    if (msg->length != sizeof(uint32_t)) return -1;
    
    uint32_t net_tunnel_id;
    memcpy(&net_tunnel_id, msg->payload, sizeof(uint32_t));
    payload->tunnel_id = ntohl_portable(net_tunnel_id);
    
    return 0;
}

int message_parse_error(const message_t* msg, error_payload_t* error) {
    if (!msg || !error || msg->type != MSG_ERR) return -1;
    
    size_t len = msg->length < MAX_ERROR_MSG_LEN ? msg->length : MAX_ERROR_MSG_LEN - 1;
    memcpy(error->error, msg->payload, len);
    error->error[len] = '\0';
    
    return 0;
}

/* ========== Send/Receive ========== */

int message_send(int sock, const message_t* msg) {
    if (sock < 0 || !msg) return -1;
    
    /* Prepare header */
    uint8_t header[MSG_HEADER_SIZE];
    header[0] = msg->type;
    uint32_t net_length = htonl_portable(msg->length);
    memcpy(header + 1, &net_length, sizeof(uint32_t));
    
#ifdef _WIN32
    int send_flags = 0;
#else
    /* Use MSG_NOSIGNAL on Linux to prevent SIGPIPE */
    int send_flags = MSG_NOSIGNAL;
#endif
    
    /* Build combined message for single send */
    if (msg->length > 0 && msg->payload) {
        uint8_t* combined = (uint8_t*)xmalloc(MSG_HEADER_SIZE + msg->length);
        memcpy(combined, header, MSG_HEADER_SIZE);
        memcpy(combined + MSG_HEADER_SIZE, msg->payload, msg->length);
        
        size_t total = MSG_HEADER_SIZE + msg->length;
        size_t total_sent = 0;
        
        /* Send in loop, handling partial sends and EINTR */
        while (total_sent < total) {
            int sent = send(sock, (const char*)combined + total_sent, total - total_sent, send_flags);
            if (sent <= 0) {
                int err = socket_errno;
                if (sent == 0 || !socket_would_block(err)) {
                    /* Connection error */
                    xfree(combined);
                    return -1;
                }
                /* Would block - socket is full, wait briefly and retry */
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(sock, &write_fds);
                struct timeval timeout = {5, 0}; /* 5 second timeout */
                int ready = select(sock + 1, NULL, &write_fds, NULL, &timeout);
                if (ready <= 0) {
                    /* Timeout or error - connection is likely dead */
                    log_error("Send timeout or error, connection may be dead");
                    xfree(combined);
                    return -1;
                }
                continue;
            }
            total_sent += sent;
        }
        
        xfree(combined);
    } else {
        /* Header only */
        size_t total_sent = 0;
        
        while (total_sent < MSG_HEADER_SIZE) {
            int sent = send(sock, (const char*)header + total_sent, MSG_HEADER_SIZE - total_sent, send_flags);
            if (sent <= 0) {
                int err = socket_errno;
                if (sent == 0 || !socket_would_block(err)) {
                    return -1;
                }
                /* Would block - wait briefly */
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(sock, &write_fds);
                struct timeval timeout = {5, 0};
                int ready = select(sock + 1, NULL, &write_fds, NULL, &timeout);
                if (ready <= 0) {
                    log_error("Send timeout or error, connection may be dead");
                    return -1;
                }
                continue;
            }
            total_sent += sent;
        }
    }
    
    return 0;
}

message_t* message_receive(int sock) {
    if (sock < 0) return NULL;
    
    /* Receive header */
    uint8_t header[MSG_HEADER_SIZE];
    int received = 0;
    
    while (received < MSG_HEADER_SIZE) {
        int n = recv(sock, (char*)header + received, MSG_HEADER_SIZE - received, 0);
        if (n <= 0) {
            if (n < 0) log_error("Failed to receive message header: %d", socket_errno);
            return NULL;
        }
        received += n;
    }
    
    /* Parse header */
    uint8_t type = header[0];
    uint32_t net_length;
    memcpy(&net_length, header + 1, sizeof(uint32_t));
    uint32_t length = ntohl_portable(net_length);
    
    log_debug("Received message header: type=0x%02x, length=%u (net=0x%08x)", type, length, net_length);
    
    if (length > MAX_PAYLOAD_SIZE) {
        log_error("Message payload too large: %u bytes", length);
        return NULL;
    }
    
    /* Create message */
    message_t* msg = message_create(type, length);
    
    /* Receive payload */
    if (length > 0) {
        received = 0;
        while (received < (int)length) {
            int n = recv(sock, (char*)msg->payload + received, length - received, 0);
            if (n < 0) {
                if (n < 0) log_error("Failed to receive message payload: %d", socket_errno);
                message_free(msg);
                return NULL;
            }
            received += n;
        }
    }
    
    return msg;
}

message_t* message_receive_nonblocking(int sock, int* would_block) {
    if (sock < 0) return NULL;
    if (would_block) *would_block = 0;
    
    /* Receive header - need to loop since we might not get all 5 bytes at once */
    uint8_t header[MSG_HEADER_SIZE];
    int received = 0;
    
    while (received < MSG_HEADER_SIZE) {
        int n = recv(sock, (char*)header + received, MSG_HEADER_SIZE - received, 0);
        
        if (n < 0) {
            int err = socket_errno;
            if (socket_would_block(err)) {
                if (would_block) *would_block = 1;
                return NULL;
            }
            /* Connection error - don't log, just return NULL to close connection */
            return NULL;
        }
        
        if (n == 0) {
            /* Connection closed - this is normal, don't log */
            return NULL;
        }
        
        received += n;
    }
    
    /* Parse header */
    uint8_t type = header[0];
    uint32_t net_length;
    memcpy(&net_length, header + 1, sizeof(uint32_t));
    uint32_t length = ntohl_portable(net_length);
    
    if (length > MAX_PAYLOAD_SIZE) {
        log_error("Message payload too large: %u bytes", length);
        return NULL;
    }
    
    /* Create message */
    message_t* msg = message_create(type, length);
    
    /* Receive payload */
    if (length > 0) {
        int received = 0;
        int n;
        while (received < (int)length) {
            n = recv(sock, (char*)msg->payload + received, length - received, 0);
            if (n < 0) {
                int err = socket_errno;
                if (socket_would_block(err)) {
                    if (would_block) *would_block = 1;
                    message_free(msg);
                    return NULL;
                }
                log_error("Failed to receive message payload: %d", err);
                message_free(msg);
                return NULL;
            }
            if (n == 0) {
                /* Connection closed while reading payload - don't log, cleanup and return */
                message_free(msg);
                return NULL;
            }
            received += n;
        }
    }
    
    return msg;
}

/* ========== Utility ========== */

void message_print(const message_t* msg) {
    if (!msg) {
        printf("Message: NULL\n");
        return;
    }
    
    const char* type_str;
    switch (msg->type) {
        case MSG_AUTH: type_str = "AUTH"; break;
        case MSG_CLAIM: type_str = "CLAIM"; break;
        case MSG_UNCLAIM: type_str = "UNCLAIM"; break;
        case MSG_LIST: type_str = "LIST"; break;
        case MSG_DATA: type_str = "DATA"; break;
        case MSG_OK: type_str = "OK"; break;
        case MSG_ERR: type_str = "ERR"; break;
        case MSG_TUNNEL_OPEN: type_str = "TUNNEL_OPEN"; break;
        case MSG_TUNNEL_CLOSE: type_str = "TUNNEL_CLOSE"; break;
        case MSG_PING: type_str = "PING"; break;
        case MSG_PONG: type_str = "PONG"; break;
        default: type_str = "UNKNOWN"; break;
    }
    
    printf("Message: type=%s, length=%u\n", type_str, msg->length);
}
