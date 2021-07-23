#ifndef rapido_h
#define rapido_h

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include "picotls.h"

/*
 * TODO:
 *  - Need a byte range abstraction for stream buf ack tracking
 */

typedef uint32_t rapido_connection_id_t;
typedef uint32_t rapido_stream_id_t;

#define STREAM_IS_CLIENT(sid) (((sid) & 0x1) == 0)
#define STREAM_IS_SERVER(sid) (((sid) & 0x1) == 1)

typedef uint8_t rapido_address_id_t;
typedef uint64_t set_t;

#define SET_LEN 64
#define SET_HAS(bs, e) (bs & (1ull << ((uint64_t) e)))
#define SET_ADD(bs, e) bs = (bs | (1ull << ((uint64_t) e)))
#define SET_REMOVE(bs, e) bs = (bs & (~(1ull << ((uint64_t) e))))

typedef struct {
    size_t capacity;
    size_t size;
    size_t item_size;
    uint8_t *data;
} rapido_array_t;

typedef struct {
    size_t capacity;
    size_t size;
    size_t front_index;
    size_t back_index;
    size_t item_size;
    uint8_t *data;
} rapido_queue_t;

typedef struct {
    size_t capacity;
    size_t size;
    size_t front_index;
    size_t back_index;
    uint8_t *data;
} rapido_stream_buffer_t;

#define RANGES_LEN 64

typedef struct {
    struct rapido_range_item {
        uint64_t low;
        uint64_t high;
    } ranges[RANGES_LEN];
    size_t size;
} rapido_range_list_t;

typedef struct {
    struct {
        void *data;
        size_t capacity;
        size_t offset;
    } buffer;
    rapido_range_list_t ranges;
    size_t read_offset;
} rapido_stream_receive_buffer_t;

void *rapido_queue_pop(rapido_queue_t *queue);

#define rapido_queue_iter(q, e, bl)                                                                                                \
    do {                                                                                                                           \
        while (q->size) {                                                                                                          \
            e = rapido_queue_pop(q);                                                                                               \
            bl                                                                                                                     \
        }                                                                                                                          \
    } while (0)

typedef struct {
    /*TODO: Make these per connection */
    ptls_t *tls;
    ptls_context_t *tls_ctx;
    ptls_handshake_properties_t tls_properties;

    rapido_array_t connections;
    rapido_connection_id_t next_connection_id;
    rapido_array_t streams;
    rapido_stream_id_t next_stream_id;

    rapido_array_t local_addresses;
    rapido_address_id_t next_local_address_id;
    rapido_array_t remote_addresses;
    rapido_address_id_t next_remote_address_id;

    rapido_array_t tls_session_ids;
    bool is_server;

    rapido_queue_t pending_notifications;

    union {
        struct {

        } client;
        struct {
            rapido_array_t listen_sockets;
            rapido_array_t pending_connections;  // We don't care about the index here
            size_t next_pending_connection;
        } server;
    };
} rapido_t;

typedef struct {
    rapido_connection_id_t connection_id;
    int socket;
    rapido_address_id_t local_address_id;
    rapido_address_id_t remote_address_id;

    set_t attached_streams;

    struct {
        uint64_t bytes_received;
        uint64_t bytes_sent;
    } conn_stats;
} rapido_connection_t;

typedef struct {
    int socket;
    ptls_context_t *tls_ctx;
    ptls_t *tls;
} rapido_pending_connection_t;

typedef struct {
    rapido_stream_id_t stream_id;

    set_t connections;

    rapido_stream_receive_buffer_t read_buffer;
    size_t read_fin;
    bool fin_received;

    rapido_stream_buffer_t send_buffer;
    size_t write_offset;
    size_t write_fin;
    bool fin_set;
    bool fin_sent;

    uint64_t bytes_received;
    uint64_t bytes_sent;
} rapido_stream_t;

typedef struct {
    enum {
        rapido_new_connection,
        rapido_connection_failed,
        rapido_new_stream,
        rapido_stream_has_data,
        rapido_stream_closed,
        rapido_new_remote_address,
    } notification_type;

    union {
        rapido_connection_id_t connection_id;
        rapido_stream_id_t stream_id;
        rapido_address_id_t address_id;
    };
} rapido_application_notification_t;

rapido_t *rapido_new(ptls_context_t *tls_ctx, bool is_server, char *server_name);

rapido_address_id_t rapido_add_address(rapido_t *session, struct sockaddr* addr, socklen_t addr_len);
rapido_address_id_t rapido_add_remote_address(rapido_t *session, struct sockaddr* addr, socklen_t addr_len);
int rapido_remove_address(rapido_t *session, rapido_address_id_t local_address_id);

rapido_connection_id_t rapido_create_connection(rapido_t *session, uint8_t local_address_id, uint8_t remote_address_id);
int rapido_run_network(rapido_t *session);
int rapido_close_connection(rapido_t *session, rapido_connection_id_t *connection_id);

rapido_stream_id_t rapido_open_stream(rapido_t *session);
int rapido_attach_stream(rapido_t *session, rapido_stream_id_t stream_id, rapido_connection_id_t connection_id);
int rapido_remove_stream(rapido_t *session, rapido_stream_id_t stream_id, rapido_connection_id_t connection_id);
int rapido_add_to_stream(rapido_t *session, rapido_stream_id_t stream_id, void *data, size_t len);
void *rapido_read_stream(rapido_t *session, rapido_stream_id_t stream_id, size_t *len);
int rapido_close_stream(rapido_t *session, rapido_stream_id_t stream_id);

int rapido_receive(rapido_t *session);
int rapido_close(rapido_t *session);

#endif