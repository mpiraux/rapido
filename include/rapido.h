/**
 * @file
 */
#ifndef rapido_h
#define rapido_h

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/socket.h>
#include "picotls.h"

typedef uint32_t rapido_connection_id_t;
typedef uint32_t rapido_stream_id_t;

#define CLIENT_STREAM(sid) (((sid)&0x1) == 0)
#define SERVER_STREAM(sid) (((sid)&0x1) == 1)

typedef uint8_t rapido_address_id_t;
typedef uint64_t set_t;

#define SET_LEN 64
#define SET_HAS(bs, e) (bs & (1ull << ((uint64_t)e)))
#define SET_ADD(bs, e) bs = (bs | (1ull << ((uint64_t)e)))
#define SET_REMOVE(bs, e) bs = (bs & (~(1ull << ((uint64_t)e))))
#define SET_SIZE(bs) __builtin_popcountll(bs)

#define TLS_SESSION_ID_LEN 32

/**
 * A growing array allocating `capacity * item_size` bytes.
 */
typedef struct {
    size_t capacity;
    size_t size;
    size_t item_size;
    uint8_t *data;
} rapido_array_t;

#define rapido_array_iter(a, i, e, bl)                                                                                             \
    do {                                                                                                                           \
        for (int i = 0; i < (a)->capacity; i++) {                                                                                  \
            size_t offset = (1 + (a)->item_size) * i;                                                                              \
            if ((a)->data[offset] == true) {                                                                                       \
                e = (void *)(a)->data + offset + 1;                                                                                \
                bl                                                                                                                 \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)

/**
 * A growing and cycling queue allocating `capacity * item_size` bytes.
 */
typedef struct {
    size_t capacity;
    size_t size;
    size_t front_index;
    size_t back_index;
    size_t item_size;
    uint8_t *data;
} rapido_queue_t;

/**
 * A growing and cycling byte buffer. Due to cycling, the buffer can allocate or return a smaller memory zone than wanted.
 */
typedef struct {
    size_t capacity;
    size_t size;
    size_t front_index;
    size_t back_index;
    uint8_t *data;
} rapido_buffer_t;

#define RANGES_LEN 64

/** A uin64_t interval list, sorted by ascending order. Overlapping ranges are merged. */
typedef struct {
    struct rapido_range_item {
        uint64_t low;
        uint64_t high;
    } ranges[RANGES_LEN];
    size_t size;
} rapido_range_list_t;

/**
 * A growing and cycling buffer, also tracking the ranges of bytes present in the buffer following a global read_offset.
 * The offset advances as data is read out of the buffer.
 * Due to cycling, the buffer can allocate or return a smaller memory zone than wanted.
 */
typedef struct {
    struct {
        void *data;
        size_t capacity;
        size_t offset;
    } buffer;
    rapido_range_list_t ranges;
    size_t read_offset;
} rapido_range_buffer_t;

void *rapido_queue_pop(rapido_queue_t *queue);

#define rapido_queue_drain(q, e, bl)                                                                                               \
    do {                                                                                                                           \
        while ((q)->size) {                                                                                                        \
            e = rapido_queue_pop(q);                                                                                               \
            bl                                                                                                                     \
        }                                                                                                                          \
    } while (0)

typedef struct {
    uint64_t tls_record_sequence; // The TLS Record sequence number of this record
    size_t ciphertext_len;        // The total length of the record as transmitted on the wire
    bool ack_eliciting;           // Whether receiving this record is expected to trigger the sending of an ACK. It also
                                  // implies that the sender of this record will retransmit the frames
    uint64_t sent_time;           // The time at which the record was sent
} rapido_record_metadata_t;

typedef struct {
    ptls_context_t *tls_ctx;
    char *server_name;

    rapido_array_t local_addresses;
    rapido_address_id_t next_local_address_id;

    rapido_array_t listen_sockets;
    rapido_array_t pending_connections;

    rapido_array_t sessions;

    bool is_server; // For QLOG macros
    struct {
        FILE *out;
        uint64_t reference_time;
    } qlog;
} rapido_server_t;

typedef struct {
    ptls_t *tls;
    ptls_context_t *tls_ctx;

    rapido_array_t connections;
    rapido_connection_id_t next_connection_id;
    rapido_array_t streams;
    rapido_stream_id_t next_stream_id;

    rapido_array_t local_addresses;
    rapido_address_id_t next_local_address_id;
    set_t addresses_advertised;
    rapido_array_t remote_addresses;
    rapido_address_id_t next_remote_address_id;

    rapido_array_t tls_session_ids;
    bool is_server;
    bool is_closed;

    rapido_queue_t pending_notifications;

    union {
        struct {

        } client;
        struct {
            rapido_array_t listen_sockets;
            rapido_array_t pending_connections;
            size_t tls_session_ids_sent;
        } server;
    };

    struct {
        FILE *out;
        uint64_t reference_time;
    } qlog;
} rapido_session_t;

typedef struct {
    rapido_connection_id_t connection_id;
    int socket;
    rapido_address_id_t local_address_id;
    rapido_address_id_t remote_address_id;
    struct sockaddr_storage peer_address;
    socklen_t peer_address_len;
    bool is_closed;

    set_t attached_streams;
    rapido_queue_t frame_queue;

    struct st_ptls_traffic_protection_t *encryption_ctx;
    struct st_ptls_traffic_protection_t *decryption_ctx;
    struct st_ptls_traffic_protection_t *own_decryption_ctx; // Cryptographic material to decrypt the records we sent when
                                                             // retransmitting
    struct {
        ptls_buffer_t rec;
        ptls_buffer_t mess;
    } tls_recvbuf;  // Used by picotls for reassembling fragmented TLS records

    rapido_buffer_t receive_buffer;
    bool receive_buffer_fragmented;
    rapido_buffer_t send_buffer;

    rapido_queue_t sent_records;
    size_t sent_offset;
    uint64_t last_received_record_sequence;

    bool require_ack;
    uint64_t last_receive_time;
    size_t non_ack_eliciting_count;

    set_t retransmit_connections;

    struct {
        uint64_t bytes_received;
        uint64_t bytes_sent;
    } stats;

    ptls_t *tls;
    void *app_ptr;
} rapido_connection_t;

#define rapido_time_to_send(conn_info, bytes_len) ((((((uint64_t) bytes_len) * 1000000ul) / (conn_info).congestion_window) * (conn_info).smoothed_rtt) / 1000000ul)
#define rapido_time_to_drain(conn_info) (rapido_time_to_send(conn_info, (conn_info).bytes_queued_for_sending))
#define rapido_time_to_transfer(conn_info, bytes_len) (rapido_time_to_drain(conn_info) + rapido_time_to_send(conn_info, bytes_len) + (conn_info).smoothed_rtt)

typedef struct {
    uint64_t smoothed_rtt;
    uint64_t congestion_window;
    uint64_t bytes_queued_for_sending;
} rapido_connection_info_t;

typedef struct {
    int socket;
    ptls_context_t *tls_ctx;
    ptls_t *tls;
    ptls_handshake_properties_t tls_properties;
    uint8_t tls_session_id[TLS_SESSION_ID_LEN];
    rapido_address_id_t local_address_id;
} rapido_pending_connection_t;

typedef uint8_t *(*rapido_stream_producer_t)(rapido_session_t *, rapido_stream_id_t, void *, uint64_t, size_t *);

typedef struct {
    uint64_t offset;
    void *app_ctx;
} rapido_stream_write_cb_t;

typedef struct {
    rapido_stream_id_t stream_id;

    set_t connections;

    rapido_range_buffer_t read_buffer;
    size_t read_fin;
    bool fin_received;

    rapido_buffer_t send_buffer;
    size_t write_offset;
    size_t write_fin;
    bool fin_set;
    bool fin_sent;

    rapido_stream_producer_t producer;
    void *producer_ctx;
    rapido_queue_t write_callbacks;

    uint64_t bytes_received;
    uint64_t bytes_sent;
} rapido_stream_t;

typedef struct {
    enum {
        rapido_new_connection,
        rapido_connection_reset,
        rapido_connection_closed,
        rapido_new_stream,
        rapido_stream_has_data,
        rapido_stream_data_was_written,
        rapido_stream_closed,
        rapido_new_remote_address,
        rapido_session_closed,
    } notification_type;

    union {
        rapido_connection_id_t connection_id;
        rapido_stream_id_t stream_id;
        rapido_address_id_t address_id;
        void *app_ctx;
    };
} rapido_application_notification_t;

/** Creates a new rapido server. */
rapido_server_t *rapido_new_server(ptls_context_t *tls_ctx, const char *server_name, FILE *qlog_out);

/** Adds a local address to the server, and creates a listen socket bound to the address when required. */
rapido_address_id_t rapido_add_server_address(rapido_server_t *server, struct sockaddr *addr, socklen_t addr_len, bool add_listen_socket);
/** Removes a local address from the server. */
int rapido_remove_server_address(rapido_session_t *session, rapido_address_id_t local_address_id);
/** Runs the server for some time. */
int rapido_run_server_network(rapido_server_t *server, int timeout);
/** Pops the next notification and gets the index of the corresponding session. */
rapido_application_notification_t *rapido_next_server_notification(rapido_server_t *server, size_t *session_index);

/** Creates a new rapido session. */
rapido_session_t *rapido_new_session(ptls_context_t *tls_ctx, bool is_server, const char *server_name, FILE *qlog_out);

/** Adds a local address to the session. */
rapido_address_id_t rapido_add_address(rapido_session_t *session, struct sockaddr *addr, socklen_t addr_len);
/** Adds a remote address to the session. */
rapido_address_id_t rapido_add_remote_address(rapido_session_t *session, struct sockaddr *addr, socklen_t addr_len);
/** Removes a local address from the session. */
int rapido_remove_address(rapido_session_t *session, rapido_address_id_t local_address_id);

/** Creates a new connection for the session with the given local and remote addresses. */
rapido_connection_id_t rapido_create_connection(rapido_session_t *session, uint8_t local_address_id, uint8_t remote_address_id);
/** Adds the given file descriptor to the session as a new connection with the given local and remote addresses. */
rapido_connection_id_t rapido_client_add_connection(rapido_session_t *session, int fd, uint8_t local_address_id, uint8_t remote_address_id);
/** Runs the session for some time. */
int rapido_run_network(rapido_session_t *session, int timeout);
/** Marks the given set of connections as eligible for retransmitting the content of the given connection. */
int rapido_retransmit_connection(rapido_session_t *session, rapido_connection_id_t connection_id, set_t connections);
/** Gracefully closes the connection. */
int rapido_close_connection(rapido_session_t *session, rapido_connection_id_t connection_id);
/** Gracefully closes the session and send the TLS alert on the given connection. */
int rapido_close_session(rapido_session_t *session, rapido_connection_id_t connection_id);

/** Add a new stream to the session. */
rapido_stream_id_t rapido_open_stream(rapido_session_t *session);
/** Marks the connection as eligible to send content of this stream. */
int rapido_attach_stream(rapido_session_t *session, rapido_stream_id_t stream_id, rapido_connection_id_t connection_id);
/** Removes the mark of elibility of this connection for sending the content of this stream. */
int rapido_detach_stream(rapido_session_t *session, rapido_stream_id_t stream_id, rapido_connection_id_t connection_id);
/** Adds the given data to the end of the stream. */
int rapido_add_to_stream(rapido_session_t *session, rapido_stream_id_t stream_id, void *data, size_t len);
/** Adds the given data to the end of the stream and registers a notification containing the given application context when the data has been written in frames. */
int rapido_add_to_stream_notify(rapido_session_t *session, rapido_stream_id_t stream_id, void *data, size_t len, void *app_ctx);
/** Sets the given function and associated context as a data producer for this stream. */
int rapido_set_stream_producer(rapido_session_t *session, rapido_stream_id_t stream_id, rapido_stream_producer_t producer,
                               void *producer_ctx);
/** Returns a pointer to read at most the *len following bytes from this stream. */
void *rapido_read_stream(rapido_session_t *session, rapido_stream_id_t stream_id, size_t *len);
/** Marks the end of this stream. */
int rapido_close_stream(rapido_session_t *session, rapido_stream_id_t stream_id);

/** Adds a given file descriptor as a new connection to a session. */
int rapido_session_accept_new_connection(rapido_session_t *session, int accept_fd, rapido_address_id_t local_address_id);
/** Accepts from a given file descriptor and adds the new connection to the server. */ 
int rapido_server_accept_new_connection(rapido_server_t *server, int accept_fd, rapido_address_id_t local_address_id);
/** Adds the new connection to pending connections and returns its index within the latter array. */
size_t rapido_server_add_new_connection(rapido_array_t *pending_connections, ptls_context_t *tls_ctx, ptls_t *tls,
                                     const char *server_name, int conn_fd, rapido_address_id_t local_address_id);
/** Processes data received by a client during the handshake and returns whether the handshake is complete. */
int rapido_client_process_handshake(rapido_session_t *session, rapido_connection_id_t connection_id, uint8_t *buffer, size_t *len);
/** Processes data received by a server during the handshake. Returns PTLS_ERROR_IN_PROGRESS when the handshake is still progressing, -1 when TCPLS could not be used and 0 when the handshake completed. */
int rapido_server_process_handshake(rapido_server_t *server, rapido_session_t *session, rapido_array_t *pending_connections, size_t pending_connection_index, uint8_t *buffer, size_t *len, ptls_buffer_t *handshake_buffer, rapido_session_t **created_session, rapido_connection_t **created_connection);
/** Processes incoming data received after the handshake. */
void rapido_process_incoming_data(rapido_session_t *session, rapido_connection_id_t connection_id, uint64_t current_time, uint8_t *buffer, size_t *len);
/** Returns whether the given connection wants to send data. */
int rapido_connection_wants_to_send(rapido_session_t *session, rapido_connection_t *connection, uint64_t current_time, bool *is_blocked);
/** Prepares data to send. */
void rapido_prepare_data(rapido_session_t *session, rapido_connection_id_t connection_id, uint64_t current_time, uint8_t *buffer, size_t *len);
/** Sets an application pointer associated with the given connection. */
void rapido_connection_set_app_ptr(rapido_session_t *session, rapido_connection_id_t connection_id, void *app_ptr);
/** Gets an application pointer associated with the given connection. */
void *rapido_connection_get_app_ptr(rapido_session_t *session, rapido_connection_id_t connection_id);
/** Returns TCP-level information on the given connection */
void rapido_connection_get_info(rapido_session_t * session, rapido_connection_id_t connection_id, rapido_connection_info_t *info);

/** Deallocates the memory zones referenced in this session structure. */
int rapido_session_free(rapido_session_t *session);
/** Deallocates the memory zones referenced in this server structure. */
int rapido_server_free(rapido_server_t *server);

#endif