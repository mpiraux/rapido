#include "rapido.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <libsync.h>

#define WARNING(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define TLS_SESSION_ID_LEN 32
#define TLS_MAX_ENCRYPTED_RECORD_SIZE (16384 + 256)

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))

#define TLS_RAPIDO_HELLO_EXT 100

int collect_rapido_extensions(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type) {
    return type == TLS_RAPIDO_HELLO_EXT;
}

int collected_rapido_extensions(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, ptls_raw_extension_t *extensions) {
    assert(extensions[0].type == TLS_RAPIDO_HELLO_EXT);
    ptls_raw_extension_t *extension = extensions;
    size_t no_extensions = 0;
    while(extension->type != UINT16_MAX) {
        no_extensions++;
        extension++;
    }
    if (properties->additional_extensions) {
        free(properties->additional_extensions);
    }
    properties->additional_extensions = malloc(sizeof(ptls_raw_extension_t) * (no_extensions + 1));
    memcpy(properties->additional_extensions, extensions, sizeof(ptls_raw_extension_t) * (no_extensions + 1));
    properties->collected_extensions = NULL;
    return 0;
}


void *rapido_array_add(rapido_array_t *array, size_t index) {
    if (index >= array->capacity) {
        size_t new_capacity = max(index * 2, max(array->capacity * 2, 1));
        array->data = reallocarray(array->data, new_capacity, 1 + array->item_size);
        assert(array->data != NULL);
        for (int i = array->capacity; i < new_capacity; i++) {
            array->data[(1 + array->item_size) * i] = false;
        }
        array->capacity = new_capacity;
    }
    assert(array->data[(1 + array->item_size) * index] == false);
    array->data[(1 + array->item_size) * index] = true;
    array->size++;
    return array->data + ((1 + array->item_size) * index) + 1;
}

void *rapido_array_get(rapido_array_t *array, size_t index) {
    if (index >= array->capacity) {
        return NULL;
    }
    size_t offset = (1 + array->item_size) * index;
    return array->data[offset] == true ? array->data + offset + 1 : NULL;
}

int rapido_array_delete(rapido_array_t *array, size_t index) {
    if (index >= array->capacity) {
        return 1;
    }
    size_t offset = (1 + array->item_size) * index;
    if(array->data[offset] == false) {
        return 1;
    }
    array->data[(1 + array->item_size) * index] = false;
    array->size--;
    return 0;
}

void rapido_array_free(rapido_array_t *array) {
    if (array->capacity && array->data) {
        free(array->data);
        memset(array, 0, sizeof(rapido_array_t));
    }
}

#define rapido_array_iter(a, e, bl)                                                                                                \
    do {                                                                                                                           \
        for (int i = 0; i < (a)->capacity; i++) {                                                                                  \
            size_t offset = (1 + (a)->item_size) * i;                                                                               \
            if ((a)->data[offset] == true) {                                                                                       \
                e = (void *)(a)->data + offset + 1;                                                                                \
                bl                                                                                                                 \
            }                                                                                                                      \
        }                                                                                                                          \
    } while (0)

void rapido_queue_init(rapido_queue_t *queue, size_t item_size, size_t capacity) {
    queue->data = malloc(item_size * capacity);
    assert(queue->data != NULL);
    queue->capacity = capacity;
    queue->size = 0;
    queue->front_index = 0;
    queue->back_index = 0;
    queue->item_size = item_size;
}

void *rapido_queue_push(rapido_queue_t *queue) {
    assert(queue->size < queue->capacity);
    size_t item_index = queue->back_index;
    queue->back_index = (queue->back_index + 1) % queue->capacity;
    queue->size++;
    return queue->data + (item_index * queue->item_size);
}

void *rapido_queue_pop(rapido_queue_t *queue) {
    assert(queue->size > 0);
    size_t item_index = queue->front_index;
    queue->front_index = (queue->front_index + 1) % queue->capacity;
    queue->size--;
    return queue->data + (item_index * queue->item_size);
}

void rapido_queue_free(rapido_queue_t *queue) {
    if (queue->capacity && queue->data) {
        free(queue->data);
        memset(queue, 0, sizeof(rapido_queue_t));
    }
}

typedef uint8_t rapido_frame_id_t;

static const rapido_frame_id_t padding_frame_type = 0x0;
static const rapido_frame_id_t ping_frame_type = 0x1;
static const rapido_frame_id_t stream_frame_type = 0x2;
static const rapido_frame_id_t ack_frame_type = 0x3;
static const rapido_frame_id_t new_session_id_frame_type = 0x4;
static const rapido_frame_id_t new_address_frame_type = 0x5;
static const rapido_frame_id_t connection_failed_frame_type = 0x6;
static const rapido_frame_id_t ebpf_code_frame_type = 0x7;

typedef struct {
    uint8_t *data;
    size_t len;
    uint64_t offset;
    rapido_stream_id_t stream_id;
} rapido_stream_frame_t;

typedef struct {
    rapido_connection_id_t connection_id;
    uint64_t last_record_acknowledged;
} rapido_ack_frame_t;

typedef struct {
    uint8_t *tls_session_id;
    rapido_connection_id_t sequence;
} rapido_new_session_id_frame_t;

typedef struct {
    rapido_address_id_t address_id;
    uint8_t family;
    uint8_t addr[16];
    uint16_t port;
} rapido_new_address_frame_t;

typedef struct {
    rapido_connection_id_t connection_id;
    uint32_t sequence;
} rapido_connection_failed_frame_t;

typedef struct {
    uint8_t *data;
    size_t len;
    size_t offset;
    rapido_connection_id_t connection_id;
} rapido_ebpf_code_frame_t;

int rapido_frame_is_ack_eliciting(rapido_frame_id_t frame_id) {
    return frame_id == padding_frame_type || frame_id == ack_frame_type;
}

rapido_t *rapido_new(ptls_context_t *tls_ctx, bool is_server, char *server_name) {
    rapido_t *session = calloc(1, sizeof(rapido_t));
    assert(session != NULL);
    session->is_server = is_server;

    session->tls_ctx = tls_ctx;
    session->tls = ptls_new(session->tls_ctx, session->is_server);
    ptls_set_server_name(session->tls, server_name, 0);
    session->tls_properties.additional_extensions = malloc(sizeof(ptls_raw_extension_t) * 2);
    session->tls_properties.additional_extensions[0].type = TLS_RAPIDO_HELLO_EXT;
    session->tls_properties.additional_extensions[0].data = ptls_iovec_init(NULL, 0);
    session->tls_properties.additional_extensions[1].type = UINT16_MAX;
    session->tls_properties.collect_extension = collect_rapido_extensions;
    session->tls_properties.collected_extensions = collected_rapido_extensions;

    session->connections.item_size = sizeof(rapido_connection_t);
    session->streams.item_size = sizeof(rapido_stream_id_t);
    session->local_addresses.item_size = sizeof(struct sockaddr_storage);
    session->remote_addresses.item_size = sizeof(struct sockaddr_storage);
    session->tls_session_ids.item_size = TLS_SESSION_ID_LEN;
    rapido_queue_init(&session->pending_notifications, sizeof(rapido_application_notification_t), 100);
    if (session->is_server) {
        session->server.listen_sockets.item_size = sizeof(int);
        session->server.pending_connections.item_size = sizeof(rapido_pending_connection_t);
    }
    return session;
}

rapido_address_id_t rapido_add_address(rapido_t *session, struct sockaddr *local_address, socklen_t local_address_len) {
    assert(local_address != NULL);
    assert(local_address_len == sizeof(struct sockaddr_in) || local_address_len == sizeof(struct sockaddr_in6));
    rapido_address_id_t local_address_id = session->next_local_address_id++;
    memcpy(rapido_array_add(&session->local_addresses, local_address_id), local_address, local_address_len);
    // TODO: Send it
    if (session->is_server) {  // TODO: Ipv6 dualstack compat mode ?
        int listen_fd = socket(local_address->sa_family, SOCK_STREAM, 0);
        assert_perror(listen_fd == -1);
        memcpy(rapido_array_add(&session->server.listen_sockets, local_address_id), &listen_fd, sizeof(listen_fd));
        int yes = 1;
        assert_perror(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)));
        //TODO Make it a poll struct rather
        assert_perror(bind(listen_fd, local_address, local_address->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
        assert_perror(listen(listen_fd, SOMAXCONN));
    }
    return local_address_id;
}

rapido_address_id_t rapido_add_remote_address(rapido_t *session, struct sockaddr *remote_address, socklen_t remote_address_len) {
    assert(remote_address != NULL);
    assert(remote_address_len == sizeof(struct sockaddr_in) || remote_address_len == sizeof(struct sockaddr_in6));
    rapido_address_id_t remote_address_id = session->next_remote_address_id++;
    memcpy(rapido_array_add(&session->remote_addresses, remote_address_id), remote_address, remote_address_len);
    return remote_address_id;
}

int rapido_remove_address(rapido_t *session, rapido_address_id_t local_address_id) {
    rapido_array_iter(&session->connections, rapido_connection_t *connection,{
        if (connection->local_address_id == local_address_id) {
            WARNING("Local address %d of connection %d is removed\n", local_address_id, connection->connection_id);
            // TODO: Migrate streams and RTX state for this connection
        }
    });
    // TODO: Send it
    if (session->is_server) {
        int *fd = rapido_array_get(&session->server.listen_sockets, local_address_id);
        if (fd != NULL) {
            assert_perror(close(*fd));
            rapido_array_delete(&session->server.listen_sockets, local_address_id);
        }
    }
    return rapido_array_delete(&session->local_addresses, local_address_id);
}

rapido_connection_id_t rapido_create_connection(rapido_t *session, uint8_t local_address_id, uint8_t remote_address_id) {
    assert(!session->is_server);
    struct sockaddr* local_address = (struct sockaddr *)rapido_array_get(&session->local_addresses, local_address_id);
    struct sockaddr* remote_address = (struct sockaddr *)rapido_array_get(&session->remote_addresses, remote_address_id);
    assert(local_address != NULL);
    assert(remote_address != NULL);
    assert(local_address->sa_family == remote_address->sa_family);

    rapido_connection_id_t connection_id = session->next_connection_id++;
    uint8_t *tls_session_id = rapido_array_get(&session->tls_session_ids, connection_id);
    assert(connection_id == 0 || tls_session_id != NULL);

    rapido_connection_t *connection = rapido_array_add(&session->connections, connection_id);
    memset(connection, 0, sizeof(rapido_connection_t));
    connection->connection_id = connection_id;
    connection->local_address_id = local_address_id;
    connection->remote_address_id = remote_address_id;

    connection->socket = socket(local_address->sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    assert_perror(connection->socket == -1);
    int yes = 1;
    assert_perror(setsockopt(connection->socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)));
    assert_perror(bind(connection->socket, local_address, local_address->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
    int ret = connect(connection->socket, remote_address, remote_address->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    if (ret && errno != EINPROGRESS) {
        assert_perror(ret);
    }

    if (connection_id == 0) {
        ptls_buffer_t handshake_buffer = { 0 };
        ptls_buffer_init(&handshake_buffer, "", 0);
        uint8_t random_tls_session_id[TLS_SESSION_ID_LEN] = { 0 }; // TODO: Fill it with random value
        session->tls_properties.client.tls_session_id = ptls_iovec_init(random_tls_session_id, sizeof(random_tls_session_id));
        ret = ptls_handshake(session->tls, &handshake_buffer, NULL, 0, &session->tls_properties);
        assert(ret == PTLS_ERROR_IN_PROGRESS);
        assert(send(connection->socket, handshake_buffer.base, handshake_buffer.off, 0) == handshake_buffer.off);
        ptls_buffer_dispose(&handshake_buffer);
    } else {
        assert("TODO JOIN"); // TODO JOIN
    }

    return connection_id;
}

int rapido_run_network(rapido_t *session) {
    if(session->is_server) {
        /* Accept new TCP connections and prepare the TLS handshake */
        size_t nfds = session->server.listen_sockets.size;
        struct pollfd listen_fds[nfds]; // TODO: cache this
        nfds = 0;
        rapido_array_iter(&session->server.listen_sockets, int *socket, {
            listen_fds[nfds].fd = *socket;
            listen_fds[nfds].events = POLLIN;
            nfds++;
        });
        int ret = poll(listen_fds, nfds, 0);
        assert(ret >= 0 || errno == EINTR);
        for (int i = 0; i < nfds && ret; i++) {
            if (listen_fds[i].revents == POLLIN) {
                struct sockaddr_storage remote_address;
                socklen_t remote_address_len = sizeof(remote_address_len);
                int conn_fd = accept(listen_fds[i].fd, (struct sockaddr *)&remote_address, &remote_address_len);
                assert_perror(conn_fd == -1);
                rapido_pending_connection_t *pending_connection = rapido_array_add(&session->server.pending_connections, session->server.next_pending_connection++);
                pending_connection->socket = conn_fd;
                if (!ptls_handshake_is_complete(session->tls)) {
                    pending_connection->tls_ctx = session->tls_ctx;
                    pending_connection->tls = session->tls;
                } else {
                    assert("TODO JOIN"); // TODO JOIN
                }
            }
        }
        /* Do the TLS handshake on pending connections */
        nfds = session->server.pending_connections.size;
        struct pollfd fds[nfds];
        size_t connections_index[nfds];
        nfds = 0;
        rapido_array_iter(&session->server.pending_connections, rapido_pending_connection_t *connection, {
            fds[nfds].fd = connection->socket;
            fds[nfds].events = POLLIN;
            connections_index[nfds] = i;
            nfds++;
        });
        ret = poll(fds, nfds, 0);
        assert(ret >= 0 || errno == EINTR);
        for (int i = 0; i < nfds && ret; i++) {
            if (fds[i].revents == POLLIN) {
                rapido_pending_connection_t *connection = rapido_array_get(&session->server.pending_connections, connections_index[i]);
                uint8_t recvbuf[TLS_MAX_ENCRYPTED_RECORD_SIZE];
                size_t recvd = recv(fds[i].fd, recvbuf, sizeof(recvbuf), 0);
                ptls_buffer_t handshake_buffer = {0};
                ptls_buffer_init(&handshake_buffer, "", 0);
                uint8_t tls_session_id_buf[TLS_SESSION_ID_LEN];
                session->tls_properties.server.tls_session_id = ptls_iovec_init(tls_session_id_buf, sizeof(tls_session_id_buf));
                ret = ptls_handshake(connection->tls, &handshake_buffer, recvbuf, &recvd, &session->tls_properties);
                if (recvd > 0) {
                    assert("More data after handshake");
                }
                if (ret == PTLS_ERROR_IN_PROGRESS) {
                    assert("Fragmented handshake"); // TODO: Handle fragmented handshake
                } else {
                    if (ret == 0) {
                        /* ClientHello */
                        if (!ptls_handshake_is_complete(session->tls)) {
                            assert(session->tls_properties.server.tls_session_id.len > 0);
                            assert(session->tls_properties.collected_extensions == NULL);
                            bool has_rapido_hello = false;
                            for (ptls_raw_extension_t *extension = session->tls_properties.additional_extensions;
                                 extension->type != UINT16_MAX && !has_rapido_hello; extension++) {
                                if (extension->type == TLS_RAPIDO_HELLO_EXT) {
                                    has_rapido_hello = true;
                                }
                            }
                            assert(has_rapido_hello);
                        }
                        assert(send(connection->socket, handshake_buffer.base, handshake_buffer.off, 0) == handshake_buffer.off);
                        /* ClientFinished */
                        if (ptls_handshake_is_complete(session->tls)) {
                            int tls_session_id_sequence = -1;
                            rapido_array_iter(&session->tls_session_ids, uint8_t * tls_session_id, {
                                if (memcmp(tls_session_id, session->tls_properties.server.tls_session_id.base,
                                           session->tls_properties.server.tls_session_id.len) == 0) {
                                    tls_session_id_sequence = i;
                                    break;
                                }
                            });
                            if (tls_session_id_sequence == -1) {
                                assert(session->tls_session_ids.size == 0);
                                memcpy(rapido_array_add(&session->tls_session_ids, 0), session->tls_properties.server.tls_session_id.base,
                                       session->tls_properties.server.tls_session_id.len);
                                tls_session_id_sequence = 0;
                            }
                            rapido_connection_t *new_connection = rapido_array_add(&session->connections, tls_session_id_sequence);
                            new_connection->socket = connection->socket;
                            new_connection->connection_id = tls_session_id_sequence;
                            // TODO: Find the addresses it uses
                            rapido_application_notification_t *notification = rapido_queue_push(&session->pending_notifications);
                            notification->notification_type = rapido_new_connection;
                            notification->connection_id = new_connection->connection_id;
                            rapido_array_delete(&session->server.pending_connections, connections_index[i]);
                        }
                    } else {
                        WARNING("Pending connection %zu returned pTLS error code %d during handshake\n", connections_index[i], ret);
                        close(connection->socket);
                        rapido_array_delete(&session->server.pending_connections, connections_index[i]);
                    }
                    // TODO: Free TLS state if JOIN
                }
            }
        }
    } else if (!ptls_handshake_is_complete(session->tls)) {
        size_t nfds = session->connections.size;
        struct pollfd fds[nfds]; // TODO: cache this
        size_t connections_index[nfds];
        nfds = 0;
        rapido_array_iter(&session->connections, rapido_connection_t *connection, {
            fds[nfds].fd = connection->socket;
            fds[nfds].events = POLLIN;
            connections_index[nfds] = i;
            nfds++;
        });
        int ret = poll(fds, nfds, 0);
        assert(ret >= 0 || errno == EINTR);

        for (int i = 0; i < nfds && ret; i++) {
            if (fds[i].revents == POLLIN) {
                uint8_t recvbuf[TLS_MAX_ENCRYPTED_RECORD_SIZE];
                size_t recvd = recv(fds[i].fd, recvbuf, sizeof(recvbuf), 0);
                ptls_buffer_t handshake_buffer = {0};
                ptls_buffer_init(&handshake_buffer, "", 0);
                ret = ptls_handshake(session->tls, &handshake_buffer, recvbuf, &recvd, &session->tls_properties);
                if (recvd > 0) {
                    assert("More data after handshake");
                }
                if (ret == PTLS_ERROR_IN_PROGRESS) {
                    assert("Fragmented handshake"); // TODO: Handle fragmented handshake
                }
                assert(ret == 0);
                assert(send(fds[i].fd, handshake_buffer.base, handshake_buffer.off, 0) == handshake_buffer.off);
            }
        }
    }
}

int rapido_close(rapido_t *session) {
    rapido_array_iter(&session->connections, rapido_connection_t *connection,{
        if (connection->socket > -1) {
            close(connection->socket);
        }
    });
    free(session->tls_properties.additional_extensions);
    ptls_free(session->tls);
    rapido_array_free(&session->connections);
    rapido_array_free(&session->streams);
    rapido_array_free(&session->local_addresses);
    rapido_array_free(&session->remote_addresses);
    rapido_array_free(&session->tls_session_ids);
    rapido_queue_free(&session->pending_notifications);
    if (session->is_server) {
        rapido_array_iter(&session->server.listen_sockets, int *socket,{
            if (*socket > -1) {
                close(*socket);
            }
        });
        rapido_array_free(&session->server.listen_sockets);
        rapido_array_iter(&session->server.pending_connections, rapido_pending_connection_t *connection,{
            if (connection->socket > -1) {
                close(connection->socket);
            }
        });
        rapido_array_free(&session->server.pending_connections);
    }
}
