#include <picotest.h>
#include "test.h"
#include "rapido.h"
#include "rapido_internals.h"
#include "util.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#define min(a, b) ((a) < (b) ? (a) : (b))

#define RUN_NETWORK_TIMEOUT_DEFAULT 500
#define RUN_NETWORK_TIMEOUT_SHORT 20

#define DEFAULT_TCPLS_SESSION_ID_AMOUNT 4

#define SESSION(server, index) ((rapido_session_t *)rapido_array_get(&(server)->sessions, (index)))

uint8_t random_data[16384] = {42};

uint8_t *stream_produce_random_data(rapido_session_t *session, rapido_stream_id_t stream_id, void *producer_ctx, uint64_t offset,
                                    size_t *len) {
    *len = min(*len, sizeof(random_data));
    return random_data;
}

void test_local_address_api() {
    rapido_session_t *s = rapido_new_session(ctx, false, "localhost", NULL);
    struct sockaddr_in a, b;
    memset(&a, 1, sizeof(a));
    memset(&b, 2, sizeof(b));
    rapido_address_id_t id_a = rapido_add_address(s, (struct sockaddr *)&a, sizeof(a));
    rapido_address_id_t id_b = rapido_add_address(s, (struct sockaddr *)&b, sizeof(a));
    ok(id_a != id_b);
    ok(rapido_remove_address(s, id_a) == 0);
    ok(rapido_remove_address(s, id_b) == 0);
    ok(rapido_remove_address(s, 42) != 0);
    rapido_address_id_t id_c = rapido_add_address(s, (struct sockaddr *)&a, sizeof(a));
    ok(id_a != id_c && id_b != id_c);
    ok(rapido_remove_address(s, 42) != 0);
    ok(rapido_remove_address(s, id_c) == 0);
    rapido_session_free(s);
    free(s);
}

void test_local_address_server() {
    rapido_session_t *s = rapido_new_session(ctx, true, "localhost", NULL);
    struct sockaddr_in a;
    struct sockaddr_in6 b;
    socklen_t len_a = sizeof(a), len_b = sizeof(b);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&b, &len_b, "localhost", "4443", AF_INET6, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(len_a == sizeof(a) && len_b == sizeof(b));
    rapido_address_id_t id_a = rapido_add_address(s, (struct sockaddr *)&a, len_a);
    rapido_address_id_t id_b = rapido_add_address(s, (struct sockaddr *)&b, len_b);
    ok(id_a != id_b);
    ok(rapido_remove_address(s, id_a) == 0);
    ok(rapido_remove_address(s, id_b) == 0);
    ok(rapido_remove_address(s, 42) != 0);
    rapido_address_id_t id_c = rapido_add_address(s, (struct sockaddr *)&a, sizeof(a));
    ok(id_a != id_c && id_b != id_c);
    ok(rapido_remove_address(s, 42) != 0);
    ok(rapido_remove_address(s, id_c) == 0);
    rapido_session_free(s);
    free(s);
}

void test_simple_stream_transfer() {
    rapido_session_t *client = rapido_new_session(ctx, false, "localhost", stderr);
    rapido_session_t *server = rapido_new_session(ctx, true, "localhost", stderr);
    struct sockaddr_in a, b;
    socklen_t len_a = sizeof(a), len_b = sizeof(b);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&b, &len_b, "localhost", "14443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    rapido_address_id_t s_aid_a = rapido_add_address(server, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_b = rapido_add_address(client, (struct sockaddr *)&b, len_b);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);
    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size > 0);
    rapido_application_notification_t *notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    ok(ptls_handshake_is_complete(server->tls));

    rapido_stream_id_t stream_id = rapido_open_stream(client);
    ok(rapido_add_to_stream(client, stream_id, "Hello, world!", 13) == 0);
    ok(rapido_close_stream(client, stream_id) == 0);
    ok(rapido_attach_stream(client, stream_id, c_cid) == 0);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 3);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_stream);
    ok(notification->stream_id == stream_id);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_stream_has_data);
    ok(notification->stream_id == stream_id);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_stream_closed);
    ok(notification->stream_id == stream_id);
    size_t read_len = 5;
    char *str = rapido_read_stream(server, stream_id, &read_len);
    ok(read_len == 5);
    ok(memcmp(str, "Hello", read_len) == 0);
    read_len = 1000;
    str = rapido_read_stream(server, stream_id, &read_len);
    ok(read_len == 8);
    ok(memcmp(str, ", world!", read_len) == 0);

    rapido_stream_id_t server_stream_id = rapido_open_stream(server);
    ok(stream_id != server_stream_id);
    ok(rapido_add_to_stream(server, server_stream_id, "Hello", 5) == 0);
    ok(rapido_add_to_stream(server, server_stream_id, ", world!", 8) == 0);
    ok(rapido_close_stream(server, server_stream_id) == 0);
    ok(rapido_attach_stream(server, server_stream_id, s_cid) == 0);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(client->pending_notifications.size == 3 + (DEFAULT_TCPLS_SESSION_ID_AMOUNT - 1));
    for (int i = 1; i < DEFAULT_TCPLS_SESSION_ID_AMOUNT; i++) {
        notification = rapido_queue_pop(&client->pending_notifications);
        ok(notification->notification_type == rapido_new_connection_token);
    }
    notification = rapido_queue_pop(&client->pending_notifications);
    ok(notification->notification_type == rapido_new_stream);
    ok(notification->stream_id == server_stream_id);
    notification = rapido_queue_pop(&client->pending_notifications);
    ok(notification->notification_type == rapido_stream_has_data);
    ok(notification->stream_id == server_stream_id);
    notification = rapido_queue_pop(&client->pending_notifications);
    ok(notification->notification_type == rapido_stream_closed);
    ok(notification->stream_id == server_stream_id);
    read_len = 1000;
    str = rapido_read_stream(client, server_stream_id, &read_len);
    ok(read_len == 13);
    ok(memcmp(str, "Hello, world!", read_len) == 0);

    ok(rapido_add_to_stream(client, server_stream_id, "Hello, server!", 14) == 0);
    ok(rapido_attach_stream(client, server_stream_id, c_cid) == 0);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 1);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_stream_has_data);
    ok(notification->stream_id == server_stream_id);
    ok(rapido_close_stream(client, server_stream_id) == 0);
    ok(server->pending_notifications.size == 0);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 1);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_stream_closed);
    ok(notification->stream_id == server_stream_id);

    rapido_stream_id_t second_stream_id = rapido_open_stream(client);
    ok(stream_id != second_stream_id);
    ok(second_stream_id != server_stream_id);
    ok(rapido_add_to_stream(client, second_stream_id, "Stream reordering test", 22) == 0);
    ok(rapido_close_stream(client, second_stream_id) == 0);
    uint8_t stream_frame_buf1[35];
    size_t stream_frame_len1 = sizeof(stream_frame_buf1);
    uint8_t stream_frame_buf2[35];
    size_t stream_frame_len2 = sizeof(stream_frame_buf2);
    ok(rapido_prepare_stream_frame(client, rapido_array_get(&client->streams, second_stream_id), stream_frame_buf1,
                                   &stream_frame_len1) == 0);
    ok(rapido_prepare_stream_frame(client, rapido_array_get(&client->streams, second_stream_id), stream_frame_buf2,
                                   &stream_frame_len2) == 0);
    ok(stream_frame_len1 <= sizeof(stream_frame_buf1));
    ok(stream_frame_len2 <= sizeof(stream_frame_buf2));
    ok(stream_frame_len1 > 0 && stream_frame_len2 > 0);
    uint8_t ciphertext[100];
    ptls_buffer_t sendbuf = {0};
    ptls_buffer_init(&sendbuf, ciphertext, sizeof(ciphertext));
    assert(ptls_send(client->tls, &sendbuf, stream_frame_buf2, stream_frame_len2) == 0);
    assert(send(((rapido_connection_t *)rapido_array_get(&client->connections, c_cid))->socket, sendbuf.base, sendbuf.off, 0) ==
           sendbuf.off);
    ptls_buffer_init(&sendbuf, ciphertext, sizeof(ciphertext));
    assert(ptls_send(client->tls, &sendbuf, stream_frame_buf1, stream_frame_len1) == 0);
    assert(send(((rapido_connection_t *)rapido_array_get(&client->connections, c_cid))->socket, sendbuf.base, sendbuf.off, 0) ==
           sendbuf.off);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 4);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_stream);
    ok(notification->stream_id == second_stream_id);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_stream_has_data);
    ok(notification->stream_id == second_stream_id);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_stream_closed);
    ok(notification->stream_id == second_stream_id);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_stream_has_data);
    ok(notification->stream_id == second_stream_id);
    read_len = 1000;
    str = rapido_read_stream(server, second_stream_id, &read_len);
    ok(read_len == 22);
    ok(memcmp(str, "Stream reordering test", read_len) == 0);

    rapido_session_free(client);
    rapido_session_free(server);
    free(client);
    free(server);
}

void test_range_list() {
    rapido_range_list_t list;
    memset(&list, 0, sizeof(rapido_range_list_t));
    ok(rapido_add_range(&list, 0, 1) == 0);
    uint64_t l, h;
    rapido_peek_range(&list, &l, &h);
    ok(l == 0 && h == 1);

    ok(rapido_add_range(&list, 2, 3) == 0);
    rapido_peek_range(&list, &l, &h);
    ok(l == 0 && h == 1);

    ok(rapido_add_range(&list, 1, 2) == 0);
    rapido_peek_range(&list, &l, &h);
    ok(l == 0 && h == 3);

    ok(rapido_trim_range(&list, 2) == 2);
    rapido_peek_range(&list, &l, &h);
    ok(l == 2 && h == 3);
    ok(rapido_trim_range(&list, 10) == 3);
    ok(rapido_trim_range(&list, 10) == -1);
}

void test_range_buffer() {
    rapido_range_buffer_t buf;
    size_t str_len = strlen("Hello, world!");
    rapido_range_buffer_init(&buf, str_len);
    ok(rapido_range_buffer_write(&buf, 7, "world!", strlen("world!")) == 0);
    size_t len = -1;
    ok(rapido_range_buffer_get(&buf, &len) == NULL);
    ok(len == 0);
    ok(rapido_range_buffer_write(&buf, 0, "Hello, ", strlen("Hello, ")) == 0);
    len = -1;
    void *ptr = rapido_range_buffer_get(&buf, &len);
    ok(ptr != NULL && len == str_len);
    ok(memcmp(ptr, "Hello, world!", str_len) == 0);
    rapido_range_buffer_free(&buf);

    rapido_range_buffer_init(&buf, str_len);
    ok(rapido_range_buffer_write(&buf, 7, "world!", strlen("world!")) == 0);
    len = -1;
    ok(rapido_range_buffer_get(&buf, &len) == NULL);
    ok(len == 0);
    ok(rapido_range_buffer_write(&buf, 0, "Hel", strlen("Hel")) == 0);
    len = -1;
    ok(rapido_range_buffer_get(&buf, &len) != NULL);
    ok(len == strlen("Hel"));
    len = -1;
    ok(rapido_range_buffer_write(&buf, 3, "lo, ", strlen("lo, ")) == 0);
    ptr = rapido_range_buffer_get(&buf, &len);
    ok(ptr != NULL && len == str_len - strlen("Hel"));
    ok(memcmp(ptr, "lo, world!", str_len - strlen("Hel")) == 0);
    rapido_range_buffer_free(&buf);
}

void test_set() {
    rapido_set_t set = { 0 };
    ok(rapido_set_size(&set) == 0);
    rapido_set_add(&set, 0);
    ok(rapido_set_has(&set, 0));
    ok(rapido_set_has(&set, 1) == 0);
    ok(rapido_set_size(&set) == 1);
    rapido_set_remove(&set, 0);
    ok(rapido_set_has(&set, 0) == 0);
    ok(rapido_set_size(&set) == 0);
    rapido_set_add(&set, 100);
    ok(rapido_set_has(&set, 100));
    ok(rapido_set_size(&set) == 1);
    rapido_set_add(&set, 128);
    ok(rapido_set_has(&set, 128));
    ok(rapido_set_size(&set) == 2);
    rapido_set_remove(&set, 100);
    ok(rapido_set_size(&set) == 1);
    rapido_set_add(&set, 180);
    ok(rapido_set_size(&set) == 2);
    ok(rapido_set_has(&set, 128));
    ok(rapido_set_has(&set, 180));
}

void test_large_transfer() {
    rapido_session_t *client = rapido_new_session(ctx, false, "localhost", stderr);
    rapido_session_t *server = rapido_new_session(ctx, true, "localhost", stderr);
    struct sockaddr_in a;
    socklen_t len_a = sizeof(a);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    rapido_address_id_t s_aid_a = rapido_add_address(server, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_b = 0;
    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size > 0);
    rapido_application_notification_t *notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    ok(ptls_handshake_is_complete(server->tls));

    rapido_stream_id_t stream_id = rapido_open_stream(client);
    uint8_t stream_data[1000000];
    ok(getrandom(stream_data, sizeof(stream_data), 0) == sizeof(stream_data));
    ok(rapido_add_to_stream(client, stream_id, stream_data, sizeof(stream_data)) == 0);
    ok(rapido_close_stream(client, stream_id) == 0);
    ok(rapido_attach_stream(client, stream_id, c_cid) == 0);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 64);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_stream);
    ok(notification->stream_id == stream_id);
    while (server->pending_notifications.size > 1) {
        notification = rapido_queue_pop(&server->pending_notifications);
        ok(notification->notification_type == rapido_stream_has_data);
        ok(notification->stream_id == stream_id);
    }
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_stream_closed);
    ok(notification->stream_id == stream_id);

    size_t read_len = 2 * sizeof(stream_data);
    void *ptr = rapido_read_stream(server, stream_id, &read_len);
    ok(read_len == sizeof(stream_data));
    ok(memcmp(ptr, stream_data, read_len) == 0);

    rapido_session_free(client);
    rapido_session_free(server);
    free(client);
    free(server);
}

void test_join() {
    rapido_session_t *client = rapido_new_session(ctx, false, "localhost", stderr);
    rapido_session_t *server = rapido_new_session(ctx, true, "localhost", stderr);
    struct sockaddr_in a, b, c;
    socklen_t len_a = sizeof(a), len_b = sizeof(b), len_c = sizeof(c);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&b, &len_b, "localhost", "14443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&c, &len_c, "localhost", "14444", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    rapido_address_id_t s_aid_a = rapido_add_address(server, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_b = rapido_add_address(client, (struct sockaddr *)&b, len_b);
    rapido_address_id_t c_aid_c = rapido_add_address(client, (struct sockaddr *)&c, len_c);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);
    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(server->tls));
    ok(server->pending_notifications.size == 2);
    rapido_application_notification_t *notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_remote_address);
    ok(notification->address_id == c_aid_c);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);

    rapido_connection_id_t c_cid2 = rapido_create_connection(client, c_aid_c, c_aid_a);
    ok(c_cid != c_cid2);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 1);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid2 = notification->connection_id;

    rapido_stream_id_t stream_id = rapido_open_stream(client);
    uint8_t stream_data[1000000];
    ok(getrandom(stream_data, sizeof(stream_data), 0) == sizeof(stream_data));
    ok(rapido_add_to_stream(client, stream_id, stream_data, sizeof(stream_data)) == 0);
    ok(rapido_close_stream(client, stream_id) == 0);
    ok(rapido_attach_stream(client, stream_id, c_cid) == 0);
    ok(rapido_attach_stream(client, stream_id, c_cid2) == 0);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    size_t client_send_buf[2];
    size_t client_send_recs[2];
    rapido_array_iter(&client->connections, i, rapido_connection_t * connection, {
        client_send_buf[connection->connection_id] = connection->send_buffer.size;
        client_send_recs[connection->connection_id] = connection->sent_records.size;
    });
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 64);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_stream);
    ok(notification->stream_id == stream_id);
    bool stream_closed = false;
    for (int i = 0; i < 63; i++) {
        notification = rapido_queue_pop(&server->pending_notifications);
        ok(notification->notification_type == rapido_stream_has_data ||
           (!stream_closed && notification->notification_type == rapido_stream_closed));
        ok(notification->stream_id == stream_id);
        if (!stream_closed) {
            stream_closed = notification->notification_type == rapido_stream_closed;
        }
    }
    ok(stream_closed);
    ok(server->pending_notifications.size == 0);
    rapido_array_iter(&server->connections, i, rapido_connection_t * connection, { ok(!connection->require_ack); });
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_array_iter(&client->connections, i, rapido_connection_t * connection, { ok(!connection->require_ack); });
    rapido_array_iter(&client->connections, i, rapido_connection_t * connection, {
        ok(connection->send_buffer.size < client_send_buf[connection->connection_id]);
        ok(connection->sent_records.size < client_send_recs[connection->connection_id]);
    });

    rapido_connection_t *s_c1 = rapido_array_get(&server->connections, s_cid);
    rapido_connection_t *s_c2 = rapido_array_get(&server->connections, s_cid2);

    ok(s_c1->stats.bytes_received > 0 && s_c2->stats.bytes_received > 0);

    size_t read_len = 2 * sizeof(stream_data);
    void *ptr = rapido_read_stream(server, stream_id, &read_len);
    ok(read_len == sizeof(stream_data));
    ok(memcmp(ptr, stream_data, read_len) == 0);

    read_len = 2 * sizeof(stream_data);
    ptr = rapido_read_stream(server, stream_id, &read_len);
    ok(read_len == 0);
    ok(ptr == NULL);

    rapido_session_free(client);
    rapido_session_free(server);
    free(client);
    free(server);
}

void test_failover() {
    rapido_session_t *client = rapido_new_session(ctx, false, "localhost", stderr);
    rapido_session_t *server = rapido_new_session(ctx, true, "localhost", stderr);
    struct sockaddr_in a, b, c;
    socklen_t len_a = sizeof(a), len_b = sizeof(b), len_c = sizeof(c);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    rapido_address_id_t s_aid_a = rapido_add_address(server, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_b = 0, c_aid_c = 1;
    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 1);
    rapido_application_notification_t *notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    ok(ptls_handshake_is_complete(server->tls));
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);

    rapido_connection_id_t c_cid2 = rapido_create_connection(client, c_aid_c, c_aid_a);
    ok(c_cid != c_cid2);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 2);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid2 = notification->connection_id;
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_remote_address);

    rapido_stream_id_t stream_id = rapido_open_stream(server);
    uint8_t stream_data[100000];
    ok(getrandom(stream_data, sizeof(stream_data), 0) == sizeof(stream_data));
    ok(rapido_add_to_stream(server, stream_id, stream_data, sizeof(stream_data)) == 0);
    ok(rapido_close_stream(server, stream_id) == 0);
    ok(rapido_attach_stream(server, stream_id, s_cid) == 0);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);

    ok(rapido_close_connection(client, c_cid) == 0);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);

    ok(server->pending_notifications.size == 1);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_connection_closed);
    ok(notification->connection_id == s_cid);
    rapido_set_t connections = { 0 };
    rapido_set_add(&connections, s_cid2);
    ok(rapido_retransmit_connection(server, notification->connection_id, connections) == 0);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);

    ok(client->pending_notifications.size == 9 + (DEFAULT_TCPLS_SESSION_ID_AMOUNT - 1));
    for (int i = 1; i < DEFAULT_TCPLS_SESSION_ID_AMOUNT; i++) {
        notification = rapido_queue_pop(&client->pending_notifications);
        ok(notification->notification_type == rapido_new_connection_token);
    }
    notification = rapido_queue_pop(&client->pending_notifications);
    ok(notification->notification_type == rapido_new_stream);
    ok(notification->stream_id == stream_id);
    bool stream_closed = false;
    for (int i = 0; i < 8; i++) {
        notification = rapido_queue_pop(&client->pending_notifications);
        ok(notification->notification_type == rapido_stream_has_data ||
           (!stream_closed && notification->notification_type == rapido_stream_closed));
        ok(notification->stream_id == stream_id);
        if (!stream_closed) {
            stream_closed = notification->notification_type == rapido_stream_closed;
        }
    }
    ok(stream_closed);
    ok(client->pending_notifications.size == 0);

    rapido_session_free(client);
    rapido_session_free(server);
    free(client);
    free(server);
}

void test_multiple_streams() {
    rapido_session_t *client = rapido_new_session(ctx, false, "localhost", stderr);
    rapido_session_t *server = rapido_new_session(ctx, true, "localhost", stderr);
    struct sockaddr_in a;
    socklen_t len_a = sizeof(a);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    rapido_address_id_t s_aid_a = rapido_add_address(server, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_b = 0;
    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size > 0);
    rapido_application_notification_t *notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    ok(ptls_handshake_is_complete(server->tls));

    size_t n_streams = 160;
    rapido_stream_id_t streams[n_streams];

    for (int i = 0; i < n_streams; i++) {
        streams[i] = rapido_open_stream(client);
        char buf[128];
        size_t data_len = snprintf(buf, sizeof(buf), "Hello stream %d", i * 2);
        ok(rapido_add_to_stream(client, streams[i], buf, data_len) == 0);
        ok(rapido_attach_stream(client, streams[i], c_cid) == 0);
        ok(rapido_close_stream(client, streams[i]) == 0);
        rapido_run_network(client, RUN_NETWORK_TIMEOUT_SHORT);
        rapido_run_network(client, RUN_NETWORK_TIMEOUT_SHORT);
    }

    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);

    bool streams_received[n_streams];
    bool streams_closed[n_streams];
    memset(streams_received, false, sizeof(streams_received));
    memset(streams_closed, false, sizeof(streams_closed));
    while (server->pending_notifications.size) {
        notification = rapido_queue_pop(&server->pending_notifications);
        if (notification->notification_type == rapido_new_stream) {
            ok(!streams_received[notification->stream_id / 2]);
            streams_received[notification->stream_id / 2] = true;
        } else if (notification->notification_type == rapido_stream_closed) {
            ok(!streams_closed[notification->stream_id / 2]);
            streams_closed[notification->stream_id / 2] = true;
            size_t len = UINT64_MAX;
            char *ptr = rapido_read_stream(server, notification->stream_id, &len);
            char buf[128];
            size_t data_len = snprintf(buf, sizeof(buf), "Hello stream %d", notification->stream_id);
            ok(len == data_len);
            ok(memcmp(ptr, buf, len) == 0);
        }
    }

    for (int i = 0; i < n_streams; i++) {
        ok(streams_received[i] && streams_closed[i]);
    }

    rapido_session_free(client);
    rapido_session_free(server);
    free(client);
    free(server);
}

void test_large_buffers() {
    rapido_session_t *client = rapido_new_session(ctx, false, "localhost", NULL);
    rapido_session_t *server = rapido_new_session(ctx, true, "localhost", NULL);
    struct sockaddr_in a;
    socklen_t len_a = sizeof(a);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    rapido_address_id_t s_aid_a = rapido_add_address(server, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_b = 0;
    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size > 0);
    rapido_application_notification_t *notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    ok(ptls_handshake_is_complete(server->tls));

    rapido_stream_id_t stream_id = rapido_open_stream(client);
    ok(rapido_set_stream_producer(client, stream_id, stream_produce_random_data, NULL) == 0);
    rapido_stream_t *stream = rapido_array_get(&client->streams, stream_id);
    stream->write_fin = 1000000000;
    stream->fin_set = true;
    ok(rapido_attach_stream(client, stream_id, c_cid) == 0);

    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);

    size_t total_size_read = 0;
    bool stream_closed = false;
    while (!stream_closed) {
        while (server->pending_notifications.size) {
            notification = rapido_queue_pop(&server->pending_notifications);
            if (notification->notification_type == rapido_stream_closed) {
                size_t len;
                do {
                    len = UINT64_MAX;
                    rapido_read_stream(server, notification->stream_id, &len);
                    total_size_read += len;
                } while (len > 0);
                stream_closed = true;
            }
        }
        rapido_run_network(client, RUN_NETWORK_TIMEOUT_SHORT);
        rapido_run_network(server, RUN_NETWORK_TIMEOUT_SHORT);
    }
    ok(total_size_read == stream->write_fin);

    rapido_session_free(client);
    rapido_session_free(server);
    free(client);
    free(server);
}

void test_multiple_server_addresses() {
    rapido_session_t *client = rapido_new_session(ctx, false, "localhost", stderr);
    rapido_session_t *server = rapido_new_session(ctx, true, "localhost", stderr);
    struct sockaddr_storage a, b, c, d;
    socklen_t len_a = sizeof(a), len_b = sizeof(b), len_c = sizeof(c), len_d = sizeof(d);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&b, &len_b, "localhost", "14443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&c, &len_c, "localhost", "4444", AF_INET6, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&d, &len_d, "localhost", "14444", AF_INET6, SOCK_STREAM, IPPROTO_TCP) == 0);
    rapido_address_id_t s_aid_a = rapido_add_address(server, (struct sockaddr *)&a, len_a);
    rapido_address_id_t s_aid_c = rapido_add_address(server, (struct sockaddr *)&c, len_c);
    rapido_address_id_t c_aid_b = rapido_add_address(client, (struct sockaddr *)&b, len_b);
    rapido_address_id_t c_aid_d = rapido_add_address(client, (struct sockaddr *)&d, len_d);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);

    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 2);
    rapido_application_notification_t *notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_remote_address);
    ok(ptls_handshake_is_complete(server->tls));
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(client->pending_notifications.size == 1 + (DEFAULT_TCPLS_SESSION_ID_AMOUNT - 1));
    for (int i = 1; i < DEFAULT_TCPLS_SESSION_ID_AMOUNT; i++) {
        notification = rapido_queue_pop(&client->pending_notifications);
        ok(notification->notification_type == rapido_new_connection_token);
    }
    notification = rapido_queue_pop(&client->pending_notifications);
    ok(notification->notification_type == rapido_new_remote_address);
    rapido_address_id_t c_aid_c = notification->address_id;

    rapido_connection_id_t c_cid2 = rapido_create_connection(client, c_aid_d, c_aid_c);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 1);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid2 = notification->connection_id;
    ok(s_cid != s_cid2);

    rapido_stream_id_t stream_id = rapido_open_stream(client);
    uint8_t stream_data[1000000];
    ok(getrandom(stream_data, sizeof(stream_data), 0) == sizeof(stream_data));
    ok(rapido_add_to_stream(client, stream_id, stream_data, sizeof(stream_data)) == 0);
    ok(rapido_close_stream(client, stream_id) == 0);
    ok(rapido_attach_stream(client, stream_id, c_cid) == 0);
    ok(rapido_attach_stream(client, stream_id, c_cid2) == 0);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    size_t client_send_buf[2];
    size_t client_send_recs[2];
    rapido_array_iter(&client->connections, i, rapido_connection_t * connection, {
        client_send_buf[connection->connection_id] = connection->send_buffer.size;
        client_send_recs[connection->connection_id] = connection->sent_records.size;
    });
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 64);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_stream);
    ok(notification->stream_id == stream_id);
    bool stream_closed = false;
    for (int i = 0; i < 63; i++) {
        notification = rapido_queue_pop(&server->pending_notifications);
        ok(notification->notification_type == rapido_stream_has_data ||
           (!stream_closed && notification->notification_type == rapido_stream_closed));
        ok(notification->stream_id == stream_id);
        if (!stream_closed) {
            stream_closed = notification->notification_type == rapido_stream_closed;
        }
    }
    ok(stream_closed);
    ok(server->pending_notifications.size == 0);
    rapido_array_iter(&server->connections, i, rapido_connection_t * connection, { ok(!connection->require_ack); });
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_array_iter(&client->connections, i, rapido_connection_t * connection, { ok(!connection->require_ack); });
    rapido_array_iter(&client->connections, i, rapido_connection_t * connection, {
        ok(connection->send_buffer.size < client_send_buf[connection->connection_id]);
        ok(connection->sent_records.size < client_send_recs[connection->connection_id]);
    });

    rapido_connection_t *s_c1 = rapido_array_get(&server->connections, s_cid);
    rapido_connection_t *s_c2 = rapido_array_get(&server->connections, s_cid2);

    ok(s_c1->stats.bytes_received > 0 && s_c2->stats.bytes_received > 0);
    ok(s_c1->remote_address_id == c_aid_b && s_c2->remote_address_id == c_aid_d);

    size_t read_len = 2 * sizeof(stream_data);
    void *ptr = rapido_read_stream(server, stream_id, &read_len);
    ok(read_len == sizeof(stream_data));
    ok(memcmp(ptr, stream_data, read_len) == 0);

    read_len = 2 * sizeof(stream_data);
    ptr = rapido_read_stream(server, stream_id, &read_len);
    ok(read_len == 0);
    ok(ptr == NULL);

    rapido_session_free(client);
    rapido_session_free(server);
    free(client);
    free(server);
}

void test_server_new_session() {
    rapido_server_t *server = rapido_new_server(ctx, "localhost", stderr);
    rapido_session_t *client = rapido_new_session(ctx, false, "localhost", stderr);
    struct sockaddr_in a, b, c;
    socklen_t len_a = sizeof(a), len_b = sizeof(b), len_c = sizeof(c);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&b, &len_b, "localhost", "14443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&c, &len_c, "localhost", "14444", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    rapido_address_id_t s_aid_a = rapido_add_server_address(server, (struct sockaddr *)&a, len_a, true);
    rapido_address_id_t c_aid_b = rapido_add_address(client, (struct sockaddr *)&b, len_b);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);
    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_server_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_server_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);

    size_t server_session_index;
    rapido_application_notification_t *notification = rapido_next_server_notification(server, &server_session_index);
    ok(notification && notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    {
        rapido_session_t *server_session = SESSION(server, server_session_index);
        ok(ptls_handshake_is_complete(server_session->tls));
        rapido_stream_id_t server_stream_id = rapido_open_stream(server_session);
        ok(rapido_add_to_stream(server_session, server_stream_id, "Hello, world!", 13) == 0);
        ok(rapido_close_stream(server_session, server_stream_id) == 0);
        ok(rapido_attach_stream(server_session, server_stream_id, s_cid) == 0);
        rapido_run_network(server_session, RUN_NETWORK_TIMEOUT_DEFAULT);
        rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
        ok(client->pending_notifications.size == 3 + (DEFAULT_TCPLS_SESSION_ID_AMOUNT - 1));
        for (int i = 1; i < DEFAULT_TCPLS_SESSION_ID_AMOUNT; i++) {
            notification = rapido_queue_pop(&client->pending_notifications);
            ok(notification->notification_type == rapido_new_connection_token);
        }
        notification = rapido_queue_pop(&client->pending_notifications);
        ok(notification->notification_type == rapido_new_stream);
        ok(notification->stream_id == server_stream_id);
        notification = rapido_queue_pop(&client->pending_notifications);
        ok(notification->notification_type == rapido_stream_has_data);
        ok(notification->stream_id == server_stream_id);
        notification = rapido_queue_pop(&client->pending_notifications);
        ok(notification->notification_type == rapido_stream_closed);
        ok(notification->stream_id == server_stream_id);
        size_t read_len = 1000;
        char *str = rapido_read_stream(client, server_stream_id, &read_len);
        ok(read_len == 13);
        ok(memcmp(str, "Hello, world!", read_len) == 0);
    }

    rapido_session_t *client2 = rapido_new_session(ctx, false, "localhost", stderr);
    rapido_address_id_t c2_aid_c = rapido_add_address(client2, (struct sockaddr *)&c, len_c);
    rapido_address_id_t c2_aid_a = rapido_add_remote_address(client2, (struct sockaddr *)&a, len_a);
    rapido_connection_id_t c2_cid = rapido_create_connection(client2, c2_aid_c, c2_aid_a);
    rapido_run_server_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client2, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client2->tls));
    rapido_run_server_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);

    size_t server_session2_index;
    notification = rapido_next_server_notification(server, &server_session2_index);
    ok(notification && notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s2_cid = notification->connection_id;

    {
        rapido_session_t *server_session2 = SESSION(server, server_session2_index);
        ok(ptls_handshake_is_complete(server_session2->tls));
        rapido_stream_id_t server_stream_id = rapido_open_stream(server_session2);
        ok(rapido_add_to_stream(server_session2, server_stream_id, "Hello, world!", 13) == 0);
        ok(rapido_close_stream(server_session2, server_stream_id) == 0);
        ok(rapido_attach_stream(server_session2, server_stream_id, s_cid) == 0);
        rapido_run_network(server_session2, RUN_NETWORK_TIMEOUT_DEFAULT);
        rapido_run_network(client2, RUN_NETWORK_TIMEOUT_DEFAULT);
        ok(client2->pending_notifications.size == 3 + (DEFAULT_TCPLS_SESSION_ID_AMOUNT - 1));
            for (int i = 1; i < DEFAULT_TCPLS_SESSION_ID_AMOUNT; i++) {
            notification = rapido_queue_pop(&client2->pending_notifications);
            ok(notification->notification_type == rapido_new_connection_token);
        }
        notification = rapido_queue_pop(&client2->pending_notifications);
        ok(notification->notification_type == rapido_new_stream);
        ok(notification->stream_id == server_stream_id);
        notification = rapido_queue_pop(&client2->pending_notifications);
        ok(notification->notification_type == rapido_stream_has_data);
        ok(notification->stream_id == server_stream_id);
        notification = rapido_queue_pop(&client2->pending_notifications);
        ok(notification->notification_type == rapido_stream_closed);
        ok(notification->stream_id == server_stream_id);
        size_t read_len = 1000;
        char *str = rapido_read_stream(client2, server_stream_id, &read_len);
        ok(read_len == 13);
        ok(memcmp(str, "Hello, world!", read_len) == 0);
    }

    rapido_session_free(client);
    rapido_session_free(client2);
    rapido_server_free(server);
    free(client);
    free(client2);
    free(server);
}

void test_server_addresses() {
    rapido_server_t *server = rapido_new_server(ctx, "localhost", stderr);
    rapido_session_t *client = rapido_new_session(ctx, false, "localhost", stderr);
    rapido_session_t *client2 = rapido_new_session(ctx, false, "localhost", stderr);
    struct sockaddr_in a, b, c, d;
    socklen_t len_a = sizeof(a), len_b = sizeof(b), len_c = sizeof(c), len_d = sizeof(d);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&b, &len_b, "localhost", "14443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&c, &len_c, "localhost", "14444", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *)&d, &len_d, "localhost", "4444", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);

    rapido_address_id_t s_aid_a = rapido_add_server_address(server, (struct sockaddr *)&a, len_a, true);
    rapido_address_id_t c_aid_b = rapido_add_address(client, (struct sockaddr *)&b, len_b);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);
    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_server_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_server_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);

    size_t server_session_index;
    rapido_application_notification_t *notification = rapido_next_server_notification(server, &server_session_index);
    ok(notification && notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    ok(ptls_handshake_is_complete(SESSION(server, server_session_index)->tls));
    rapido_run_network(SESSION(server, server_session_index), RUN_NETWORK_TIMEOUT_DEFAULT);

    rapido_address_id_t c2_aid_c = rapido_add_address(client2, (struct sockaddr *)&c, len_c);
    rapido_address_id_t c2_aid_a = rapido_add_remote_address(client2, (struct sockaddr *)&a, len_a);
    rapido_connection_id_t c2_cid = rapido_create_connection(client2, c2_aid_c, c2_aid_a);
    rapido_run_server_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client2, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client2->tls));
    rapido_run_server_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);

    size_t server_session2_index;
    notification = rapido_next_server_notification(server, &server_session2_index);
    ok(notification && notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid2 = notification->connection_id;
    ok(ptls_handshake_is_complete(SESSION(server, server_session2_index)->tls));
    rapido_run_network(SESSION(server, server_session2_index), RUN_NETWORK_TIMEOUT_DEFAULT);

    rapido_address_id_t s_aid_d = rapido_add_server_address(server, (struct sockaddr *)&d, len_d, true);
    rapido_run_network(SESSION(server, server_session_index), RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(SESSION(server, server_session2_index), RUN_NETWORK_TIMEOUT_DEFAULT);

    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(client->pending_notifications.size == 1 + (DEFAULT_TCPLS_SESSION_ID_AMOUNT - 1));
    for (int i = 1; i < DEFAULT_TCPLS_SESSION_ID_AMOUNT; i++) {
        notification = rapido_queue_pop(&client->pending_notifications);
        ok(notification->notification_type == rapido_new_connection_token);
    }
    notification = rapido_queue_pop(&client->pending_notifications);
    ok(notification->notification_type == rapido_new_remote_address);
    rapido_address_id_t c_aid_d = notification->address_id;
    rapido_run_network(client2, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(client2->pending_notifications.size == 1 + (DEFAULT_TCPLS_SESSION_ID_AMOUNT - 1));
    for (int i = 1; i < DEFAULT_TCPLS_SESSION_ID_AMOUNT; i++) {
        notification = rapido_queue_pop(&client2->pending_notifications);
        ok(notification->notification_type == rapido_new_connection_token);
    }
    notification = rapido_queue_pop(&client2->pending_notifications);
    ok(notification->notification_type == rapido_new_remote_address);
    rapido_address_id_t c2_aid_d = notification->address_id;

    rapido_connection_id_t c_cid2 = rapido_create_connection(client, c_aid_b, c2_aid_d);
    rapido_connection_id_t c2_cid2 = rapido_create_connection(client2, c2_aid_c, c2_aid_d);
    rapido_run_server_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client2, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_server_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);

    size_t tmp_index1, tmp_index2;
    notification = rapido_next_server_notification(server, &tmp_index1);
    ok(notification && notification->notification_type == rapido_new_connection);
    notification = rapido_next_server_notification(server, &tmp_index2);
    ok(notification && notification->notification_type == rapido_new_connection);
    ok((tmp_index1 == server_session_index && tmp_index2 == server_session2_index) ||
       (tmp_index1 == server_session2_index && tmp_index2 == server_session_index));

    rapido_session_free(client);
    rapido_session_free(client2);
    rapido_server_free(server);
    free(client);
    free(client2);
    free(server);
}

void test_connection_reset() {
    rapido_session_t *client = rapido_new_session(ctx, false, "localhost", stderr);
    rapido_session_t *server = rapido_new_session(ctx, true, "localhost", stderr);
    struct sockaddr_in a, b, c;
    socklen_t len_a = sizeof(a), len_b = sizeof(b), len_c = sizeof(c);
    ok(resolve_address((struct sockaddr *)&a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    rapido_address_id_t s_aid_a = rapido_add_address(server, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_b = 0, c_aid_c = 1;
    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 1);
    rapido_application_notification_t *notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    ok(ptls_handshake_is_complete(server->tls));
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);

    rapido_connection_id_t c_cid2 = rapido_create_connection(client, c_aid_c, c_aid_a);
    ok(c_cid != c_cid2);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 2);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid2 = notification->connection_id;
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_remote_address);

    int socket = ((rapido_connection_t *) rapido_array_get(&server->connections, s_cid))->socket;
    struct linger l = {.l_onoff = 1, .l_linger = 0};
    setsockopt(socket, SOL_SOCKET, SO_LINGER, &l, sizeof(struct linger));
    close(socket);

    rapido_run_network(client, RUN_NETWORK_TIMEOUT_DEFAULT);
    rapido_run_network(server, RUN_NETWORK_TIMEOUT_DEFAULT);
    ok(server->pending_notifications.size == 2);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_connection_reset);
    rapido_connection_id_t s_cid3 = notification->connection_id;
    ok(s_cid3 == s_cid);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_connection_closed);
    rapido_connection_id_t s_cid4 = notification->connection_id;
    ok(s_cid4 == s_cid);

    rapido_session_free(client);
    rapido_session_free(server);
    free(client);
    free(server);
}

void test_rapido() {
    subtest("test_local_address_api", test_local_address_api);
    subtest("test_local_address_server", test_local_address_server);
    subtest("test_range_list", test_range_list);
    subtest("test_range_buffer", test_range_buffer);
    subtest("test_set", test_set);
    subtest("test_simple_stream_transfer", test_simple_stream_transfer);
    subtest("test_large_transfer", test_large_transfer);
    subtest("test_join", test_join);
    subtest("test_failover", test_failover);
    subtest("test_multiple_streams", test_multiple_streams);
    subtest("test_multiple_server_addresses", test_multiple_server_addresses);
    subtest("test_large_buffers", test_large_buffers);
    subtest("test_server_new_session", test_server_new_session);
    subtest("test_server_addresses", test_server_addresses);
    subtest("test_connection_reset", test_connection_reset);
}