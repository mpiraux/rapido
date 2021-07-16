#include <picotest.h>
#include "test.h"
#include "rapido.h"
#include "util.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>


void test_local_address_api() {
    rapido_t *s = rapido_new(ctx, false, "localhost");
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
    rapido_close(s);
    free(s);
}

void test_local_address_server() {
    rapido_t *s = rapido_new(ctx, true, "localhost");
    struct sockaddr_in a;
    struct sockaddr_in6 b;
    socklen_t len_a = sizeof(a), len_b = sizeof(b);
    ok(resolve_address((struct sockaddr *) &a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *) &b, &len_b, "localhost", "4443", AF_INET6, SOCK_STREAM, IPPROTO_TCP) == 0);
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
    rapido_close(s);
    free(s);
}

void test_simple_stream_transfer() {
    rapido_t *client = rapido_new(ctx, false, "localhost");
    rapido_t *server = rapido_new(ctx, true, "localhost");
    struct sockaddr_in a, b;
    socklen_t len_a = sizeof(a), len_b = sizeof(b);
    ok(resolve_address((struct sockaddr *) &a, &len_a, "localhost", "4443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    ok(resolve_address((struct sockaddr *) &b, &len_b, "localhost", "14443", AF_INET, SOCK_STREAM, IPPROTO_TCP) == 0);
    rapido_address_id_t s_aid_a = rapido_add_address(server, (struct sockaddr *)&a, len_a);
    rapido_address_id_t c_aid_b = rapido_add_address(client, (struct sockaddr *)&b, len_b);
    rapido_address_id_t c_aid_a = rapido_add_remote_address(client, (struct sockaddr *)&a, len_a);
    rapido_connection_id_t c_cid = rapido_create_connection(client, c_aid_b, c_aid_a);
    rapido_run_network(server);
    rapido_run_network(client);
    ok(ptls_handshake_is_complete(client->tls));
    rapido_run_network(server);
    ok(server->pending_notifications.size > 0);
    rapido_application_notification_t *notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_new_connection);
    rapido_connection_id_t s_cid = notification->connection_id;
    ok(ptls_handshake_is_complete(server->tls));

    rapido_stream_id_t stream_id = rapido_open_stream(client);
    ok(rapido_add_to_stream(client, stream_id, "Hello, world!", 13) == 0);
    ok(rapido_close_stream(client, stream_id) == 0);
    ok(rapido_attach_stream(client, stream_id, c_cid) == 0);
    rapido_run_network(client);
    rapido_run_network(server);
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
    rapido_run_network(server);
    rapido_run_network(client);
    ok(client->pending_notifications.size == 3);
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
    rapido_run_network(client);
    rapido_run_network(server);
    ok(server->pending_notifications.size == 1);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_stream_has_data);
    ok(notification->stream_id == server_stream_id);
    ok(rapido_close_stream(client, server_stream_id) == 0);
    rapido_run_network(client);
    rapido_run_network(server);
    ok(server->pending_notifications.size == 1);
    notification = rapido_queue_pop(&server->pending_notifications);
    ok(notification->notification_type == rapido_stream_closed);
    ok(notification->stream_id == server_stream_id);

    rapido_close(client);
    rapido_close(server);
    free(client);
    free(server);
}

void test_rapido() {
    subtest("test_local_address_api", test_local_address_api);
    subtest("test_local_address_server", test_local_address_server);
    subtest("test_simple_stream_transfer", test_simple_stream_transfer);
}