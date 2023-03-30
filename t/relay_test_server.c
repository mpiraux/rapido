#include "rapido.h"
#include "rapido_internals.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "util.h"
#include <openssl/pem.h>
#include <stdio.h>
#include <sys/socket.h>

#define RUN_NETWORK_TIMEOUT 100

void ctx_load_cert(ptls_context_t *ctx, const char* cert_file);
void ctx_add_sign_cert(ptls_context_t *ctx, const char* pk_file);

int main(int argc, char *argv[]) {
    ptls_context_t ctx;
    struct sockaddr_in sa;
    socklen_t salen;
    const char *host = "localhost", *port = "8443";

    memset(&ctx, 0, sizeof(ctx));
    ctx.random_bytes = ptls_openssl_random_bytes;
    ctx.key_exchanges = ptls_openssl_key_exchanges;
    ctx.cipher_suites = ptls_openssl_cipher_suites;
    ctx.get_time = &ptls_get_time;

    // Prepare the server context with dev private key and certificate.
    ctx_load_cert(&ctx, "dev_certs/cert.pem");
    ctx_add_sign_cert(&ctx, "dev_certs/key.pem");

    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET6, SOCK_STREAM, IPPROTO_TCP) != 0) {
        exit(1);
    }

    rapido_server_t* server = rapido_new_server(&ctx, "localhost", stderr);
    rapido_address_id_t server_addr = rapido_add_server_address(server, (struct sockaddr *)&sa, salen, true);

    size_t server_session_index;
    rapido_application_notification_t *notification = NULL;
    rapido_stream_id_t active_server_stream_id;
    rapido_session_t* server_session = NULL;

    const char *test_payload = "Hello World!";
    
    fprintf(stderr, "Waiting for connections...");

    while (1) {
        rapido_run_server_network(server, RUN_NETWORK_TIMEOUT);
        if (server_session) {
            rapido_run_network(server_session, RUN_NETWORK_TIMEOUT);
        }
        notification = rapido_next_server_notification(server, &server_session_index);
        if (notification && notification->notification_type == rapido_new_connection) {
            fprintf(stdout, "Accepting a connection\n");
            fprintf(stdout, "SessionID = %zd\n", server_session_index);
            server_session = ((rapido_session_t *) rapido_array_get(&(server->sessions), server_session_index));
            fprintf(stdout, "Session is_closed = %d\n", server_session->is_closed);
            active_server_stream_id = rapido_open_stream(server_session);
            rapido_add_to_stream(server_session, active_server_stream_id, "", 1); // Blank stream message to init stream
            // rapido_close_stream(server_session, active_server_stream_id);
            rapido_attach_stream(server_session, active_server_stream_id, notification->connection_id);
            rapido_run_network(server_session, RUN_NETWORK_TIMEOUT);
            // rapido_close_session(server_session, notification->connection_id);
        } else {
            fprintf(stdout, "Nope, still waiting...\n");
        }
        sleep(2);
    }

    rapido_server_free(server);
    free(server);
}

void ctx_load_cert(ptls_context_t *ctx, const char *cert_file) {
    // Read a certificate chain from a PEM file and add it to the PicoTCPLS context.
    load_certificate_chain(ctx, cert_file);
}

void ctx_add_sign_cert(ptls_context_t *ctx, const char* pk_file) {
    // Add the sign_certificate attribute to the current context.
    load_private_key(ctx, pk_file);
}
