#include "rapido.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "util.h"
#include <openssl/pem.h>
#include <stdio.h>
#include <sys/socket.h>

void ctx_load_cert(ptls_context_t *ctx, const char* cert_file);
void ctx_add_sign_cert(ptls_context_t *ctx, const char* pk_file);

int main(int argc, char *argv[]) {
    ptls_context_t ctx;
    struct sockaddr_storage sa;
    socklen_t salen;
    const char *host = "127.0.0.1", *port = "8443";

    memset(&ctx, 0, sizeof(ctx));
    ctx.random_bytes = ptls_openssl_random_bytes;
    ctx.key_exchanges = ptls_openssl_key_exchanges;
    ctx.cipher_suites = ptls_openssl_cipher_suites;

    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET, SOCK_STREAM, IPPROTO_TCP) != 0) {
        exit(1);
    }

    rapido_session_t *session = rapido_new_session(&ctx, false, host, stderr);
    rapido_address_id_t remote_addr = rapido_add_remote_address(session, (struct sockaddr *)&sa, salen);
    rapido_create_connection(session, 0, remote_addr);

    
}
