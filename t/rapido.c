#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/pem.h>
#include <resolv.h>
#include <getopt.h>
#include <signal.h>

#include "rapido.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "util.h"

static void usage(const char *cmd)
{
    printf("Usage: %s [options] host port\n"
           "\n"
           "Options:\n"
           "  -c certificate-file  certificate chain used for server authentication\n"
           "  -k key-file          specifies the credentials for signing the certificate\n"
           "  -l log-file          file to log events (incl. traffic secrets)\n"
           "  -q qlog-file         file to output qlog events\n"
           "  -y cipher-suite      cipher-suite to be used, e.g., aes128gcmsha256 (default:\n"
           "                       all)\n"
           "  -h                   prints this help\n"
           "\n"
           "Supported named groups: secp256r1"
           #if PTLS_OPENSSL_HAVE_SECP384R1
           ", secp384r1"
           #endif
           #if PTLS_OPENSSL_HAVE_SECP521R1
           ", secp521r1"
           #endif
           #if PTLS_OPENSSL_HAVE_X25519
           ", X25519"
           #endif
           "\n"
           "Supported signature algorithms: rsa, secp256r1"
           #if PTLS_OPENSSL_HAVE_SECP384R1
           ", secp384r1"
           #endif
           #if PTLS_OPENSSL_HAVE_SECP521R1
           ", secp521r1"
           #endif
           #if PTLS_OPENSSL_HAVE_ED25519
           ", ed25519"
           #endif
           "\n\n",
           cmd);
}

static uint8_t random_data[16384 * 64] = { 42 };

static uint64_t get_time() {
    struct timespec tv;
    assert(clock_gettime(CLOCK_REALTIME, &tv) == 0);
    return tv.tv_sec * 1000000 + tv.tv_nsec / 1000;
}

void stream_queue_random_data(rapido_t *session, rapido_stream_id_t stream_id, void *producer_ctx) {
    rapido_add_to_stream(session, stream_id, random_data, sizeof(random_data));
}

void run_server(rapido_t *session) {
    bool connection_closed = false;
    while (!connection_closed) {
        rapido_run_network(session);
        while (session->pending_notifications.size > 0) {
            rapido_application_notification_t *notification = rapido_queue_pop(&session->pending_notifications);
            if (notification->notification_type == rapido_new_connection) {
                printf("Accepted connection\n");
                rapido_stream_id_t stream = rapido_open_stream(session);
                rapido_attach_stream(session, stream, notification->connection_id);
                rapido_set_stream_producer(session, stream, stream_queue_random_data, NULL);
            } else if (notification->notification_type == rapido_connection_closed) {
                printf("Connection closed\n");
                connection_closed = true;
                break;
            }
        }
    }
    rapido_free(session);
    free(session);
}

void run_client(rapido_t *session) {
    uint64_t start_time = get_time();
    uint64_t data_received = 0;
    while (data_received < 2000000000) {
        rapido_run_network(session);
        while (session->pending_notifications.size > 0) {
            rapido_application_notification_t *notification = rapido_queue_pop(&session->pending_notifications);
            if (notification->notification_type == rapido_new_stream) {
                printf("New stream from server\n");
            }
            if (notification->notification_type == rapido_stream_has_data) {
                size_t read_len = UINT64_MAX;
                rapido_read_stream(session, notification->stream_id, &read_len);
                data_received += read_len;
                rapido_queue_iter(&session->pending_notifications, notification, {});
            }
        }
    }
    uint64_t end_time = get_time();
    printf("Received %lu bytes over %f seconds, (%.02f Mbit/s)\n", data_received, (end_time - start_time) / 1000000.0, (data_received * 8.0) / (end_time - start_time));
    rapido_free(session);
    free(session);
}

int main(int argc, char **argv) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
    /* Load all compiled-in ENGINEs */
    ENGINE_load_builtin_engines();
    ENGINE_register_all_ciphers();
    ENGINE_register_all_digests();
#endif

    res_init();

    ptls_key_exchange_algorithm_t *key_exchanges[128] = {&ptls_openssl_secp256r1};
    ptls_cipher_suite_t *cipher_suites[128] = {NULL};
    ptls_context_t ctx = {ptls_openssl_random_bytes, &ptls_get_time, key_exchanges, cipher_suites};

    const char *host, *port;
    int is_server = 0, ch;
    struct sockaddr_storage sa;
    socklen_t salen;
    const char *cert_location = NULL;

    while ((ch = getopt(argc, argv, "c:k:l:q:y:h")) != -1) {
        switch (ch) {
        case 'c':
            if (cert_location != NULL) {
                fprintf(stderr, "-C/-c can only be specified once\n");
                return 1;
            }
            cert_location = optarg;
            is_server = ch == 'c';
            load_certificate_chain(&ctx, cert_location);
            break;
        case 'k':
            load_private_key(&ctx, optarg);
            break;
        case 'l':
            setup_log_event(&ctx, optarg);
            break;
        case 'q':
            break;
        case 'y': {
            size_t i;
            for (i = 0; cipher_suites[i] != NULL; ++i)
                ;
#define MATCH(name)                                                                                                                \
    if (cipher_suites[i] == NULL && strcasecmp(optarg, #name) == 0)                                                                \
    cipher_suites[i] = &ptls_openssl_##name
            MATCH(aes128gcmsha256);
            MATCH(aes256gcmsha384);
#if PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
            MATCH(chacha20poly1305sha256);
#endif
#undef MATCH
            if (cipher_suites[i] == NULL) {
                fprintf(stderr, "unknown cipher-suite: %s\n", optarg);
                exit(1);
            }
        } break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            exit(1);
        }
    }
    argc -= optind;
    argv += optind;

    if ((ctx.certificates.count == 0) != (ctx.sign_certificate == NULL)) {
        fprintf(stderr, "-C/-c and -k options must be used together\n");
        return 1;
    }

    if (is_server) {
        if (ctx.certificates.count == 0) {
            fprintf(stderr, "-c and -k options must be set\n");
            return 1;
        }
        setup_session_cache(&ctx);
    }

    if (cipher_suites[0] == NULL) {
        size_t i;
        for (i = 0; ptls_openssl_cipher_suites[i] != NULL; ++i)
            cipher_suites[i] = ptls_openssl_cipher_suites[i];
    }

    if (argc != 2) {
        fprintf(stderr, "missing host and port\n");
        usage(*(argv - optind));
        return 1;
    }
    host = (--argc, *argv++);
    port = (--argc, *argv++);

    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, 0, SOCK_STREAM, IPPROTO_TCP) != 0) {
        exit(1);
    }

    signal(SIGPIPE, SIG_IGN);

    rapido_t *session = rapido_new(&ctx, is_server, host, NULL);
    if (is_server) {
        rapido_add_address(session, (struct sockaddr *)&sa, salen);
        run_server(session);
    } else {
        rapido_address_id_t ra_id = rapido_add_remote_address(session, (struct sockaddr *)&sa, salen);
        rapido_create_connection(session, 0, ra_id);
        run_client(session);
    }
}