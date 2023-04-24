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

static void usage(const char *cmd) {
    printf("Usage: %s [options] host port\n"
           "\n"
           "Options:\n"
           "  -c                   client mode"
           "  -s                   server mode"
           "  -C certificate-file  certificate chain used for server authentication\n"
           "  -k key-file          server private key file\n"
           "  -l port              expose the tunnel as a loopback TCP socket on port"
           "  -j hostname:port     enable multihop tunneling through another TCPLS host"
           "  --tun interface      expose the tunnel as a TUN virtual interface"
           "  --tap interface      expose the tunnel as a TAP virtual interface"
           "  -q qlog-file         file to output qlog events, use value - for stderr\n"
           "  -h                   prints this help\n"
           "\n",
           cmd);
}

int main(int argc, char *argv[]) {
    ptls_context_t ctx;
    struct sockaddr_storage sa, la;
    socklen_t salen, lalen;
    const char *host = "localhost", *port = "8443";

    int ch;
    while ((ch = getopt(argc, argv, "c:k:l:n:q:s:g:r:y:h0")) != -1) {
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
        case 'n':
            hostname = optarg;
            break;
        case 'q':
            qlog_filename = optarg;
            break;
        case 's': {
            char *endarg = NULL;
            data_to_receive = strtol(optarg, &endarg, 10) * 1000000;
            if (optarg == endarg) {
                fprintf(stderr, "-s must be an integer\n");
                return 1;
            }
        } break;
        case 'g':
            get_path = optarg;
            break;
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

    memset(&ctx, 0, sizeof(ctx));
    ctx.random_bytes = ptls_openssl_random_bytes;
    ctx.key_exchanges = ptls_openssl_key_exchanges;
    ctx.cipher_suites = ptls_openssl_cipher_suites;
    ctx.get_time = &ptls_get_time;

    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET6, SOCK_STREAM, IPPROTO_TCP) != 0) {
        exit(1);
    }

    // Tunnel endpoint address resolution
    struct sockaddr_storage tunnel_endpoint;
    socklen_t tunnel_endpoint_len;
    if (resolve_address((struct sockaddr *)&tunnel_endpoint, &tunnel_endpoint_len, "localhost", "8888", AF_INET6, SOCK_STREAM, IPPROTO_TCP) != 0) {
        exit(1);
    }

    rapido_session_t *session = rapido_new_session(&ctx, false, host, stderr);
    rapido_address_id_t remote_addr = rapido_add_remote_address(session, (struct sockaddr *)&sa, salen);
    // rapido_address_id_t local_addr = rapido_add_address(session, (struct sockaddr *)&la, salen);
    rapido_connection_id_t conn = rapido_create_connection(session, 0, remote_addr);

    rapido_application_notification_t* notification;
    char *data;
    size_t readlen = 64;

    rapido_tunnel_id_t tun_id;
    rapido_tunnel_t *tun = NULL;

    while (!session->is_closed) {
        rapido_run_network(session, RUN_NETWORK_TIMEOUT);
        if (!tun) {
            tun_id = rapido_open_tunnel(session);
            tun = rapido_array_get(&session->tunnels, tun_id);
            tun->destination_addr = tunnel_endpoint;
        }

        while (session->pending_notifications.size > 0) {
            notification = rapido_queue_pop(&session->pending_notifications);
            if (notification->notification_type == rapido_tunnel_ready) {
                const char payload[] = "Hello from client\n";
                int fd = rapido_get_tunnel_fd(session, tun_id);
                write(fd, &payload[0], sizeof(payload));
            }

            if (notification->notification_type == rapido_tunnel_failed) {
                fprintf(stderr, "Client: A connection error occurred while opening tunnel.\n");
                exit(-1);
            }

            if (notification->notification_type == rapido_tunnel_closed) {
                fprintf(stderr, "Client: The remote closed the destination socket gracefully.\n");
                exit(0);
            }
        }
        sleep(1);
    }
}

void ctx_load_cert(ptls_context_t *ctx, const char *cert_file) {
    // Read a certificate chain from a PEM file and add it to the PicoTCPLS context.
    load_certificate_chain(ctx, cert_file);
}

void ctx_add_sign_cert(ptls_context_t *ctx, const char* pk_file) {
    // Add the sign_certificate attribute to the current context.
    load_private_key(ctx, pk_file);
}
