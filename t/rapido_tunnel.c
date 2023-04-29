#include "rapido.h"
#include "rapido_internals.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include "util.h"
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <poll.h>
#include <sys/socket.h>

#define RUN_NETWORK_TIMEOUT 100

void ctx_load_cert(ptls_context_t *ctx, const char* cert_file);
void ctx_add_sign_cert(ptls_context_t *ctx, const char* pk_file);

static void usage(const char *cmd) {
    printf("Usage: %s [options] host port\n"
           "\n"
           "Options:\n"
           "  -c                   client mode\n"
           "  -s                   server mode\n"
           "  -C certificate-file  certificate chain used for server authentication\n"
           "  -k key-file          server private key file\n"
           "  -j hostname:port     enable multihop tunneling through another TCPLS host\n"
           "  --tun interface      expose the tunnel as a TUN virtual interface\n"
           "  --tap interface      expose the tunnel as a TAP virtual interface\n"
           "  -q qlog-file         file to output qlog events, use value - for stderr\n"
           "  -h                   prints this help\n"
           "\n",
           cmd);
}

int main(int argc, char *argv[]) {
    ptls_context_t ctx;
    struct sockaddr_storage sa;
    socklen_t salen;

    int ch;
    bool client_mode = 0;
    bool server_mode = 0;
    char *cert_file = NULL;
    char *key_file = NULL;
    char *nexthop_hostname = NULL;
    char *nexthop_port = NULL;
    char *tun_interface = NULL;
    char *tap_interface = NULL;
    char *qlog_filename = NULL;

    while ((ch = getopt(argc, argv, "csC:k:j:-:q:h")) != -1) {
        switch (ch) {
            case 'c':
                client_mode = true;
                break;
            case 's':
                server_mode = true;
                break;
            case 'C':
                cert_file = optarg;
                break;
            case 'k':
                key_file = optarg;
                break;
            case 'j':
                nexthop_hostname = strtok(optarg, ":");
                nexthop_port = strtok(NULL, ":");
                break;
            case '-':
                if (strcmp(optarg, "tun") == 0) {
                    tun_interface = argv[optind++];
                } else if (strcmp(optarg, "tap") == 0) {
                    tap_interface = argv[optind++];
                }
                break;
            case 'q':
                qlog_filename = optarg;
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
            case '?':
                printf("Invalid option: %c\n", optopt);
                exit(1);
        }
    }

    if (optind != argc - 2) {
        printf("Error: Wrong number of arguments.\n");
        exit(1);
    }

    const char *host = argv[optind++];
    const char *port = argv[optind++];

    // Prepare log file
    FILE* qlog_file = NULL;
    if (!strcmp(qlog_filename, "-")) {
        qlog_file = stderr;
    } else {
        qlog_file = fopen(qlog_filename, "w");
    }

    // Prepare TLS context
    memset(&ctx, 0, sizeof(ctx));
    ctx.random_bytes = ptls_openssl_random_bytes;
    ctx.key_exchanges = ptls_openssl_key_exchanges;
    ctx.cipher_suites = ptls_openssl_cipher_suites;
    ctx.get_time = &ptls_get_time;

    // Resolve hostname
    if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET, SOCK_STREAM, IPPROTO_TCP) != 0) {
        if (resolve_address((struct sockaddr *)&sa, &salen, host, port, AF_INET6, SOCK_STREAM, IPPROTO_TCP) != 0) {
            exit(1);
        }
    }

    if (server_mode) {
        // Prepare the server context with dev private key and certificate.
        ctx_load_cert(&ctx, cert_file);
        ctx_add_sign_cert(&ctx, key_file);

        rapido_server_t* server = rapido_new_server(&ctx, host, qlog_file);
        rapido_address_id_t server_addr = rapido_add_server_address(server, (struct sockaddr *)&sa, salen, true);

        size_t server_session_index;
        rapido_application_notification_t *notification = NULL;
        rapido_stream_id_t active_server_stream_id;
        rapido_session_t* server_session = NULL;

        fprintf(stdout, "Waiting for connections...");

        while (true) {
            rapido_run_server_network(server, RUN_NETWORK_TIMEOUT);
            while (notification = rapido_next_server_notification(server, &server_session_index)) {
                server_session = ((rapido_session_t *) rapido_array_get(&(server->sessions), server_session_index));
                
                if (notification->notification_type == rapido_new_connection) {
                    fprintf(stdout, "Accepting a connection\n");
                    fprintf(stdout, "Session ID = %zd\n", server_session_index);
                }

                if (notification->notification_type == rapido_tunnel_ready) {
                    fprintf(stdout, "Tunnel with ID %d is now ready.\n", notification->tunnel_id);
                }

                if (notification->notification_type == rapido_tunnel_has_data) {
                    size_t len;
                    char *data = rapido_read_from_tunnel(server_session, notification->tunnel_id, &len);
                    fprintf(stdout, "Received %lu bytes on tunnel ID %d: %s\n", len, notification->tunnel_id, data);
                    const char* reply = "Hello from server!";
                    rapido_write_to_tunnel(server_session, notification->tunnel_id, reply, strlen(reply));
                }

            }

            if (server_session) {
                rapido_run_network(server_session, RUN_NETWORK_TIMEOUT);
            }
        }

        rapido_server_free(server);
        free(server);
    }

    if (client_mode) {
        rapido_session_t *session = rapido_new_session(&ctx, false, host, qlog_file);
        rapido_address_id_t remote_addr = rapido_add_remote_address(session, (struct sockaddr *)&sa, salen);
        rapido_connection_id_t conn = rapido_create_connection(session, 0, remote_addr);
        
        rapido_application_notification_t* notification;

        rapido_tunnel_id_t tun_id;
        rapido_tunnel_t *tun = NULL;
        bool multihop_frame_sent = false;

        while (!session->is_closed) {
            if (!tun) {
                tun_id = rapido_open_tunnel(session);
                tun = rapido_array_get(&session->tunnels, tun_id);
            }

            while (session->pending_notifications.size > 0) {
                notification = rapido_queue_pop(&session->pending_notifications);
                if (notification->notification_type == rapido_tunnel_ready) {
                    // Tunnel is ready, send test message
                    const char *payload = "Hello from client!";
                    rapido_write_to_tunnel(session, tun_id, payload, strlen(payload));

                    // If enabled, send the control frame to extend the tunnel to the relay specified with -j
                    if (nexthop_hostname && nexthop_port && !multihop_frame_sent) {
                        rapido_extend_tunnel(session, tun_id, nexthop_hostname, nexthop_port);
                        multihop_frame_sent = true;
                    }
                }

                if (notification->notification_type == rapido_tunnel_has_data) {
                    // Received data, print to stdout.
                    size_t len;
                    char *data = rapido_read_from_tunnel(session, notification->tunnel_id, &len);
                    fprintf(stdout, "Received %lu bytes on tunnel ID %d: %s\n", len, notification->tunnel_id, data);
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

            rapido_run_network(session, RUN_NETWORK_TIMEOUT);
        }
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
