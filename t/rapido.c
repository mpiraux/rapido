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

#define min(a, b) ((a) < (b) ? (a) : (b))
#define RUN_NETWORK_TIMEOUT 100

static void usage(const char *cmd) {
    printf("Usage: %s [options] host port\n"
           "\n"
           "Options:\n"
           "  -c certificate-file  certificate chain used for server authentication\n"
           "  -k key-file          specifies the credentials for signing the certificate\n"
           "  -l log-file          file to log events (incl. traffic secrets)\n"
           "  -n hostname          hostname used for certificate verification\n"
           "  -q qlog-file         file to output qlog events, use value - for stderr\n"
           "  -s download-size     amount of data to receive in MB\n"
           "  -g path              requests the given path using HTTP/0.9 over stream 0\n"
           "  -0                   enables the HTTP/1.0 server\n"
           "  -r repeat            repeat the request a given amount of times\n"
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

static uint8_t random_data[16384 * 64] = {42};

static char *index_page = ""
"<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n"
"<html>\r\n"
"<head><title>rapido index page</title></head>\r\n"
"<body>\r\n"
"<h1>rapido index page</h1>\r\n"
"<p>Welcome to the rapido test server</p>\r\n"
"<\\body>\r\n"
"<\\html>\r\n";

static char* index_response = ""
"HTTP/1.1 200 OK\r\n"
"Server: rapido/0.0.1\r\n"
"Content-Type: text/html\r\n"
"Content-Length: 203\r\n"
"\r\n";


static uint64_t get_usec_time() {
    struct timespec tv;
    assert(clock_gettime(CLOCK_REALTIME, &tv) == 0);
    return tv.tv_sec * 1000000 + tv.tv_nsec / 1000;
}

uint8_t *stream_produce_random_data(rapido_session_t *session, rapido_stream_id_t stream_id, void *producer_ctx, uint64_t offset,
                                    size_t *len) {
    *len = min(*len, sizeof(random_data));
    return random_data;
}

ssize_t seek_next_char(char *data, size_t len, char c) {
    for (int i = 0; i < len; i++) {
        if (data[i] == c) {
            return i;
        }
    }
    return -1;
}

struct st_http_server_context {
    char *method;
    char *path;
    char *version;
    bool first_line_parsed;
    char *header_host;
    char *header_user_agent;
    bool request_is_complete;
};

size_t handle_http_request(uint8_t *read_ptr, size_t read_len, struct st_http_server_context *ctx) {
    size_t offset = 0;
    while (!ctx->request_is_complete && offset < read_len) {
        if (!ctx->first_line_parsed) {
            ssize_t next_eol = seek_next_char(read_ptr + offset, read_len - offset, '\n');
            assert(next_eol != -1 && "handle_http() does not support fragmented header");
            ssize_t next_space = seek_next_char(read_ptr + offset, read_len - offset, ' ');
            assert(next_space != -1 && next_space < next_eol && "malformed request");
            ctx->method = strndup(read_ptr + offset, next_space);
            offset += next_space + 1;
            next_eol -= next_space + 1;
            next_space = seek_next_char(read_ptr + offset, read_len - offset, ' ');
            assert(next_space != -1 && next_space < next_eol && "malformed request");
            ctx->path = strndup(read_ptr + offset, next_space);
            offset += next_space + 1;
            next_eol -= next_space + 1;
            ctx->version = strndup(read_ptr + offset, next_eol);
            offset += next_eol + 1;
            assert(strcmp(ctx->method, "GET") == 0 && "other methods than GET not supported");
            ctx->first_line_parsed = true;
        }
        if (ctx->first_line_parsed) {
            if (read_len - offset >= 6 && memcmp(read_ptr + offset, "Host: ", 6) == 0) {
                assert(!ctx->header_host && "Host already parsed!");
                offset += 6;
                ssize_t next_eol = seek_next_char(read_ptr + offset, read_len - offset, '\n');
                assert(next_eol != -1 && "handle_http() does not support fragmented header");
                ctx->header_host = strndup(read_ptr + offset, next_eol);
                offset += next_eol + 1;
            }
            if (read_len - offset >= 12 && memcmp(read_ptr + offset, "User-Agent: ", 12) == 0) {
                offset += 12;
                ssize_t next_eol = seek_next_char(read_ptr + offset, read_len - offset, '\n');
                assert(next_eol != -1 && "handle_http() does not support fragmented header");
                ctx->header_user_agent = strndup(read_ptr + offset, next_eol);
                offset += next_eol + 1;
            }
            ssize_t next_hdr = seek_next_char(read_ptr + offset, read_len - offset, ':');
            if (next_hdr != -1 && next_hdr < seek_next_char(read_ptr + offset, read_len - offset, '\n')) {
                ssize_t next_eol = seek_next_char(read_ptr + offset, read_len - offset, '\n');
                assert(next_eol != -1 && "handle_http() does not support fragmented header");
                offset += next_eol + 1;
            }
            if (seek_next_char(read_ptr + offset, read_len - offset, '\n') == 1 && read_ptr[offset] == '\r') {
                offset += 2;
                ctx->request_is_complete = true;
            }
        }
    }
    return read_len - offset;
};

void run_server(rapido_session_t *session, bool enable_http_server) {
    bool closed = false;
    struct st_http_server_context http_ctx = {0};
    while (!closed) {
        rapido_run_network(session, RUN_NETWORK_TIMEOUT);
        while (session->pending_notifications.size > 0) {
            rapido_application_notification_t *notification = rapido_queue_pop(&session->pending_notifications);
            if (notification->notification_type == rapido_new_connection) {
                printf("Accepted connection\n");
                if (!enable_http_server) {
                    rapido_stream_id_t stream = rapido_open_stream(session);
                    rapido_attach_stream(session, stream, notification->connection_id);
                    rapido_set_stream_producer(session, stream, stream_produce_random_data, NULL);
                }
            } else if (notification->notification_type == rapido_stream_has_data) {
                size_t read_len = UINT64_MAX;
                uint8_t *read_ptr = rapido_read_stream(session, notification->stream_id, &read_len);
                while (read_len > 0) {
                    if (notification->stream_id == 0) {
                        size_t left_to_process = 0;
                        do {
                            left_to_process = handle_http_request(read_ptr + left_to_process, read_len, &http_ctx);
                            if (http_ctx.request_is_complete) {
                                rapido_attach_stream(session, notification->stream_id, notification->connection_id);
                                rapido_add_to_stream(session, notification->stream_id, index_response, strlen(index_response));
                                rapido_add_to_stream(session, notification->stream_id, index_page, strlen(index_page));
                                memset(&http_ctx, 0, sizeof(http_ctx));
                            }
                            read_len -= left_to_process;
                        } while (left_to_process > 0);
                    }
                    read_len = UINT64_MAX;
                    read_ptr = rapido_read_stream(session, notification->stream_id, &read_len);
                }
            } else if (notification->notification_type == rapido_connection_closed) {
                printf("Connection closed\n");
                closed = true;
            } else if (notification->notification_type == rapido_session_closed) {
                printf("Session closed\n");
                closed = true;
            }
        }
    }
}

struct st_http_client_context {
    bool has_parsed_headers;
    bool has_parsed_content_length;
    bool response_is_complete;
    size_t content_length;
    size_t response_offset;
    uint8_t *response_body;
};

int handle_http_response(uint8_t *read_ptr, size_t read_len, struct st_http_client_context *ctx) {
    size_t offset = 0;
    while (!ctx->has_parsed_headers && offset < read_len) {
        if (read_len >= 16 && memcmp(read_ptr + offset, "Content-Length: ", 16) == 0) {
            assert(!ctx->has_parsed_content_length && "Content-Length already parsed!");
            offset += 16;
            ssize_t next_eol = seek_next_char(read_ptr + offset, read_len - offset, '\n');
            assert(next_eol != -1 && "handle_http() does not support fragmented header");
            char *end = NULL;
            ctx->content_length = strtol(read_ptr + offset, &end, 10);
            assert(read_ptr + offset != end && read_ptr + offset + next_eol - 1 == end);
            offset += next_eol;  // To handle when this header is the last one
            ctx->has_parsed_content_length = true;
        } else {
            ssize_t next_eol = seek_next_char(read_ptr + offset, read_len - offset, '\n');
            assert(next_eol != -1 && "handle_http() does not support fragmented header");
            offset += next_eol + 1;
            if (seek_next_char(read_ptr + offset, read_len - offset, '\n') == 1 && read_ptr[offset] == '\r') {
                offset += 2;
                ctx->has_parsed_headers = true;
                assert(ctx->response_body == NULL);
                ctx->response_body = malloc(ctx->content_length);
                assert(ctx->response_body != NULL);
            }
        }
    }
    if (ctx->has_parsed_headers && ctx->response_offset < ctx->content_length) {
        size_t copy_len = min(read_len - offset, ctx->content_length - ctx->response_offset);
        memcpy(ctx->response_body + ctx->response_offset, read_ptr + offset, copy_len);
        ctx->response_offset += copy_len;
        offset += copy_len;
    }
    if (ctx->has_parsed_headers && ctx->response_offset == ctx->content_length) {
        SHA256_CTX sha_ctx = {0};
        uint8_t hash[SHA256_DIGEST_LENGTH] = {0};
        SHA256_Init(&sha_ctx);
        SHA256_Update(&sha_ctx, ctx->response_body, ctx->content_length);
        SHA256_Final(hash, &sha_ctx);
        char hash_str[(SHA256_DIGEST_LENGTH*2) + 1];
        tohex(hash, sizeof(hash), hash_str);

        printf("Parsed a %zu-byte long HTTP response with sha256sum %s\n", ctx->content_length, hash_str);
        free(ctx->response_body);
        memset(ctx, 0, sizeof(struct st_http_client_context));
        if (offset < read_len) {
            return handle_http_response(read_ptr + offset, read_len - offset, ctx) + 1;
        }
        return 1;
    }
    assert(offset == read_len);
    return 0;
};

void enqueue_get_request(rapido_session_t *session, rapido_stream_id_t stream, const char *get_path) {
    char *server_name = ptls_get_server_name(session->tls);
    rapido_add_to_stream(session, stream, "GET ", 4);
    rapido_add_to_stream(session, stream, get_path, strlen(get_path));
    rapido_add_to_stream(session, stream, " HTTP/1.1\r\n", 11);
    rapido_add_to_stream(session, stream, "Host: ", 6);
    rapido_add_to_stream(session, stream, server_name, strlen(server_name));
    rapido_add_to_stream(session, stream, "\r\nUser-Agent: rapido/0.0.1/", 27);
    char stream_id_str[9] = {0};
    snprintf(stream_id_str, sizeof(stream_id_str) - 1, "%d", stream);
    rapido_add_to_stream(session, stream, stream_id_str, strlen(stream_id_str));
    rapido_add_to_stream(session, stream, "\r\n\r\n", 4);
}

void run_client(rapido_session_t *session, size_t data_to_receive, const char *get_path, size_t no_requests) {
    rapido_stream_id_t app_stream = rapido_open_stream(session);
    if (get_path) {
        rapido_attach_stream(session, app_stream, 0);
        for (int i = 0; i < no_requests; i++) {
            enqueue_get_request(session, app_stream, get_path);
        }
    }
    uint64_t start_time = get_usec_time();
    uint64_t data_received = 0;
    bool closed = false;
    struct st_http_client_context http_ctx = {0};
    rapido_connection_id_t extra_connection = 0;
    size_t no_requests_received = 0;
    while (!closed && (get_path == NULL ? data_received < data_to_receive : no_requests_received < no_requests)) {
        rapido_run_network(session, RUN_NETWORK_TIMEOUT);
        bool has_read = false;
        while (session->pending_notifications.size > 0) {
            rapido_application_notification_t *notification = rapido_queue_pop(&session->pending_notifications);
            if (notification->notification_type == rapido_new_stream) {
                printf("New stream from server\n");
            } else if (!has_read && notification->notification_type == rapido_stream_has_data) {
                size_t read_len = UINT64_MAX;
                uint8_t *read_ptr = rapido_read_stream(session, notification->stream_id, &read_len);
                while (read_len > 0) {
                    if (get_path) {
                        no_requests_received += handle_http_response(read_ptr, read_len, &http_ctx);
                    }
                    data_received += read_len;
                    read_len = UINT64_MAX;
                    read_ptr = rapido_read_stream(session, notification->stream_id, &read_len);
                }
                has_read = true;
            } else if (!extra_connection && notification->notification_type == rapido_new_remote_address) {
                printf("Creating a new connection to the secondary address advertised by the server\n");
                extra_connection = rapido_create_connection(session, 1, notification->address_id);
                if (get_path) {
                    rapido_attach_stream(session, app_stream, extra_connection);
                    enqueue_get_request(session, app_stream, get_path);
                    no_requests++;
                    rapido_close_stream(session, app_stream);
                }
            } else if (notification->notification_type == rapido_session_closed) {
                printf("Session closed\n");
                closed = true;
            }
        }
    }
    uint64_t end_time = get_usec_time();
    printf("Received %lu bytes over %f seconds at %.02f Mbit/s\n", data_received, (end_time - start_time) / 1000000.0,
           (data_received * 8.0) / (end_time - start_time));
    rapido_close_session(session, 0);
    rapido_close_connection(session, 0);
    if (extra_connection > 0) {
        rapido_close_connection(session, extra_connection);
    }
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
    const char *hostname = NULL;
    const char *get_path = NULL;
    const char *qlog_filename = NULL;
    size_t no_requests = 1;
    size_t data_to_receive = 10000000;
    bool enable_http_server = false;

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
        case 'r': {
            char *endarg = NULL;
            no_requests = strtol(optarg, &endarg, 10);
            if (optarg == endarg) {
                fprintf(stderr, "-r must be an integer\n");
                return 1;
            }
        } break;
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
        case '0':
            enable_http_server = true;
            break;
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

    struct sockaddr_storage extra_sa;
    socklen_t extra_salen;
    if (resolve_address((struct sockaddr *)&extra_sa, &extra_salen, host, port, sa.ss_family == AF_INET ? AF_INET6 : AF_INET, SOCK_STREAM, IPPROTO_TCP) != 0) {
        extra_salen = 0;
    }

    signal(SIGPIPE, SIG_IGN);
    FILE *qlog_file = NULL;
    if (qlog_filename) {
        if (memcmp(qlog_filename, "-", 1) == 0) {
            qlog_file = stderr;
        } else {
            qlog_file = fopen(qlog_filename, "w");
            if (!qlog_file) {
                perror("Could not open qlog file");
                exit(1);
            }
        }
    }

    rapido_session_t *session = rapido_new_session(&ctx, is_server, hostname ? hostname : host, qlog_file);
    if (is_server) {
        rapido_add_address(session, (struct sockaddr *)&sa, salen);
        if (extra_salen > 0) {
            rapido_add_address(session, (struct sockaddr *)&extra_sa, extra_salen);
        }
        run_server(session, enable_http_server);
    } else {
        rapido_address_id_t ra_id = rapido_add_remote_address(session, (struct sockaddr *)&sa, salen);
        rapido_create_connection(session, 0, ra_id);
        run_client(session, data_to_receive, get_path, no_requests);
    }
    rapido_session_free(session);
    free(session);
}