#include "rapido.h"
#include "rapido_internals.h"
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <netinet/in.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define WARNING(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#ifndef NO_LOG
#define LOG if (1)
#define QLOG(session, ev_type, cat, trigger, data_fmt, ...)                                                                        \
    do {                                                                                                                           \
        if (!(session)->qlog.out)                                                                                                  \
            break;                                                                                                                 \
        fprintf((session)->qlog.out, "[%lu, \"%s:%s:%s\", \"%s\", ", get_usec_time() - (session)->qlog.reference_time,             \
                (session)->is_server ? "server" : "client", ev_type, cat, trigger);                                                \
        fprintf((session)->qlog.out, data_fmt ? data_fmt : "{}", ##__VA_ARGS__);                                                   \
        fprintf((session)->qlog.out, "],\n");                                                                                      \
    } while (0)
#else
#define QLOG(session, ev_type, cat, trigger, data_fmt, ...)
#define LOG if (0)
#endif

#define min(a, b) ((a) < (b) ? (a) : (b))
#define max(a, b) ((a) > (b) ? (a) : (b))
#define todo(expr) assert(!(expr))
#define todo_perror(errnum) assert_perror(errnum)

#define SOCKADDR_ADDR(a)                                                                                                           \
    (((struct sockaddr *)(a))->sa_family == AF_INET ? (void *)&((struct sockaddr_in *)(a))->sin_addr                               \
                                                    : (void *)&((struct sockaddr_in6 *)(a))->sin6_addr)
#define SOCKADDR_PORT(a)                                                                                                           \
    (((struct sockaddr *)(a))->sa_family == AF_INET ? &((struct sockaddr_in *)(a))->sin_port                                       \
                                                    : &((struct sockaddr_in6 *)(a))->sin6_port)

#define TLS_MAX_RECORD_SIZE 16384
#define TLS_MAX_ENCRYPTED_RECORD_SIZE (TLS_MAX_RECORD_SIZE + 22)
#define TLS_RECORD_CIPHERTEXT_TO_CLEARTEXT_LEN(l) ((l)-22)
#define TLS_RECORD_HEADER_LEN (1 + 2 + 2)
#define TLS_RAPIDO_HELLO_EXT 100

static uint8_t random_data[16384];

#define DEFAULT_TCPLS_SESSION_ID_AMOUNT 4
#define DEFAULT_DELAYED_ACK_COUNT 16
#define DEFAULT_DELAYED_ACK_TIME 25000

#define debug_dump(src, len)                                                                                                       \
    do {                                                                                                                           \
        WARNING("Dumping %zu bytes from %p (%s:%d)\n", (size_t)len, src, __FILE__, __LINE__);                                      \
        for (int i = 0; i < len;) {                                                                                                \
            fprintf(stderr, "%04x:  ", (int)i);                                                                                    \
                                                                                                                                   \
            for (int j = 0; j < 16 && i < len; j++) {                                                                              \
                fprintf(stderr, "%02x ", ((uint8_t *)src)[i + j]);                                                                 \
            }                                                                                                                      \
            fprintf(stderr, "\t");                                                                                                 \
            for (int j = 0; j < 16 && i < len; j++, i++) {                                                                         \
                if (32 <= ((uint8_t *)src)[i] && ((uint8_t *)src)[i] > 127) {                                                      \
                    fprintf(stderr, "%c", ((uint8_t *)src)[i]);                                                                    \
                } else {                                                                                                           \
                    fprintf(stderr, " ");                                                                                          \
                }                                                                                                                  \
            }                                                                                                                      \
            fprintf(stderr, "\n");                                                                                                 \
        }                                                                                                                          \
    } while (0);

void tohex(uint8_t *in, size_t len, char *out) {
    uint8_t *max_in = in + len;
    const char *hex = "0123456789abcdef";
    for (; in < max_in; out += 2, in++) {
        out[0] = hex[(*in >> 4) & 0xf];
        out[1] = hex[*in & 0xf];
    }
    *out = 0;
}

int sockaddr_equal(struct sockaddr *a, struct sockaddr *b) {
    if (a->sa_family != b->sa_family) {
        return 0;
    }
    return memcmp(SOCKADDR_ADDR(a), SOCKADDR_ADDR(b), a->sa_family == AF_INET ? 4 : 16) == 0 &&
           *SOCKADDR_PORT(a) == *SOCKADDR_PORT(b);
}

int collect_rapido_extensions(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, uint16_t type) {
    return type == TLS_RAPIDO_HELLO_EXT;
}

int collected_rapido_extensions(ptls_t *tls, struct st_ptls_handshake_properties_t *properties, ptls_raw_extension_t *extensions) {
    ptls_raw_extension_t *extension = extensions;
    size_t no_extensions = 0;
    while (extension->type != UINT16_MAX) {
        no_extensions++;
        extension++;
    }
    properties->additional_extensions =
        reallocarray(properties->additional_extensions, no_extensions + 1, sizeof(ptls_raw_extension_t));
    if (!properties->additional_extensions) {
        return 1;
    }
    memcpy(properties->additional_extensions, extensions, sizeof(ptls_raw_extension_t) * (no_extensions + 1));
    properties->collected_extensions = NULL;
    return 0;
}

void derive_connection_aead_iv(uint8_t *iv, rapido_connection_id_t connection_id) {
    /* XOR the upper 4 bytes with the given connection id */
    uint32_t msb_iv = ntohl(*(uint32_t *)(iv));
    msb_iv ^= connection_id;
    msb_iv = htonl(msb_iv);
    *(uint32_t *)iv = msb_iv;
}

int setup_connection_crypto_context(rapido_t *session, rapido_connection_t *connection) {
    struct st_ptls_traffic_protection_t *ctx_enc = ptls_get_traffic_protection(session->tls, 0);
    struct st_ptls_traffic_protection_t *ctx_dec = ptls_get_traffic_protection(session->tls, 1);
    uint8_t key[PTLS_MAX_SECRET_SIZE];
    uint8_t iv[PTLS_MAX_IV_SIZE];
    int ret;

    ptls_cipher_suite_t *cipher = ptls_get_cipher(session->tls);

    if ((ret = ptls_hkdf_expand_label(cipher->hash, key, cipher->aead->key_size,
                                      ptls_iovec_init(ctx_enc->secret, cipher->hash->digest_size), "key", ptls_iovec_init(NULL, 0),
                                      session->tls_ctx->hkdf_label_prefix__obsolete)) != 0)
        return -1;
    if ((ret = ptls_hkdf_expand_label(cipher->hash, iv, cipher->aead->iv_size,
                                      ptls_iovec_init(ctx_enc->secret, cipher->hash->digest_size), "iv", ptls_iovec_init(NULL, 0),
                                      session->tls_ctx->hkdf_label_prefix__obsolete)) != 0)
        return -1;

    derive_connection_aead_iv(iv, connection->connection_id);

    connection->encryption_ctx = malloc(sizeof(struct st_ptls_traffic_protection_t));
    todo(connection->encryption_ctx == NULL);
    memcpy(connection->encryption_ctx, ctx_enc, sizeof(struct st_ptls_traffic_protection_t));
    connection->encryption_ctx->aead = ptls_aead_new_direct(cipher->aead, 1, key, iv);
    if (connection->connection_id > 0) {
        connection->encryption_ctx->seq = 0;
    } else {
        // Connection with connection ID 0, i.e. the first connection of the session, reuses the crypto materials
        // from the session structure, as it does not need to derive a new IV or have its own sequence.
        ptls_aead_free(ctx_enc->aead);
    }

    connection->own_decryption_ctx = malloc(sizeof(struct st_ptls_traffic_protection_t));
    todo(connection->own_decryption_ctx == NULL);
    memcpy(connection->own_decryption_ctx, ctx_enc, sizeof(struct st_ptls_traffic_protection_t));
    connection->own_decryption_ctx->aead = ptls_aead_new_direct(cipher->aead, 0, key, iv);
    if (connection->connection_id > 0) {
        connection->own_decryption_ctx->seq = 0;
    }

    if ((ret = ptls_hkdf_expand_label(cipher->hash, key, cipher->aead->key_size,
                                      ptls_iovec_init(ctx_dec->secret, cipher->hash->digest_size), "key", ptls_iovec_init(NULL, 0),
                                      session->tls_ctx->hkdf_label_prefix__obsolete)) != 0)
        return -1;
    if ((ret = ptls_hkdf_expand_label(cipher->hash, iv, cipher->aead->iv_size,
                                      ptls_iovec_init(ctx_dec->secret, cipher->hash->digest_size), "iv", ptls_iovec_init(NULL, 0),
                                      session->tls_ctx->hkdf_label_prefix__obsolete)) != 0)
        return -1;

    derive_connection_aead_iv(iv, connection->connection_id);

    connection->decryption_ctx = malloc(sizeof(struct st_ptls_traffic_protection_t));
    todo(connection->decryption_ctx == NULL);
    memcpy(connection->decryption_ctx, ctx_dec, sizeof(struct st_ptls_traffic_protection_t));
    connection->decryption_ctx->aead = ptls_aead_new_direct(cipher->aead, 0, key, iv);
    if (connection->connection_id > 0) {
        connection->decryption_ctx->seq = 0;
    } else {
        // Connection with connection ID 0, i.e. the first connection of the session, reuses the crypto materials
        // from the session structure, as it does not need to derive a new IV or have its own sequence.
        ptls_aead_free(ctx_dec->aead);
    }
    return 0;
}

void parse_tls_record_header(const uint8_t *data, uint8_t *type, uint16_t *version, uint16_t *length) {
    if (type) {
        *type = data[0];
    }
    if (version) {
        *version = ntohs(*(uint16_t *)(data + 1));
    }
    if (length) {
        *length = ntohs(*(uint16_t *)(data + 3));
    }
}

bool is_tls_record_complete(const uint8_t *data, size_t data_len, size_t *missing_len) {
    if (!data || !missing_len) {
        return false;
    }
    if (data_len < TLS_RECORD_HEADER_LEN) {
        *missing_len = TLS_RECORD_HEADER_LEN - data_len;
        return false;
    } else {
        uint16_t length;
        parse_tls_record_header(data, NULL, NULL, &length);
        if (data_len < TLS_RECORD_HEADER_LEN + length) {
            *missing_len = TLS_RECORD_HEADER_LEN + length - data_len;
        } else {
            *missing_len = 0;
        }
        return *missing_len == 0;
    }
}

uint64_t get_usec_time() {
    struct timespec tv;
    todo(clock_gettime(CLOCK_REALTIME, &tv) != 0);
    return tv.tv_sec * 1000000 + tv.tv_nsec / 1000;
}

/** Returns a pointer to element at index, ensuring element is not already used. The array grows if the index is currently not
 * allocated to an array of maximum 2*index elements. */
void *rapido_array_add(rapido_array_t *array, size_t index) {
    if (index >= array->capacity) {
        size_t new_capacity = max(index * 2, max(array->capacity * 2, 1));
        array->data = reallocarray(array->data, new_capacity, 1 + array->item_size);
        todo(array->data == NULL);
        for (int i = array->capacity; i < new_capacity; i++) {
            array->data[(1 + array->item_size) * i] = false;
        }
        array->capacity = new_capacity;
    }
    assert(array->data);
    assert(array->data[(1 + array->item_size) * index] == false);
    array->data[(1 + array->item_size) * index] = true;
    array->size++;
    return array->data + ((1 + array->item_size) * index) + 1;
}

/** Returns a pointer to element at index */
void *rapido_array_get(rapido_array_t *array, size_t index) {
    if (index >= array->capacity) {
        return NULL;
    }
    size_t offset = (1 + array->item_size) * index;
    return array->data[offset] == true ? array->data + offset + 1 : NULL;
}

/** Marks element at index as not used. */
int rapido_array_delete(rapido_array_t *array, size_t index) {
    if (index >= array->capacity) {
        return 1;
    }
    size_t offset = (1 + array->item_size) * index;
    if (array->data[offset] == false) {
        return 1;
    }
    array->data[(1 + array->item_size) * index] = false;
    array->size--;
    return 0;
}

/** Free the array associated data and reset its structure */
void rapido_array_free(rapido_array_t *array) {
    if (array->capacity && array->data) {
        free(array->data);
        memset(array, 0, sizeof(rapido_array_t));
    }
}

/** Initialises and allocates a queue of given item size and capacity */
void rapido_queue_init(rapido_queue_t *queue, size_t item_size, size_t capacity) {
    queue->data = malloc(item_size * capacity);
    todo(queue->data == NULL);
    queue->capacity = capacity;
    queue->size = 0;
    queue->front_index = 0;
    queue->back_index = 0;
    queue->item_size = item_size;
}

/** Returns a pointer to a new element pushed at the back of the queue */
void *rapido_queue_push(rapido_queue_t *queue) {
    assert(queue->size < queue->capacity);
    size_t item_index = queue->back_index;
    queue->back_index = (queue->back_index + 1) % queue->capacity;
    queue->size++;
    return queue->data + (item_index * queue->item_size);
}

/** Returns a pointer to the element peeked from the front of the queue, or NULL if none is present. */
void *rapido_queue_peek(rapido_queue_t *queue) {
    return queue->size ? queue->data + (queue->front_index * queue->item_size) : NULL;
}

/** Returns a pointer to an element poped from the front of the queue.
 * Note: Pushing on the queue can overwrite the memory zone returned. */
void *rapido_queue_pop(rapido_queue_t *queue) {
    assert(queue->size > 0);
    size_t item_index = queue->front_index;
    queue->front_index = (queue->front_index + 1) % queue->capacity;
    queue->size--;
    return queue->data + (item_index * queue->item_size);
}

/** Free the queue associated data and reset its structure */
void rapido_queue_free(rapido_queue_t *queue) {
    if (queue->capacity && queue->data) {
        free(queue->data);
        memset(queue, 0, sizeof(rapido_queue_t));
    }
}

/** Initialises and allocates a circular buffer of given capacity */
void rapido_buffer_init(rapido_buffer_t *buffer, size_t capacity) {
    buffer->data = malloc(capacity);
    todo(buffer->data == NULL);
    buffer->capacity = capacity;
    buffer->size = 0;
    buffer->front_index = 0;
    buffer->back_index = 0;
}

/** Returns a pointer to a memory zone at the back of the buffer. Its length is in the range [min_len, *len].
 * The buffer grows when its maximum capacity is exceeded or when min_len cannot be satisfied. */
void *rapido_buffer_alloc(rapido_buffer_t *buffer, size_t *len, size_t min_len) {
    size_t wrap_len = buffer->capacity - buffer->back_index; // The length after which the space left wraps around the end of the
                                                             // buffer
    // TODO: Find the right coeff instead
    while (buffer->size + *len > buffer->capacity || wrap_len < min_len) { // While the required size exceed the capacity or the
                                                                           // wrap_len is too low, grow the buffer.
        buffer->data = reallocarray(buffer->data, 1, buffer->capacity * 2);
        todo(buffer->data == NULL);
        buffer->capacity *= 2;
        if (buffer->back_index <= buffer->front_index) {
            /*    v-----------v wrap_len               v-----------v wrap_len
             * |xx.........xxx|  =>   |...........xxxxx............|
             *    |        |_ front_index         |    |_ back_index
             *    |_ back_index                   |_ front_index                                                                  */
            memcpy(buffer->data + buffer->front_index + buffer->size - buffer->back_index, buffer->data, buffer->back_index);
            buffer->back_index = buffer->front_index + buffer->size;
        }
        wrap_len = buffer->capacity - buffer->back_index;
    }
    *len = min(*len, wrap_len);
    void *ptr = buffer->data + buffer->back_index;
    buffer->size += *len;
    buffer->back_index = (buffer->back_index + *len) % buffer->capacity;
    return ptr;
}

/** Releases len bytes at the back of the buffer. */
void rapido_buffer_trim_end(rapido_buffer_t *buffer, size_t len) {
    assert(len <= buffer->size);
    buffer->back_index = (buffer->back_index - len) % buffer->capacity;
    buffer->size -= len;
    if (buffer->size == 0) {
        buffer->front_index = 0;
        buffer->back_index = 0;
    }
}

/** Copies a memory zone to the back of the buffer. */
void rapido_buffer_push(rapido_buffer_t *buffer, void *input, size_t len) {
    size_t total_len = len;
    void *ptr = rapido_buffer_alloc(buffer, &len, 0);
    memcpy(ptr, input, len);
    len = total_len - len;
    if (len) {
        ptr = rapido_buffer_alloc(buffer, &len, 0);
        memcpy(ptr, input + len, total_len - len);
    }
}

/** Returns a pointer to a memory zone starting at a given offset from the front of the buffer.
 * The zone spans at most *len bytes. */
void *rapido_buffer_peek(rapido_buffer_t *buffer, size_t offset, size_t *len) {
    if (offset >= buffer->size) {
        *len = 0;
        return NULL;
    }
    size_t read_len = min(*len, buffer->size - offset);
    *len = min(read_len, buffer->capacity - ((buffer->front_index + offset) % buffer->capacity));
    return buffer->data + ((buffer->front_index + offset) % buffer->capacity);
}

/** Returns a pointer to a memory zone starting from the front of the buffer and spanning at most *len bytes.
 * The zone is released from the buffer. */
void *rapido_buffer_pop(rapido_buffer_t *buffer, size_t *len) {
    void *ptr = rapido_buffer_peek(buffer, 0, len);
    buffer->front_index = (buffer->front_index + *len) % buffer->capacity;
    buffer->size -= *len;
    if (buffer->size == 0) {
        buffer->front_index = 0;
        buffer->back_index = 0;
    }
    return ptr;
}

/** Free the circular buffer associated data and reset its structure */
void rapido_buffer_free(rapido_buffer_t *buffer) {
    if (buffer->capacity && buffer->data) {
        free(buffer->data);
    }
    memset(buffer, 0, sizeof(rapido_buffer_t));
}

/** Adds the given inclusive range to the list and merges overlapping ranges. */
int rapido_add_range(rapido_range_list_t *list, uint64_t low, uint64_t high) {
    assert(low < high);
    assert(list->size < RANGES_LEN);
    bool merged = false;
    for (int i = 0; i < list->size && !merged; i++) {
        struct rapido_range_item *r = list->ranges + i;
        if (r->low <= low && low <= r->high) {
            /* Range overlaps, potentially extending the high limit */
            r->high = max(r->high, high);
            merged = true;
        }
        if (r->low <= high && high <= r->high) {
            /* Range overlaps, potentially extending the low limit */
            r->low = min(r->low, low);
            merged = true;
        }
        if (!merged && low < r->low) {
            /* Range is strictly before next range */
            memmove(list->ranges + i + 1, list->ranges + i, (list->size - i) * sizeof(struct rapido_range_item));
            list->size++;
            r->low = low;
            r->high = high;
            return 0;
        }
    }
    for (int i = 0; i + 1 < list->size; i++) {
        struct rapido_range_item *r = list->ranges + i;
        struct rapido_range_item *n = list->ranges + i + 1;
        if (r->high >= n->low) {
            /* Range overlaps next one */
            n->low = r->low;
            memmove(list->ranges + i, list->ranges + i + 1, (list->size - i - 1) * sizeof(struct rapido_range_item));
            list->size--;
            i--;
        }
    }
    if (!merged) {
        /* No range is inferior to this range */
        assert(list->size < RANGES_LEN);
        list->ranges[list->size].low = low;
        list->ranges[list->size].high = high;
        list->size++;
    }
    return 0;
}

/** Returns the lowest range from the list. */
void rapido_peek_range(rapido_range_list_t *list, uint64_t *low, uint64_t *high) {
    *low = 0;
    *high = 0;
    if (list->size > 0) {
        *low = list->ranges[0].low;
        *high = list->ranges[0].high;
    }
}

/** Removes ranges below or equal to the given value. Returns the largest value within a range removed, -1 if no range was removed
 */
uint64_t rapido_trim_range(rapido_range_list_t *list, uint64_t limit) {
    uint64_t offset = -1;
    for (int i = 0; i < list->size; i++) {
        struct rapido_range_item *r = list->ranges + i;
        if (r->low <= limit && limit < r->high) {
            offset = limit;
            r->low = limit;
        } else if (r->high <= limit) {
            offset = r->high;
            memmove(list->ranges + i, list->ranges + i + 1, (list->size - i - 1) * sizeof(struct rapido_range_item));
            list->size--;
        }
    }
    return offset;
}

/** Initialises and allocates the buffer. */
void rapido_range_buffer_init(rapido_range_buffer_t *receive, size_t capacity) {
    memset(receive, 0, sizeof(rapido_range_buffer_t));
    receive->buffer.data = malloc(capacity);
    todo(receive->buffer.data == NULL);
    receive->buffer.capacity = capacity;
}

/** Copies a given memory zone to a given offset in the buffer. */
int rapido_range_buffer_write(rapido_range_buffer_t *receive, size_t offset, void *input, size_t len) {
    assert(offset >= receive->read_offset);
    size_t write_offset = offset - receive->read_offset; // Converts the external ever-increasing offset into the buffer offset.
    while (write_offset + len > receive->buffer.capacity) {
        size_t new_cap = receive->buffer.capacity * 2; // TODO: Find the right coeff instead
        receive->buffer.data = reallocarray(receive->buffer.data, new_cap, 1);
        todo(receive->buffer.data == NULL);
        size_t wrap_len = receive->buffer.capacity - receive->buffer.offset; // The length after which the space left wraps around
                                                                             // the end of the buffer.
        memcpy(receive->buffer.data + receive->buffer.capacity, receive->buffer.data + wrap_len,
               receive->buffer.capacity - wrap_len); // Always copies what is before the offset to the back of the buffer without
                                                     // discerning whether it is actually used, for simplicity.
        receive->buffer.capacity = new_cap;
    }
    size_t real_offset = (receive->buffer.offset + write_offset) % receive->buffer.capacity; // The wrapped write_offset.
    size_t wrap_len = receive->buffer.capacity - real_offset; // The amount of space from the real_offset before the buffer wraps.
    memcpy(receive->buffer.data + real_offset, input, min(len, wrap_len));
    if (wrap_len < len) { // Copies what remains in the wrapped part of the buffer, if any.
        memcpy(receive->buffer.data, input + wrap_len, len - wrap_len);
    }

    rapido_add_range(&receive->ranges, offset, offset + len);
    return 0;
}

/** Returns a pointer to a memory zone at the start of the buffer of at most *len bytes.
 * The zone is released from the buffer.*/
void *rapido_range_buffer_get(rapido_range_buffer_t *receive, size_t *len) {
    size_t limit = max(*len, receive->read_offset + *len);
    size_t read_offset = rapido_trim_range(&receive->ranges, limit);
    void *ptr = NULL;
    if (read_offset != -1) {
        *len = min(*len, read_offset - receive->read_offset);
        size_t wrap_offset = receive->buffer.capacity - receive->buffer.offset;
        *len = min(*len, wrap_offset);
        ptr = receive->buffer.data + receive->buffer.offset;
        receive->read_offset += *len;
        receive->buffer.offset = (receive->buffer.offset + *len) % receive->buffer.capacity;
    } else {
        *len = 0;
    }
    return ptr;
}

/** Free the circular buffer associated data and reset its structure */
void rapido_range_buffer_free(rapido_range_buffer_t *receive) {
    if (receive->buffer.capacity && receive->buffer.data != NULL) {
        free(receive->buffer.data);
    }
    memset(receive, 0, sizeof(rapido_range_buffer_t));
}

typedef uint8_t rapido_frame_type_t;

static const rapido_frame_type_t padding_frame_type = 0x0;
static const rapido_frame_type_t ping_frame_type = 0x1;
static const rapido_frame_type_t stream_frame_type = 0x2;
static const rapido_frame_type_t ack_frame_type = 0x3;
static const rapido_frame_type_t new_session_id_frame_type = 0x4;
static const rapido_frame_type_t new_address_frame_type = 0x5;
static const rapido_frame_type_t connection_failed_frame_type = 0x6;
static const rapido_frame_type_t ebpf_code_frame_type = 0x7;

typedef struct {
    rapido_stream_id_t stream_id;
    uint64_t offset;
    size_t len;
    uint8_t fin;
    uint8_t *data;
} rapido_stream_frame_t;

typedef struct {
    rapido_connection_id_t connection_id;
    uint64_t last_record_acknowledged;
} rapido_ack_frame_t;

typedef struct {
    rapido_connection_id_t sequence;
    uint8_t *tls_session_id;
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

int rapido_frame_is_ack_eliciting(rapido_frame_type_t frame_id) {
    return frame_id != padding_frame_type && frame_id != ack_frame_type;
}

void rapido_connection_init(rapido_t *session, rapido_connection_t *connection) {
    memset(connection, 0, sizeof(rapido_connection_t));
    connection->last_received_record_sequence = -1;
    rapido_buffer_init(&connection->receive_buffer, 32 * TLS_MAX_RECORD_SIZE);
    rapido_buffer_init(&connection->send_buffer, 32 * TLS_MAX_RECORD_SIZE);
    rapido_queue_init(&connection->sent_records, sizeof(rapido_record_metadata_t), 512);
}

void rapido_connection_close(rapido_t *session, rapido_connection_t *connection) {
    close(connection->socket);
    connection->socket = -1;
    rapido_application_notification_t *notification = rapido_queue_push(&session->pending_notifications);
    notification->notification_type = rapido_connection_closed;
    notification->connection_id = connection->connection_id;
    // TODO: Properly close the connection
}

rapido_t *rapido_new(ptls_context_t *tls_ctx, bool is_server, const char *server_name, FILE *qlog_out) {
    rapido_t *session = calloc(1, sizeof(rapido_t));
    todo(session == NULL);
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

    session->next_stream_id = is_server ? 1 : 0;

    session->connections.item_size = sizeof(rapido_connection_t);
    session->streams.item_size = sizeof(rapido_stream_t);
    session->local_addresses.item_size = sizeof(struct sockaddr_storage);
    session->remote_addresses.item_size = sizeof(struct sockaddr_storage);
    session->tls_session_ids.item_size = TLS_SESSION_ID_LEN;
    rapido_queue_init(&session->pending_notifications, sizeof(rapido_application_notification_t), 256);

    if (session->is_server) {
        session->server.listen_sockets.item_size = sizeof(int);
        session->server.pending_connections.item_size = sizeof(rapido_pending_connection_t);
    }

    session->qlog.out = qlog_out;
    session->qlog.reference_time = get_usec_time();
    QLOG(session, "api", "rapido_new", "", "{\"is_server\": %d, \"server_name\": \"%s\"}", is_server, server_name);
    return session;
}

rapido_address_id_t rapido_add_address(rapido_t *session, struct sockaddr *local_address, socklen_t local_address_len) {
    assert(local_address != NULL);
    assert(local_address_len == sizeof(struct sockaddr_in) || local_address_len == sizeof(struct sockaddr_in6));
    rapido_address_id_t local_address_id = session->next_local_address_id++;
    memcpy(rapido_array_add(&session->local_addresses, local_address_id), local_address, local_address_len);
    if (session->is_server) { // TODO: Ipv6 dualstack compat mode ?
        int listen_fd = socket(local_address->sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
        todo_perror(listen_fd == -1);
        memcpy(rapido_array_add(&session->server.listen_sockets, local_address_id), &listen_fd, sizeof(listen_fd));
        int yes = 1;
        todo_perror(setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)));
        // TODO Make it a poll struct rather
        todo_perror(bind(listen_fd, local_address,
                           local_address->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
        todo_perror(listen(listen_fd, SOMAXCONN));
    }
    LOG {
        char a[INET6_ADDRSTRLEN];
        QLOG(session, "api", "rapido_add_address", "", "{\"local_address_id\": \"%d\", \"local_address\": \"%s:%d\"}",
             local_address_id,
             inet_ntop(local_address->sa_family,
                       (local_address->sa_family == AF_INET ? (void *)&((struct sockaddr_in *)local_address)->sin_addr
                                                            : &((struct sockaddr_in6 *)local_address)->sin6_addr),
                       a, sizeof(a)),
             ntohs(local_address->sa_family == AF_INET ? ((struct sockaddr_in *)local_address)->sin_port
                                                       : ((struct sockaddr_in6 *)local_address)->sin6_port));
    }
    return local_address_id;
}

rapido_address_id_t rapido_add_remote_address(rapido_t *session, struct sockaddr *remote_address, socklen_t remote_address_len) {
    assert(remote_address != NULL);
    assert(remote_address_len == sizeof(struct sockaddr_in) || remote_address_len == sizeof(struct sockaddr_in6));
    rapido_address_id_t remote_address_id = session->next_remote_address_id++;
    memcpy(rapido_array_add(&session->remote_addresses, remote_address_id), remote_address, remote_address_len);
    LOG {
        char a[INET6_ADDRSTRLEN];
        QLOG(session, "api", "rapido_add_remote_address", "", "{\"local_address_id\": \"%d\", \"local_address\": \"%s:%d\"}",
             remote_address_id,
             inet_ntop(remote_address->sa_family,
                       remote_address->sa_family == AF_INET ? (void *)&((struct sockaddr_in *)remote_address)->sin_addr
                                                            : &((struct sockaddr_in6 *)remote_address)->sin6_addr,
                       a, sizeof(a)),
             ntohs(remote_address->sa_family == AF_INET ? ((struct sockaddr_in *)remote_address)->sin_port
                                                        : ((struct sockaddr_in6 *)remote_address)->sin6_port));
    }
    return remote_address_id;
}

int rapido_remove_address(rapido_t *session, rapido_address_id_t local_address_id) {
    rapido_array_iter(&session->connections, rapido_connection_t * connection, {
        if (connection->local_address_id == local_address_id) {
            WARNING("Local address %d of connection %d is removed\n", local_address_id, connection->connection_id);
            // TODO: Migrate streams and RTX state for this connection
        }
    });
    // TODO: Send it
    if (session->is_server) {
        int *fd = rapido_array_get(&session->server.listen_sockets, local_address_id);
        if (fd != NULL) {
            todo_perror(close(*fd));
            rapido_array_delete(&session->server.listen_sockets, local_address_id);
        }
    }
    QLOG(session, "api", "rapido_remove_address", "", "{\"local_address_id\": \"%d\"}", local_address_id);
    return rapido_array_delete(&session->local_addresses, local_address_id);
}

rapido_connection_id_t rapido_create_connection(rapido_t *session, uint8_t local_address_id, uint8_t remote_address_id) {
    assert(!session->is_server);
    struct sockaddr *local_address = (struct sockaddr *)rapido_array_get(&session->local_addresses, local_address_id);
    struct sockaddr *remote_address = (struct sockaddr *)rapido_array_get(&session->remote_addresses, remote_address_id);
    assert(local_address != NULL || local_address_id == session->next_local_address_id);
    assert(remote_address != NULL);
    assert(local_address == NULL || local_address->sa_family == remote_address->sa_family);

    rapido_connection_id_t connection_id = session->next_connection_id++;
    uint8_t *tls_session_id = rapido_array_get(&session->tls_session_ids, connection_id);
    assert(connection_id == 0 || tls_session_id != NULL);

    rapido_connection_t *connection = rapido_array_add(&session->connections, connection_id);
    rapido_connection_init(session, connection);
    connection->connection_id = connection_id;
    connection->local_address_id = local_address_id;
    connection->remote_address_id = remote_address_id;
    connection->socket = socket(remote_address->sa_family, SOCK_STREAM, 0);
    todo_perror(connection->socket == -1);
    int yes = 1;
    todo_perror(setsockopt(connection->socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)));
    if (local_address != NULL) {
        todo_perror(bind(connection->socket, local_address,
                           local_address->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
    }
    int ret = connect(connection->socket, remote_address,
                      remote_address->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    if (ret && errno != EINPROGRESS) {
        todo_perror(ret);
    }

    if (local_address == NULL) {
        local_address = rapido_array_add(&session->local_addresses, local_address_id);
        session->next_local_address_id++;
        socklen_t local_address_len = sizeof(struct sockaddr_storage);
        todo_perror(getsockname(connection->socket, local_address, &local_address_len));
        LOG {
            char a[INET6_ADDRSTRLEN];
            QLOG(session, "network", "new_local_address", "", "{\"local_address_id\": \"%d\", \"local_address\": \"%s:%d\"}",
                 local_address_id,
                 inet_ntop(local_address->sa_family,
                           (local_address->sa_family == AF_INET ? (void *)&((struct sockaddr_in *)local_address)->sin_addr
                                                                : &((struct sockaddr_in6 *)local_address)->sin6_addr),
                           a, sizeof(a)),
                 ntohs(local_address->sa_family == AF_INET ? ((struct sockaddr_in *)local_address)->sin_port
                                                           : ((struct sockaddr_in6 *)local_address)->sin6_port));
        }
    }

    ptls_buffer_t handshake_buffer = {0};
    ptls_buffer_init(&handshake_buffer, "", 0);
    if (connection_id == 0) {
        connection->tls = session->tls;
        session->tls_ctx->random_bytes(rapido_array_add(&session->tls_session_ids, 0), TLS_SESSION_ID_LEN);
        session->tls_properties.client.tls_session_id =
            ptls_iovec_init(rapido_array_get(&session->tls_session_ids, 0), TLS_SESSION_ID_LEN);
        ret = ptls_handshake(session->tls, &handshake_buffer, NULL, 0, &session->tls_properties);
    } else {
        connection->tls = ptls_new(session->tls_ctx, session->is_server);
        ptls_set_server_name(connection->tls, ptls_get_server_name(session->tls), 0);
        ptls_handshake_properties_t tls_properties = {0};
        tls_properties.client.tls_session_id =
            ptls_iovec_init(rapido_array_get(&session->tls_session_ids, connection_id), TLS_SESSION_ID_LEN);
        ret = ptls_handshake(connection->tls, &handshake_buffer, NULL, 0, &tls_properties);
    }

    todo(ret != PTLS_ERROR_IN_PROGRESS);
    todo(send(connection->socket, handshake_buffer.base, handshake_buffer.off, 0) != handshake_buffer.off);
    ptls_buffer_dispose(&handshake_buffer);
    // TODO: Keep it as non-blocking and add the handshake data to the send buffer
    todo_perror(fcntl(connection->socket, F_SETFL, fcntl(connection->socket, F_GETFL, 0) | O_NONBLOCK));

    QLOG(session, "api", "rapido_create_connection", "",
         "{\"connection_id\": \"%d\", \"local_address_id\": \"%d\", \"remote_address_id\": \"%d\"}", connection_id,
         local_address_id, remote_address_id);
    return connection_id;
}

int rapido_close_connection(rapido_t *session, rapido_connection_id_t connection_id) {
    rapido_connection_t *connection = rapido_array_get(&session->connections, connection_id);
    assert(connection != NULL);
    close(connection->socket);
    connection->socket = -1;
    return 0;
}

rapido_stream_id_t rapido_open_stream(rapido_t *session) {
    rapido_stream_id_t next_stream_id = session->next_stream_id;
    session->next_stream_id += 2;
    rapido_stream_t *stream = rapido_array_add(&session->streams, next_stream_id);
    memset(stream, 0, sizeof(rapido_stream_t));
    stream->stream_id = next_stream_id;
    rapido_range_buffer_init(&stream->read_buffer, 2 * TLS_MAX_RECORD_SIZE);
    rapido_buffer_init(&stream->send_buffer, 2 * TLS_MAX_RECORD_SIZE);
    QLOG(session, "api", "rapido_open_stream", "", "{\"stream_id\": \"%d\"}", next_stream_id);
    return next_stream_id;
}
int rapido_attach_stream(rapido_t *session, rapido_stream_id_t stream_id, rapido_connection_id_t connection_id) {
    assert(stream_id < SET_LEN && connection_id < SET_LEN);
    rapido_stream_t *stream = rapido_array_get(&session->streams, stream_id);
    assert(stream != NULL);
    rapido_connection_t *connection = rapido_array_get(&session->connections, connection_id);
    assert(connection != NULL);

    SET_ADD(stream->connections, connection_id);
    SET_ADD(connection->attached_streams, stream_id);
    QLOG(session, "api", "rapido_attach_stream", "", "{\"stream_id\": \"%d\", \"connection_id\": \"%d\"}", stream_id,
         connection_id);
    return 0;
}
int rapido_remove_stream(rapido_t *session, rapido_stream_id_t stream_id, rapido_connection_id_t connection_id) {
    assert(stream_id < SET_LEN && connection_id < SET_LEN);
    rapido_stream_t *stream = rapido_array_get(&session->streams, stream_id);
    assert(stream != NULL);
    rapido_connection_t *connection = rapido_array_get(&session->connections, connection_id);
    assert(connection != NULL);

    SET_REMOVE(stream->connections, connection_id);
    SET_REMOVE(connection->attached_streams, stream_id);
    QLOG(session, "api", "rapido_remove_stream", "", "{\"stream_id\": \"%d\", \"connection_id\": \"%d\"}", stream_id,
         connection_id);
    return 0;
}
int rapido_add_to_stream(rapido_t *session, rapido_stream_id_t stream_id, void *data, size_t len) {
    rapido_stream_t *stream = rapido_array_get(&session->streams, stream_id);
    assert(stream != NULL);
    rapido_buffer_push(&stream->send_buffer, data, len);
    QLOG(session, "api", "rapido_add_to_stream", "", "{\"stream_id\": \"%d\", \"len\": \"%zu\"}", stream_id, len);
    return 0;
}
int rapido_set_stream_producer(rapido_t *session, rapido_stream_id_t stream_id, rapido_stream_producer_t producer,
                               void *producer_ctx) {
    rapido_stream_t *stream = rapido_array_get(&session->streams, stream_id);
    assert(stream != NULL);
    stream->producer = producer;
    stream->producer_ctx = producer_ctx;
    QLOG(session, "api", "rapido_set_stream_producer", "", "{\"stream_id\": \"%d\"}", stream_id);
    return 0;
}
void *rapido_read_stream(rapido_t *session, rapido_stream_id_t stream_id, size_t *len) {
    rapido_stream_t *stream = rapido_array_get(&session->streams, stream_id);
    assert(stream != NULL);
    QLOG(session, "api", "rapido_read_stream", "", "{\"stream_id\": \"%d\", \"len\": \"%zu\"}", stream_id, *len);
    return rapido_range_buffer_get(&stream->read_buffer, len);
}
int rapido_close_stream(rapido_t *session, rapido_stream_id_t stream_id) {
    rapido_stream_t *stream = rapido_array_get(&session->streams, stream_id);
    assert(stream != NULL);
    assert(!stream->fin_set);
    stream->fin_set = true;
    stream->write_fin = stream->write_offset + stream->send_buffer.size;
    QLOG(session, "api", "rapido_close_stream", "", "{\"stream_id\": \"%d\", \"fin_offset\": \"%zu\"}", stream_id,
         stream->write_fin);
    return 0;
}
int rapido_prepare_stream_frame(rapido_t *session, rapido_stream_t *stream, uint8_t *buf, size_t *len) {
    // TODO: Handle ACK/RTX buffers
    size_t stream_header_len = sizeof(rapido_frame_type_t) + sizeof(rapido_stream_id_t) + (2 * sizeof(uint64_t));
    size_t consumed = 0;
    if (*len < 1 + stream_header_len)
        goto Exit;
    size_t payload_len = min(*len, TLS_MAX_RECORD_SIZE) - 1 - stream_header_len;
    void *stream_data;
    if (stream->producer) {
        if (stream->fin_set) {
            payload_len = min(payload_len, stream->write_fin - stream->write_offset);
        }
        stream_data = stream->producer(session, stream->stream_id, stream->producer_ctx, stream->write_offset, &payload_len);
    } else {
        // TODO: Handle when the buffer returns a smaller pointer due to buffer cycling
        stream_data = rapido_buffer_pop(&stream->send_buffer, &payload_len);
    }
    bool fin = stream->fin_set && stream->write_offset + payload_len == stream->write_fin;
    if (payload_len == 0 && !fin)
        goto Exit;

    *(uint8_t *)(buf + consumed) = stream_frame_type;
    consumed += sizeof(rapido_frame_type_t);
    *(rapido_stream_id_t *)(buf + consumed) = htobe32(stream->stream_id);
    consumed += sizeof(rapido_stream_id_t);
    *(uint64_t *)(buf + consumed) = htobe64(stream->write_offset);
    consumed += sizeof(uint64_t);
    *(uint64_t *)(buf + consumed) = htobe64(payload_len);
    consumed += sizeof(uint64_t);
    *(uint8_t *)(buf + consumed) = fin;
    consumed += sizeof(uint8_t);
    memcpy(buf + consumed, stream_data, payload_len);
    consumed += payload_len;

    QLOG(session, "frames", "prepare_stream_frame", "",
         "{\"stream_id\": \"%d\", \"offset\": \"%lu\", \"len\": \"%lu\", \"fin\": %d}", stream->stream_id, stream->write_offset,
         payload_len, fin);

    if (fin) {
        stream->fin_sent = true;
    }
    stream->write_offset += payload_len;
Exit:
    *len = consumed;
    return 0;
}

int rapido_decode_stream_frame(rapido_t *session, uint8_t *buf, size_t *len, rapido_stream_frame_t *frame) {
    size_t stream_header_len = sizeof(rapido_frame_type_t) + sizeof(rapido_stream_id_t) + (2 * sizeof(uint64_t));
    assert(buf[0] == stream_frame_type);
    assert(*len > stream_header_len);
    size_t consumed = 1;
    frame->stream_id = be32toh(*(rapido_stream_id_t *)(buf + consumed));
    consumed += sizeof(rapido_stream_id_t);
    frame->offset = be64toh(*(uint64_t *)(buf + consumed));
    consumed += sizeof(uint64_t);
    frame->len = be64toh(*(uint64_t *)(buf + consumed));
    consumed += sizeof(uint64_t);
    frame->fin = buf[consumed];
    consumed += sizeof(uint8_t);
    frame->data = buf + consumed;
    consumed += frame->len;
    *len = consumed;
    QLOG(session, "frames", "decode_stream_frame", "",
         "{\"stream_id\": \"%d\", \"offset\": \"%lu\", \"len\": \"%lu\", \"fin\": %d}", frame->stream_id, frame->offset, frame->len,
         frame->fin);
    return 0;
}

int rapido_process_stream_frame(rapido_t *session, rapido_stream_frame_t *frame) {
    rapido_stream_t *stream = rapido_array_get(&session->streams, frame->stream_id);
    if (stream == NULL) {
        assert(CLIENT_STREAM(frame->stream_id) == session->is_server);
        stream = rapido_array_add(&session->streams, frame->stream_id);
        memset(stream, 0, sizeof(rapido_stream_t));
        stream->stream_id = frame->stream_id;
        rapido_range_buffer_init(&stream->read_buffer, 2 * TLS_MAX_RECORD_SIZE);
        rapido_buffer_init(&stream->send_buffer, 2 * TLS_MAX_RECORD_SIZE);
        rapido_application_notification_t *notification = rapido_queue_push(&session->pending_notifications);
        notification->notification_type = rapido_new_stream;
        notification->stream_id = frame->stream_id;
    }
    assert(!stream->fin_received || (frame->offset + frame->len <= stream->read_fin));
    assert(!frame->fin || !stream->fin_received);
    assert(frame->len > 0 || frame->fin);
    if (frame->len) {
        rapido_range_buffer_write(&stream->read_buffer, frame->offset, frame->data, frame->len);
        rapido_application_notification_t *notification = rapido_queue_push(&session->pending_notifications);
        notification->notification_type = rapido_stream_has_data;
        notification->stream_id = frame->stream_id;
    }
    if (frame->fin) {
        stream->fin_received = frame->fin;
        stream->read_fin = frame->offset + frame->len;
        rapido_application_notification_t *notification = rapido_queue_push(&session->pending_notifications);
        notification->notification_type = rapido_stream_closed;
        notification->stream_id = frame->stream_id;
    }
    return 0;
}

int rapido_prepare_new_session_id_frame(rapido_t *session, uint8_t *tls_session_id, rapido_connection_id_t sequence, uint8_t *buf,
                                        size_t *len) {
    size_t new_session_id_len = sizeof(rapido_frame_type_t) + sizeof(rapido_connection_id_t) + 32;
    size_t consumed = 0;
    if (*len < 1 + new_session_id_len)
        goto Exit;

    *(uint8_t *)(buf + consumed) = new_session_id_frame_type;
    consumed += sizeof(rapido_frame_type_t);
    *(uint32_t *)(buf + consumed) = htobe32(sequence);
    consumed += sizeof(uint32_t);
    memcpy(buf + consumed, tls_session_id, TLS_SESSION_ID_LEN);
    consumed += TLS_SESSION_ID_LEN;

    QLOG(session, "frames", "prepare_new_session_id_frame", "", "{\"sequence\": \"%d\"}", sequence);

Exit:
    *len = consumed;
    return 0;
}

int rapido_decode_new_session_id_frame(rapido_t *session, uint8_t *buf, size_t *len, rapido_new_session_id_frame_t *frame) {
    size_t new_session_id_len = sizeof(rapido_frame_type_t) + sizeof(rapido_connection_id_t) + 32;
    assert(*len >= new_session_id_len);
    size_t consumed = 1;
    frame->sequence = be32toh(*(rapido_connection_id_t *)(buf + consumed));
    consumed += sizeof(rapido_connection_id_t);
    frame->tls_session_id = buf + consumed;
    consumed += TLS_SESSION_ID_LEN;

    LOG {
        char tls_session_id_str[TLS_SESSION_ID_LEN * 2 + 1];
        tohex(frame->tls_session_id, TLS_SESSION_ID_LEN, tls_session_id_str);
        QLOG(session, "frames", "decode_new_session_id_frame", "", "{\"sequence\": \"%d\", \"session_id\": \"%s\"}",
             frame->sequence, tls_session_id_str);
    }

    *len = consumed;
    return 0;
}

int rapido_process_new_session_id_frame(rapido_t *session, rapido_new_session_id_frame_t *frame) {
    assert(!session->is_server);
    memcpy(rapido_array_add(&session->tls_session_ids, frame->sequence), frame->tls_session_id, TLS_SESSION_ID_LEN);
    return 0;
}

int rapido_prepare_ack_frame(rapido_t *session, uint8_t *buf, size_t *len) {
    size_t consumed = 0;
    rapido_array_iter(&session->connections, rapido_connection_t * connection, {
        if (*len - consumed < 1 + sizeof(rapido_connection_id_t) + sizeof(uint64_t)) {
            break;
        }
        if (connection->require_ack) {
            buf[consumed] = ack_frame_type;
            consumed++;
            *(uint32_t *)(buf + consumed) = htonl(connection->connection_id);
            consumed += sizeof(uint32_t);
            *(uint64_t *)(buf + consumed) = htobe64(connection->last_received_record_sequence);
            consumed += sizeof(uint64_t);
            connection->require_ack = false;
            connection->last_receive_time = 0;
            connection->non_ack_eliciting_count = 0;
            QLOG(session, "frames", "rapido_prepare_ack_frame", "",
                 "{\"connection_id\": \"%d\", \"last_record_acknowledged\": \"%lu\"}", connection->connection_id,
                 connection->last_received_record_sequence);
        }
    });
    *len = consumed;
    return 0;
}

int rapido_decode_ack_frame(rapido_t *session, uint8_t *buf, size_t *len, rapido_ack_frame_t *frame) {
    assert(*len >= 1 + sizeof(rapido_connection_id_t) + sizeof(uint64_t));
    size_t consumed = 1;
    frame->connection_id = ntohl(*(uint32_t *)(buf + consumed));
    consumed += sizeof(rapido_connection_id_t);
    frame->last_record_acknowledged = be64toh(*(uint64_t *)(buf + consumed));
    consumed += sizeof(uint64_t);
    *len = consumed;
    QLOG(session, "frames", "rapido_decode_ack_frame", "", "{\"connection_id\": \"%d\", \"last_record_acknowledged\": \"%lu\"}",
         frame->connection_id, frame->last_record_acknowledged);
    return 0;
}

int rapido_process_ack_frame(rapido_t *session, rapido_ack_frame_t *frame) {
    rapido_connection_t *connection = rapido_array_get(&session->connections, frame->connection_id);
    assert(connection != NULL);
    rapido_record_metadata_t *record;
    while ((record = rapido_queue_peek(&connection->sent_records))) {
        if (record->tls_record_sequence <= frame->last_record_acknowledged) {
            size_t record_len = record->ciphertext_len;
            rapido_buffer_pop(&connection->send_buffer, &record_len);
            if (record_len < record->ciphertext_len) {
                record_len = record->ciphertext_len - record_len;
                rapido_buffer_pop(&connection->send_buffer, &record_len);
            }
            connection->sent_offset -= record->ciphertext_len;
            rapido_queue_pop(&connection->sent_records);
        } else {
            break;
        }
    }
    return 0;
}

int rapido_prepare_new_address_frame(rapido_t *session, rapido_address_id_t address_id, uint8_t *buf, size_t *len) {
    struct sockaddr_storage *address = rapido_array_get(&session->local_addresses, address_id);
    assert(address);
    size_t consumed = 0;

    uint8_t family = address->ss_family == AF_INET ? 4 : 6;
    size_t address_len = address->ss_family == AF_INET ? 4 : 16;
    size_t min_size = sizeof(rapido_frame_type_t) + sizeof(rapido_address_id_t) + 1 + address_len + 2;
    if (*len > min_size) {
        buf[consumed++] = new_address_frame_type;
        buf[consumed++] = address_id;
        buf[consumed++] = family;
        memcpy(buf + consumed, SOCKADDR_ADDR(address), address_len);
        consumed += address_len;
        *(uint16_t *)(buf + consumed) = *SOCKADDR_PORT(address);
        consumed += sizeof(uint16_t);
        SET_ADD(session->addresses_advertised, address_id);
    }
    *len = consumed;
    LOG {
        char a[INET6_ADDRSTRLEN];
        todo_perror(inet_ntop(address->ss_family, SOCKADDR_ADDR(address), a, sizeof(a)) == NULL);
        QLOG(session, "frames", "rapido_prepare_new_address_frame", "",
             "{\"address_id\": \"%d\", \"family\": \"%d\", \"address\": \"%s\", \"port\": \"%d\"}", address_id, family, a,
             *SOCKADDR_PORT(address));
    };
    return 0;
}

int rapido_decode_new_address_frame(rapido_t *session, uint8_t *buf, size_t *len, rapido_new_address_frame_t *frame) {
    assert(*len >= sizeof(rapido_frame_type_t) + sizeof(rapido_address_id_t) + 1 + 4 + 2);
    size_t consumed = 1;
    frame->address_id = buf[consumed++];
    frame->family = buf[consumed++];
    memcpy(frame->addr, buf + consumed, frame->family == 4 ? 4 : 16);
    consumed += frame->family == 4 ? 4 : 16;
    frame->port = ntohs(*(uint16_t *)(buf + consumed));
    consumed += sizeof(uint16_t);
    *len = consumed;
    LOG {
        char a[INET6_ADDRSTRLEN];
        todo_perror(inet_ntop(frame->family == 4 ? AF_INET : AF_INET6, frame->addr, a, sizeof(a)) == NULL);
        QLOG(session, "frames", "rapido_decode_new_address_frame", "",
             "{\"address_id\": \"%d\", \"family\": \"%d\", \"address\": \"%s\", \"port\": \"%d\"}", frame->address_id,
             frame->family, a, frame->port);
    };
    return 0;
}

int rapido_process_new_address_frame(rapido_t *session, rapido_new_address_frame_t *frame) {
    if (rapido_array_get(&session->remote_addresses, frame->address_id) != NULL) {
        // TODO: Deal with NAT
        return 0;
    }
    struct sockaddr_storage *address = rapido_array_add(&session->remote_addresses, frame->address_id);
    memset(address, 0, sizeof(struct sockaddr_storage));
    address->ss_family = frame->family == 4 ? AF_INET : AF_INET6;
    memcpy(SOCKADDR_ADDR(address), frame->addr, frame->family == 4 ? 4 : 16);
    *SOCKADDR_PORT(address) = htons(frame->port);
    rapido_array_iter(&session->connections, rapido_connection_t * connection, {
        if (connection->socket != -1) {
            struct sockaddr_storage peer_address;
            socklen_t peer_address_len = sizeof(struct sockaddr_storage);
            todo_perror(getpeername(connection->socket, (struct sockaddr *)&peer_address, &peer_address_len) == -1);
            if (sockaddr_equal((struct sockaddr *)address, (struct sockaddr *)&peer_address)) {
                connection->remote_address_id = frame->address_id;
            }
        }
    });
    if (!session->is_server || frame->address_id != 0) { // TODO: Fix this notification
        rapido_application_notification_t *notification = rapido_queue_push(&session->pending_notifications);
        notification->notification_type = rapido_new_remote_address;
        notification->address_id = frame->address_id;
    }
    return 0;
}

int rapido_connection_wants_to_send(rapido_t *session, rapido_connection_t *connection, uint64_t current_time) {
    if (connection->socket == -1 || !ptls_handshake_is_complete(connection->tls) ||
        connection->sent_records.size == connection->sent_records.capacity) {
        return 0;
    }
    int wants_to_send = 0;
    char *reason = NULL;

    wants_to_send |= connection->send_buffer.size > connection->sent_offset;
    LOG if (wants_to_send) {
        reason = "Connection send buffer has data";
    }

    rapido_array_iter(&session->connections, rapido_connection_t * connection, {
        if (connection->non_ack_eliciting_count >= DEFAULT_DELAYED_ACK_COUNT) {
            connection->require_ack = true;
            connection->non_ack_eliciting_count = 0;
        } else if (connection->last_receive_time > 0 && connection->last_receive_time + DEFAULT_DELAYED_ACK_TIME < current_time) {
            connection->require_ack = true;
            connection->last_receive_time = 0;
        }
        wants_to_send |= connection->require_ack;
        LOG if (connection->require_ack) {
            reason = "Connection requires ACK";
        }
    });

    size_t streams_to_write = SET_SIZE(connection->attached_streams);
    for (int i = 0; !wants_to_send && streams_to_write && i < SET_LEN; i++) {
        if (SET_HAS(connection->attached_streams, i)) {
            rapido_stream_t *stream = rapido_array_get(&session->streams, i);
            wants_to_send |=
                (stream->producer && !stream->fin_set) || stream->send_buffer.size || (stream->fin_set && !stream->fin_sent);
            LOG if (wants_to_send) {
                reason = "Stream can send";
            }
        }
    }

    if (!wants_to_send && session->is_server) {
        wants_to_send |= session->tls_session_ids.size - session->server.tls_session_ids_sent > 0;
        LOG if (wants_to_send) {
            reason = "TLS Session ID to send";
        }
    }

    if (!wants_to_send) {
        wants_to_send |= SET_SIZE(session->addresses_advertised) < session->local_addresses.size;
        LOG if (wants_to_send) {
            reason = "New address to advertise";
        }
    }

    if (!wants_to_send && connection->retransmit_connections) {
        for (int j = 0; j < SET_LEN && !wants_to_send; j++) {
            if (SET_HAS(connection->retransmit_connections, j)) {
                rapido_connection_t *source_connection = rapido_array_get(&session->connections, j);
                if (source_connection->sent_records.size > 0) {
                    rapido_record_metadata_t *record = NULL;
                    while ((record = rapido_queue_peek(&source_connection->sent_records)) && !record->ack_eliciting) {
                        size_t record_len = record->ciphertext_len;
                        rapido_buffer_pop(&source_connection->send_buffer, &record_len);
                        if (record_len < record->ciphertext_len) {
                            record_len = record->ciphertext_len - record_len;
                            rapido_buffer_pop(&source_connection->send_buffer, &record_len);
                        }
                        rapido_queue_pop(&source_connection->sent_records);
                    }
                    wants_to_send |= record->ack_eliciting;
                    LOG if (wants_to_send) {
                        reason = "Received record needs ACK";
                    }
                }
                if (source_connection->sent_records.size == 0) {
                    SET_REMOVE(connection->retransmit_connections, j);
                }
            }
        }
    }

    LOG {
        QLOG(session, "connection", "rapido_connection_wants_to_send", "", "{\"reason\": \"%s\", \"wants_to_send\": \"%d\"}",
             reason, wants_to_send);
    };

    return wants_to_send;
}

int rapido_prepare_record(rapido_t *session, rapido_connection_t *connection, uint8_t *cleartext, size_t *len,
                          bool *is_ack_eliciting) {
    *len = min(*len, TLS_MAX_RECORD_SIZE);
    *is_ack_eliciting = false;
    size_t consumed = 0;

    if (connection->retransmit_connections) {
        for (int j = 0; j < SET_LEN && consumed < *len; j++) {
            if (SET_HAS(connection->retransmit_connections, j)) {
                rapido_connection_t *source_connection = rapido_array_get(&session->connections, j);
                rapido_queue_drain(&source_connection->sent_records, rapido_record_metadata_t * record, {
                    if (record->ack_eliciting) {
                        if (consumed + TLS_RECORD_CIPHERTEXT_TO_CLEARTEXT_LEN(record->ciphertext_len) > *len) {
                            break;
                        }
                        source_connection->own_decryption_ctx->seq = record->tls_record_sequence;
                        ptls_set_traffic_protection(session->tls, source_connection->own_decryption_ctx, 1);
                        uint8_t record_plaintext[TLS_MAX_ENCRYPTED_RECORD_SIZE];
                        ptls_buffer_t plaintext = {0};
                        ptls_buffer_init(&plaintext, record_plaintext, sizeof(record_plaintext));
                        size_t record_len = record->ciphertext_len;
                        uint8_t *ciphertext = rapido_buffer_peek(&source_connection->send_buffer, 0, &record_len);
                        assert(record_len == record->ciphertext_len);
                        size_t record_consumed = record_len;
                        int ret = ptls_receive(session->tls, &plaintext, ciphertext, &record_consumed);
                        QLOG(session, "transport", "retransmit_record", "",
                             "{\"connection_id\": \"%d\", \"record_sequence\": \"%lu\"}", source_connection->connection_id,
                             record->tls_record_sequence);
                        assert(ret == 0 && record_consumed == record_len);
                        assert(!plaintext.is_allocated);
                        memcpy(cleartext + consumed, plaintext.base, plaintext.off);
                        consumed += plaintext.off;
                        *is_ack_eliciting = true;
                    }
                    size_t record_len = record->ciphertext_len;
                    rapido_buffer_pop(&source_connection->send_buffer, &record_len);
                    if (record_len < record->ciphertext_len) {
                        record_len = record->ciphertext_len - record_len;
                        rapido_buffer_pop(&source_connection->send_buffer, &record_len);
                    }
                    if (consumed >= *len) {
                        break;
                    }
                });
            }
        }
    }

    if (session->is_server) {
        for (int i = session->server.tls_session_ids_sent; consumed < *len && i < session->tls_session_ids.size; i++) {
            size_t frame_len = *len - consumed;
            rapido_prepare_new_session_id_frame(session, rapido_array_get(&session->tls_session_ids, i), i, cleartext + consumed,
                                                &frame_len);
            if (frame_len > 0) {
                consumed += frame_len;
                *is_ack_eliciting = true;
                session->server.tls_session_ids_sent++;
            }
        }
    }

    if (SET_SIZE(session->addresses_advertised) < session->local_addresses.size) {
        rapido_array_iter(&session->local_addresses, struct sockaddr_storage * address, {
            rapido_address_id_t address_id = i;
            size_t frame_len = *len - consumed;
            rapido_prepare_new_address_frame(session, address_id, cleartext + consumed, &frame_len);
            consumed += frame_len;
        });
    }

    if (consumed < *len) {
        size_t frame_len = *len - consumed;
        rapido_prepare_ack_frame(session, cleartext + consumed, &frame_len);
        consumed += frame_len;
    }

    size_t streams_to_write = SET_SIZE(connection->attached_streams);
    for (int i = 0; consumed < *len && i < SET_LEN && streams_to_write; i++) {
        if (SET_HAS(connection->attached_streams, i)) {
            rapido_stream_t *stream = rapido_array_get(&session->streams, i);
            if ((stream->producer && !stream->fin_set) || stream->send_buffer.size || (stream->fin_set && !stream->fin_sent)) {
                size_t frame_len = *len - consumed;
                assert(rapido_prepare_stream_frame(session, stream, cleartext + consumed, &frame_len) == 0);
                consumed += frame_len;
                *is_ack_eliciting = frame_len > 0;
            } else {
                streams_to_write--;
            }
        }
    }

    assert(consumed <= TLS_MAX_RECORD_SIZE);
    *len = consumed;
    return 0;
}

int rapido_server_add_new_connection(rapido_t *session, int conn_fd, rapido_address_id_t local_address_id) {
    assert(session->is_server);
    rapido_pending_connection_t *pending_connection =
        rapido_array_add(&session->server.pending_connections, session->server.next_pending_connection++);
    memset(pending_connection, 0, sizeof(rapido_pending_connection_t));
    pending_connection->socket = conn_fd;
    pending_connection->tls_ctx = session->tls_ctx;
    if (!ptls_handshake_is_complete(session->tls)) {
        pending_connection->tls = session->tls;
    } else {
        pending_connection->tls = ptls_new(session->tls_ctx, session->is_server);
        ptls_set_server_name(pending_connection->tls, ptls_get_server_name(session->tls), 0);
    }
    pending_connection->local_address_id = local_address_id;
    return 0;
}

int rapido_server_accept_new_connection(rapido_t *session, int accept_fd, rapido_address_id_t local_address_id) {
    assert(session->is_server);
    struct sockaddr_storage remote_address;
    socklen_t remote_address_len = sizeof(remote_address_len);
    int conn_fd = accept(accept_fd, (struct sockaddr *)&remote_address, &remote_address_len);
    todo_perror(conn_fd == -1);
    todo_perror(fcntl(conn_fd, F_SETFL, O_NONBLOCK));
    rapido_server_add_new_connection(session, conn_fd, local_address_id);
    return 0;
}

int rapido_server_handshake(rapido_t *session, size_t pending_connection_index) {
    rapido_pending_connection_t *connection = rapido_array_get(&session->server.pending_connections, pending_connection_index);
    uint8_t recvbuf[TLS_MAX_ENCRYPTED_RECORD_SIZE];
    assert(connection->socket > -1);
    size_t recvd = recv(connection->socket, recvbuf, sizeof(recvbuf), 0);
    todo_perror(recvd == -1 && (errno == EWOULDBLOCK || errno == EAGAIN));
    ptls_buffer_t handshake_buffer = {0};
    ptls_buffer_init(&handshake_buffer, "", 0);
    uint8_t tls_session_id_buf[TLS_SESSION_ID_LEN];
    session->tls_properties.server.tls_session_id = ptls_iovec_init(tls_session_id_buf, sizeof(tls_session_id_buf));
    size_t consumed = recvd;
    int ret = ptls_handshake(connection->tls, &handshake_buffer, recvbuf, &consumed, &session->tls_properties);
    todo(ret != 0 && ret != PTLS_ERROR_IN_PROGRESS);
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
            session->tls_properties.collected_extensions = collected_rapido_extensions;
            session->tls_properties.additional_extensions =
                reallocarray(session->tls_properties.additional_extensions, 2, sizeof(ptls_raw_extension_t));
            assert(session->tls_properties.additional_extensions);
            session->tls_properties.additional_extensions[0].type = TLS_RAPIDO_HELLO_EXT;
            session->tls_properties.additional_extensions[0].data = ptls_iovec_init(NULL, 0);
            session->tls_properties.additional_extensions[1].type = UINT16_MAX;
        }
        if (!ptls_handshake_is_complete(connection->tls)) {
            memcpy(connection->tls_session_id, session->tls_properties.server.tls_session_id.base,
                   session->tls_properties.server.tls_session_id.len);
        }
        todo(send(connection->socket, handshake_buffer.base, handshake_buffer.off, 0) != handshake_buffer.off);
        ptls_buffer_dispose(&handshake_buffer);
        /* ClientFinished */
        if (ptls_handshake_is_complete(connection->tls)) {
            int tls_session_id_sequence = -1;
            rapido_array_iter(&session->tls_session_ids, uint8_t * tls_session_id, {
                if (memcmp(tls_session_id, connection->tls_session_id, TLS_SESSION_ID_LEN) == 0) {
                    tls_session_id_sequence = i;
                    break;
                }
            });
            if (tls_session_id_sequence == -1) {
                assert(session->tls_session_ids.size == 0);
                memcpy(rapido_array_add(&session->tls_session_ids, 0), connection->tls_session_id, TLS_SESSION_ID_LEN);
                session->server.tls_session_ids_sent = 1;
                tls_session_id_sequence = 0;

                for (int sid = 1; sid < DEFAULT_TCPLS_SESSION_ID_AMOUNT; sid++) {
                    session->tls_ctx->random_bytes(rapido_array_add(&session->tls_session_ids, sid), TLS_SESSION_ID_LEN);
                }
            }
            rapido_connection_t *new_connection = rapido_array_add(&session->connections, tls_session_id_sequence);
            rapido_connection_init(session, new_connection);
            new_connection->socket = connection->socket;
            new_connection->connection_id = tls_session_id_sequence;
            new_connection->tls = session->tls;
            new_connection->local_address_id = connection->local_address_id;
            struct sockaddr_storage peer_address;
            socklen_t peer_address_len = sizeof(struct sockaddr_storage);
            todo_perror(getpeername(new_connection->socket, (struct sockaddr *)&peer_address, &peer_address_len) == -1);
            rapido_array_iter(&session->remote_addresses, struct sockaddr_storage * remote_address, {
                if (sockaddr_equal((struct sockaddr *)remote_address, (struct sockaddr *)&peer_address)) {
                    new_connection->remote_address_id = (rapido_address_id_t)i;
                }
            });

            todo(setup_connection_crypto_context(session, new_connection) != 0);
            // TODO: Find the addresses it uses

            if (consumed < recvd) {
                size_t allocated = recvd - consumed;
                memcpy(rapido_buffer_alloc(&new_connection->receive_buffer, &allocated, allocated), recvbuf + consumed, allocated);
            }

            rapido_application_notification_t *notification = rapido_queue_push(&session->pending_notifications);
            notification->notification_type = rapido_new_connection;
            notification->connection_id = new_connection->connection_id;
            if (connection->tls != session->tls) {
                ptls_free(connection->tls);
            }
            rapido_array_delete(&session->server.pending_connections, pending_connection_index);
        }
    } else if (ret != PTLS_ERROR_IN_PROGRESS) {
        WARNING("Pending connection %zu returned pTLS error code %d during handshake\n", pending_connection_index, ret);
        close(connection->socket);
        rapido_array_delete(&session->server.pending_connections, pending_connection_index);
    }
    return 0;
}

int rapido_read_connection(rapido_t *session, rapido_connection_id_t connection_id, uint64_t current_time) {
    rapido_connection_t *connection = rapido_array_get(&session->connections, connection_id);
    size_t recvbuf_max = 32 * TLS_MAX_ENCRYPTED_RECORD_SIZE;
    uint8_t *recvbuf = rapido_buffer_alloc(&connection->receive_buffer, &recvbuf_max, TLS_RECORD_HEADER_LEN);
    size_t recvd = recv(connection->socket, recvbuf, recvbuf_max, 0);
    int wants_to_read = 1;
    if (recvd == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
        recvd = 0;
        wants_to_read = 0;
        if (connection->receive_buffer.size == recvbuf_max) { // Else there is something to read in the receiver buffer already
            rapido_buffer_trim_end(&connection->receive_buffer, recvbuf_max);
            return wants_to_read;
        }
    } else if (recvd == 0 || (recvd == -1 && (errno == EPIPE || errno == ECONNRESET))) {
        wants_to_read = 0;
        rapido_buffer_trim_end(&connection->receive_buffer, recvbuf_max);
        rapido_connection_close(session, connection);
        return wants_to_read;
    } else if (recvd == -1) {
        recvd = 0;
    }
    current_time = get_usec_time();
    rapido_buffer_trim_end(&connection->receive_buffer, recvbuf_max - recvd);
    size_t consumed = 0;
    recvd = UINT64_MAX;
    recvbuf = rapido_buffer_peek(&connection->receive_buffer, 0, &recvd);
    if (!session->is_server && !ptls_handshake_is_complete(connection->tls)) {
        ptls_buffer_t handshake_buffer = {0};
        ptls_buffer_init(&handshake_buffer, "", 0);
        consumed = recvd;
        int ret = ptls_handshake(connection->tls, &handshake_buffer, recvbuf, &consumed, &session->tls_properties);
        todo(ret != 0 && ret != PTLS_ERROR_IN_PROGRESS);
        if (ret == 0) {
            assert(session->tls_properties.collected_extensions == NULL);
            bool has_rapido_hello = false;
            for (ptls_raw_extension_t *extension = session->tls_properties.additional_extensions;
                 extension->type != UINT16_MAX && !has_rapido_hello; extension++) {
                if (extension->type == TLS_RAPIDO_HELLO_EXT) {
                    has_rapido_hello = true;
                }
            }
            assert(has_rapido_hello || ptls_handshake_is_complete(session->tls));
            todo(send(connection->socket, handshake_buffer.base, handshake_buffer.off, 0) != handshake_buffer.off);
            ptls_buffer_dispose(&handshake_buffer);
            session->tls_properties.collected_extensions = collected_rapido_extensions;
            free(session->tls_properties.additional_extensions);
            session->tls_properties.additional_extensions = NULL;
            if (connection->tls != session->tls) {
                ptls_free(connection->tls);
                connection->tls = session->tls;
            }
            assert(ptls_get_cipher(session->tls)->aead->iv_size >= 12);
            todo(setup_connection_crypto_context(session, connection) != 0);
        }
    }
    if (ptls_handshake_is_complete(connection->tls) && consumed < recvd) {
        ptls_set_traffic_protection(session->tls, connection->decryption_ctx, 1);
        size_t recvd_offset = consumed;
        while (recvd_offset < recvd) {
            size_t record_missing_len = 0;
            bool is_record_complete = is_tls_record_complete(recvbuf + recvd_offset, recvd - recvd_offset, &record_missing_len);
            if (!is_record_complete) {
                size_t additional_len = record_missing_len;
                uint8_t *additional_data = rapido_buffer_peek(&connection->receive_buffer, recvd, &additional_len);
                if (additional_len != record_missing_len) {
                    consumed = recvd_offset;
                    connection->receive_buffer_fragmented = true;
                    break;
                }
                connection->receive_buffer_fragmented = false;
            }

            uint8_t plaintext_buf[TLS_MAX_ENCRYPTED_RECORD_SIZE];
            ptls_buffer_t plaintext = {0};
            ptls_buffer_init(&plaintext, plaintext_buf, sizeof(plaintext_buf));
            consumed = recvd - recvd_offset;
            int ret = ptls_receive(session->tls, &plaintext, recvbuf + recvd_offset, &consumed);
            recvd_offset += consumed;
            if (ret != 0) {
                printf("ret: %d\n", ret);
            }
            todo(ret != 0);
            if (plaintext.off > 0) {
                QLOG(session, "transport", "receive_record", "",
                     "{\"connection_id\": \"%u\", \"record_sequence\": \"%lu\", \"ciphertext_len\": \"%zu\"}", connection_id,
                     ptls_get_traffic_protection(session->tls, 1)->seq - 1, consumed);
            }
            bool is_ack_eliciting = false;
            for (size_t offset = 0; offset < plaintext.off;) {
                rapido_frame_type_t frame_type = plaintext.base[offset];
                size_t len = plaintext.off - offset;
                is_ack_eliciting |= rapido_frame_is_ack_eliciting(frame_type);
                switch (frame_type) {
                case stream_frame_type: {
                    rapido_stream_frame_t frame;
                    assert(rapido_decode_stream_frame(session, plaintext.base + offset, &len, &frame) == 0);
                    assert(rapido_process_stream_frame(session, &frame) == 0);
                } break;
                case ack_frame_type: {
                    rapido_ack_frame_t frame;
                    assert(rapido_decode_ack_frame(session, plaintext.base + offset, &len, &frame) == 0);
                    assert(rapido_process_ack_frame(session, &frame) == 0);
                } break;
                case new_session_id_frame_type: {
                    rapido_new_session_id_frame_t frame;
                    assert(rapido_decode_new_session_id_frame(session, plaintext.base + offset, &len, &frame) == 0);
                    assert(rapido_process_new_session_id_frame(session, &frame) == 0);
                } break;
                case new_address_frame_type: {
                    rapido_new_address_frame_t frame;
                    assert(rapido_decode_new_address_frame(session, plaintext.base + offset, &len, &frame) == 0);
                    assert(rapido_process_new_address_frame(session, &frame) == 0);
                } break;
                default:
                    WARNING("Unsupported frame type: %d\n", frame_type);
                    assert(!"Unsupported frame type");
                    offset = plaintext.off;
                    break;
                }
                offset += len;
            }
            consumed = recvd_offset;
            if (!is_ack_eliciting) {
                connection->non_ack_eliciting_count++;
            }
            connection->last_receive_time = current_time;
            connection->require_ack |= is_ack_eliciting;
            connection->last_received_record_sequence = ptls_get_traffic_protection(session->tls, 1)->seq - 1;
        }
        connection->decryption_ctx->seq = ptls_get_traffic_protection(session->tls, 1)->seq;
        connection->stats.bytes_received += consumed;
    }
    size_t len = consumed;
    rapido_buffer_pop(&connection->receive_buffer, &len);
    if (len < consumed) {
        len = consumed - len;
        rapido_buffer_pop(&connection->receive_buffer, &len);
    }
    return wants_to_read;
}

int rapido_send_on_connection(rapido_t *session, rapido_connection_id_t connection_id, uint64_t current_time) {
    int wants_to_write = 1;
    rapido_connection_t *connection = rapido_array_get(&session->connections, connection_id);
    if (connection->send_buffer.size == connection->sent_offset) {
        size_t ciphertext_len = 16 * TLS_MAX_ENCRYPTED_RECORD_SIZE;
        size_t produced = 0;
        uint8_t *ciphertext = rapido_buffer_alloc(&connection->send_buffer, &ciphertext_len, TLS_MAX_ENCRYPTED_RECORD_SIZE);
        todo(ciphertext == NULL);
        assert(ciphertext_len >= TLS_MAX_ENCRYPTED_RECORD_SIZE);
        ptls_set_traffic_protection(session->tls, connection->encryption_ctx, 0);
        while (produced < ciphertext_len && connection->sent_records.size < connection->sent_records.capacity) {
            size_t cleartext_len =
                TLS_RECORD_CIPHERTEXT_TO_CLEARTEXT_LEN(min(ciphertext_len - produced, TLS_MAX_ENCRYPTED_RECORD_SIZE));
            uint8_t cleartext[cleartext_len];
            bool is_ack_eliciting = false;
            rapido_prepare_record(session, connection, cleartext, &cleartext_len, &is_ack_eliciting);
            ptls_buffer_t sendbuf = {0};
            ptls_buffer_init(&sendbuf, ciphertext + produced, ciphertext_len - produced);
            if (cleartext_len > 0) {
                todo(ptls_send(session->tls, &sendbuf, cleartext, cleartext_len) != 0);
                assert(sendbuf.is_allocated == 0);
                QLOG(session, "transport", "sent_record", "",
                     "{\"connection_id\": \"%u\", \"record_sequence\": \"%lu\", \"ciphertext_len\": \"%zu\"}", connection_id,
                     ptls_get_traffic_protection(session->tls, 0)->seq - 1, sendbuf.off);
                produced += sendbuf.off;

                rapido_record_metadata_t *record = rapido_queue_push(&connection->sent_records);
                record->ciphertext_len = sendbuf.off;
                record->tls_record_sequence = ptls_get_traffic_protection(session->tls, 0)->seq - 1;
                record->ack_eliciting = is_ack_eliciting;
                record->sent_time = get_usec_time();
                connection->encryption_ctx->seq = ptls_get_traffic_protection(session->tls, 0)->seq;
            } else {
                break;
            }
        }
        rapido_buffer_trim_end(&connection->send_buffer, ciphertext_len - produced);
    }

    size_t send_len = 16 * TLS_MAX_ENCRYPTED_RECORD_SIZE;
    void *send_data = rapido_buffer_peek(&connection->send_buffer, connection->sent_offset, &send_len);
    if (send_len > 0) {
        ssize_t sent_len = send(connection->socket, send_data, send_len, 0);
        if (sent_len == -1 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EPIPE)) {
            wants_to_write = 0;
            sent_len = 0;
            if (errno == EPIPE || errno == ECONNRESET) {
                rapido_connection_close(session, connection);
            }
        }
        connection->stats.bytes_sent += sent_len;
        connection->sent_offset += sent_len;
    }

    if (wants_to_write && rapido_connection_wants_to_send(session, connection, current_time) == 0) {
        wants_to_write = 0;
    }
    return wants_to_write;
}

int rapido_run_network(rapido_t *session, int timeout) {
    // TODO: Read and writes until it blocks
#define has_low_occupancy(queue) ((queue).size < (queue).capacity / 2)
    typedef enum { fd_listen_socket, fd_pending_connection, fd_connection } fd_types_t;
    QLOG(session, "api", "rapido_run_network", "", NULL);
    int no_fds = 0;
    bool fds_change;
    do {
        uint64_t current_time = get_usec_time();
        fds_change = false;
        size_t nfds = session->connections.size;
        if (session->is_server) {
            nfds += session->server.listen_sockets.size + session->server.pending_connections.size;
        }
        struct pollfd fds[nfds];
        size_t connections_index[nfds];
        fd_types_t fd_types[nfds];
        nfds = 0;
        if (session->is_server) {
            rapido_array_iter(&session->server.listen_sockets, int *socket, {
                fds[nfds].fd = *socket;
                fds[nfds].events = POLLIN;
                connections_index[nfds] = -1;
                fd_types[nfds] = fd_listen_socket;
                nfds++;
            });
            rapido_array_iter(&session->server.pending_connections, rapido_pending_connection_t * connection, {
                fds[nfds].fd = connection->socket;
                fds[nfds].events = POLLIN;
                connections_index[nfds] = i;
                fd_types[nfds] = fd_pending_connection;
                nfds++;
            });
        }
        bool wants_to_write = false;
        rapido_array_iter(&session->connections, rapido_connection_t * connection, {
            fds[nfds].fd = connection->socket;
            fds[nfds].events = POLLIN;
            if (rapido_connection_wants_to_send(session, connection, current_time)) {
                fds[nfds].events |= POLLOUT;
                wants_to_write = true;
            }
            connections_index[nfds] = i;
            fd_types[nfds] = fd_connection;
            nfds++;
        });

        int polled_fds = poll(fds, nfds, no_fds > 0 ? timeout : 0);
        todo(polled_fds < 0 && errno != EINTR);
        if (polled_fds == 0) {
            no_fds++;
        } else {
            no_fds = 0;
        }

        size_t fd_offset = 0;
        /* Accept new TCP connections and prepare the TLS handshake */
        while (fd_offset < nfds && fd_types[fd_offset] == fd_listen_socket) {
            if (fds[fd_offset].revents & POLLIN) {
                todo(rapido_server_accept_new_connection(session, fds[fd_offset].fd, connections_index[fd_offset]) != 0);
                fds_change = true;
                polled_fds--;
            }
            fd_offset++;
        }

        /* Do the TLS handshake on pending connections */
        while (fd_offset < nfds && fd_types[fd_offset] == fd_pending_connection) {
            if (fds[fd_offset].revents & POLLIN) {
                todo(rapido_server_handshake(session, connections_index[fd_offset]) != 0);
                fds_change = true;
                polled_fds--;
            }
            fd_offset++;
        }

        bool wants_to_read;
        do {
            wants_to_read = false;
            for (int i = fd_offset; i < nfds; i++) {
                /* Read incoming TLS records */
                rapido_connection_t *connection = rapido_array_get(&session->connections, connections_index[i]);
                if (fds[i].revents & POLLIN || (connection->receive_buffer.size > 0 && !connection->receive_buffer_fragmented)) {
                    if (rapido_read_connection(session, connections_index[i], current_time)) {
                        wants_to_read = true;
                    } else {
                        fds[i].revents &= ~(POLLIN);
                    }
                }
            }
        } while (polled_fds && wants_to_read && has_low_occupancy(session->pending_notifications));

        /* Write outgoing TLS records */
        current_time = get_usec_time();
        rapido_array_iter(&session->connections, rapido_connection_t * connection, {
            if (rapido_connection_wants_to_send(session, connection, current_time)) {
                if (!wants_to_write) {
                    fds_change = true;
                }
                wants_to_write = true;
                break;
            }
        });
        while (polled_fds && wants_to_write && has_low_occupancy(session->pending_notifications)) {
            wants_to_write = 0;
            for (int i = fd_offset; i < nfds; i++) {
                if (fds[i].revents & POLLOUT) {
                    if (rapido_send_on_connection(session, connections_index[i], current_time)) {
                        wants_to_write = true;
                    } else {
                        fds[i].revents &= ~(POLLOUT);
                    }
                }
            }
        }
    } while ((no_fds < 2 || fds_change) && has_low_occupancy(session->pending_notifications));
    return 0;
}

int rapido_retransmit_connection(rapido_t *session, rapido_connection_id_t connection_id, set_t connections) {
    QLOG(session, "api", "rapido_retransmit_connection", "", "{\"source_connection_id\": \"%d\", \"connections\": \"%lu\"}",
         connection_id, connections);
    rapido_connection_t *source_connection = rapido_array_get(&session->connections, connection_id);
    assert(source_connection != NULL);
    for (int i = 0; i < SET_LEN; i++) {
        if (SET_HAS(connections, i)) {
            rapido_connection_t *destination_connection = rapido_array_get(&session->connections, i);
            assert(destination_connection != NULL);
            SET_ADD(destination_connection->retransmit_connections, source_connection->connection_id);
        }
    }
    return 0;
}

int rapido_free(rapido_t *session) {
    rapido_array_iter(&session->connections, rapido_connection_t * connection, {
        if (connection->socket > -1) {
            close(connection->socket);
        }
        rapido_buffer_free(&connection->receive_buffer);
        rapido_buffer_free(&connection->send_buffer);
        rapido_queue_free(&connection->sent_records);
        ptls_aead_free(connection->encryption_ctx->aead);
        free(connection->encryption_ctx);
        ptls_aead_free(connection->decryption_ctx->aead);
        free(connection->decryption_ctx);
        ptls_aead_free(connection->own_decryption_ctx->aead);
        free(connection->own_decryption_ctx);
        if (connection->tls != session->tls) {
            ptls_free(connection->tls);
        }
    });
    rapido_array_iter(&session->streams, rapido_stream_t * stream, {
        rapido_range_buffer_free(&stream->read_buffer);
        rapido_buffer_free(&stream->send_buffer);
    });
    free(session->tls_properties.additional_extensions);
    ptls_get_traffic_protection(session->tls, 0)->aead = NULL;
    ptls_get_traffic_protection(session->tls, 1)->aead = NULL;
    ptls_free(session->tls);
    rapido_array_free(&session->connections);
    rapido_array_free(&session->streams);
    rapido_array_free(&session->local_addresses);
    rapido_array_free(&session->remote_addresses);
    rapido_array_free(&session->tls_session_ids);
    rapido_queue_free(&session->pending_notifications);
    if (session->is_server) {
        rapido_array_iter(&session->server.listen_sockets, int *socket, {
            if (*socket > -1) {
                close(*socket);
            }
        });
        rapido_array_free(&session->server.listen_sockets);
        rapido_array_iter(&session->server.pending_connections, rapido_pending_connection_t * connection, {
            if (connection->socket > -1) {
                close(connection->socket);
            }
        });
        rapido_array_free(&session->server.pending_connections);
    }
    return 0;
}
