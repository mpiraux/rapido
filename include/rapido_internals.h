#ifndef PICOTLS_RAPIDO_INTERNALS_H
#define PICOTLS_RAPIDO_INTERNALS_H

void *rapido_array_get(rapido_array_t *array, size_t index);
int rapido_add_range(rapido_range_list_t *list, uint64_t low, uint64_t high);
void rapido_peek_range(rapido_range_list_t *list, uint64_t *low, uint64_t *high);
uint64_t rapido_trim_range(rapido_range_list_t *list, uint64_t limit);
int rapido_prepare_stream_frame(rapido_session_t *session, rapido_stream_t *stream, uint8_t *buf, size_t *len);
void rapido_range_buffer_init(rapido_range_buffer_t *receive, size_t capacity);
int rapido_range_buffer_write(rapido_range_buffer_t *receive, size_t offset, void *input, size_t len);
void *rapido_range_buffer_get(rapido_range_buffer_t *receive, size_t *len);
void rapido_range_buffer_free(rapido_range_buffer_t *receive);
bool rapido_set_has(rapido_set_t *set, uint32_t value);
void rapido_set_add(rapido_set_t *set, uint32_t value);
void rapido_set_remove(rapido_set_t *set, uint32_t value);
size_t rapido_set_size(rapido_set_t *set);

#endif // PICOTLS_RAPIDO_INTERNALS_H
