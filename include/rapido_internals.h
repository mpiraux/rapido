#ifndef PICOTLS_RAPIDO_INTERNALS_H
#define PICOTLS_RAPIDO_INTERNALS_H

void *rapido_array_get(rapido_array_t *array, size_t index);
int rapido_add_range(rapido_range_list_t *list, uint64_t low, uint64_t high);
void rapido_peek_range(rapido_range_list_t *list, uint64_t *low, uint64_t *high);
uint64_t rapido_trim_range(rapido_range_list_t *list, uint64_t limit);
int rapido_prepare_stream_frame(rapido_t *session, rapido_stream_t *stream, uint8_t *buf, size_t *len);

#endif // PICOTLS_RAPIDO_INTERNALS_H
