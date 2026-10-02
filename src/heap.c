#include "halo2/heap.h"
#include <stdlib.h>
#include <stdint.h>

typedef struct span {
    uint32_t offset, size;
    int used;
    struct span *next;
} span;
struct h2_heap {
    h2_memory memory;
    span *spans;
    size_t live, in_use;
};

h2_heap *h2_heap_create(uint32_t base, uint32_t size) {
    if (!base || (base & 15) || !size || (size & 15) ||
        (uint64_t)base + size > UINT64_C(0x100000000)) return NULL;
    h2_heap *h = calloc(1, sizeof(*h));
    if (!h) return NULL;
    h->memory.bytes = calloc(1, size);
    h->spans = calloc(1, sizeof(*h->spans));
    if (!h->memory.bytes || !h->spans) { h2_heap_destroy(h); return NULL; }
    h->memory.base = base;
    h->memory.size = size;
    h->spans->size = size;
    return h;
}
void h2_heap_destroy(h2_heap *h) {
    if (!h) return;
    for (span *s = h->spans, *next; s; s = next) {
        next = s->next;
        free(s);
    }
    free(h->memory.bytes);
    free(h);
}
h2_memory *h2_heap_memory(h2_heap *h) { return &h->memory; }
uint32_t h2_heap_allocate(h2_heap *h, uint32_t size) {
    if (!size || size > UINT32_MAX - 15) return 0;
    uint32_t rounded = (size + 15) & ~UINT32_C(15);
    for (span *s = h->spans; s; s = s->next) {
        if (s->used || s->size < rounded) continue;
        if (s->size > rounded) {
            span *rest = malloc(sizeof(*rest));
            if (!rest) return 0;
            *rest = (span){s->offset + rounded, s->size - rounded, 0, s->next};
            s->next = rest;
            s->size = rounded;
        }
        s->used = 1;
        h->live++;
        h->in_use += rounded;
        return h->memory.base + s->offset;
    }
    return 0;
}
int h2_heap_release(h2_heap *h, uint32_t allocation) {
    if (allocation < h->memory.base) return 0;
    uint32_t offset = allocation - h->memory.base;
    for (span *s = h->spans, *previous = NULL; s; previous = s, s = s->next) {
        if (s->offset != offset) continue;
        if (!s->used) return 0;
        s->used = 0;
        h->live--;
        h->in_use -= s->size;
        if (s->next && !s->next->used) {
            span *next = s->next;
            s->size += next->size;
            s->next = next->next;
            free(next);
        }
        if (previous && !previous->used) {
            previous->size += s->size;
            previous->next = s->next;
            free(s);
        }
        return 1;
    }
    return 0;
}
static uint32_t host_allocate(void *context, uint32_t identity, uint32_t size) {
    (void)identity;
    return h2_heap_allocate(context, size);
}
static void host_release(void *context, uint32_t identity, uint32_t allocation) {
    (void)identity;
    if (!h2_heap_release(context, allocation)) abort();
}
h2_allocator h2_heap_allocator(h2_heap *h) {
    return (h2_allocator){h, host_allocate, host_release};
}
size_t h2_heap_live_allocations(const h2_heap *h) { return h->live; }
size_t h2_heap_bytes_in_use(const h2_heap *h) { return h->in_use; }
