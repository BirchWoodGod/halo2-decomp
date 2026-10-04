#ifndef HALO2_NETWORK_OBSERVER_SORT_H
#define HALO2_NETWORK_OBSERVER_SORT_H
#include "halo2/memory.h"
typedef uint8_t (*h2_sort_compare)(void *context,uint32_t left,uint32_t right,uint32_t data);
/* 00078a90: stack left/right/priority-array, ret12, AL. */
uint8_t h2_network_observer_compare_priority(h2_memory *,uint32_t left,uint32_t right,uint32_t priorities);
/* 0013e0e0: EAX inclusive last pointer, stack first/comparator/data, ret12. */
void h2_sort_u32_small(h2_memory *,h2_sort_compare,void *,uint32_t first,uint32_t last,uint32_t data);
/* 0013de30: ECX first, EAX count, stack unused/comparator/data, ret12.
 * Valid contiguous guest array; callbacks may change its values. */
void h2_sort_u32(h2_memory *,h2_sort_compare,void *,uint32_t first,uint32_t count,uint32_t data);
#endif
