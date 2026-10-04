#ifndef HALO2_NETWORK_OBSERVER_CONTROL_H
#define HALO2_NETWORK_OBSERVER_CONTROL_H
#include "halo2/network_observer_bandwidth_allocate.h"
#include "halo2/network_observer_bandwidth_update.h"
#include "halo2/network_observer_probe_update.h"
#include "halo2/network_observer_sort.h"
#include "halo2/network_game_activity.h"
typedef struct {
    void *context;
    uint32_t (*invoke)(void *,uint32_t function,uint32_t object,uint32_t index);
} h2_observer_control_callbacks;
/* 00078ac0: stack observer, ret4. Scratch is 152 disjoint guest bytes:
 * 15 priorities, 15 indices, 28 activity bytes and a probe output byte. */
void h2_network_observer_control_bandwidth(h2_memory *,const h2_network_state_operations *,const h2_observer_control_callbacks *,uint32_t observer,uint32_t scratch);
#endif
