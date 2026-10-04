#ifndef HALO2_NETWORK_OBSERVER_FRAME_H
#define HALO2_NETWORK_OBSERVER_FRAME_H
#include "halo2/network_observer_tick.h"
#include "halo2/network_observer_async.h"
#include "halo2/network_observer_control.h"
typedef struct {
    const h2_observer_tick_context *tick;
    const h2_async_task_create_platform *async;
    const h2_observer_control_callbacks *control;
    /* Disjoint from tick/async scratch and persistent state. */
    uint32_t records60,control152;
} h2_observer_frame_context;
/* 00075da0: stack observer, ret4, void. */
void h2_network_observer_frame(h2_memory *,const h2_observer_frame_context *,uint32_t observer);
#endif
