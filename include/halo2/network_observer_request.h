#ifndef HALO2_NETWORK_OBSERVER_REQUEST_H
#define HALO2_NETWORK_OBSERVER_REQUEST_H
#include "halo2/network_connection_accept.h"
#include "halo2/network_connection_open.h"
#include "halo2/network_identity_resolve.h"
#include "halo2/network_observer_query.h"
typedef struct {
    const h2_connection_accept_context *accept;
    const h2_network_query_platform *query;
    const h2_identity_resolve_platform *identity;
    const h2_network_resolution_platform *resolution;
    const h2_connection_callbacks *callbacks;
    const h2_network_registration_platform *registration;
    const h2_observer_events *events;
    const h2_network_storage_operations *storage;
    /* All temporaries disjoint from each other and live guest objects. */
    uint32_t local88,query4,prepare4,close16,storage8,open_message8;
} h2_observer_request_context;
/* 000785d0: stack observer/address/request8, ret12. */
void h2_network_observer_handle_request(h2_memory *,const h2_observer_request_context *,uint32_t observer,uint32_t address,uint32_t request8);
#endif
