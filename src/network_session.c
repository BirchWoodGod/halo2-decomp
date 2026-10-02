#include "halo2/network_session.h"
#include "internal/memory.h"
#include <string.h>
uint8_t h2_network_session_shutdown_guard(h2_memory *m, uint32_t session) {
    switch (h2_read32(m, session+0x741c)) {
    case 2: case 4: case 6: return 1;
    case 7: case 8: return *h2_ptr(m, session+0x7420, 1);
    default: return 0;
    }
}

uint32_t h2_network_session_find_peer(h2_memory *m, uint32_t session, uint32_t identity) {
    if (!h2_read32(m, session+0x741c) || h2_read32(m, session+0x4c) == UINT32_MAX)
        return UINT32_MAX;
    uint32_t count = h2_read32(m, session+0x54);
    if (count & 0x80000000u) return UINT32_MAX;
    for (uint32_t i = 0; i < count; ++i)
        if (!memcmp(h2_ptr(m, identity, 36), h2_ptr(m, session+0x58+i*0x10c, 36), 36))
            return i;
    return UINT32_MAX;
}

static int signed_greater(uint32_t a, uint32_t b) {
    return (a ^ 0x80000000u) > (b ^ 0x80000000u);
}
uint8_t h2_network_session_find_reservation(h2_memory *m, uint32_t session,
    uint32_t identity, uint32_t output) {
    uint32_t first = session+0x7668, end = first+0x240;
    for (uint32_t p = first; p < end; p += 0x24) {
        if (*h2_ptr(m, p, 1) && !memcmp(h2_ptr(m, identity, 12), h2_ptr(m, p+10, 12), 12)) {
            if (output) h2_write32(m, output, p);
            return 1;
        }
    }
    return 0;
}

uint8_t h2_network_session_reservation_capacity(h2_memory *m, uint32_t session,
    uint32_t identities, uint8_t skip_matches, uint32_t count) {
    uint32_t matches = 0, reserved = 0;
    if (!skip_matches && !(count & 0x80000000u))
        for (uint32_t i = 0; i < count; ++i)
            matches += h2_network_session_find_reservation(m, session, identities+i*12, 0);
    uint32_t first = session+0x7668, end = first+0x240;
    for (uint32_t p = first; p < end; p += 0x24)
        if (*h2_ptr(m, p, 1) && !*h2_ptr(m, p+1, 1)) ++reserved;
    uint32_t available = h2_read32(m, session+0x4994)-h2_read32(m, session+0x1118)-reserved+matches;
    return !signed_greater(count, available);
}

uint32_t h2_network_session_request_status(h2_memory *m, uint32_t session, uint32_t request) {
    uint32_t state = h2_read32(m, session+0x741c);
    if (state < 5 || state > 8) return 3;
    if (signed_greater(h2_read32(m, session+0x498c), 1)) return 2;
    if (state != 5) return 3;
    if (h2_network_session_find_peer(m, session, request+0x188) != UINT32_MAX) return 0;
    uint32_t count = h2_read32(m, request);
    if (h2_network_session_capacity_exceeded(m, session, 1, count)) return 4;
    if (!h2_network_session_reservation_capacity(m, session, request+4,
        *h2_ptr(m, request+0x14c, 1), count)) return 4;
    return 0;
}

uint8_t h2_network_session_capacity_exceeded(h2_memory *m, uint32_t session,
    uint32_t peers, uint32_t players) {
    uint32_t state = h2_read32(m, session+0x741c);
    if (state < 3 || state > 8) return 0;
    if (signed_greater(h2_read32(m, session+0x54)+peers, h2_read32(m, session+0x4990)))
        return 1;
    return signed_greater(h2_read32(m, session+0x1118)+players, h2_read32(m, session+0x4994));
}

uint8_t h2_network_session_storage_initialize(h2_memory *m,uint32_t registry,uint32_t state,uint32_t observer,uint32_t index,uint32_t kind,uint32_t dependency,uint32_t owner) {
    h2_write32(m,state+0x14,kind);h2_write32(m,state+0x38,dependency);
    h2_write32(m,state+4,owner);h2_write32(m,state+8,observer);
    h2_write32(m,state+0xc,registry);h2_write32(m,state+0x10,index);
    h2_write32(m,registry+index*4,state);
    uint32_t slot=observer+h2_read32(m,state+0x10)*36;
    h2_write32(m,slot+0x18,UINT32_MAX);h2_write32(m,slot+0x1c,UINT32_MAX);
    h2_write32(m,slot+0x14,state);
    h2_write32(m,state+0x18,UINT32_MAX);h2_write32(m,state+0x40,UINT32_MAX);
    *h2_ptr(m,state+0x48,1)=0;
    memset(h2_ptr(m,state+0x4c,0x2494),0,0x2494);
    memset(h2_ptr(m,state+0x24e0,0x2494),0,0x2494);
    h2_write32(m,state+0x24e0,UINT32_MAX);h2_write32(m,state+0x4c,UINT32_MAX);
    memset(h2_ptr(m,state+0x4978,0x14b0),0,0x14b0);
    memset(h2_ptr(m,state+0x5e28,0x14b0),0,0x14b0);
    h2_write32(m,state+0x4978,UINT32_MAX);h2_write32(m,state+0x5e28,UINT32_MAX);
    h2_write32(m,state+0x741c,0);h2_write32(m,state+0x72d8,UINT32_MAX);
    h2_write32(m,state+0x7618,0);
    memset(h2_ptr(m,state+0x72dc,0x140),0,0x140);
    memset(h2_ptr(m,state+0x761c,0x34),0,0x34);
    h2_write32(m,state+0x7650,0);h2_write32(m,state+0x7654,UINT32_MAX);h2_write32(m,state+0x7658,UINT32_MAX);
    memset(h2_ptr(m,state+0x7668,0x240),0,0x240);
    h2_write32(m,state+0x78a8,0);*h2_ptr(m,state+0x78ac,1)=0;
    return 1;
}
