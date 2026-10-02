#ifndef HALO2_NETWORK_SESSION_H
#define HALO2_NETWORK_SESSION_H
#include "halo2/memory.h"
uint8_t h2_network_session_find_reservation(h2_memory *, uint32_t session,
    uint32_t identity, uint32_t output); /* 00062f40 */
uint8_t h2_network_session_reservation_capacity(h2_memory *, uint32_t session,
    uint32_t identities, uint8_t skip_matches, uint32_t count); /* 0005afc0 */
uint32_t h2_network_session_request_status(h2_memory *, uint32_t session,
    uint32_t request); /* 00062fe0 */
uint8_t h2_network_session_shutdown_guard(h2_memory *, uint32_t session); /* 00058d90 */
uint32_t h2_network_session_find_peer(h2_memory *, uint32_t session, uint32_t identity); /* 0005f760 */
uint8_t h2_network_session_capacity_exceeded(h2_memory *, uint32_t session,
    uint32_t peers, uint32_t players); /* 0005af70 */
/* Recovered storage initialization, not the session state machine. All guest
 * pointers and indexed registry slots must name valid writable regions. */
uint8_t h2_network_session_storage_initialize(h2_memory *,uint32_t registry,uint32_t state,uint32_t observer,uint32_t index,uint32_t kind,uint32_t dependency,uint32_t owner); /* 00059ad0 */
#endif
