#ifndef HALO2_NETWORK_SESSION_MIGRATION_PAYLOAD_H
#define HALO2_NETWORK_SESSION_MIGRATION_PAYLOAD_H
#include "halo2/memory.h"
/* 00062b70: EDX session, EBX output (0xc0 bytes), EAX local peer index.
 * Forward word copies and reloads retain the original overlap behavior. */
uint32_t h2_network_session_build_migration_payload(h2_memory *,uint32_t session,uint32_t output);
#endif
