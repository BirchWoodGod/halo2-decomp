#ifndef HALO2_NETWORK_SESSION_CANDIDATE_RANK_H
#define HALO2_NETWORK_SESSION_CANDIDATE_RANK_H
#include "halo2/memory.h"
typedef struct {
    void *context;
    /* CRT00372d48 boundary: ST1 base, ST0 exponent, extended ST0 result.
     * Provider must preserve original CRT semantics; no default pow substitution. */
    void (*power)(void *,float base,float exponent,long double *result);
} h2_candidate_rank_math;
/* 000619b0: ECX session, EDX candidate, EAX incumbent, stack count index,
 * ret4, AL boolean. Default nearest-even FP environment required. */
uint8_t h2_network_session_candidate_preferred(h2_memory *,const h2_candidate_rank_math *,uint32_t session,uint32_t candidate,uint32_t incumbent,uint32_t count_index);
#endif
