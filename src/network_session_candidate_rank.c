#include "halo2/network_session_candidate_rank.h"
#include "halo2/network_peer_mask_count.h"
#include "internal/memory.h"
#include <string.h>
static int64_t sv(uint32_t n) {return n&UINT32_C(0x80000000) ? (int64_t)n-INT64_C(0x100000000) : n;}
static float rf(h2_memory *m,uint32_t p) {float f;memcpy(&f,h2_ptr(m,p,4),4);return f;}
uint8_t h2_network_session_candidate_preferred(h2_memory *m,const h2_candidate_rank_math *math,uint32_t session,uint32_t candidate,uint32_t incumbent,uint32_t count_index) {
    uint32_t a=session+candidate*0x10c,b=session+incumbent*0x10c;
    uint32_t ac=h2_network_peer_mask_count(h2_read32(m,a+0x9c));
    uint32_t bc=h2_network_peer_mask_count(h2_read32(m,b+0x9c));
    if(ac!=bc) return ac>bc;
    int64_t ap=sv(h2_read32(m,a+0xf8)),bp=sv(h2_read32(m,b+0xf8));
    if(ap!=bp) return ap<bp;
    int64_t cap=sv(h2_read32(m,0x4ce0c4+count_index*4));
    int64_t ar=sv(h2_read32(m,a+0x94)),br=sv(h2_read32(m,b+0x94));
    if(ar>cap) ar=cap;
    if(br>cap) br=cap;
    volatile float rate=(float)sv((uint32_t)ar-(uint32_t)br);
    rate=rate*rf(m,0x4ce074);
    volatile float delta=(float)sv(h2_read32(m,b+0xa4)-h2_read32(m,a+0xa4));
    delta=delta*rf(m,0x4ce078);
    uint8_t positive=delta>rf(m,0x45dbd8);
    long double power;
    math->power(math->context,positive?delta:-delta,rf(m,0x4ce07c),&power);
    volatile float score=(float)(positive ? (long double)rate+power : (long double)rate-power);
    return score>rf(m,0x44ae90);
}
