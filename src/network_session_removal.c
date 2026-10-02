#include "halo2/network_session_removal.h"
#include "halo2/network_session.h"
#include "halo2/network_session_lifecycle.h"
#include "internal/memory.h"
#include <string.h>
static int64_t signed32(uint32_t v) {return v&0x80000000u ? (int64_t)v-INT64_C(0x100000000) : v;}
static void revisions(h2_memory *m,uint32_t session) {
    uint32_t membership=h2_read32(m,session+0x4c),update=h2_read32(m,session+0x7618);
    h2_write32(m,session+0x4c,membership+1);h2_write32(m,session+0x7618,update+1);
}
void h2_network_session_refresh_peer_flag(h2_memory *m,uint32_t session) {
    uint32_t state=h2_read32(m,session+0x741c);
    if (state<5 || state>8 || !*h2_ptr(m,session+0x765c,1)) return;
    for (uint32_t i=0;signed32(i)<signed32(h2_read32(m,session+0x54));++i)
        if (*h2_ptr(m,session+0x72de + i*20,1)) return;
    *h2_ptr(m,session+0x765c,1)=0;
}
void h2_network_session_remove_player(h2_memory *m,uint32_t session,uint32_t index,uint32_t scratch) {
    uint32_t identity=session+0x1120+index*0x13c,state=h2_read32(m,session+0x741c);
    if (state>=5 && state<=8) {
        h2_write32(m,scratch,0);
        if (h2_network_session_find_reservation(m,session,identity,scratch))
            *h2_ptr(m,h2_read32(m,scratch)+1,1)=0;
    } else h2_write32(m,scratch,state);
    uint32_t owner=h2_read32(m,identity+12),slot=h2_read32(m,identity+16);
    h2_write32(m,session+0x154+(owner*0x43+slot)*4,UINT32_MAX);
    uint32_t count=session+0x150+h2_read32(m,identity+12)*0x10c;
    h2_write32(m,count,h2_read32(m,count)-1);
    uint32_t players=h2_read32(m,session+0x1118),mask=h2_read32(m,session+0x111c);
    h2_write32(m,session+0x111c,mask&~(UINT32_C(1)<<(index&31)));
    h2_write32(m,session+0x1118,players-1);
}
void h2_network_session_remove_peer(h2_memory *m,uint32_t session,uint32_t index,uint32_t scratch) {
    uint32_t remaining=h2_read32(m,session+0x54)-index-1,base=session+index*0x10c;
    for (uint32_t i=0;i<4;++i) {
        uint32_t player=h2_read32(m,base+0x154+i*4);
        if (player!=UINT32_MAX) {h2_network_session_remove_player(m,session,player,scratch);revisions(m,session);}
    }
    for (uint32_t i=0;i<16;++i) {
        if (!(h2_read32(m,session+0x111c)&(UINT32_C(1)<<i))) continue;
        uint32_t p=session+0x112c+i*0x13c,owner=h2_read32(m,p);
        if (signed32(owner)>signed32(index)) h2_write32(m,p,owner-1);
    }
    if (h2_read32(m,session+0x50)==index) h2_write32(m,session+0x50,0);
    h2_network_session_detach_peer(m,session,index);
    if (signed32(remaining)>0) {
        uint32_t bytes=remaining*0x10c;
        memmove(h2_ptr(m,base+0x58,bytes),h2_ptr(m,base+0x164,bytes),bytes);
        uint32_t peer=session+index*20+0x72dc;bytes=remaining*20;
        memmove(h2_ptr(m,peer,bytes),h2_ptr(m,peer+20,bytes),bytes);
        const uint32_t offsets[]={0x40,0x72d8,0x50};
        for (uint32_t i=0;i<3;++i) {
            uint32_t value=h2_read32(m,session+offsets[i]);
            if (signed32(value)>signed32(index)) h2_write32(m,session+offsets[i],value-1);
        }
    }
    uint32_t last=session+h2_read32(m,session+0x54)*0x10c-0xb4;
    for (uint32_t i=0;i<0x43;++i) h2_write32(m,last+i*4,0);
    last=session+h2_read32(m,session+0x54)*20+0x72c8;
    for (uint32_t i=0;i<5;++i) h2_write32(m,last+i*4,0);
    uint32_t count=h2_read32(m,session+0x54),revision=h2_read32(m,session+0x4c),update=h2_read32(m,session+0x7618);
    h2_write32(m,session+0x54,count-1);h2_write32(m,session+0x4c,revision+1);h2_write32(m,session+0x7618,update+1);
    h2_network_session_refresh_peer_flag(m,session);
}
