#include "halo2/network_peer_changes.h"
#include "internal/memory.h"
#include <string.h>
static int text_diff(h2_memory *m,uint32_t a,uint32_t b,uint32_t n) {
    for(uint32_t i=0;i<n;++i) {
        const uint8_t *x=h2_ptr(m,a+i*2,2),*y=h2_ptr(m,b+i*2,2);
        if(x[0]!=y[0] || x[1]!=y[1]) return 1;
        if(!x[0] && !x[1]) break;
    }
    return 0;
}
static void text_copy(h2_memory *m,uint32_t out,uint32_t in,uint32_t n) {
    for(uint32_t i=0;i<n;++i) {
        const uint8_t *x=h2_ptr(m,in+i*2,2);uint8_t *y=h2_ptr(m,out+i*2,2);
        y[0]=x[0];y[1]=x[1];
        if(!x[0] && !x[1]) {memset(h2_ptr(m,out+(i+1)*2,(n-i-1)*2),0,(n-i-1)*2);break;}
    }
    memset(h2_ptr(m,out+n*2,2),0,2);
}
void h2_network_peer_changes(h2_memory *m,uint32_t c,uint32_t b,uint32_t out) {
    if(!b || text_diff(m,c,b,16) || text_diff(m,c+32,b+32,32)) {
        *h2_ptr(m,out,1)=1;text_copy(m,out+2,c,15);text_copy(m,out+34,c+32,31);
    }
    static const uint32_t groups[][4]={{0x60,8,0x62,0x64},{0x68,28,0x6c,0x70},{0x84,64,0x8c,0x90},{0xc4,4,0xd0,0xd4}};
    for(uint32_t i=0;i<4;++i) {
        uint32_t off=groups[i][0],n=groups[i][1];
        if(!b || memcmp(h2_ptr(m,c+off,n),h2_ptr(m,b+off,n),n)) {
            *h2_ptr(m,out+groups[i][2],1)=1;
            memcpy(h2_ptr(m,out+groups[i][3],n),h2_ptr(m,c+off,n),n);
        }
    }
}
