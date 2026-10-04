#include "halo2/network_observer_sort.h"
#include "internal/memory.h"
#include <string.h>
static float rf(h2_memory *m,uint32_t p) {uint32_t v=h2_read32(m,p);float f;memcpy(&f,&v,4);return f;}
static void swap(h2_memory *m,uint32_t a,uint32_t b) {uint32_t x=h2_read32(m,a),y=h2_read32(m,b);h2_write32(m,a,y);h2_write32(m,b,x);}
uint8_t h2_network_observer_compare_priority(h2_memory *m,uint32_t a,uint32_t b,uint32_t data) {return rf(m,data+b*4)>rf(m,data+a*4);}
void h2_sort_u32_small(h2_memory *m,h2_sort_compare cmp,void *ctx,uint32_t first,uint32_t last,uint32_t data) {
    while(first<last) {
        uint32_t best=first;
        for(uint32_t p=first+4;p<=last;p+=4) if(cmp(ctx,h2_read32(m,p),h2_read32(m,best),data)) best=p;
        swap(m,best,last);last-=4;
    }
}
static int64_t sv(uint32_t x) {return x&0x80000000u ? (int64_t)x-INT64_C(0x100000000) : x;}
void h2_sort_u32(h2_memory *m,h2_sort_compare cmp,void *ctx,uint32_t first,uint32_t count,uint32_t data) {
    if(count<2) return;
    uint32_t last=first+count*4-4,lo[30],hi[30],depth=0;
    for(;;) {
        uint32_t n=(last-first)/4+1;
        if(n<=8) h2_sort_u32_small(m,cmp,ctx,first,last,data);
        else {
            swap(m,first+(n/2)*4,first);
            uint32_t left=first,right=last+4;
            for(;;) {
                do {left+=4;} while(left<=last && !cmp(ctx,h2_read32(m,left),h2_read32(m,first),data));
                do {right-=4;} while(right>first && !cmp(ctx,h2_read32(m,first),h2_read32(m,right),data));
                if(right<left) break;
                swap(m,left,right);
            }
            swap(m,first,right);
            if(sv((right-first-4)&~3u)<sv((last-left)&~3u)) {
                if(left<last) {if(depth==30) abort();lo[depth]=left;hi[depth++]=last;}
                if(first+4<right) {last=right-4;continue;}
            } else {
                if(first+4<right) {if(depth==30) abort();lo[depth]=first;hi[depth++]=right-4;}
                if(left<last) {first=left;continue;}
            }
        }
        if(!depth) return;
        --depth;first=lo[depth];last=hi[depth];
    }
}
