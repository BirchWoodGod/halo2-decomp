#include "halo2/network_parameters.h"
#include "internal/memory.h"
#include <string.h>
void h2_network_parameter_request_remove(h2_memory *m,
    const h2_parameter_buffer_platform *buffers, uint32_t owner, uint32_t request) {
    uint32_t link = owner+0xc;
    while (h2_read32(m, link) && h2_read32(m, link) != request)
        link = h2_read32(m, link);
    if (h2_read32(m, link) != request) return;
    h2_write32(m, link, h2_read32(m, request));
    uint32_t wrapper = h2_read32(m, 0x4d87f8);
    buffers->query(buffers->context, h2_read32(m, wrapper), request);
    wrapper = h2_read32(m, 0x4d87f8);
    buffers->release(buffers->context, h2_read32(m, wrapper), request, UINT32_MAX);
    if (request) h2_write32(m, wrapper+4, h2_read32(m, wrapper+4)-1);
    h2_write32(m, owner+0x10, h2_read32(m, owner+0x10)-1);
}

void h2_network_parameter_operation_dispose(h2_memory *m,
    const h2_online_task_platform *online, const h2_async_task_platform *async,
    const h2_parameter_buffer_platform *buffers, uint32_t p) {
    if (h2_read32(m, p+8) == 1) h2_write32(m, p+8, 2);
    uint32_t handle = h2_read32(m, p+0x70);
    if (handle != UINT32_MAX) {
        h2_online_task_cancel(m, online, handle);
        h2_write32(m, p+0x70, UINT32_MAX);
    }
    for (unsigned offset = 0x74; offset <= 0x78; offset += 4) {
        handle = h2_read32(m, p+offset);
        if (handle != UINT32_MAX) {
            h2_async_task_release(m, async, handle);
            h2_write32(m, p+offset, UINT32_MAX);
        }
    }
    const uint32_t offsets[] = {0x90, 0x8c, 0xa0};
    for (unsigned i = 0; i < 3; ++i) {
        uint32_t buffer = h2_read32(m, p+offsets[i]);
        if (buffer) {
            uint32_t wrapper = h2_read32(m, 0x4d87f8);
            buffers->query(buffers->context, h2_read32(m, wrapper), buffer);
            wrapper = h2_read32(m, 0x4d87f8);
            buffers->release(buffers->context, h2_read32(m, wrapper), buffer, UINT32_MAX);
            h2_write32(m, wrapper+4, h2_read32(m, wrapper+4)-1);
            h2_write32(m, p+offsets[i], 0);
        }
    }
    *h2_ptr(m, p, 1) = 0;
}

void h2_network_parameter_runtime_dispose(h2_memory *m, const h2_online_task_platform *ops) {
    const uint32_t slots[] = {0x477098, 0x4770a0, 0x477138, 0x477140};
    for (unsigned i = 0; i < 4; ++i) {
        uint32_t handle = h2_read32(m, slots[i]);
        if (i == 2) *h2_ptr(m, 0x477094, 1) = 0;
        if (handle != UINT32_MAX) {
            h2_online_task_cancel(m, ops, handle);
            h2_write32(m, slots[i], UINT32_MAX);
        }
    }
    *h2_ptr(m, 0x477134, 1) = 0;
    *h2_ptr(m, 0x477088, 1) = 0;
}

void h2_network_parameter_set_initialize(h2_memory *m,uint32_t set,uint32_t a,uint32_t b,uint32_t c,uint32_t d,uint32_t e,uint32_t f,uint32_t g) {
    memset(h2_ptr(m,set+4,40),0,40);
    h2_write32(m,set+0x40,a);h2_write32(m,set+0x44,b);
    h2_write32(m,set+0x2c,c);h2_write32(m,set+0x30,d);h2_write32(m,set+0x34,e);h2_write32(m,set+0x38,f);
    h2_write32(m,set,0);h2_write32(m,set+0x3c,g);
    *h2_ptr(m,set+0x49,1)=0;*h2_ptr(m,set+0x48,1)=0;*h2_ptr(m,set+0x4a,1)=0;
}
void h2_network_parameter5_initialize(h2_memory *m,uint32_t p,uint32_t set) {
    h2_write32(m,p+8,set);h2_write32(m,p+4,5);
    *h2_ptr(m,p+0xd,1)=1;*h2_ptr(m,p+0xc,1)=0;
    h2_write32(m,set+0x18,p);h2_write32(m,p+0x104,16);
    h2_write32(m,p+0xf0,UINT32_MAX);h2_write32(m,p+0xf4,UINT32_MAX);
    const uint32_t bytes[]={0x68,0x10,0x11,0xf8};
    for (unsigned i=0;i<4;i++) *h2_ptr(m,p+bytes[i],1)=0;
    h2_write32(m,p+0xe4,0);*h2_ptr(m,p+0xe8,1)=0;*h2_ptr(m,p+0xf9,1)=0;*h2_ptr(m,p+0xe9,1)=0;h2_write32(m,p+0xec,0);
}
static uint32_t signed16(uint32_t v) { v&=0xffff;return v&0x8000 ? v|0xffff0000 : v; }
static uint32_t draw(h2_memory *m,uint32_t seed,uint32_t bound) {
    uint32_t next=h2_read32(m,seed)*UINT32_C(0x19660d)+UINT32_C(0x3c6ef35f);
    h2_write32(m,seed,next);
    return signed16(((next>>16)*signed16(bound))>>16);
}
void h2_network_parameter6_initialize(h2_memory *m,uint32_t p,uint32_t set) {
    h2_write32(m,p+8,set);h2_write32(m,p+4,6);*h2_ptr(m,p+0xd,1)=1;*h2_ptr(m,p+0xc,1)=0;
    h2_write32(m,set+0x1c,p);*h2_ptr(m,p+0x97c,1)=0;
    h2_write32(m,p+0xa08,0);h2_write32(m,p+0xa0c,0);h2_write32(m,p+0xa1c,0);
    h2_write32(m,p+0x9ec,UINT32_MAX);h2_write32(m,p+0x9f0,UINT32_MAX);h2_write32(m,p+0x9f4,UINT32_MAX);
    uint32_t seed=h2_read32(m,0x4e7408)+4;
    h2_write32(m,p+0x978,1);
    h2_write32(m,p+0x96c,draw(m,seed,h2_read32(m,0x4ce1dc)));
    h2_write32(m,p+0x974,draw(m,seed,h2_read32(m,0x4ce1d4)));
    *h2_ptr(m,p+0xa64,1)=0;
    h2_write32(m,p+0xa80,0);h2_write32(m,p+0xa84,0);h2_write32(m,p+0xa88,0);
    *h2_ptr(m,p+0xa78,1)=0;
    h2_write32(m,p+0xa8c,0);h2_write32(m,p+0xa90,0);h2_write32(m,p+0xa94,0);
}
void h2_network_parameter_runtime_initialize(h2_memory *m,uint32_t dependency,uint32_t owner) {
    for (unsigned i=0;i<2;i++) {
        uint32_t p=0x477090+i*0xa0;
        h2_write32(m,p,dependency);*h2_ptr(m,p+6,1)=0;
        for (unsigned j=0;j<3;j++) { h2_write32(m,p+8+j*8,UINT32_MAX);h2_write32(m,p+12+j*8,0); }
        h2_write32(m,p+0x28,4-i);*h2_ptr(m,p+0x2c,1)=0;*h2_ptr(m,p+5,1)=0;*h2_ptr(m,p+4,1)=1;
        if (i==0) h2_write32(m,0x477128,owner);
    }
    *h2_ptr(m,0x477088,1)=1;
}

/* Partial object initialization: preserve vtables, padding and payload fields. */
static void parameter_link(h2_memory *m, uint32_t p, uint32_t index,
                           uint8_t enabled, uint8_t status) {
    h2_write32(m, p+8, 0x527334);
    h2_write32(m, p+4, index);
    *h2_ptr(m, p+0xd, 1) = enabled;
    *h2_ptr(m, p+0xc, 1) = status;
    h2_write32(m, 0x527338+index*4, p);
}

uint8_t h2_network_parameters_initialize(h2_memory *m, uint32_t session,
    uint32_t dependency_ecx, uint32_t dependency_edx,
    uint32_t dependency_a, uint32_t dependency_b, uint32_t dependency_c) {
    h2_write32(m, 0x527fec, session);
    h2_write32(m, 0x527ff4, 0);
    h2_write32(m, 0x527ff8, 0);
    h2_write32(m, 0x527ff0, 1);
    h2_write32(m, session+0x78a8, 0x527fe8);
    h2_network_parameter_set_initialize(m, 0x527334,
        dependency_a, dependency_b, dependency_edx, dependency_ecx,
        dependency_c, session, 0x527fe8);
    parameter_link(m, 0x52738c, 0, 0, 0);
    parameter_link(m, 0x52739c, 1, 1, 0);
    h2_write32(m, 0x5273ac, 0x527500);
    parameter_link(m, 0x5273bc, 2, 1, 0);
    parameter_link(m, 0x5273d0, 3, 1, 0);
    parameter_link(m, 0x5273e8, 4, 1, 0);
    h2_network_parameter5_initialize(m, 0x5273f8, 0x527334);
    h2_network_parameter6_initialize(m, 0x527500, 0x527334);
    h2_write32(m, 0x527fc8, 0);
    parameter_link(m, 0x527f98, 7, 1, 1);
    h2_write32(m, 0x527fa8, 1);
    parameter_link(m, 0x527fb8, 8, 1, 1);
    parameter_link(m, 0x527fd8, 9, 1, 1);
    h2_network_parameter_runtime_initialize(m, 0x527334, 0x527500);
    *h2_ptr(m, 0x527330, 1) = 1;
    return 1;
}
