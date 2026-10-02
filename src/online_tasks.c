#include "halo2/online_tasks.h"
#include "halo2/data_array.h"
#include "halo2/transport.h"
#include "internal/memory.h"
#include <string.h>

void h2_online_address_classify(h2_memory *m) {
    const uint8_t *address = h2_ptr(m, 0x4cf7cc, 6);
    for (uint32_t i = 0; i < 2; ++i) {
        if (memcmp(address, h2_ptr(m, 0x43ff84+i*6, 6), 6) == 0) {
            *h2_ptr(m, 0x50944e, 1) = 1;
            return;
        }
    }
    *h2_ptr(m, 0x50944e, 1) = 0;
}

void h2_online_tasks_initialize(h2_memory *m, const h2_allocator *ops) {
    uint32_t identity = h2_read32(m, 0x468758);
    uint32_t array = ops->allocate(ops->context, identity, 0x230);
    if (array) {
        h2_data_init(m, array, 0, 0x14, 0x18, 0x450b34, identity);
        *h2_ptr(m, array+0x2a, 1) |= 4;
    }
    h2_write32(m, 0x4cf78c, array);
    *h2_ptr(m, array+0x29, 1) = 1;
    h2_data_clear(m, array);
    h2_online_address_classify(m);
    memset(h2_ptr(m, 0x4771c8, 0x2580), 0, 0x2580);
    h2_write32(m, 0x479748, UINT32_MAX);
}

uint32_t h2_online_task_find(h2_memory *m, uint32_t kind, uint32_t owner) {
    uint32_t array=h2_read32(m,0x4cf78c);
    uint32_t limit=h2_read32(m,array+0x38);
    if (limit&UINT32_C(0x80000000)) return 0;
    for (uint32_t index=0;index<limit;++index) {
        uint32_t bitmap=h2_read32(m,array+0x48);
        if (!(h2_read32(m,bitmap+(index>>5)*4)&(UINT32_C(1)<<(index&31)))) continue;
        uint32_t entry=h2_read32(m,array+0x44)+h2_read32(m,array+0x24)*index;
        if (!entry) return 0;
        if (h2_read32(m,entry+4)==kind &&
            (h2_read32(m,entry+8)==owner || owner==UINT32_MAX || owner==255)) return 1;
    }
    return 0;
}

uint32_t h2_online_task_get(h2_memory *m, uint32_t handle) {
    if (handle==UINT32_MAX) return 0;
    uint32_t array=h2_read32(m,0x4cf78c), index=handle&0xffff;
    uint32_t limit=h2_read32(m,array+0x38);
    if ((limit&UINT32_C(0x80000000)) || index>=limit) return 0;
    uint32_t entry=h2_read32(m,array+0x44)+h2_read32(m,array+0x24)*index;
    const uint8_t *p=h2_ptr(m,entry,2);
    uint32_t salt=(uint32_t)p[0]|(uint32_t)p[1]<<8;
    return salt && salt==(handle>>16) ? entry : 0;
}

uint32_t h2_online_login_status(h2_memory *m, const h2_online_task_platform *ops, uint32_t handle) {
    uint32_t task=h2_online_task_get(m,handle);
    if (!task) return h2_read32(m,0x467218);
    if (h2_read32(m,task+4)==1 || (*h2_ptr(m,task+2,1)&0x20)) return h2_read32(m,task+0x10);
    uint32_t sdk_handle=h2_read32(m,task+0xc), status;
    if (!sdk_handle || sdk_handle==UINT32_MAX) {
        h2_write32(m,0x467218,10);
        return 10;
    }
    if (!h2_transport_is_active(m)) status=5;
    else {
        uint32_t result=ops->login_status(ops->context,sdk_handle);
        if (result==0 || result==0x1510f0) {
            status=result ? 1 : 0;
            h2_write32(m,0x467218,status);
            return status;
        }
        switch (result) {
            case 0x80151001: status=4; break;
            case 0x80151002: status=3; break;
            case 0x80151003: status=8; break;
            case 0x80151004: status=5; break;
            case 0x80151005: status=7; break;
            case 0x80151006: status=6; break;
            case 0x80151200: status=2; break;
            default:
                if (result==0x1512f0) *h2_ptr(m,0x50944f,1)=1;
                status=10;
        }
    }
    *h2_ptr(m,task+2,1)|=0x20;
    h2_write32(m,task+0x10,status);
    h2_write32(m,0x467218,status);
    return status;
}

uint32_t h2_online_task_continue(h2_memory *m, const h2_online_task_platform *ops, uint32_t task) {
    if (!task) return UINT32_C(0x80004005);
    uint32_t handle=h2_read32(m,task+0xc);
    if (!handle || handle==UINT32_MAX) return UINT32_C(0x80004005);
    if (!(h2_read32(m,task+4)==0 && h2_transport_is_active(m))) {
        uint32_t login=h2_read32(m,0x467214);
        if (login==UINT32_MAX || h2_online_login_status(m,ops,login)!=1)
            return UINT32_C(0x80151000);
    }
    return ops->continue_task(ops->context,h2_read32(m,task+0xc));
}

void h2_online_task_cancel_kind33(h2_memory *m, const h2_online_task_platform *ops, uint32_t handle) {
    uint32_t task=h2_online_task_get(m,handle);
    if (!task) return;
    uint32_t login=h2_read32(m,0x467214);
    if (login!=UINT32_MAX && h2_online_login_status(m,ops,login)==1)
        (void)ops->cancel_kind33(ops->context,h2_read32(m,task+0xc));
}

void h2_online_task_cancel(h2_memory *m, const h2_online_task_platform *ops, uint32_t handle) {
    if (handle==UINT32_MAX) return;
    uint32_t array=h2_read32(m,0x4cf78c);
    uint32_t task=h2_online_task_get(m,handle);
    if (!task) return;
    uint32_t sdk_handle=h2_read32(m,task+0xc);
    if (sdk_handle && sdk_handle!=UINT32_MAX) {
        uint32_t kind=h2_read32(m,task+4);
        if (kind==2) {
            uint32_t result=0;
            while (result!=0x1500f2 && !(result&UINT32_C(0x80000000)))
                result=h2_online_task_continue(m,ops,task);
        } else if (kind==3) {
            if (!(ops->prepare_cancel(ops->context,sdk_handle)&UINT32_C(0x80000000)))
                (void)h2_online_task_continue(m,ops,task);
        } else if (kind==33) h2_online_task_cancel_kind33(m,ops,handle);
        (void)ops->close_task(ops->context,h2_read32(m,task+0xc));
        array=h2_read32(m,0x4cf78c);
        h2_write32(m,task+0xc,0);
    }
    h2_data_delete(m,array,handle);
}

static int positive32(uint32_t value) {
    return value && !(value&UINT32_C(0x80000000));
}
static int at_most32(uint32_t value,uint32_t bound) {
    return (value&UINT32_C(0x80000000)) || value<=bound;
}
void h2_online_tasks_drain(h2_memory *m, const h2_online_task_platform *ops) {
    uint32_t pool=h2_read32(m,0x4cf78c);
    while (positive32(h2_read32(m,pool+0x3c))) {
        uint32_t scan=pool;
        for (uint32_t i=0;!(i&UINT32_C(0x80000000));++i) {
            uint32_t high=h2_read32(m,scan+0x38);
            if ((high&UINT32_C(0x80000000)) || i>=high) break;
            uint32_t bitmap=h2_read32(m,scan+0x48);
            if (!(h2_read32(m,bitmap+(i>>5)*4)&(UINT32_C(1)<<(i&31)))) continue;
            uint32_t entry=h2_read32(m,scan+0x44)+h2_read32(m,scan+0x24)*i;
            const uint8_t *salt=h2_ptr(m,entry,2);
            uint32_t handle=((uint32_t)salt[0]|(uint32_t)salt[1]<<8)<<16|i;
            uint32_t kind=h2_read32(m,entry+4), count=h2_read32(m,pool+0x3c);
            int cancel=1;
            switch (kind) {
                case 0: cancel=count==1; break;
                case 1: cancel=at_most32(count,2); break;
                case 2: cancel=at_most32(count,3); break;
                case 11: cancel=!h2_online_task_find(m,12,255); break;
                case 33: cancel=at_most32(count,4); break;
            }
            if (cancel) {
                h2_online_task_cancel(m,ops,handle);
                pool=h2_read32(m,0x4cf78c);
            }
        }
    }
}

void h2_online_tasks_dispose(h2_memory *m, const h2_allocator *allocator,
                             const h2_online_task_platform *ops) {
    h2_online_tasks_drain(m,ops);
    h2_data_dispose(m,allocator,h2_read32(m,0x4cf78c));
    uint32_t handle=h2_read32(m,0x479748);
    if (handle!=UINT32_MAX) {
        h2_online_task_cancel(m,ops,handle);
        h2_write32(m,0x479748,UINT32_MAX);
    }
}
