#include "halo2/network_session_tasks.h"
#include "halo2/network_session.h"
#include "internal/memory.h"
void h2_network_session_cancel_tasks(h2_memory *m,const h2_session_control_context *control,const h2_online_task_platform *online,const h2_async_task_platform *async,uint32_t object) {
    uint32_t session=h2_read32(m,h2_read32(m,object+8)+0x34);
    if (!h2_read32(m,object+0x104)) h2_write32(m,object+0x104,16);
    uint32_t handle=h2_read32(m,object+0xf0);
    if (handle!=UINT32_MAX) {
        h2_online_task_cancel(m,online,handle);
        h2_write32(m,object+0xf0,UINT32_MAX);
    }
    handle=h2_read32(m,object+0xf4);
    if (handle!=UINT32_MAX) {
        h2_async_task_release(m,async,handle);
        h2_write32(m,object+0xf4,UINT32_MAX);
    }
    if (h2_read32(m,session+0x741c) && !h2_network_session_shutdown_guard(m,session))
        h2_network_session_request_shutdown(m,control,session,0);
    *h2_ptr(m,object+0x68,1)=0;
    *h2_ptr(m,object+0x10,1)=0;
    *h2_ptr(m,object+0x11,1)=0;
    *h2_ptr(m,object+0xf8,1)=0;
    h2_write32(m,object+0xe4,0);
    *h2_ptr(m,object+0xe8,1)=0;
    *h2_ptr(m,object+0xf9,1)=0;
    *h2_ptr(m,object+0xe9,1)=0;
    h2_write32(m,object+0xec,0);
}
