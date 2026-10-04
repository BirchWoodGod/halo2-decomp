#include "halo2/network_session_disconnect.h"
#include "halo2/network_session_migration_start.h"
#include "internal/memory.h"
void h2_network_session_handle_disconnect(h2_memory *m,const h2_session_control_context *c,const h2_connection_callbacks *callbacks,uint32_t session,uint32_t close_scratch,uint32_t migration_scratch) {
    uint32_t state=h2_read32(m,session+0x741c);
    /* The jump table sends state 4 directly to cleanup; after the signed
     * bounds and explicit exclusions, only state 3 can reach migration. */
    uint32_t count;
    if(state!=3 || h2_read32(m,session+0x4c)==UINT32_MAX ||
       (count=h2_read32(m,session+0x54))<=1 || (count&UINT32_C(0x80000000))) {
        h2_network_session_cleanup(m,c,session);return;
    }
    const h2_session_send_context *s=c->messages;
    uint32_t index=h2_read32(m,session+h2_read32(m,session+0x40)*20+0x72e0);
    h2_network_observer_close_established(m,s->clock,s->send,s->codec,callbacks,
        h2_read32(m,session+8),index,close_scratch,s->packet,s->address_workspace);
    h2_network_session_begin_migration(m,s->clock,session,migration_scratch);
}
