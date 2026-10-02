#ifndef HALO2_NETWORK_SESSION_CONTROL_H
#define HALO2_NETWORK_SESSION_CONTROL_H
#include "halo2/network_session_send.h"
#include "halo2/network_session_lifecycle.h"
typedef struct {
    const h2_session_send_context *messages;
    const h2_session_registration_platform *registration;
    void *context;
    /* Original virtual method: ECX object, no stack arguments, ignored return. */
    void (*cleanup_callback)(void *,uint32_t function,uint32_t object);
    /* Disjoint guest scratch: 112, 16, 52, and 36 bytes respectively.
     * Also disjoint from messages' scratch and all live engine objects. */
    uint32_t join_saved,join_message,control_message,handoff;
} h2_session_control_context;
/* Valid original session states are 0..10. Unknown jump-table targets abort;
 * no equivalence to the original invalid-address exception is claimed. */
void h2_network_session_request_shutdown(h2_memory *,const h2_session_control_context *,uint32_t session,uint8_t force); /* 0005a400 */
void h2_network_session_cleanup(h2_memory *,const h2_session_control_context *,uint32_t session); /* 0005a520 */
void h2_network_session_begin_handoff(h2_memory *,const h2_session_control_context *,uint32_t session,uint8_t flag,uint32_t peer); /* 000614a0 */
#endif
