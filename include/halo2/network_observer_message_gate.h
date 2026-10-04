#ifndef HALO2_NETWORK_OBSERVER_MESSAGE_GATE_H
#define HALO2_NETWORK_OBSERVER_MESSAGE_GATE_H
#include "halo2/network_observer_retry.h"
/* ECX observer, EAX peer index, stack message type; ret4. Only AL is the query
 * result. Type shifts use the low byte, with shifts64..255 yielding zero. */
uint8_t h2_network_observer_message_deferred(h2_memory *,uint32_t observer,uint32_t index,uint32_t type); /* 000768b0 */
void h2_network_observer_defer_message(h2_memory *,uint32_t observer,uint32_t index,uint32_t type); /* 00076930 */
#endif
