#ifndef HALO2_NETWORK_OBSERVER_ADMISSION_H
#define HALO2_NETWORK_OBSERVER_ADMISSION_H
#include "halo2/network_connection.h"
/* Scratch contracts are those of h2_network_connection_close. */
void h2_network_observer_close_established(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,const h2_message_codec_platform *,const h2_connection_callbacks *,uint32_t observer,uint32_t index,uint32_t local_scratch,uint32_t packet_scratch,uint8_t address_workspace[28]); /* 00075e40: ECX observer, EAX index */
#endif
