#ifndef HALO2_NETWORK_MESSAGES_H
#define HALO2_NETWORK_MESSAGES_H
#include "halo2/memory.h"
#include "halo2/network_packet.h"
/* Bridge a guest encoder address to its native implementation. The caller must
 * provide encoders for the descriptors it uses; this is not an x86 executor. */
typedef struct {
    void *context;
    void (*encode)(void *, uint32_t function, uint32_t stream, uint32_t size, uint32_t payload);
} h2_message_codec_platform;
uint8_t h2_message_writer_enqueue(h2_memory *, const h2_network_state_operations *,
    const h2_socket_send_platform *, const h2_message_codec_platform *,
    uint32_t writer, uint32_t address, uint32_t type, uint32_t size, uint32_t payload,
    uint32_t scratch, uint8_t address_workspace[28]); /* 0007b140 */
void h2_message_writer_flush(h2_memory *, const h2_network_state_operations *,
    const h2_socket_send_platform *, uint32_t writer, uint32_t scratch,
    uint8_t address_workspace[28]); /* 0007b330 */
/* Reply scratch is 12 bytes, with incoming padding at +2/+3 preserved.
 * Keep it disjoint from live objects and packet scratch; see packet APIs for
 * the latter's size. The original ignores enqueue failure. */
void h2_message_handle_ping(h2_memory *, const h2_network_state_operations *,
    const h2_socket_send_platform *, const h2_message_codec_platform *,
    uint32_t handler, uint32_t address, uint32_t ping, uint32_t reply,
    uint32_t packet_scratch, uint8_t address_workspace[28]); /* 00093f60 */
void h2_message_join_request_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000acc20 */
uint8_t h2_message_join_request_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000acfa0 */
void h2_message_config_fields_write(h2_memory *, uint32_t stream, uint32_t fields); /* 0007ee10 */
uint8_t h2_message_config_fields_read(h2_memory *, uint32_t stream, uint32_t fields); /* 0007efa0 */
void h2_message_ping_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac490 */
uint8_t h2_message_ping_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac530 */
void h2_message_pong_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac580 */
uint8_t h2_message_pong_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac610 */
void h2_message_broadcast_search_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac670 */
uint8_t h2_message_broadcast_search_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac6e0 */
void h2_message_connect_request_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac8a0 */
uint8_t h2_message_connect_request_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac900 */
void h2_message_connect_refuse_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac940 */
uint8_t h2_message_connect_refuse_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac9a0 */
void h2_message_connect_establish_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ac9e0 */
uint8_t h2_message_connect_establish_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000aca00 */
void h2_message_connect_closed_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000aca40 */
uint8_t h2_message_connect_closed_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000acab0 */
uint32_t h2_message_session_lookup(h2_memory *, uint32_t sessions, uint32_t identity); /* 00075800 */
uint32_t h2_message_session_time(h2_memory *, const h2_network_state_operations *, uint32_t identity); /* 000758c0 */
void h2_message_time_sync_write(h2_memory *, const h2_network_state_operations *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad940 */
uint8_t h2_message_time_sync_read(h2_memory *, const h2_network_state_operations *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad9e0 */
uint8_t h2_message_time_sync_clear(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ada90 */
void h2_message_election_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad5c0 */
uint8_t h2_message_election_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad710 */
void h2_message_election_refuse_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad820 */
uint8_t h2_message_election_refuse_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad8d0 */
void h2_message_join_abort_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad1c0 */
uint8_t h2_message_join_abort_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad1e0 */
void h2_message_host_decline_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad430 */
uint8_t h2_message_host_decline_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad530 */
void h2_message_session_id_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad5a0 */
uint8_t h2_message_leave_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad2e0 */
uint8_t h2_message_session_control_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad3f0 */
void h2_message_handoff_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad320 */
uint8_t h2_message_handoff_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad390 */
void h2_message_join_refuse_write(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad230 */
uint8_t h2_message_join_refuse_read(h2_memory *, uint32_t stream, uint32_t size, uint32_t payload); /* 000ad290 */
void h2_message_header_write(h2_memory *, uint32_t stream, uint32_t type, uint32_t size); /* 000937e0 */
uint8_t h2_message_header_read(h2_memory *, uint32_t stream, uint32_t type_output,
    uint32_t table, uint32_t size_output); /* 00093860 */
/* Populate the original 0x5a0-byte message table. Preserve three reserved bytes
 * per descriptor. Callback guest addresses are metadata, not native functions. */
void h2_messages_register_discovery(h2_memory *,uint32_t table); /* 000ac800 */
void h2_messages_register_connection(h2_memory *,uint32_t table); /* 000acb10 */
void h2_messages_register_session(h2_memory *,uint32_t table); /* 000adab0 */
void h2_messages_register_membership(h2_memory *,uint32_t table); /* 000af680 */
void h2_messages_register_parameters(h2_memory *,uint32_t table); /* 000b2220 */
void h2_messages_register_simulation(h2_memory *,uint32_t table); /* 000b2680 */
void h2_messages_register_synchronous(h2_memory *,uint32_t table); /* 000b2b30 */
void h2_messages_register_results(h2_memory *,uint32_t table); /* 000b2cc0 */
void h2_messages_register_test(h2_memory *,uint32_t table); /* 000b2de0 */
void h2_message_writer_flush_address(h2_memory *,const h2_network_state_operations *,const h2_socket_send_platform *,uint32_t writer,uint32_t address,uint32_t scratch,uint8_t address_workspace[28]); /* 0007b390 */
#endif
