#!/usr/bin/env bash
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
python_bin=${H2_TEST_PYTHON:-"$root/.tools/venv/bin/python"}
if [[ ! -x "$python_bin" ]]; then
    echo 'Create .tools/venv and install requirements-test.txt first; see README.md.' >&2
    exit 1
fi
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
"$python_bin" tests/data_array_oracle.py
"$python_bin" tests/allocator_oracle.py
"$python_bin" tests/engine_pools_oracle.py
"$python_bin" tests/hash_crc_oracle.py
"$python_bin" tests/arena_oracle.py
"$python_bin" tests/game_lifecycle_oracle.py
"$python_bin" tests/transport_oracle.py
"$python_bin" tests/random_oracle.py
"$python_bin" tests/network_messages_oracle.py
"$python_bin" tests/network_endpoint_oracle.py
"$python_bin" tests/network_socket_oracle.py
"$python_bin" tests/network_options_oracle.py
"$python_bin" tests/network_address_oracle.py
"$python_bin" tests/network_bind_oracle.py
"$python_bin" tests/network_open_oracle.py
"$python_bin" tests/network_state_oracle.py
"$python_bin" tests/network_session_oracle.py
"$python_bin" tests/network_session_lifecycle_oracle.py
"$python_bin" tests/network_parameters_oracle.py
"$python_bin" tests/online_tasks_oracle.py
"$python_bin" tests/online_poll_oracle.py
"$python_bin" tests/online_cancel_oracle.py
"$python_bin" tests/online_drain_oracle.py
"$python_bin" tests/async_tasks_oracle.py
"$python_bin" tests/async_task_create_oracle.py
"$python_bin" tests/async_task_result_oracle.py
"$python_bin" tests/network_observer_async_oracle.py
"$python_bin" tests/network_observer_poll_oracle.py
"$python_bin" tests/network_observer_bandwidth_oracle.py
"$python_bin" tests/network_observer_measurement_oracle.py
"$python_bin" tests/network_observer_rates_oracle.py
"$python_bin" tests/bitstream_oracle.py
"$python_bin" tests/session_description_oracle.py
"$python_bin" tests/message_dispatch_oracle.py
"$python_bin" tests/message_reader_oracle.py
"$python_bin" tests/discovery_oracle.py
"$python_bin" tests/discovery_update_oracle.py
"$python_bin" tests/discovery_start_oracle.py
"$python_bin" tests/discovery_stop_oracle.py
"$python_bin" tests/network_registration_oracle.py
"$python_bin" tests/network_tracking_oracle.py
"$python_bin" tests/resource_release_oracle.py
"$python_bin" tests/network_task_complete_oracle.py
"$python_bin" tests/network_connection_oracle.py
"$python_bin" tests/network_storage_oracle.py
"$python_bin" tests/network_storage_queue_oracle.py
"$python_bin" tests/network_resolution_oracle.py
"$python_bin" tests/network_session_send_oracle.py
"$python_bin" tests/network_session_control_oracle.py
"$python_bin" tests/network_session_tasks_oracle.py
"$python_bin" tests/network_session_identity_oracle.py
"$python_bin" tests/network_observer_admission_oracle.py
"$python_bin" tests/network_session_membership_oracle.py
"$python_bin" tests/network_session_removal_oracle.py
"$python_bin" tests/network_observer_query_oracle.py
"$python_bin" tests/network_observer_retry_oracle.py
"$python_bin" tests/network_connection_setup_oracle.py
"$python_bin" tests/network_route_insert_oracle.py
"$python_bin" tests/network_handshake_oracle.py
"$python_bin" tests/network_connection_open_oracle.py
"$python_bin" tests/network_observer_selection_oracle.py
"$python_bin" tests/network_observer_tick_oracle.py
"$python_bin" tests/network_observer_timeout_oracle.py
"$python_bin" tests/network_observer_admit_oracle.py
"$python_bin" tests/text_format_oracle.py
"$python_bin" tests/network_connection_allocate_oracle.py
"$python_bin" tests/network_slot_alloc_oracle.py
"$python_bin" tests/network_observer_oracle.py
"$python_bin" tests/network_observer_dispose_oracle.py
"$python_bin" tests/network_observer_state_oracle.py
"$python_bin" tests/network_packet_oracle.py
"$python_bin" tests/network_send_oracle.py
"$python_bin" tests/network_submit_oracle.py
"$python_bin" tests/network_final_state_oracle.py
"$python_bin" tests/network_config_oracle.py
"$python_bin" tests/file_path_oracle.py
"$python_bin" tests/file_io_oracle.py
"$python_bin" tests/file_metadata_oracle.py
"$python_bin" tests/file_open_oracle.py
"$python_bin" tests/network_config_load_oracle.py
"$python_bin" tests/host_files_test.py
build/halo2-engine-host --probe-pools default.xbe
cmake -S . -B build/ubsan -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DH2_SANITIZE=ON
cmake --build build/ubsan
"$python_bin" tests/data_array_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/data-array-tests-ubsan.json
"$python_bin" tests/allocator_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/allocator-tests-ubsan.json
"$python_bin" tests/engine_pools_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/engine-pool-tests-ubsan.json
build/ubsan/halo2-engine-host --probe-pools default.xbe
"$python_bin" tests/hash_crc_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/hash-crc-tests-ubsan.json
"$python_bin" tests/arena_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/arena-tests-ubsan.json
"$python_bin" tests/game_lifecycle_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/game-lifecycle-tests-ubsan.json
"$python_bin" tests/transport_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/transport-tests-ubsan.json
"$python_bin" tests/random_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/random-tests-ubsan.json
"$python_bin" tests/network_messages_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-message-tests-ubsan.json
"$python_bin" tests/network_endpoint_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-endpoint-tests-ubsan.json
"$python_bin" tests/network_socket_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-socket-tests-ubsan.json
"$python_bin" tests/network_options_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-option-tests-ubsan.json
"$python_bin" tests/network_address_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-address-tests-ubsan.json
"$python_bin" tests/network_bind_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-bind-tests-ubsan.json
"$python_bin" tests/network_open_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-open-tests-ubsan.json
"$python_bin" tests/network_state_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-state-tests-ubsan.json
"$python_bin" tests/network_session_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-session-tests-ubsan.json
"$python_bin" tests/network_session_lifecycle_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-session-lifecycle-tests-ubsan.json
"$python_bin" tests/network_parameters_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-parameter-tests-ubsan.json
"$python_bin" tests/online_tasks_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/online-task-tests-ubsan.json
"$python_bin" tests/network_final_state_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-final-state-tests-ubsan.json
"$python_bin" tests/network_config_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-config-tests-ubsan.json
"$python_bin" tests/file_path_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/file-path-tests-ubsan.json
"$python_bin" tests/file_io_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/file-io-tests-ubsan.json
"$python_bin" tests/file_metadata_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/file-metadata-tests-ubsan.json
"$python_bin" tests/file_open_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/file-open-tests-ubsan.json
"$python_bin" tests/network_config_load_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/network-config-load-tests-ubsan.json
"$python_bin" tests/host_files_test.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/host-file-tests-ubsan.json
"$python_bin" tests/online_poll_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/online-poll-tests-ubsan.json
"$python_bin" tests/online_cancel_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/online-cancel-tests-ubsan.json
"$python_bin" tests/online_drain_oracle.py --library build/ubsan/libhalo2_engine.so \
    --report analysis/online-drain-tests-ubsan.json

"$python_bin" tests/async_tasks_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/async-task-tests-ubsan.json
"$python_bin" tests/async_task_create_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/async-task-create-tests-ubsan.json
"$python_bin" tests/async_task_result_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/async-task-result-tests-ubsan.json
"$python_bin" tests/network_observer_async_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-async-tests-ubsan.json
"$python_bin" tests/network_observer_poll_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-poll-tests-ubsan.json
"$python_bin" tests/network_observer_bandwidth_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-bandwidth-tests-ubsan.json
"$python_bin" tests/network_observer_measurement_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-measurement-tests-ubsan.json
"$python_bin" tests/network_observer_rates_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-rates-tests-ubsan.json

"$python_bin" tests/bitstream_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/bitstream-tests-ubsan.json
"$python_bin" tests/session_description_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/session-description-tests-ubsan.json
"$python_bin" tests/message_dispatch_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/message-dispatch-tests-ubsan.json
"$python_bin" tests/message_reader_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/message-reader-tests-ubsan.json
"$python_bin" tests/discovery_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/discovery-tests-ubsan.json
"$python_bin" tests/discovery_update_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/discovery-update-tests-ubsan.json
"$python_bin" tests/discovery_start_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/discovery-start-tests-ubsan.json
"$python_bin" tests/discovery_stop_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/discovery-stop-tests-ubsan.json
"$python_bin" tests/network_registration_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-registration-tests-ubsan.json
"$python_bin" tests/network_tracking_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-tracking-tests-ubsan.json
"$python_bin" tests/resource_release_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/resource-release-tests-ubsan.json
"$python_bin" tests/network_task_complete_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-task-complete-tests-ubsan.json
"$python_bin" tests/network_connection_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-connection-tests-ubsan.json
"$python_bin" tests/network_storage_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-storage-tests-ubsan.json
"$python_bin" tests/network_storage_queue_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-storage-queue-tests-ubsan.json
"$python_bin" tests/network_resolution_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-resolution-tests-ubsan.json
"$python_bin" tests/network_session_send_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-session-send-tests-ubsan.json
"$python_bin" tests/network_session_control_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-session-control-tests-ubsan.json
"$python_bin" tests/network_session_tasks_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-session-tasks-tests-ubsan.json
"$python_bin" tests/network_session_identity_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-session-identity-tests-ubsan.json
"$python_bin" tests/network_observer_admission_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-admission-tests-ubsan.json
"$python_bin" tests/network_session_membership_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-session-membership-tests-ubsan.json
"$python_bin" tests/network_session_removal_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-session-removal-tests-ubsan.json
"$python_bin" tests/network_observer_query_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-query-tests-ubsan.json
"$python_bin" tests/network_observer_retry_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-retry-tests-ubsan.json
"$python_bin" tests/network_connection_setup_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-connection-setup-tests-ubsan.json
"$python_bin" tests/network_route_insert_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-route-insert-tests-ubsan.json
"$python_bin" tests/network_handshake_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-handshake-tests-ubsan.json
"$python_bin" tests/network_connection_open_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-connection-open-tests-ubsan.json
"$python_bin" tests/network_observer_selection_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-selection-tests-ubsan.json
"$python_bin" tests/network_observer_tick_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-tick-tests-ubsan.json
"$python_bin" tests/network_observer_timeout_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-timeout-tests-ubsan.json
"$python_bin" tests/network_observer_admit_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-admit-tests-ubsan.json
"$python_bin" tests/text_format_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/text-format-tests-ubsan.json
"$python_bin" tests/network_connection_allocate_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-connection-allocate-tests-ubsan.json
"$python_bin" tests/network_slot_alloc_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-slot-alloc-tests-ubsan.json
"$python_bin" tests/network_observer_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-tests-ubsan.json
"$python_bin" tests/network_observer_dispose_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-dispose-tests-ubsan.json
"$python_bin" tests/network_observer_state_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-observer-state-tests-ubsan.json

"$python_bin" tests/network_packet_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-packet-tests-ubsan.json

"$python_bin" tests/network_send_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-send-tests-ubsan.json

"$python_bin" tests/network_submit_oracle.py --library build/ubsan/libhalo2_engine.so --report analysis/network-submit-tests-ubsan.json
