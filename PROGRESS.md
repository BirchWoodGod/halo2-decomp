# Full objective and current evidence

The active objective remains complete Halo 2 decompilation and a playable Linux
build of the original Xbox game. A pseudocode export, an emulator run, a native
library, or an isolated test pass does not satisfy that objective.

## Current state

- The original local XBE is copied and hash-pinned. Its Ghidra mapping passes
  byte-for-byte verification, including after saving and reopening the project.
- Automatic x86 analysis and pseudocode export are available. Function discovery
  is incomplete; no percentage of total game decompilation is established.
  Currently all 11,422 discovered main-section functions export. The input-varnode
  error in `0006D080` is resolved by modeling the instruction-reviewed CRT stack
  probe at `00320560`; two previous enum-table errors remain fixed. This is pseudocode coverage
  of a partial inventory, not source-recovery coverage of the whole game.
- 264 engine routines have compiled native C implementations,
  reviewed custom calling conventions, and differential tests against original
  instructions, including an undefined-behavior-sanitized build.
  Both configurations passed 10,510 comparisons, including the 16-bit index limit.
  That count covers the original 16 data-array routines. Fourteen additional recovered
  functions cover allocation, three engine pool initializers, hash tables, and CRC:
  289 allocator boundary comparisons, 26 full-memory initialization comparisons,
  and 1,299 hash/CRC comparisons pass in both configurations.
- Five further routines recover arena initialization, reservation, alignment, and
  its virtual allocate/release methods. The Linux probe now uses this allocator
  for script and actor storage. Xbox backing memory and save-file setup remain
  external boundaries; the diagnostic omits save-file preparation explicitly.
  All 711 arena comparisons pass in Release and UBSan, including the combined
  startup/pool/disposal path through the original allocator vtable. Two more
  recovered routines cover per-map state initialization and arena shutdown.
  Tests include string truncation, option copying, state clearing, and platform
  callback ordering; actual map loading and save-file I/O remain unimplemented.
- Six further routines recover subsystem initialization, map/structure transitions,
  and game-options copying. All 144 orchestration comparisons pass in Release
  and UBSan; subsystem bodies, FP control, and variant validation are controlled
  boundaries. The startup audit finds 23 of 68 direct initialization slots
  in the native catalog, but 20 of those use the same no-op function. The next
  missing startup subsystem is `0008D9F0`.
- Five transport routines are recovered, including the first startup entrypoint
  `0008D690`. All 82 comparisons pass in Release and UBSan, including startup
  connected to the actual transport initializer. Allocator, link-query, and
  online-start boundaries are controlled; networking is not implemented.
- Three random routines and a shared no-op callback bring the total to 52.
  All 1,127 comparisons pass in Release and UBSan, including all 1,026 direction
  table entries and startup connected to the random initializer. CRT/SDK entropy
  sources remain external; the additional floating-point random rotation routine
  is unrecovered. The audit reports repeated no-op slots separately.
- Nine network-message registration routines bring the total to 61. All 360
  comparisons pass in Release and UBSan, including all 45 descriptors, reserved
  bytes, unaligned table addresses, and re-registration. The enclosing network
  startup routine `0008D9F0`, codecs, and session machinery remain unrecovered.
- Three endpoint/statistics routines bring the total to 64. All 136 comparisons
  pass in Release and UBSan, covering every socket-open failure combination,
  cleanup results, signed intervals, float bit patterns, and preserved padding.
  Socket operations remain external. Endpoint initialization returns success
  independently of its separate sockets-open flag, matching the original.
- Socket-record creation, socket close, and endpoint cleanup bring the total
  to 67. All 464 comparisons pass in Release and UBSan, including partial-open
  failures with actual recovered cleanup. OS allocation and socket APIs remain
  controlled boundaries; this is not a working Linux network backend.
- Three socket-option routines bring the total to 70. All 820 comparisons pass
  in Release and UBSan, covering option mapping, scalar/pointer values, inactive
  transport, invalid handles, SDK errors, and values written on error. The SDK
  operations remain external; no Linux socket backend is established.
- Address conversion in both directions and socket-handle setup bring the
  total to 73. All 592 comparisons pass in Release and UBSan, covering retained
  bytes, overlapping buffers, invalid formats, handle reuse, and SDK failures.
  The Linux SDK backend remains incomplete; endpoint open is now recovered below.
- The bind wrapper brings the total to 74. All 256 comparisons pass in Release
  and UBSan, using recovered address conversion, handle setup, and option code.
  The native API explicitly represents the original incoming stack-local bytes,
  including untouched IPv6 auxiliary fields. SDK binding is still external.
- Endpoint socket opening brings the total to 75. All 448 comparisons pass
  in Release and UBSan, including the complete four-socket endpoint initializer
  and cleanup using recovered engine callees. Only SDK/kernel operations are
  controlled in that combined path. No Linux networking backend is claimed.
- Three network state/provider setup routines bring the total to 78. All 112
  comparisons pass in Release and UBSan. They cover fifteen fixed-size records,
  timing overrides changed during callbacks, shared state, and flag updates.
  The enclosing network startup and session machinery remain incomplete.
- Session storage construction brings the total to 79. All 44 comparisons
  pass in Release and UBSan, including the three startup objects linked to the
  recovered observer state. The session state machine and enclosing network
  startup remain incomplete.
- Four parameter setup routines bring the total to 83. All 240 comparisons
  pass in Release and UBSan, covering registration links, partial resets, signed
  random bounds, and overlapping seed/output storage. The enclosing setup
  routine is now recovered below; parameter state machines remain unrecovered.
- The enclosing parameter setup and two further network reset routines bring
  the total to 86. The parameter suite now passes 300 comparisons and the state
  suite 176 in both builds. The full parameter setup uses all four recovered
  constructors, links ten objects, and attaches them to a session. The two resets
  retain padding and the fifth word of each tracking record. Network startup
  still requires file/configuration and remaining state setup; online-task
  construction is now recovered below.
- Online-task pool construction and its six-byte address classifier bring the
  total to 88. All 90 comparisons pass in both builds, including each constant
  match, single-byte mismatches, unaligned storage, and a changed allocator global
  during allocation. The native Linux probe also exercises this pool. Task
  execution and full network startup remain unfinished.
- Three final network state constructors bring the total to 91. All 144
  comparisons pass in Release and UBSan, including the complete parent routine
  with both original callees intact. Sixteen record indices, partial resets,
  sentinels, flags, and preserved padding match. Persisted configuration handling
  and failure cleanup remain dependencies of complete network startup.
- Persisted-state defaults, byte-field validation, and the full state validator
  bring the total to 94. All 2,492 comparisons pass in Release and UBSan, with
  every original callee intact. Coverage includes 350-record defaults, exhaustive
  individual byte values, ordering, bounds, and both linked lists. Actual file
  loading, startup orchestration, and cleanup remain unfinished.
- Three file-path helpers bring the total to 97. All 534 comparisons pass
  in Release and UBSan, with original CRT calls intact. They recover Xbox path
  append, parent removal, and drive resolution, including truncation and padding.
  Linux filesystem translation and actual file operations remain unimplemented.
- File read, write, and close wrappers bring the total to 100. All 498
  comparisons pass in Release and UBSan, covering complete/short/failed I/O,
  unchanged output counts, position wraparound, callback side effects, and error
  ordering. SDK operations remain controlled boundaries; this is not a Linux
  filesystem backend. Opening and metadata lookup remain unrecovered.
- Seek and set-end wrappers bring the total to 102. The file-I/O suite now
  passes 678 comparisons in both builds, including 180 new cases for cached
  positions, failure sentinels, low-byte flags, changed handles, and repeated
  error handling. Opening, metadata lookup, and the Linux backend remain undone.
- File existence and size queries bring the total to 104. All 280 comparisons
  pass in Release and UBSan, including original path resolution, repeated error
  queries, path truncation, and preserved output on failure. SDK queries remain
  controlled; file opening and the Linux filesystem backend are not implemented.
- File opening brings the total to 105. All 840 comparisons pass in both
  builds, covering flag combinations, error mapping, initial seek failure and
  cleanup, callback mutations, and aliased output storage. The engine file
  wrappers are recovered; the Linux backend and enclosing configuration loader
  remain unfinished.
- The complete persisted-configuration loader brings the total to 106. All 44
  comparisons pass in both builds with every original engine callee intact.
  Existence, size, opening, reads, CRC, validation and closing are connected.
  A caller-supplied temporary workspace represents stack-local objects and is
  checked separately. SDK I/O remains controlled; the Linux backend and full
  game startup are still unfinished.
- A Linux filesystem adapter now connects recovered file operations to real
  files. Temporary-file tests exercise read/write/seek/truncate/close, drive
  mounts, ASCII case lookup, sharing conflicts, deletion, handle exhaustion,
  and descriptor cleanup. The recovered configuration loader and standalone
  `--probe-config` command accept a valid on-disk fixture and reject invalid
  inputs in both builds. This is host integration, not an additional recovered
  routine; the count remains 106. Timestamp metadata, threading/TLS,
  cross-process sharing and some deletion semantics remain incomplete.
- Two online-task lookup helpers bring the recovered total to 108. The expanded
  online-task suite passes 810 comparisons in both builds, including 720 new
  checks of bitmap scans, owner wildcards, salt matching, and signed high-water
  limits. These support cancellation and cleanup, which remain unrecovered.
- Online login-status polling and task continuation bring the total to 110.
  All 215 comparisons pass in both builds, including recovered lookup and
  transport callees, cached results, terminal error mapping, and callback side
  effects. SDK task operations remain controlled and cancellation is unfinished.
- Task cancellation and its kind-33 helper bring the total to 112. All 399
  comparisons pass in both builds, including polling to completion/error,
  preparation failure, conditional cancellation, SDK close, and actual pool
  deletion. SDK operations remain controlled; full shutdown is unfinished.
- Online-task draining and pool disposal bring the total to 114. All 72
  comparisons pass in both builds, including shuffled task dependencies, pool
  replacement, allocator callbacks, and pending-handle cleanup. The Linux pool
  probe now uses the recovered disposer for its empty task pool. Full network
  shutdown remains unfinished.
- A native Linux heap supports a single guest arena with allocation, reuse, and
  coalescing; 3,000 stress operations pass. The native XBE loader checks the exact
  SHA-256 and its mapping matches the independent Python parser. The standalone
  `halo2-engine-host --probe-pools default.xbe` initializes and exercises the
  original command-script, Havok-component, actor, and online-task pools plus actor owner storage in native C. It is a
  diagnostic bring-up executable; it does not boot the game or run original code.
- The startup callback, game-entry/main-loop path, and a 68-entry subsystem
  lifecycle table have been identified statically. These guide further recovery.
  Its 175 distinct nonzero callbacks plus two thread entries are now functions;
  two reviewed tail-call splits resolved the discovered boundary conflicts.
- There is no runnable Linux Halo 2 executable yet. No menu, level, gameplay,
  rendering, sound, input, saves, multiplayer, or full-campaign equivalence has
  been demonstrated by this project.

## Outstanding work required by the objective

1. Establish and audit a complete executable/function inventory, including
   indirect callbacks, embedded data, SDK/middleware boundaries, and failed
   decompilations. Resolve overlapping function bodies and missing call targets.
2. Recover all required engine source, structures, and calling conventions.
   Validate reconstructed behavior against original instruction execution and
   whole-game traces. Automatic C-like output is not recovered buildable source.
3. Build the Linux host runtime and connect recovered engine code to memory,
   threading/TLS, files, time, input, rendering, audio, networking, and game data.
   Replace Xbox platform dependencies while preserving game behavior.
4. Verify startup, menu navigation, map loading, playable campaign and multiplayer
   modes, audio/video/input, persistence, and representative completion paths.
   Resolve differences against the Xbox version; do not infer full correctness
   from one boot or one scene.
5. Audit the full implementation and reproducible build against the 100% objective.
   Keep discovery completeness, source recovery, behavioral verification, and
   playability distinct. The goal is unfinished until all requirements are proven.

Latest machine-readable evidence lives under `analysis/`; test reports include
the input executable, native library, recovered source, ABI, and test hashes.
The next work follows the lifecycle callbacks and shared engine allocators,
while tracing startup dependencies toward a real Linux host executable.
The first host probe exists; the remaining work is to connect actual game startup,
not to treat the probe as a playable build. Threading/TLS, graphics, sound, files,
input, map loading, networking, and the unrecovered engine remain outstanding.

Parameter runtime cleanup `00072D30` is now recovered and covered by 64 additional
original-instruction comparisons, including callback ordering and changed pending
handles. The native catalog contains 149 routines. Full parameter shutdown and
network shutdown remain unfinished.

Two asynchronous task-pool routines (`0007B650`, `0007B6C0`) are recovered in
`src/async_tasks.c`. Their 135 comparisons cover release failures, callback pool
replacement, stale handles and idle queries. The SDK service remains a controlled
boundary. These supply dependencies for the unfinished parameter shutdown path.

Parameter operation cleanup `00090C80` now composes recovered online and async
task routines and preserves three buffer releases and allocator counter updates.
Its 192 original-instruction comparisons include callback mutation and ordering.
Buffer virtual methods remain external boundaries.

Pending request removal `0006DDB0` is recovered with 84 comparisons covering
list positions, absent requests and allocator callback mutations. The catalog
now contains 149 routines; request draining still depends on session admission
and response handling.

Three session helpers now cover shutdown guarding, peer lookup, and capacity
checks. Their 1,136 new original-instruction comparisons include raw flag-byte
returns, identity matching, signed bounds and wrapping additions. Native catalog:
122 routines. The enclosing session state machine remains unfinished.

Reservation lookup, reservation-aware capacity checking and composed request
admission add three native routines and 516 original-instruction comparisons.
The current catalog contains 149 routines. Pending-request draining still needs
response handling, and gameplay is not running.

Bitstream read/write primitives `001959C0` and `00195720` are recovered with
3,036 original-instruction comparisons, including capacity exhaustion and
position aliasing. Native catalog: 127 routines. Message framing, rollback,
serialization callbacks and transmission remain dependencies of response handling.

Bitstream checkpoint rollback `00194710` is recovered and compared with original
instructions in 512 cases. The native catalog now contains 149 routines. The
message writer can now compose recovered bit writes and rollback, but its
framing/dispatch/transmission path remains unfinished.

Message header encoding/decoding and the bitstream error query add three
routines, for 149 recovered routines. All 576 added original-instruction cases
include the original CRT diagnostics and output aliasing. Message-body dispatch
and transmission remain unfinished.

Bulk bitstream transfer and join-refusal encoding/decoding add four routines
and 1,216 original-instruction comparisons. Current native catalog: 135 routines.
The response payload is recovered; message queuing and packet transmission
remain dependencies of the enclosing request-cleanup path.

Packet packing, unpacking and size accounting add three routines and 704 original
instruction comparisons. Current catalog: 138 routines. These supply packet
submission dependencies; actual Linux socket transmission and gameplay are
still unfinished.

Datagram send wrapper `000B5110` is recovered with 512 instruction comparisons.
The catalog contains 149 routines. Address conversion and 16-bit length/return
semantics are native; SDK sendto remains a controlled platform boundary.

Traffic-statistics advancement and sample-ring reset/insertion add three routines
and 528 original-instruction comparisons. Current native catalog: 142 routines.
Packet submission still requires the remaining transport/scheduling path.

Endpoint route/connection lookup and send dispatch add three routines and 640
instruction comparisons, bringing the catalog to 145. The dispatcher composes
recovered address conversion, send semantics and route failure marking. Full
packet submission and the Linux networking backend remain unfinished.

Packet submission and raw-datagram construction now compose recovered packing,
statistics, routing, conversion and send wrappers. Their 288 comparisons keep
all original engine callees intact. Native catalog: 147 routines. Actual Linux
socket transmission, message queuing and gameplay remain unfinished.

Message-writer flush now composes the complete recovered datagram path to the
SDK boundary. Its 160 comparisons include alignment, inactive state, send failure
and callback mutation. Native catalog: 148 routines. Message enqueue/body
dispatch and live Linux socket I/O remain unfinished.

Message enqueue/encoder dispatch and flush-retry logic are recovered with 144
additional comparisons. Native catalog: 149 routines. The join-refusal encoder
is integrated; other message encoders and live Linux networking remain missing.

Five session-message codecs add native session-ID encoding, leave/session-control
decoding, and host/peer handoff encoding/decoding. They cover the shared bodies
used by descriptors 11–18 and 20–21. Native catalog: 154 routines. Other codecs,
live Linux networking, and game startup remain unfinished.

Join-abort and host-decline codecs, plus the boolean bit reader used by decline
decoding, bring the native catalog to 159 routines. The decoder retains omitted
fields and the original inclusive capacity boundary for boolean reads. Other
message bodies, Linux transport and complete engine startup remain unfinished.

Election and election-refusal encoder/decoder pairs bring the native catalog to
163 routines. Election decoding preserves invalid-count consumption and rejects
out-of-count mask bits; refusal decoding validates reasons 1–10 after consuming
the optional identity block. Complete startup and gameplay remain unfinished.

Time-sync encoding, decoding and timestamp clearing, plus session identity lookup
and adjusted session time, bring the native catalog to 168 routines. SDK time is
still supplied through the clock boundary. The original decoder's early-only
overflow check is retained; full game startup and gameplay remain unfinished.

Eight connection-message codecs bring the native catalog to 176 routines:
request, refusal, establishment and closed-message encoding/decoding. Closed
reason validation and partial-write behavior match the executable. The complete
connection state machine, Linux transport, game boot and gameplay remain absent.

Ping, pong and broadcast-search codec pairs bring the native catalog to 182
routines. Decoder writes preserve padding, and pong rejects its reserved wire
value after consuming fields. Broadcast-reply session-description serialization,
live discovery, complete startup and gameplay remain unfinished.

Broadcast-reply dependencies now include compact configuration encoding/decoding
and three original text-conversion helpers. Native catalog: 187 routines. Text
conversion preserves permissive decoding and truncation behavior. The parent
session-description codecs and broadcast replies remain unfinished.

Full session-description decoding and its validator bring the native catalog to
189 routines. The decoder handles player records, text, mask-selected fields,
optional data and malformed-count rejection with original callees recovered.
The encoder and broadcast-reply wrappers are still outstanding, as are live
networking and game boot.

Session-description encoding and both broadcast-reply wrappers bring the native
catalog to 192 routines. Fixed name-buffer tails, captured/reloaded counts and
masks, player fields and optional data match original instructions. Live LAN
discovery still requires orchestration and Linux transport; game boot and
gameplay remain unfinished.

Join-request encoding/decoding brings the native catalog to 194 routines.
Variable player records, sentinel encodings, optional blocks and mode-specific
fields preserve original behavior, including the lack of a 16-player clamp.
Message serialization does not yet provide session admission or game boot.

Native codec dispatch now connects all registered encoder/decoder addresses for
message types 0–24, including clock-dependent time sync and scratch-dependent
broadcast replies. The native queue adapter uses this dispatcher. Unsupported
callbacks are reported explicitly. This is integration work; the recovered
routine catalog remains 194. Live networking and game boot remain unfinished.

Packet message reading (0007afd0) brings the native catalog to 195 routines.
It initializes the stream, rejects the debug marker, walks message markers,
checks headers, zeroes payloads and invokes decode/delivery callbacks. Native
codec dispatch is integrated in the oracle. Engine handler 000938e0 is still
a controlled dependency, and live receive I/O/game startup remain unfinished.

The ping handler (00093f60) now builds and queues a native pong response through
the recovered writer, codec dispatch, flush and datagram path. Native catalog:
196 routines. Response padding and ignored enqueue result match the original.
The general handler dispatcher and live socket I/O remain unfinished.

Discovery cache update and broadcast-reply handling bring the native catalog to
198 routines. Replies are matched to the active query before cache insertion,
refresh or replacement; description-change flags and clock behavior are retained.
Live discovery still needs orchestration and transport; game boot is unfinished.

- Discovery maintenance `000b2ea0` brings the native catalog to 199 routines.
  It queues periodic broadcast searches through the recovered writer/codec and
  expires stale cache entries. The 512 additional instruction comparisons cover
  timer boundaries/rollover, changing clock overrides and cache globals,
  captured timestamps, inactive search and preserved address padding. This
  suite uses fresh writers; flush/send behavior is tested separately. Live
  Linux networking and playable game startup remain unfinished.

Discovery start and its random-byte/identity dependencies (`000b2e30`,
`0007ad80`, `0007ad50`) bring the catalog to 202 native routines. The new
832-comparison suite covers entropy ordering, sentinel retries, callback
changes, transport gates and wrapped cache clearing, plus sixteen complete
start/query/reply/expiry sequences with the actual recovered engine callees.
CRT/SDK entropy remains a platform boundary. These are memory-level discovery
sequences; live Linux networking and playable game startup are unfinished.

Discovery cancellation and stop (`000b31b0`, `000b3670`) bring the native
catalog to 204 routines. All original online/async task cancellation callees
execute in the new 768-comparison oracle, including invalid handles, SDK
errors, poisoned deletion, callback mutation and virtual allocation release.
The allocator release and SDK task APIs remain controlled boundaries. Full
network shutdown and playable Linux startup are still unfinished.

Registration release (`000b3b10`) and endpoint route removal (`00092e00`)
bring the native catalog to 206 routines. The additional 1,152 comparisons
cover release ordering/callback mutations, ignored SDK failures, repeated
cleanup, wrapped counts/addresses, duplicate route IDs and swap-last removal.
These close two more cleanup dependencies; full network shutdown and playable
Linux startup remain unfinished.

Connection close (`00088650`) and endpoint-wide close (`00092f10`) bring the
native catalog to 208 routines. The new suite adds 768 comparisons through
actual queue/codec/route-removal callees, and the packet integration suite adds
144 connection-close cases through queue overflow, flush and datagram send.
Connection callbacks and SDK socket APIs remain controlled boundaries. The
original index advance while removing routes is preserved, including skipped
swapped entries. Full shutdown and playable Linux startup remain unfinished.

Queued storage cleanup (`00094bf0`) and connection disposal (`000886e0`)
bring the native catalog to 210 routines. The new 1,024-case oracle checks
two circular queues, virtual lookup/release ordering, reference counters,
callback mutation, and disposal through the actual close/queue/codec path.
Virtual storage-provider methods remain explicit controlled boundaries.
Complete networking shutdown and playable Linux startup remain unfinished.

Observer detach and its matching-address flush/registered-IPv4 helpers
(`000784a0`, `0007b390`, `0007aec0`) bring the catalog to 213 native routines.
The 1,056 new comparisons cover actual close/queue/codec calls, conditional
flush through datagram send, address aliases, callback mutation and flag
updates. Observer slot disposal and its complete state machine remain
unrecovered; full shutdown and playable Linux startup are unfinished.

Observer slot release (`00076ef0`) and observer disposal (`00075a40`) bring
the native catalog to 215 routines. The new 512-case oracle executes the
actual detach/connection/storage/async cleanup chain, including SDK errors,
later-slot activation, shared connections, stale task handles and pool
replacement. Queued storage is empty in this integration fixture; nonempty
queue cleanup and socket sending retain separate coverage. The observer
state machine, full networking shutdown and playable Linux startup are
still unfinished.

Observer state setting/updating and observer connection close (`00077330`,
`00076ff0`, `00078880`) bring the catalog to 218 native routines. The new
1,536-case transition suite and 256 additional cleanup-loop comparisons
cover retries, consumer notifications, sample resets, callback mutations,
clock overrides and actual connection disposal. Consumer virtual methods
and SDK operations remain controlled boundaries. Other observer transitions,
full networking shutdown and playable Linux startup remain incomplete.

Global connection-manager cleanup (`00081f80`) brings the catalog to 219
native routines. Another 256 integration comparisons execute actual observer
close/update/dispose callees and verify global resets, destructor/free call
ordering, captured wrapper pointers and preserved flag padding. Virtual
provider destruction and CRT free remain controlled boundaries. Main shutdown
still directly depends on unrecovered `0008e0f0`, `000590b0` and `0005a520`;
playable Linux startup remains unfinished.


Tracked-task scheduling (`0008e1e0`, `0008e500`, `0008e580`, `00080f70`,
`00080ff0`) brings the native catalog to 224 routines. The five routines pass
2,560 original-instruction comparisons, including actual CRC and full-table
writes. They supply dependencies of task completion and tracked-task cleanup;
those enclosing routines and playable Linux startup remain unfinished.
Validation for the 224-routine checkpoint is complete: all 98 Release/UBSan
reports pass and match the current library and recorded source hashes. The new
tracking suite passes 2,560 comparisons in each build, both native pool probes
pass, and the refreshed export has 224 annotations and zero decompiler failures.
Instruction-review notes for the next shutdown dependencies are preserved in
`analysis/tracking-shutdown-review.json`; those notes are not native recovery.


Task completion (`00081050`), resource protection/release (`002d15da`, `0013d830`,
`0012d520`) and integrated tracked-task removal (`0008e0f0`) bring the native
catalog to 229 routines. This closes another direct dependency of the main
networking shutdown routine. New suites cover 3,584 comparisons per build,
including original scheduling, CRC, online cancellation and data deletion;
SDK and object callback operations remain explicit boundaries. Main shutdown
still needs session/parameter cleanup, and Linux game startup is unfinished.
The reviewed call at `0005a43c` also exposed a missing function entry at
`00061180`. Adding that seed produced one new pseudocode export, for 11,422
exported discovered functions with zero failures and no discovery conflicts.
It is an unrecovered session transition, not an additional native routine.
Validation for the 229-routine checkpoint is complete: all 102 Release/UBSan
reports pass and match current library and recorded source hashes, and both
native pool probes pass. The new suites pass 3,584 comparisons in each build.
The refreshed mapping and all 229 ABI annotations verify successfully.


Session peer detach (`0005f970`), registration release (`0005fb60`), the join-abort
update (`000623e0`) and transition (`00061180`) bring the native catalog to 233
routines. The previously missing function `00061180` now has a native body and
instruction-reviewed ABI. Its actual peer cleanup, message encoding, queue,
flush, packet construction and socket helpers execute in 2,560 new comparisons.
SDK clock, send and registration operations remain controlled boundaries.
The enclosing session state machine, main shutdown and Linux game boot remain
unfinished.
Validation for the 233-routine checkpoint is complete: all 104 reports pass
and match current library and recorded source hashes; both native pool probes
pass. The session lifecycle suite passes 2,560 comparisons per build. Its
sanitizer run was executed explicitly after detecting the missing script entry;
that entry is now fixed and the script passes shell syntax validation. All 233
ABI annotations and the XBE mapping verify, with 11,422 exports and zero failures.


Reliable-message storage enqueue (`00095580`) brings the native catalog to 234
routines. It executes recovered header/codec/CRC code, fragments messages into
32-byte chunks, and preserves the original queue-full and allocation-retry
protocol. New comparisons include 768 cases using 24 actual recovered codecs,
384 explicit bulk-codec boundary cases, and 86 enqueue-then-clear sequences.
Virtual poll/allocation/collection methods remain controlled boundaries. The
observer send dispatcher and remaining session transitions are still missing;
this is not live reliable transport or playable game startup.
Validation for the 234-routine checkpoint is complete: all 106 Release/UBSan
reports pass and match current library and recorded source hashes. The new
queue suite passes 1,238 comparisons in each build, including 86 cleanup cycles.
Both native pool probes pass. All 234 ABI annotations and the original mapping
verify, with 11,422 pseudocode exports and zero failures.


Address validation/resolution and observer message dispatch (`0007af40`,
`0007adf0`, `0007ab10`, `0007acc0`, `000783d0`, `00075e80`) bring the
implemented total to 240. Targeted Release comparisons pass: 3,328 resolution
and datagram cases plus 512 new reliable dispatcher cases. SDK address operations
remain controlled boundaries; session transitions and playable startup remain
unfinished. Full regression and sanitizer validation for this checkpoint is pending.

Ghidra refresh for 240 routines completed successfully: 240 ABI annotations,
5,722,958 mapped bytes verified, and 11,422 exports with zero failures.
The full Release/UBSan run is in progress (`analysis/engine-validation.log`;
execution session 90222). No full-suite success is claimed until its terminal
status and report hashes are checked. Instruction review for the next session
send/broadcast and transition routines is recorded in
`analysis/tracking-shutdown-review.json` and `analysis/review-*.asm`.


Validation for the 240-routine checkpoint completed (execution session 90222,
exit 0). All 108 Release/UBSan reports pass and match current library, host
where recorded, and source hashes. Both native pool probes pass. The 240 unique
ABI records match 240 annotations; mapping verification and all 11,422 exports
pass with zero failures. The six-routine batch adds 3,840 comparisons per build.

Five further session routines have a preview implementation in
`src/network_session_send.c`: peer send, broadcast, leave update, begin leave,
and begin disband. They are deliberately not in the production build/catalog
count yet. The separate preview library passes 1,280 original-instruction
comparisons, including actual reliable enqueue/CRC/fragmentation (287 allocations),
datagram flush/send (596 SDK calls), and 1,001 clock calls. Message, dispatcher,
and reliable scratch are compared; callbacks mutate session count, peer index,
identity and timeout. Report: `analysis/network-session-send-preview.json`.
Next: integrate these five into CMake/ABI and both validation configurations,
expand edge coverage as needed, and continue forced session cleanup.


The five session send/leave/disband routines are now integrated into the main
CMake build, ABI catalog and both validation configurations, bringing the
implemented total to 245. Full checkpoint validation is pending. The preview
report remains historical evidence; current results use
`analysis/network-session-send-tests*.json` and the main engine library.

The integrated five-routine suite passes 1,280 comparisons against the main
Release library. Ghidra annotation refresh finished with 245 annotations,
verified mapping, 11,422 exports and zero failures. Full validation is running
in execution session 21406 (`analysis/engine-validation.log`); its terminal
status and 110 expected report hashes still need auditing. Instruction review
now covers the complete recursive shutdown/cleanup/handoff cluster at
`0005a400`, `0005a520`, and `000614a0`, including exact virtual callback ABI,
post-callback field reloads, byte flags and 32-bit shift behavior.


The recursive shutdown request, final session cleanup and handoff initialization
(`0005a400`, `0005a520`, `000614a0`) now have a preview implementation in
`src/network_session_control.c`, outside the production build/catalog pending
integration. All 1,536 comparisons pass (512 per routine), executing actual
join-abort, leave, disband, reliable queue, datagram send, registration release
and peer cleanup. Observed boundaries include 320 sends, 118 fragment
allocations, 418 virtual cleanup calls, 325 registration/key release pairs, and
690 clock calls. Local scratch and full persistent memory/callback snapshots
are compared. States 0..10 and low-byte force/flag values are covered; invalid
jump-table targets are not modeled as successful returns. Report:
`analysis/network-session-control-preview.json`.
The 245-routine validation process (session 21406) remains live in its sanitizer
phase; do not restart it merely because this progress entry precedes completion.

The recursive session control preview now also passes all 1,536 comparisons
under UBSan. Both preview reports match their corresponding preview library,
engine dependency library and recorded source hashes. Additional instruction
review records the captured session pointer and post-cancellation async-handle
reload in `0006f0f0`, plus `000630f0` admission/refusal arguments. The zero-reason
admission path still requires `0005c720`; it must not be replaced by unconditional
refusal to shortcut final shutdown recovery.


The 245-routine checkpoint is fully validated: execution session 21406 exited 0;
all 110 Release/UBSan reports pass and match current library, host where recorded,
and source hashes. Both native pool probes pass. All 245 unique ABI records match
245 annotations; mapping verifies and all 11,422 pseudocode exports succeed.
The session send suite passes 1,280 comparisons per build. The next three control
routines remain separate previews with 1,536 passing comparisons per build;
production integration and their ABI registration are the next steps.


The three recursive control routines are integrated into production CMake, the
ABI catalog, and both validation configurations, bringing the implemented total
to 248. Their preview reports remain historical; current comparisons use
`analysis/network-session-control-tests*.json`. Full checkpoint validation is
pending. Remaining network shutdown dependencies include parameter cleanup
`000590b0`, task cancellation `0006f0f0`, and request draining/admission.

The integrated control suite passes 1,536 comparisons against the main Release
library. Ghidra accepted all 248 annotations; mapping verification passes and
11,422 pseudocode exports succeed with zero failures. Full validation is live
in execution session 3927 (`analysis/engine-validation.log`); after terminal
completion, audit all 112 expected Release/UBSan reports and current hashes.
Next implementation target: `0006f0f0`, retaining the captured session pointer
across online cancellation and reloading the async handle afterward, with actual
recovered cancellation and session-control calls.


Task cancellation `0006f0f0` now has a preview implementation in
`src/network_session_tasks.c`. All 512 Release comparisons pass through actual
online/async cancellation, pool deletion and recursive session shutdown. SDK
callbacks replace provider/session pointers and mutate the async handle,
checking captured-session and reloaded-handle behavior. Coverage includes task
kinds 0/2/3/33 (33 prepare calls, 66 continue calls, 165 close calls), 220 async
releases, 119 sends and 74 final cleanup callbacks. Full memory, callback snapshots
and inherited session scratch checks pass. The preview is not yet counted in
production totals; UBSan and integration remain. Report:
`analysis/network-session-tasks-preview.json`. Full 248-routine validation
continues in execution session 3927; do not restart the live process.


Task cancellation preview now passes 512 comparisons under UBSan as well as
Release. Three further admission helpers (`0005f6f0`, `0005f890`, `00062eb0`)
are implemented in `src/network_session_identity.c`: six-byte machine lookup,
twelve-byte player lookup and queued identity insertion. All 1,536 comparisons
pass in both builds, including 241 SDK clock callbacks, first-match behavior,
signed counts, masks, full queues and overlapping inputs. All four preview
reports match their preview/engine binaries and source hashes. These four
routines remain outside production CMake/ABI pending integration (current main
count still248). Expected next integrated count252. Full 248-routine validation
continues in session 3927; audit its112 reports after terminal completion.


The 248-routine checkpoint is fully validated. Execution session 3927 exited 0;
all 112 Release/UBSan reports pass and match current library, host where recorded,
and source hashes. Both native pool probes pass. The 248 unique ABI records
match 248 annotations; mapping passes and all 11,422 exports succeed. The control
suite passes 1,536 comparisons per build. Four further preview routines have
already passed 2,048 comparisons per build and can now be integrated.


Task cancellation and three identity helpers are integrated into production
CMake, the ABI catalog and both test configurations. The implemented count is
252. Preview reports remain historical; current results use the main library
and `network-session-tasks-tests*.json`/`network-session-identity-tests*.json`.
Full checkpoint validation is pending.

Integrated task-cancellation and identity suites pass 2,048 comparisons against
the main Release library. Ghidra refresh completed with 252 annotations, verified
mapping and 11,422 successful exports. Full 252-routine validation is running in
execution session 67990 (`analysis/engine-validation.log`); audit 116 expected
reports and current hashes after it exits. Next admission dependencies include
`00075e40` (close an established observer connection), peer attach/remove,
observer admission and the remaining reservation/membership helpers.


Three further admission dependencies have preview implementations: observer
established-connection close (`00075e40`, 512 comparisons), peer attachment and
membership insertion (`0005f900`, `0005fbd0`, 1,024 comparisons). All Release
comparisons pass, including actual close/queue/route/codec callees and original
CRT wide-string instructions, signed states, callback mutation, byte flags,
wrapping counters and aliasing inputs. The 252-routine production run remains
live in session 67990; preview sanitizer checks and integration are pending.
Preview reports: `network-observer-admission-preview.json` and
`network-session-membership-preview.json`. Current production count remains 252;
these three would bring the integrated count to 255.


Observer close and the two membership-add previews now pass their combined
1,536 comparisons under UBSan as well as Release. Three removal helpers are
also implemented in `src/network_session_removal.c`: flag refresh `0005a2e0`,
player removal `00060200`, and peer removal `0005fe20`. Their 1,536 comparisons
pass in both builds, executing 1,403 player-removal calls, 561 reservation
lookups, 512 detaches and 818 original CRT memmoves per run. Checks include
reused argument scratch, masks, duplicate reservations, revision/count wrapping,
index shifts and last-peer removal. All six preview reports match their source,
preview-library and engine-dependency hashes. Current production count is 252;
these six routines would bring the integrated count to 258. Production validation
continues in session 67990 until its terminal status is confirmed.


The 252-routine checkpoint is fully validated: execution session 67990 exited 0;
all 116 Release/UBSan reports pass and match current library, host where recorded,
and source hashes. Both native pool probes pass. All 252 unique ABI records
match 252 annotations; mapping verifies and all 11,422 exports succeed. Six
preview routines have already passed 3,072 comparisons per build; their
production integration is next, before further observer admission recovery.


The six observer-close/membership routines are integrated into production CMake,
the ABI catalog and both test configurations, bringing the implemented count
to 258. The three suites add 3,072 comparisons per build. Preview reports remain
historical; current reports use `network-observer-admission-tests*.json`,
`network-session-membership-tests*.json` and `network-session-removal-tests*.json`.
Full checkpoint validation is pending.

The integrated six-routine batch passes all 3,072 focused Release comparisons.
Ghidra refresh completed with 258 annotations, verified mapping and 11,422
exports with zero failures. Full 258-routine validation is running in execution
session 85012 (`analysis/engine-validation.log`); audit 122 expected reports and
current hashes after terminal completion. Next observer transition dependencies
are recorded at `00076f50`/`000776a0` in the instruction-review ledger; query
`00078580` is the next direct missing helper.


Address SDK-status query `0007acf0`, observer query `00078580`, and observer
address-state refresh `00076f50` now have preview implementations in
`src/network_observer_query.c`. All 1,536 Release comparisons pass. The fixture
explicitly exercises state 3 with every SDK result class after a coverage audit
found correlated fields had skipped some query branches. Tests cover null and
wrapped addresses, widths, signed states, retry-word wrap, callback mutation and
query/detach scratch. Connections are state 2 and writers inactive in this suite;
actual close/flush behavior has separate coverage. Preview UBSan and integration
remain pending (production count 258, prospective count 261). Full validation is
still live in session 85012.


The three observer-query previews pass all 1,536 comparisons under UBSan as
well as Release. Three more retry dependencies are now implemented in
`src/network_observer_retry.c`: elapsed time `00075890`, connection send
capacity `00089070`, and retry eligibility `00077580`. Their 1,536 comparisons
pass in both builds, including 808 clock calls and 10 actual connection-close
calls, signed/wrapping capacity and timeout arithmetic, callback-modified timers
and clock overrides, close scratch and full memory. All four preview reports
match their source and library hashes. Six previews are pending integration:
current production count 258, prospective count 264. Production validation
session 85012 remains live until its terminal result is confirmed.


The 258-routine checkpoint is fully validated: execution session 85012 exited 0;
all 122 Release/UBSan reports pass and match current library, host where recorded,
and source hashes. Both native pool probes pass. All 258 unique ABI records
match 258 annotations; mapping verifies and all 11,422 exports succeed. Six
query/retry previews have passed 3,072 comparisons per build and are ready for
production integration before further observer admission recovery.


The six observer-query/retry routines are integrated into production CMake, the
ABI catalog and both validation configurations, bringing the implemented total
to 264. Their two suites add 3,072 comparisons per build. Preview reports remain
historical; current reports use `network-observer-query-tests*.json` and
`network-observer-retry-tests*.json`. Full checkpoint validation is pending.

The integrated query/retry suites pass all 3,072 focused Release comparisons.
Ghidra refresh completed with 264 annotations, verified mapping and 11,422
successful exports. Full 264-routine validation is live in execution session
35261 (`analysis/engine-validation.log`); audit 126 expected reports and current
hashes after terminal completion. Full instruction review of address selection
`00078330` confirms all direct dependencies are now native. Connection opening
`00088220` still requires route insertion and connection/stream setup helpers;
its exact ABI and sequencing are recorded in the review ledger.


Connection timer reset `00088d20` and stream initialization `00095cf0` now
have preview implementations in `src/network_connection_setup.c`. All 1,024
original-instruction comparisons pass in both Release and UBSan, including
1,362 clock callbacks and 172 callback-triggered override changes per build.
Tests compare full guest memory and callback snapshots, sequence multiplication
wrap and untouched stream fields. They remain outside production (264 routines)
while the current full pipeline runs. Observer address selection `00078330`
also has a compiled preview, with oracle validation pending. Connection opening
next requires route insertion `00092d10` and handshake retry `000890b0`.
Full validation was confirmed live as PID 3004601, running UBSan suites;
no replacement pipeline was started. Preview reports are
`analysis/network-connection-setup-preview{,-ubsan}.json`.


Route insertion `00092d10` now has a tested preview in
`src/network_route_insert.c`. All 1,024 original-instruction comparisons pass
in Release and UBSan; reports and current source/library hashes were audited.
Each build executes 136 actual connection disposals and 40 close callbacks.
The fixture covers route capacity, address-kind filters, equal sequence and
same-index decisions, plus callback-mutated counts and addresses. Allocated
storage and send paths remain outside this fixture (covered in dependencies).
Production remains 264 routines. Handshake retry `000890b0` was fully reviewed
and is the remaining direct unrecovered callee of connection open `00088220`.


The 264-routine checkpoint is fully validated: execution session 35261 exited0;
all 126 Release/UBSan reports pass and match current library, host where
recorded, and source hashes. Both native pool probes pass. The 264 unique ABI
records match 264 annotations; mapping verifies and all 11,422 exports succeed.
Three connection setup/route previews have passed 2,048 comparisons per build
and await integration. Address-selection preview remains unvalidated.


Handshake `000890b0` passed 1,024 comparisons in Release and UBSan, including
256 actual connection-request enqueues, 371 closes and 902 clock callbacks
per build. Four tested setup/route/handshake routines are now integrated into
CMake, ABI catalogs and both validation configurations (268 native routines).
The three suites add 3,072 comparisons per build; expected full report count132.
The last fully audited checkpoint remains264. All direct dependencies of
connection open `00088220` are now recovered; its implementation is next.
Historical preview reports predate test-default changes; current production
reports use `network-{connection-setup,route-insert,handshake}-tests*.json`.


The integrated four-routine batch passes all 3,072 focused Release comparisons.
Ghidra refresh exited0 with268 annotations, verified mapping and11,422 exports
with zero failures. Full268 validation is running in execution session34210
(`analysis/engine-validation.log`); expected132 reports, audit after completion.
Connection open `00088220` has a compiled preview in
`src/network_connection_open.c`, using actual route insertion, handshake, timer
reset, stream reset and storage clear. Combined oracle validation is pending;
it is not in the production count. Observer selection preview also remains
unvalidated. No boot/menu/gameplay has been demonstrated.


Connection open `00088220` now passes1,024 integrated original-instruction
comparisons in both Release and UBSan. Actual callees include route insertion,
224 disposals,742 closes,227 request enqueues,533 stream resets,609 storage
clears and760 virtual lookup/release pairs per build. Tests compare full memory,
message/close/storage scratch, callback snapshots and mutable config/clock/
active/capacity/storage-index behavior. Fresh writers avoid flush/send.
Preview source/library hashes were audited; production remains268.
The UBSan preview compiles the four newly integrated setup/route/handshake
routines directly alongside connection open, linked to the previous UBSan
engine while full268 validation runs. Session34210 was polled live; do not
restart it. Next: validate observer selection78330, then observer tick776a0.


Observer address selection `00078330` now passes2,048 comparisons in Release
and UBSan with current source/library hashes verified. The oracle explicitly
requires successful selection of each of four consumers and exercises SDK
query/resolution/preparation failures, inactive/attempted consumer masks, mask
and identity mutations, reused scratch, full memory and AL. Actual query,
detach and resolution run; connections state2 and inactive writer avoid close/
flush in this fixture. Production stays268 while validation34210 runs.
Connection open and address selection are tested previews pending integration.
Full observer tick `000776a0` instruction span was re-exported through ret4
(0x291 bytes); next implement its recursive state transitions using these
recovered callees and consumer virtual callback boundaries.


The268-routine checkpoint is fully validated: execution session34210 exited0.
All132 Release/UBSan reports pass and match current library, host where
recorded, and source hashes. Both native pool probes pass;268 unique ABI
records match annotations; mapping and11,422 exports succeed.


Observer tick776a0 and request-connection76a40 have compiled previews in
`src/network_observer_tick.c` using a shared context of recovered callees and
consumer virtual methods.2,048 partial integration comparisons pass Release
and UBSan, including explicit recursive-call coverage, signed retry bounds,
consumer mask mutation and wrapper refresh/update-slot. A reused detach-mark
tracking bug in the test harness was corrected before these passing results.
All preview hashes were verified. The fixture delays states5/9 connection
opening and uses fixed clock override; those combined paths still require
coverage before integration. Production remains268. Connection open and
address selection have separate tested previews; next extend this oracle to
actual open/handshake/stream/storage paths and mutable clock callbacks.


Expanded observer tick/wrapper passes2,048 comparisons in both builds, with
99 actual connection opens (explicit state5/state9 coverage),99 handshake
enqueues,99 stream/storage resets and58 recursive ticks. Clock callbacks
mutate config/flags/override. Four previews are now integrated into CMake and
ABI catalogs: connection open, address selection, observer tick and request
connection. Production272; last audited268. Three suites add5,120 comparisons
per build; expected138 full reports. Preview reports are historical after
test-default changes. Full272 validation pending.


All5,120 focused comparisons pass against the integrated272-routine Release
library. Ghidra refresh session13390 exited0 with272 annotations, verified
mapping and11,422 exports with zero failures. Full validation runs in session
85607 (`analysis/engine-validation.log`); expected138 reports after completion.
Next missing admission path is76aa0, used by session admission5c720. Initial
pseudocode inspection identifies allocator82060 and initialization88110, plus
formatting11c9c0/11c9e0 as unrecovered dependencies; instruction review required
before assigning exact ABI or implementing. No playable boot yet.


Four connection-allocation dependencies have tested previews: stream820f0 and
storage82150 in `network_slot_alloc.c`; initialization88110 and allocation
82060 in `network_connection_allocate.c`. Two suites total3,072 comparisons
per Release/UBSan with current hashes audited. Actual reset/clear/dispose
callees run. Tests cover signed-count/disabled/full pools, first free slots,
flag combinations, failure rollback and mutable clock flags/count/base/enable.
An initially correlated override fixture skipped initialization clock calls;
fixed before accepting. Corrected suite executes127 clocks and595 disposals.
Incoming indices10/14=-1; selected storage inactive, so no queued releases.
UBSan suites were rerun after the full pipeline rebuilt its engine to272,
and dependency hashes now match. Production stays272; full85607 remains live.
Formatting helpers11c9c0/11c9e0 instruction-reviewed (CRT321980 varargs boundary);
next implement them and admission76aa0. Previews remain outside CMake/catalog.


Formatting wrappers11c9c0/11c9e0 in `text_format.c` pass1,024 comparisons
per Release/UBSan. Tests compare argument bytes, append scan, wraparound
capacity, callback writes/returns, forced termination and full memory.
CRT321980 is an explicit guest-varargs runtime boundary; format specifier
interpretation is not implemented by these wrappers. Test models cdecl caller
cleanup at wrapper return to match the shared harness stack contract.
Observer admission76aa0 is now instruction-reviewed and compiled as preview
`network_observer_admit.c`; no oracle validation yet, not counted as recovered
production. Uses actual release/allocate/sample/detach callees; floating window
initialization uses original SSE single-precision conversions/divisions.
Next build admission oracle including formatter output, new/matching/reclaimed
slots, callback mutations, allocation failure and float edge values.
Production remains272; full validation85607 was confirmed live this turn.


Full272 validation session85607 exited0. All138 reports pass and match current
source/library/host hashes; two probes,272 ABI records/annotations, mapping
and11,422 exports pass. This is now the latest audited native checkpoint.


User explicitly authorized using Xita. Located main checkout at
`/home/birchwoodgod/github/xboxvita` (older dirty tree) and newer Halo2 worktree
`/home/birchwoodgod/xita-backups/2026-09-24-halo2-vita3k/source` at
5eb63f5b1304aa6b67f6150ff46850d5bced9d77. Its retained x86 host harness and
app0-h2v1r artifacts exist; owned XBE hash matches this project exactly.
Xita is GPLv3; no source copied into engine so far. Added reproducible runner
`scripts/run-xita-reference.sh` (isolated save copies) and hashed provenance
`analysis/xita-reference.json`. This runs Xita separately, not libhalo2_engine.
Fresh120-second headless run decomp-baseline-01 launched via original runner
in session98683. Driver traversed title/profile/main menu/lobby; map file
cyclotron.map opened; LEVEL/in-match heuristic reached67s. Terminal result
still pending at this note. GXM host backend is explicitly null, so this
is neither visible playable Linux rendering nor full engine decompilation.
Priority should now use this proven whole-game startup reference: inspect
Xita kernel/file/thread/input and dispatch bridges, compare recovered engine
routines against full-game traces, and develop a visible Linux runtime.
Continue exact engine recovery without substituting a headless harness for
the requested playable and fully recovered final result. Preserve Xita trees.

Xita baseline session98683 completed: runner exited0; harness stopped at the
intentional120-second timeout. Match heuristic and map-open evidence verified;
full logs hashed in `analysis/xita-host-baseline-result.json`. Final status 4740 119.8; 0 blocked/strict/fatal/abort/exception diagnostic matches.

Xita software scanout test software-scanout-01 completed its intentional90-second
timeout. XV_MENU_GXM=0 bypasses the null GPU draw backend. Captures120–480
were black, but frame600 visibly shows the Halo2 title scene and PRESS START
TO CONTINUE. CPU rendering and scanout therefore produce real Linux pixels.
Saved viewable capture analysis/xita-software-latest.png and hashed measurements
in analysis/xita-software-scanout-result.json. Last60-frame interval was1.95fps.
No interactive window or gameplay verified; still separate from recovered engine.
Runner now honors H2_DRIVE and forwards runtime knob arguments after the tag.
The existing automated driver requires menu-gxm ready, so software test disabled
it; a software-aware readiness condition is needed before using that driver.
Next runtime milestone: attach Linux display/input, then verify menu interaction
and in-match rendering. Preserve exact native engine recovery alongside this.

Added runtime/xita-linux/display.c: SDL2 frame presentation on a dedicated thread,
mutex-protected copied scanout, focus-scoped keyboard controller overlay, window
close handling, and retained original host instrumentation/scripted input. GPLv3
license included. scripts/build-xita-linux.py derives exact original object list
and wrap flags from Xita dry-run, links preserved objects with local adapter, and
records object/binary/source SHA256 provenance. Original Xita remains untouched.
scripts/run-xita-linux.sh launches software renderer with isolated saves; base
runner now accepts H2_HOST_BIN override.
Validation: warning-clean compilation/link, Python/shell syntax checks, 100-second
runtime linux-display-01 with SDL dummy driver. Terminal intentional timeout124,
715 flips, frame600 visibly shows title scene, SDL upload diagnostics through600;
last60-frame sample1.96fps. Evidence analysis/xita-linux-display-result.json.
Dummy backend verifies SDL initialization and texture-upload path only, not a
visible desktop window or keyboard interaction. Game capture is upstream of SDL
presentation. Those checks and in-match software rendering remain next work.
Full native decompilation still272 integrated routines; reference frontend remains
separate from libhalo2_engine. Previous goal turn was progress (software title
render evidence); this turn adds and executes the Linux frontend.

Real X11 presentation verified in180-second linux-window-01 run on display:1
with explicit XAUTHORITY=/run/user/1000/lyxauth (environment default:0 was stale).
SDL reports x11 backend, final857flips, title interval1.95fps. Captured only
the game window88080440 using ImageMagick import; image
analysis/xita-linux-x11-window.png visibly shows centered title scene and prompt.
Keyboard injection was refused by test guard because game window did not retain
focus; no keyboard/game interaction verified. Window focus restoration attempted
only if still owned by game; actual focus remained the prior window throughout.
Temporary SDL readback diagnostic cropped its viewport and was removed; actual
X11 screenshot confirms window output is correct. Input transition logs retained.
Warning-clean rebuild and hashed provenance complete. Test binary provenance is
retained separately in analysis/xita-linux-window-tested-provenance.json; result
analysis/xita-linux-window-result.json describes post-test diagnostic removal.
Software renderer already uses3workers+caller. Profile late in run: ~1s texture
acquire,~14s transform,~102s raster accumulated; every20draws also writes a full
backbuffer diagnostic file unconditionally. Next: local renderer override to gate
those diagnostic writes and measure, then software-aware menu/input progression.
No changes to original Xita tree, no new native integrated routines this turn.
Previous goal turn: progress (SDL adapter implementation and executed dummy test).

Local build now compiles a copied Xita menu_render.c with repeated framebuffer
dumps controlled by XV_LINUX_DUMP_EVERY(default0,reference20), retaining source
hashes and failing if exact patch site differs. Original tree/objects unchanged.
160-second linux-menu-input-01 completed timeout124,832flips,zero repeated dumps.
Frame540-60024.00s versus reference24.13s: no material speedup established.
Scripted Start at650held15flips visibly reaches CHOOSE PROFILE at660and720.
Prompt PRESS START remains behind profile UI; rendering fidelity is not complete.
Evidence analysis/xita-linux-menu-input-result.json and xita-linux-profile.png.
Added GPL-attributed software-aware scripts/xita-menu-driver.py adapted from
Xita. Readiness uses software profile or GXMready; frame delays60,holds10;
preserves map/clear heuristic and logs. Cleans held input on exit/SIGTERM.
H2_DRIVE=1 enables it via Linux launcher. Syntax/build checks passed.
Long run linux-software-match-01 launched600seconds, session40652; confirmed
live at launch. Output analysis/xita-linux-software-match.log, saves/captures
analysis/xita-host/runs/linux-software-match-01. Do not restart until terminal.
Next continuation: poll40652, inspect driver/captures, verify actual rendered
lobby/match rather than relying on LEVELheuristic. Native routine count272.
Prior turn classified progress(real X11window verified). Temporary /tmp full
prevented one shell heredoc; workspace volume has869GBfree. Switched file writes
to direct patch/Python-c; did not delete any unrelated temporary files.

Menu-to-match run40652 remains live; driver pressed Start620,profile690,
mainmenu760,lobbyprofile830,STARTGAME900. Frame1020 visibly shows pregame lobby
waiting for map, Slayer on Ivory Tower. Current status1430at203.6s; map-open
not yet logged. Preserve this session and poll; no restart.
Investigated renderer hot path. Added tests/xita_raster_build_probe.c generating
512finite randomized cases/4096triangles, complete color+depth+zpass output.
Strict O3 unity compilation of unchanged menu_combiner.c+menu_raster.c matches
reference separate-O2 byte-for-byte(37,752,832bytes). CPU1.215s vs0.767s in this
probe; existing Xita raster assertions also pass with O3 unity. No fast-math.
Analysis xita-raster-unity-probe.json. This is not a full-game speed claim.
Build script now supports XITA_BUILD_OUT and opt-in XITA_UNITY_RASTER=1;
candidate built build/xita-linux-unity/harness with source/object provenance.
Default baseline unchanged. Candidate must receive title/menu/match runtime
verification before becoming default. Avoid overlapping benchmarks with active
software-match run to preserve meaningful timing.
Previous goal turn was progress(controller-driven Choose Profile verified).

Software match run40652 passed LEVELheuristic at289s/flip1980, and the actual
capture confirms first-person Ivory Tower geometry, weapon, ammo and Slayer
timer. This goes beyond the old headless heuristic. Live scripted rleft2100–2160
visibly changes camera view; righttrigger2160–2190 was sent but firing is not
visually verified. Events analysis/xita-software-input-events.json. Captures
xita-software-level-1980.png,xita-software-camera.png,xita-software-fire.png.
Serious fidelity defects: overbright surfaces and large polygons obscure rotated
view, weapon/HUD visibility errors. Not yet playable or faithful. Interim result
analysis/xita-software-match-interim.json; run600s still active, session40652.
Do not restart; poll to terminal then collect fullresult. Unity candidate is
already built but has not run in-game; perform sequential timing after baseline.
Source inspection: software transform_out retains only2texture coordinates and
does no clipping in one_tri; sample_tex supports only2D whereas texture cache/GXM
supports cube faces. These are concrete missing capabilities, not proven causes
of each screenshot defect. Do not patch by guessing shader/viewport semantics.
Audio mixer is producing nonzero grains in match, but host outputs are paced
and discarded. SDL audio output remains future work; do not claim sound support.
Previous goal turn: progress(probe and candidate build). This turn: rendered
match and camera response verified, graphics defects recorded. Native272unchanged.

Baseline40652 terminal: completed intentional600-second timeout,2901flips,
last60interval2.85fps. Full result analysis/xita-software-match-result.json with
log hashes, performance windows, screenshot references and fidelity limitations.
Read shader_recomp_gen.py: GXM strips Xbox viewport epilogue and uses hardware
clip-space division/clipping; software transform_out+one_tri has no triangle
clip stage. Added optional XV_LINUX_VERTEX_AUDIT observation hook (defaultoff)
in local copied renderer: counts all/nonpositive or crossing w, out-of-rangez,
nonfinite positions, logs first8suspect triples. No geometry changes.
Build hashes audit header. Linux launcher now honors explicit H2_HOST_BIN.
Candidate unity+audit built in build/xita-linux-unity/harness; syntax checks pass.
Sequential candidate600s run linux-unity-match-01 launched session95264 after
baseline terminal. Output analysis/xita-linux-unity-match.log, run files
analysis/xita-host/runs/linux-unity-match-01. Poll95264; do not restart.
Next: compare title and match performance, view candidate frames, inspect
[linux/vertex] stats/samples to constrain clipping diagnosis. Audit observations
are not yet proof of artifact cause. Default baseline binary remains unchanged.
Previous goal turn progress(actual rendered match/camera verified); this turn
progress(diagnostic implemented, baseline finalized, candidate launched).

Unity run95264 remains live;1930flips234.2s; map opened, awaiting next
in-match window. Title540–600 interval19.08s(3.15fps)vsbaseline24.00s(2.50fps);
600–66025.75s(2.33fps)vs29.34s(2.05fps). Probe37%CPUgain not full-game gain.
Vertex audit at16.55mtriangles:1,450,001allwnonpositive,218,301crossing,
27,232nearz,1,679,814farz,0nonfinite. Firstsamples include mixedw +/-100k;
software is actually feeding behind-camera triangles to rasterizer.
Added experimental runtime/xita-linux/clip.c: reconstruct homogeneous window
coords, Sutherland-Hodgman clip positivew/targetbounds/near/far, interpolate
attributes before projection, fan triangulate. Fullyinside bypass unchanged.
Explicit positivew guard1e-6 and assumed depth0..1 remain hardware-unverified.
tests/xita_clip_test.c passes analytic unequal-w attribute/near intersection,
fullyinside byteidentity,rejection,mixedw,nonfinite,4096random bounded-output
cases under ASan+UBSan. analysis/xita-clip-probe.json records coverage/limits.
Build supports opt-in XITA_CLIP=1; separate unity+clip candidate built at
build/xita-linux-clip/harness with hashes. Not run yet, not default, no visual
improvement claim. Nextpoll95264 throughterminal, collectunityvisual/perf,
then sequentialclipruntime with same menus and camerainput. No concurrent runs.
Prior goal turn progress(baselinefinalized,diagnostic+candidate launched).

User reaffirmed Xita is to help engine decompilation. Returned priority to native
engine recovery; no additional renderer run launched. Existing95264 retained.
Integrated4previouslypreviewed routines820f0/82150/88110/82060 into CMake and
ABIcatalog, native count276. Reviewed actual Xita translations in code_017.c
andcode_018.c; hashed function references and key findings in
analysis/xita-engine-allocation-reference.json. OriginalXBE remains testoracle.
Fresh Release native shared-library tests pass1,024slot+2,048connection cases.
Updated two suites to normal engine/report defaults and full Release/UBSan
pipeline. Text-format wrappers and observer admission remain previews.
Annotation refresh session69465 running, loganalysis/abi-refresh.log; after it
finishes start fullscripts/test-engine.sh and audit142expectedfreshreports.
README/ENGINE record276integrated, broader regression not yet audited.
Previous latest user-reassurance turn was status-only; this goal turn makes
concrete engine integration and fresh instruction-level validation progress.

Annotation session69465 completed0:276annotations,11,422exports,0failed,
mapping verifier passed. Full engine validation launched session21444 with
analysis/engine-validation.log; poll same handle to terminal and audit hashes.
Xita unity session95264 still live at2850flips462.6s; leave it to finish and
archive result, but primary next work remains native engine recovery/admission.
Do not launch clipping runtime while the user's engine priority is active.

Engine admission76aa0 preview now has tests/network_observer_admit_oracle.py.
Fresh1,024original-instruction comparisons pass with fullguestmemory/returns,
callback snapshots, CRT boundaryvarargs and actual recovered allocation/reset/
detach/dispose/task-release callees. Coverage:259existingidentity,255free,
255reclaim,255full;136free successes170reclaim successes,170ownedconnection
reclaims,204SDKtask releases with actual pool deletion,187consumer notifications,
850clock calls. Clock changes identity/config and flags; signed interval includes
zero,negative andINTlimits; 2 SSE floatwindows comparebyteexactly.
Crt321980 remainscontrolledformatter, SDKtask release controlled; scratchprivate
to originalstack/nativecontext is restored in nativeheap aftercall. No registered
address/close-packet cases yet; reclaimconnectionstate1 andstorageinactive.
Built preview with onlyadmit+textformat linked to fresh276engine. Original Xita
f_00076AA0 call/SSE sequence reviewed; hashedsource reference in
analysis/xita-engine-admission-reference.json. Admission NOT integrated, count276.
Next: UBSanpreview against fresh276UBSanlibrary once enginepipeline reaches it;
then integrate admission plus its two already-tested formattingwrapper dependencies
only after required validation. Do not modify mainlibrary during fullregression.
Fullvalidation21444 stilllive, at routeinsert/handshake area ofRelease whenpolled.
Xitaunity95264 terminal0(wrapper),intentional600s timeout,3392flips; archived
analysis/xita-unity-match-result.json. No clippingruntime launched perenginefocus.
Previous goalturn progress(fourroutinesintegrated); thisturn progress(admission
oracle and1024passingcomparisons). Nativecount remains276pendingfullaudit.

Extended admission oracle to registered/unregistered IPv4 cleanup at fresh/reclaim
slots. Real detach, address conversion and inactive-writer flush gating execute;
SDK address release3cd344 is controlled, returns0/error and mutatesidentity.
Fresh1,024Release+1,024UBSan comparisons both pass. UBSanpreview compiled only
admit+textformat against the newlybuilt276UBSanengine. Source and engine hashes
audited in analysis/network-observer-admit-preview-audit.json. Header/context
and dependent source/test hashes added to report provenance.
Full276validation21444 stilllive inUBSan section; do not rebuild mainlibrary or
restart it. Nativecount276. Admission andtwoformatwrappers readyforintegration
review afterfullpipeline completes/audit142reports. Those3wouldyield279native;
newformat+admissionsuites yield146reports, providedallrequiredchecks pass.
Still no admission close-packet/activewriter coverage; dependency suites cover
close/send separately. Preserve these limits. All Xita processes terminal; no
rendererwork running. Priorityremainsengine peruser. This goalturnprogress:
additionaladmissionboundarycoverage andfreshsanitizer/hashvalidation.

Recovered observer timeout773a0 into src/network_observer_timeout.c and header,
outsideCMake/catalog. Reviewed original asm analysis/review-000773a0.asm and
Xita f_000773A0 code_015.c; referencehash in xita-engine-timeout-reference.json.
Preserves initialconnection/starttime capture, signed elapsed/count comparisons,
state/config reloads aroundclock callbacks, actualreason16close, idle refresh.
Fresh2,048Release+2,048UBSan originalinstruction comparisons pass. Tests execute
actualelapsed, close, closepacketqueue/nativecodec androuteremoval; clocks mutate
state/config/override, closecallbackoverwritesstate thenfinalstate2wins. Local
close scratch compared againstoriginalstack before restoring disjointnativeheap.
Freshwriter preventsnetworkflush; no liveI/O claim. Source/libraryhashaudit in
analysis/network-observer-timeout-preview-audit.json. Notintegrated,count276.
Full276pipeline21444 remainslive inUBSan. Afterterminal audit142freshreports,
then integrate4readyroutines (admission1,formatwrappers2,timeout1) for280;
3newsuites wouldyield148reports. Do notchangeintegratedlibrary duringcurrentrun.
Previousgoalturnprogress(admissionboundary+UBSan). Thisturnprogress(newengine
timeoutrecovery and4,096passingcomparisons). No renderer jobs running.

Full276validation21444 completedexit0. Audited142passing reports againstcurrent
Release/UBSan libraries, host binaries, XBE andallsourcehashes;276uniqueABIentries,
276annotations andmapping pass. Saved analysis/engine-checkpoint-276.json.
Integrated four validated routines:76aa0admission,773a0timeout,11c9c0/11c9e0
formatwrappers into CMake/catalog;nativecount280. Three testdefaults nowmainengine,
addedRelease+UBSan invocationstomainpipeline. FreshintegratedRelease4096comparisons
passed. Ghidraannotator nowallowscalling_convention/variadic metadata;format
wrappers correctlydeclarecdecl,varargs withcustomregisterstorage andret0.
Annotation session45089 running; loganalysis/abi-refresh.log. Afterterminal
verify280annotations thenstartfulltest-engine.sh; expected148freshreports.
No graphicswork resumed. Previousgoalturnprogress(timeoutrecovery+validation).
Thisturnprogress(276checkpointaudit and4engineintegrations).

Annotation45089 completed0:280annotations,11,422exports,0failed,mappingpassed.
Inspectedexport0011c9c0: __cdecl h2_text_format(buffer,capacity,format,...).
Full280validation nowrunning session64214, analysis/engine-validation.log.
Do not restart. Afterterminal audit148reports/source/library/host hashes.
Earlier276checkpoint remains latest fullaudited baseline until280finishes.
Next independentrecovery candidate77480(async observer maintenance) has
unrecovered dependencies7b4c0/7b7b0; inspectoriginal/Xitacallflow whilepipeline
runs, keepnewpreviews outsideintegratedlibrary untilcurrentregressionterminal.

### Task-result recovery preview (0007b7b0)

Recovered `h2_async_task_result` in `src/async_task_result.c` using original disassembly and Xita `f_0007B7B0`. Reference provenance: `analysis/xita-engine-task-result-reference.json`. Both normal and UBSan preview libraries pass 1,288 original-XBE comparisons each (`analysis/async-task-result-preview.json` and `analysis/async-task-result-preview-ubsan.json`). Coverage includes all 256 flag bytes, signed salts and pool limits, wrapped index arithmetic, invalid handles, and five output placements including overlap. Original instruction order and the DWORD at record+8 are preserved. This routine is not yet integrated into the 280-routine catalog; full regression session 64214 was confirmed live during this work. Next: audit that regression once terminal, integrate the decoder with ABI annotation, and recover task creation 0007b4c0 to support observer maintenance 00077480.

### Task-creation recovery preview (0007b4c0)

Recovered `h2_async_task_create` in `src/async_task_create.c`, corroborated by Xita `f_0007B4C0` and original disassembly. Reference: `analysis/xita-engine-task-create-reference.json`. Normal and UBSan preview suites each pass 512 original-XBE comparisons, including actual data-pool allocation, full memory, normalized 0x304-byte temporary storage, callback pointer arrays and snapshots, signed count clamp, default options, SDK failures, pool replacement and exhaustion cleanup. SDK creation/release remain controlled platform boundaries. This preview is outside the integrated 280-routine catalog while regression session64214 remains live. The task-result and task-creation previews now provide the dependencies for observer asynchronous maintenance at00077480.

### Observer asynchronous lifecycle preview and 280 checkpoint

Full regression session64214 completed with exit0. `analysis/engine-checkpoint-280.json` records148 passing reports with current library/source/XBE/ABI/host hashes,280 unique catalog addresses and280 annotations.

Recovered `h2_network_observer_async` at00077480 using original instructions and Xita. The normal and UBSan preview suites each pass1,107 comparisons:1,024 varied initial states plus83 tasks created in one poll and completed in a later poll. Actual engine task creation, idle detection, result decode, release, allocation and deletion run; only SDK task services are controlled boundaries.203 SDK creations and417 releases occur per suite across both phases. Provenance: `analysis/xita-engine-observer-async-reference.json`; reports: `analysis/network-observer-async-preview{,-ubsan}.json`. Three previews (task creation, result decoding, observer maintenance) are ready for integration after this audited280checkpoint. They are not yet counted in the catalog.

### 283-routine integration

Integrated task creation, task-result decoding and observer asynchronous maintenance into CMake, the custom ABI catalog and both full-regression variants. Fresh normal-library integration tests pass2,907 comparisons (512+1,288+1,107). Ghidra refresh session33152 exited0:283 annotations,11,422 exports,0 failures, and5,722,958 mapped bytes verified. Full regression session81993 is running with output in `analysis/engine-validation.log`;154 reports are expected when terminal. The previous280checkpoint remains preserved in `analysis/engine-checkpoint-280.json`. SDK task services remain explicit boundaries; the full engine and playable Linux runtime remain incomplete. Next engine investigation: observer maintenance continuation at00077580 and its dependencies, using Xita and original instructions.

### Observer consumer-poll preview (00077940)

Confirmed00077580 was already recovered; advanced to the missing consumer-poll routine at00077940. Implemented `h2_network_observer_poll_consumers` with Xita/original instruction review recorded in `analysis/xita-engine-observer-poll-reference.json`. Normal and UBSan previews each pass1,536 comparisons (466 SDK clock calls,535 consumer calls,217 accepted results). Tests preserve captured timestamps and reload configuration after clock callbacks, signed/wrapping elapsed values, consumer-mask reloads, virtual target replacement and early return. Reports: `analysis/network-observer-poll-preview{,-ubsan}.json`. This is outside the283catalog; full regression session81993 remains live. Next missing neighboring function000779f0 performs observer bandwidth/statistics updates and needs instruction-level floating-point review.

### Observer bandwidth preview (000779f0)

Recovered `h2_network_observer_update_bandwidth` including congestion counters, actual statistics advance, bandwidth estimate/clamping, active connection selection, rate tables, and per-stream budgets. Used original disassembly and Xita translation (reference: `analysis/xita-engine-observer-bandwidth-reference.json`). Optimized normal and UBSan previews each pass1,024 full-memory original-XBE comparisons with clock snapshots. Branch instrumentation confirms877 update bodies,702 statistics advances,215 decreases,58 increases,702 budget calculations and174 unlimited branches per suite. Cases include floating infinities/NaNs, wrapped signed integer products, estimate conversion overflow, and callback configuration mutation. Default nearest-even floating environment is the documented current assumption. Compile with `-O2 -ffp-contract=off` and link `-lm` on integration. Reports: `analysis/network-observer-bandwidth-preview{,-ubsan}.json`. This and consumer polling remain outside the283catalog while full regression session81993 continues.

### Observer measurement preview (00077f90)

Recovered `h2_network_observer_record_measurement`, reviewed against original instructions and Xita (reference `analysis/xita-engine-observer-measurement-reference.json`). Optimized normal and UBSan previews each pass1,536 comparisons, including426 threshold transitions,383 counter updates,498 smoothing updates and780 SDK ticks. Full memory and callback snapshots verify signed/wrapped arithmetic, masked arithmetic-shift counts, floating NaNs/infinities, config replacement, byte-index mutation and override clock changes. Reports: `analysis/network-observer-measurement-preview{,-ubsan}.json`. The283full regression session81993 remains live. Consumer polling, bandwidth updating and measurement recording are tested previews awaiting integration after the regression checkpoint; next missing neighbor is00078090.

### Observer rate-helper previews (00078090/00078150/00078190)

Recovered rate selection, rate-to-budget conversion, and limited-rate detection in `src/network_observer_rates.c`. Original instructions and Xita correct incomplete pseudocode:78090 returns XMM0 and takes three stack arguments,78190 reads XMM1. Both optimized normal and UBSan suites pass2,304 comparisons each (768 per helper), checking exact XMM0 result bits, EAX/AL, stack purge and full memory. Cases include both overhead modes, caps, empty table fallback, signed wrapping, NaN/infinity and conversion overflow. Floating environment remains default nearest-even. Reference: `analysis/xita-engine-observer-rates-reference.json`; reports: `analysis/network-observer-rates-preview{,-ubsan}.json`. Six preview routines now await integration after283regression session81993 (confirmed live). Integration needs float/XMM return/parameter support in Ghidra ABI annotations and libm linkage with strict float operation ordering. Next neighbor00078210 can use these helpers.

### 283 checkpoint and next-rate preview

Full regression session81993 exited0. Audited all154 passing reports against current sources, libraries, XBE, recorded ABI/test/host hashes;283 unique ABI addresses and annotations. Saved `analysis/engine-checkpoint-283.json`.

Added next-rate helper00078210 to the rates preview after original/Xita review. The four-helper suite now passes3,072 comparisons per optimized normal/UBSan build, checking exact XMM0 bits and original register/stack behavior. An initial UBSan invocation mistakenly selected the integrated library and failed at symbol lookup; the corrected preview-library invocation passed. Seven preview routines are ready for integration: consumer poll, bandwidth update, measurement recording, and four rate helpers. Integration must add float32 and explicit XMM storage support to `scripts/ghidra/AnnotateDataArray.java` (currently only integer/byte/word returns), link libm, preserve `-ffp-contract=off`, add ABI definitions and four oracle suites to regression. Expected integrated total290. No active full regression remains.

### 290-routine integration

Integrated seven observer routines: poll consumers, update bandwidth, record measurement, select rate, rate budget, rate limited and next rate. Added four oracle suites to both full-regression variants; integrated Release suites pass7,168 comparisons. CMake links libm and disables floating contraction on affected sources. ABI annotation supports float32 parameters and explicit XMM return storage; Ghidra session31905 exited0 with290 annotations,11,422 exports,0 failures and mapping passed. Inspected generated78090/78210 signatures to confirm float returns and parameters. Full regression session65607 is running (`analysis/engine-validation.log`), expecting162 reports. Previous verified283checkpoint is preserved in `analysis/engine-checkpoint-283.json`. Next substantial missing observer routine000785d0 can now use recovered rate/measurement helpers.

### Incoming connection-request dependencies

Inspection of000785d0 identifies an incoming connection-request handler, not a rate-update routine. Missing dependencies include880b0 flag validation,75930 current-address copy,7af80 address comparison,7ab60 address-to-identity resolution,88360 accept transition and89180 downstream response. Recovered the first three in `src/network_accept_helpers.c` using original instructions and Xita. Normal and UBSan previews each pass2,560 comparisons (1,024 flags,768 copy,768 equality), including overlap and signed length gates. Reports: `analysis/network-accept-helpers-preview{,-ubsan}.json`; provenance: `analysis/xita-engine-accept-helpers-reference.json`. Outside290catalog while full regression65607 remains live. Next: recover7ab60 and88360/89180 dependencies, then compose785d0 with actual recovered callees.
