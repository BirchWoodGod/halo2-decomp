# Full objective and current evidence

The active objective remains complete Halo 2 decompilation and a playable Linux
build of the original Xbox game. A pseudocode export, an emulator run, a native
library, or an isolated test pass does not satisfy that objective.

## Current state

Latest checkpoint: 382 integrated routines passed the 276-report source/build
hash audit. The old regression handle is gone and its exit code is unavailable;
the log reaches the final UBSan suite. Main now contains 389 after integrating
seven reviewed serializers. Expanded regression is running with exit-status
capture; the session coordinator remains an unvalidated draft.


- The original local XBE is copied and hash-pinned. Its Ghidra mapping passes
  byte-for-byte verification, including after saving and reopening the project.
- Automatic x86 analysis and pseudocode export are available. Function discovery
  is incomplete; no percentage of total game decompilation is established.
  Currently all 11,422 discovered main-section functions export. The input-varnode
  error in `0006D080` is resolved by modeling the instruction-reviewed CRT stack
  probe at `00320560`; two previous enum-table errors remain fixed. This is pseudocode coverage
  of a partial inventory, not source-recovery coverage of the whole game.
- At the earlier 264-routine checkpoint, implementations had
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

### 294-routine integration and regression recovery

Identity resolution0007ab60 passed1,024 comparisons in each preview build, with177 SDK calls per suite, normalized local scratch, actual registered IPv4 extraction and optional/overlapping outputs. Integrated it and the three accept helpers into CMake, ABI annotations and regression scripts. Fresh Release integration checks pass3,584 comparisons. Ghidra session81377 exited0 with294 annotations and mapping verified.

Regression65607 was no longer live (missing handle, no matching processes); attempted290checkpoint audit found stale library hashes beginning with file-io tests. No290checkpoint was claimed or saved;283 remains the last fully audited checkpoint. New full294regression session74852 is running with166 reports expected. A zero-byte identity-reference manifest was discovered during integration metadata refresh and regenerated from retained Xita source with translation hashes. Source/tests were intact. Next recovery remains88360 accept transition and89180 response before composing785d0. Public repository created at https://github.com/BirchWoodGod/halo2-decomp; initial main commit25cb45a contains source/tools/tests, excluding binaries/assets/generated analysis. Subsequent integration changes are local pending validation.

### 296-routine connection-accept integration

Recovered accept transition 00088360 and response sender 00089180 with Xita/original instruction review. Corrected the new oracle stack mapping to accommodate the real reliable enqueue frame; no engine callee was replaced with a stub. Both preview and integrated Release/UBSan suites pass 768 comparisons per configuration, covering 384 writer calls, 192 reliable enqueue calls, 154 allocations and 672 clock calls. Integrated CMake, ABI catalog and both regression variants. Reports: `analysis/network-connection-accept-tests{,-ubsan}.json`; provenance: `analysis/xita-engine-connection-accept-reference.json`.

Earlier regression session74852 is no longer live in the current runtime; its log stops during the suite and no successful completion is established. The last audited complete checkpoint remains283. Ghidra initially failed because its config directory was read-only; rerunning with workspace-local XDG_CONFIG_HOME and XDG_CACHE_HOME permits annotation refresh. Incoming request handler000785d0 is next: recovered dependencies now cover validation, identity resolution, address comparison, close/open, acceptance and observer updates. Complete decompilation and a playable native Linux game remain unachieved.

Ghidra refresh session32732 exited0:296 annotations, mapping passed,11,422 exports and0 export failures. Full296 regression started as session58880, output `analysis/engine-validation.log`;168 reports expected. Await terminal status and audit current library/source hashes before claiming a full checkpoint.

### Incoming connection-request handler preview (000785d0)

Implemented `h2_network_observer_handle_request` using original instruction review and Xita `f_000785D0` (provenance: `analysis/xita-engine-observer-request-reference.json`). Optimized Release and UBSan preview libraries each pass1,536 original-XBE comparisons (`analysis/network-observer-request-preview{,-ubsan}.json`). Actual recovered callees perform identity lookup, fifteen-slot matching, close/reopen, route insertion, acceptance, refusal/accept serialization, timer resets and observer notifications. Per suite:637 opens,865 accept calls,91 closes and734 consumer notifications. Checks compare full guest memory, the entire0x88-byte handler-local frame and SDK/event snapshots. Coverage includes every low request flag byte, ignored high bits, absent/mismatched identities, matching entries with zero consumer masks, signed connection states and callback mutation of request/connection IDs or state.

This remains a preview outside the296-routine catalog while full regression session58880 is confirmed live. The composition suite exercises ordinary writer queues; live flushes, reliable storage, stream reset and queued storage cleanup are not exercised here, although individual recovered dependencies have separate tests. Next: audit the296regression once terminal, extend composition coverage as needed, then integrate this handler and its stack-based three-argument ABI. The full game objective remains incomplete.

### Request-handler reliable composition coverage

Extended the000785d0 preview suite to1,792 cases in each optimized Release/UBSan build. Added168 reliable enqueue executions and136 provider allocations per suite, using actual queue/codec routines and external provider callbacks. The test compares normalized reliable scratch at enqueue return: comparing it after the entire handler returns was invalid because subsequent original observer calls reuse the stack (the mismatch was in the final three bytes). Both suites now pass with full guest memory, main handler locals, reliable scratch and callback snapshots. No native source change was needed. Live socket flushes, stream reset and queued storage cleanup remain outside this composition suite. Full296 regression session58880 remains live; do not replace or restart it. Next integration remains the request handler once the regression is terminal and audited. Neighboring00078900 reallocates active observer connections;00078ac0/00078e60 manage their bandwidth configuration and remain unrecovered.

### Request-handler stream/storage reopen coverage

Both preview configurations now pass2,048 comparisons. Added the combined reopen path with actual stream reset, queued storage lookup/release/clear, then reliable accept enqueue. Each run executes170 stream resets and170 queued cleanups,338 reliable enqueues total,273 allocations and807 opens. Full memory, main frame, clear scratch, reliable scratch and SDK/event snapshots match. The external release stub at the end of the mapped Unicorn page needed terminating instruction bytes so decoder lookahead stayed mapped; native source was unchanged. Live socket flush remains outside this suite. Full296 regression58880 is still live in UBSan; it must complete before integration changes.

Reviewed original78900..78a01 and Xita inline body `f_00081780:L_00078900`; provenance and frame/ABI notes are in `analysis/xita-engine-observer-rebuild-review.json`. This routine has no separate Xita function and remains unimplemented.

### Audited296 checkpoint and298 integration

Full regression58880 exited0. `analysis/engine-checkpoint-296.json` records168 passed reports matching current library/XBE/source/ABI/test/host hashes,296 unique catalog entries and296 annotations. Recovered observer rebuild78900 using original instructions and Xita inline `f_00081780:L_00078900`. Preview Release/UBSan each pass256 full-memory/frame/event comparisons including999 allocation/refresh/update/tick sequences, pool exhaustion, occupied slots and a formatter callback activating a later slot. SDK clock/query/release and CRT formatting remain explicit boundaries.

Integrated request785d0 and rebuild78900 into CMake, custom ABI and both regression variants, bringing the catalog to298. Fresh integration suites and Ghidra annotation refresh are underway. Previous296checkpoint remains preserved; full298regression will expect172 reports. Complete decompilation and playable Linux game remain unfinished.

Fresh integrated Release and UBSan suites each pass2,304 comparisons (2,048 request +256 rebuild), with source/library hashes verified. Ghidra39878 exited0 with298 annotations and mapping passed. Full298regression started as session59140;172 reports expected. Audit only after terminal success; previous296checkpoint is the most recent complete regression.

### Observer metrics/rate-setting preview

Recovered00078a10 metrics query and00079600 rate setter in `src/network_observer_metrics.c`, with original instructions and Xita reference hashes in `analysis/xita-engine-observer-metrics-reference.json`. Optimized Release and UBSan previews each pass2,048 comparisons (1,024 per function), including319 accepted metric queries, all output aliases, signed/invalid indexes, inactive slots, overlapping source fields and scale constant, single-precision divide/multiply, cvttss2si truncation/overflow, zeros, infinities, quiet NaNs and subnormals. Rate setter invokes actual recovered rate-limit helper and preserves XMM5 payload bits. Default floating environment only.

Both remain outside298catalog while regression59140 is confirmed live. Next substantive target00078e60 allocates/rebalances per-connection bandwidth and now has its79600 dependency recovered; caller00078ac0 also needs79c00,7a2a0,7a330,79260 and sort/comparator helpers. Do not treat raw pseudocode as recovered implementations. Next integration must retain `-ffp-contract=off` and annotate XMM5 parameter storage. Full objective remains incomplete.

### Per-connection bandwidth allocation preview (00078e60)

Recovered `h2_network_observer_allocate_bandwidth` using original instructions and Xita redistribution/x87 reference. It captures active-slot counts/budgets before the clock callback, reloads configuration afterward, computes a signed/wrapping total cap, redistributes existing budgets with nearest-even conversion, initializes the target provider/stream state, and computes its final rate and burst using truncation. Actual recovered78090 selection and79600 setter run. Reference: `analysis/xita-engine-observer-bandwidth-allocate-reference.json`.

Release and UBSan previews each pass1,024 full-memory comparisons and clock snapshots, with512 controlled clock calls,1,476 redistribution updates,707 provider branches and256 stream-latency reads. Includes configuration, peer activation and provider changes during clock callbacks and signed/wrapped inputs. Default floating environment and valid integer divisors only; no fault-equivalence claim. Outside298catalog with metrics/setter previews while full regression59140 remains confirmed live. Integration must link libm and retain `-ffp-contract=off`. Next substantial caller78ac0 still needs bandwidth update/reset/scoring helpers (79260,79c00,7a2a0,7a330) and sort/comparator support.

### Bandwidth probe helper previews

Recovered reset79d90, saved-rate restore7a110 and probe priority7a2a0 in `src/network_observer_probe.c`. Xita/original review: `analysis/xita-engine-observer-probe-reference.json`. Priority returns float in XMM0; raw Ghidra pseudocode incorrectly omitted this result. Release and UBSan previews each pass3,072 comparisons (1,024 per function), including491 SDK clock calls and768 actual79600 rate restorations. Tests compare full memory, callback snapshots and exact XMM0 bits under captured timestamps, config/slot mutation, wrapping arithmetic, quiet NaNs/infinities/subnormals and flag variants. Default floating environment only.

These three remain outside298catalog along with78a10/79600/78e60 previews. Full regression59140 is still confirmed live. Next79a10 and79c00 form a bounded call cycle:79c00(flag1) may call79a10, which calls79c00(flag0); they can be recovered together now that restore/reset helpers exist. Other78ac0 dependencies remain7a330,7a160,7a1c0,79de0,79260 and sorting. No complete observer loop or playable game is claimed.

### Paired bandwidth reduction and306 integration

Recovered peer selection79a10 and bandwidth reduction79c00 with their bounded recursive call intact. Release/UBSan previews each pass2,048 comparisons, including1,601 reductions,528 saved-rate restores,1,087 pending-budget paths and1,401 clock calls. Original/Xita review exposed an omitted float-to-integer-to-float truncation in the pending-rate path; native code preserves it. Full memory and callback snapshots match; integer divisors must be valid and floating environment default. Reference: `analysis/xita-engine-observer-reduce-reference.json`.

Regression59140 exited0. `analysis/engine-checkpoint-298.json` audits172 passing reports with current library/XBE/source/ABI/test/host hashes,298 unique catalog entries and298 annotations. Integrated eight tested routines (metrics query, rate setter, bandwidth allocation, three probe helpers, peer selection and reduction) into CMake, ABI and both regression variants. Local catalog now306. Floating contraction stays disabled and libm remains linked. Fresh Release integration and Ghidra refresh are underway; next full regression expects180 reports. Entire observer update loop/gameplay remains incomplete.

Fresh306 Release integration passes8,192 comparisons, with report source/library hashes checked. Ghidra86002 exited0:306 annotations, mapping passed; inspected priority7a2a0 float return and79600 float rate parameter in refreshed exports. Full306regression started as session83565, output `analysis/engine-validation.log`;180 reports expected.298checkpoint remains the last full audited regression.

### Probe rate/result preview

Recovered79560/795b0 counter-rate measurements,7a160 failure progression and7a1c0 probe-result decision in `src/network_observer_probe_result.c`. Reference: `analysis/xita-engine-observer-probe-result-reference.json`. Release and UBSan previews each pass4,096 comparisons, including1,830 clock calls,289 actual bandwidth reductions,1,138 failure executions and all result statuses (49 zero,716 one,259 two). Tests compare full memory/EAX where meaningful, captured timestamps, signed wraps, counter/config mutation across distinct clock reads, cooldown and latency thresholds.7a160 is exposed as void because reviewed callers discard its incidental EAX. Valid integer divisors/default floating environment only.

These four remain outside306catalog; full306regression83565 is confirmed live. UBSan preview compiles the dependent reduction/probe/metrics sources directly because the integrated UBSan library may still be the previous298 build until the full regression reaches its rebuild. Next substantial target79de0 initiates probes and now has its measurement helpers recovered; then7a330 can compose the full per-slot controller. Whole observer update78ac0 also still requires79260 and sorting support.

### Probe initiation preview validated

Recovered `00079de0` as `h2_network_observer_start_probe` in
`src/network_observer_probe_start.c`, using the original XBE as the execution
oracle and Xita's `f_00079DE0` translation as a corroborating reference. Both
normal and undefined-behavior-sanitized previews passed 1,536 comparisons each
(3,072 total). Tests compare full guest memory, AL, and clock callback snapshots,
and exercise burst/budget/rate selection priority, cooldown, concurrent-probe
limits, exhausted-output aliases, saved-state mutations, signed wrapping, and
quiet NaN/Infinity rates. Actual recovered rate and measurement callees execute.
The fixtures use valid integer divisors and the default floating environment.

Reports: `analysis/network-observer-probe-start-preview.json` and
`analysis/network-observer-probe-start-preview-ubsan.json`; Xita provenance:
`analysis/xita-engine-observer-probe-start-reference.json`.
This remains a separate preview while the 306-routine regression runs; it is
not included in the integrated routine count. The per-slot probe controller and
whole observer update remain to be recovered. This does not establish game boot
or playable Linux execution.

### Per-slot probe controller preview validated

Recovered `0007a330` as `h2_network_observer_update_probe` after reviewing its
complete original instruction sequence and Xita's `f_0007A330` translation.
Normal and UBSan previews each passed 1,536 original-XBE comparisons, using
actual recovered engine callees and comparing full persistent memory plus clock
callback snapshots. Each suite exercised 192 readiness transitions, 34 successful
probe results, 256 restoration paths, 64 bandwidth-reduction paths, 213 failure
paths, 159 controller reset paths, and 47 initiated probes. One disjoint guest
scratch byte replaces the original stack-local exhausted flag and is excluded
from persistent-memory comparison. Valid integer division and the default
floating environment remain fixture constraints.

Source/header/test use the `network_observer_probe_update` basename. Reports:
`analysis/network-observer-probe-update-preview{,-ubsan}.json`; provenance:
`analysis/xita-engine-observer-probe-update-reference.json`. This preview remains
outside the integrated 306-routine build while its full regression is running.
Whole observer bandwidth update, complete engine recovery, and playable native
Linux execution remain unfinished.

### 306 checkpoint audited; 312 integration prepared

Full regression session 83565 exited successfully. All 180 reports passed and
were checked against current source, XBE, Release/UBSan library and host hashes;
the ABI annotation count was 306 and mapping verification passed. Evidence is
saved in `analysis/engine-checkpoint-306.json`.

Added the six validated probe lifecycle routines to CMake, the original ABI
catalog and both regression modes, bringing the integrated count to 312. New
test defaults now target the main library. During annotation refresh the catalog
initially used unsupported return type `uint8`; corrected it to the existing
`byte` type for the original AL return and reran annotation. The 312 checkpoint
is not yet validated; prior preview evidence does not substitute for regression.

### Observer cycle-finalization preview

Recovered `00079480` as `h2_network_observer_finish_cycle` in
`src/network_observer_cycle.c`. Reviewed the complete original instructions and
used Xita to corroborate initial timestamp capture and the second clock check.
Normal and UBSan previews each passed 512 full-memory comparisons against the
original XBE (1,024 total). Each suite executed 5,515 active-slot visits and 5,764
SDK clock callbacks, covering accumulated flags, idle/busy counters, signed
minimum updates, callback activation of later slots and changed clock overrides.
The saved initial timestamp remains the value written at cycle completion.
Reports use `analysis/network-observer-cycle-preview{,-ubsan}.json`; provenance
is `analysis/xita-engine-observer-cycle-reference.json`.

This preview is outside the 312-routine build while full regression session
66941 runs. The parent bandwidth update at `00079260` has been instruction-reviewed
and remains to be implemented; whole engine recovery and Linux gameplay remain
unfinished.

### Bandwidth-update composition preview validated

Recovered `00079260` as `h2_network_observer_update_bandwidth`, composing the
actual counter measurements, measurement recorder, probe restoration and cycle
finalization. Original instructions were reviewed and Xita corroborates wrapped
rate arithmetic, signed smoothing and the finalization call. Normal and UBSan
previews each passed 512 full-memory/clock-snapshot comparisons (1,024 total).
Each suite exercised 794 restoration calls, 28 measurement-recording calls,
160 smoothed estimate stores and 288 cycle-finalization calls, including callback
changes and inactive slots. Update flags clear even when the timing gate skips
processing. Reports: `analysis/network-observer-bandwidth-update-preview{,-ubsan}.json`;
provenance: `analysis/xita-engine-observer-bandwidth-update-reference.json`.

This remains outside the integrated 312-routine build while regression session
66941 runs. The top-level observer bandwidth controller at `00078ac0`, its sort
and external consumer dependencies, and full playable Linux execution remain
unfinished.

### Probe ordering dependencies validated

Recovered priority comparator `00078a90`, small-array selection sort `0013e0e0`
and iterative quicksort `0013de30` in `network_observer_sort.c/.h`. Reviewed the
original instructions and used Xita to corroborate comparator semantics and the
small-sort call. Exact algorithm order matters for duplicate and unordered float
priorities, so both sort algorithms preserve original swaps and traversal order.
Normal and UBSan previews each passed 1,536 comparisons (3,072 total), including
389,558 comparator calls per suite with exact argument/order/array snapshots.
Tests cover up to 64 entries, duplicates, signed zeros, quiet NaNs, infinities and
subnormals. The generic callback API has only been tested with the actual engine
priority comparator; arbitrary mutating comparators remain unverified.

Reports: `analysis/network-observer-sort-preview{,-ubsan}.json`; provenance:
`analysis/xita-engine-observer-sort-reference.json`. These three routines remain
outside the 312-routine build during regression session 66941. Top-level
`00078ac0` still needs implementation and review of consumer/game dependencies;
full recovery and playable Linux execution remain unfinished.

### Game-session selection dependency recovered

Reviewed the game-activity query chain behind observer controller `00078ac0`.
Raw Ghidra callers `00053de0` and `00054a20` lose an EDX output pointer and show
incorrect near-zero memory accesses. Original instructions and Xita establish
that session selection writes a session pointer through optional EDX.
Recovered `00059670`, `000596a0` and dispatcher `00053c30` in
`network_game_session.c/.h`, retaining neutral slot A/B names.

Normal and UBSan previews each passed 3,072 AL/full-memory comparisons (6,144
total), covering gates, selectors, null output, untouched failure output and
output aliases into globals or session state. Each suite observed 1,524 successes,
1,548 failures and 1,197 successful aliased writes. Reports:
`analysis/network-game-session-preview{,-ubsan}.json`; provenance:
`analysis/xita-engine-game-session-reference.json`. Callers and whole activity
query remain unrecovered. These routines are outside the integrated 312 build
while full regression 66941 runs; no playable-game claim follows from these tests.

### Session-query callers validated

Recovered `00053de0`, `00054a20`, `00054b10`, `000549d0`, `00053be0` and
`00053bb0` in `network_game_queries.c/.h`. The descriptor and ID queries now
follow the original stack-output-pointer flow through the recovered session
selector; descriptor access is session-relative, correcting the misleading raw
Ghidra near-zero accesses. Original instructions reviewed and Xita pointer-flow
reference retained in `analysis/xita-engine-game-queries-reference.json`.

Normal and UBSan previews each passed 6,144 comparisons (12,288 total), comparing
full persistent memory and EAX/AL with actual callees. Fixtures cover all gates,
selectors, descriptor sentinel, ID matching, member masks and flags, and masked
index shifts for indices 0..63. A disjoint four-byte native scratch cell replaces
the original stack output and is restored before persistent-memory comparison.
Reports: `analysis/network-game-queries-preview{,-ubsan}.json`. These six routines
remain outside the integrated 312 build while regression 66941 is active. The
whole game-activity predicate and top-level observer controller remain unfinished.

### Session member filter and lookup validated

Recovered `00054d20` and `00055960` in `network_game_members.c/.h`, using actual
session-selection, descriptor, mask and ID queries. Original instructions were
reviewed and Xita corroborates the mask-gated table lookup. Normal and UBSan
previews each passed 4,096 full-memory/EAX comparisons (8,192 total), including
sixteen membership records, enabled/disabled table gates and index shifts 0..63.
Disjoint stack-replacement scratch is restored before persistent-memory checks.
Reports: `analysis/network-game-members-preview{,-ubsan}.json`; provenance:
`analysis/xita-engine-game-members-reference.json`.

These remain outside the integrated 312 build during regression 66941. The
remaining game-activity chain includes peer-mask conversion `00056990`, routing
selection `000565c0` and wrapper `00056590`; their raw pseudocode was inspected
but they are not yet recovered. Complete engine recovery and Linux gameplay
remain unfinished.

### Member-to-peer mask preview validated

Recovered `00056990` as `h2_network_game_peer_mask`, preserving its two descriptor
lookups, selected-ID lookup, sixteen membership tests, local/invalid-peer
exclusion and masked shifts. Original complete instructions reviewed; Xita
translation provenance retained in `analysis/xita-engine-game-peer-mask-reference.json`.
Normal and UBSan previews each passed 2,048 full-memory/EAX comparisons (4,096
total), executing actual recovered query callees. Scratch replacing stack-local
session output remains disjoint and excluded from persistent comparison.
Reports: `analysis/network-game-peer-mask-preview{,-ubsan}.json`.

This routine remains outside the integrated 312 build during regression 66941.
Routing-selection dependencies `00054cc0`, `00054c70`, and `00054ac0` have had
raw pseudocode inspected but still require instruction review/recovery, along
with routing composition and full activity query. Playable Linux game execution
is not yet established.

### 312 checkpoint audited; routing queries preview validated

Full regression session 66941 exited successfully. All 186 reports passed and
matched current source, XBE, Release/UBSan libraries and host hashes. The catalog
and annotation count were 312; mapping verification passed. Evidence saved as
`analysis/engine-checkpoint-312.json`. No full regression remains running.

Recovered routing queries `00054cc0`, `00054c70`, `00054ac0` in
`network_game_route_queries.c/.h`, using actual session-query callees. Reviewed
original instructions and Xita descriptor/ID lookup flow. Normal and UBSan
previews each passed 3,072 comparisons (6,144 total), covering gates, modes,
sentinels, ID matching and selected peer masks. Persistent memory and EAX/AL are
compared; disjoint guest scratch replaces nested stack output. Reports:
`analysis/network-game-route-queries-preview{,-ubsan}.json`; provenance:
`analysis/xita-engine-game-route-queries-reference.json`. These and the prior
post-312 previews still require main-build integration. Routing composition,
whole activity query, engine completion and playable Linux execution remain open.

### 332 integration prepared

Added twenty post-312 preview routines across eight source groups to CMake,
original ABI catalogs and normal/UBSan regression modes. Updated test defaults
to the integrated library and README count to 332. Main linking caught the new
`00079260` symbol colliding with the existing bandwidth-update routine; renamed
it `h2_network_observer_commit_bandwidth` in source/header/test/catalog. Main
Release library and host now build successfully. The last fully audited
checkpoint remains 312; integrated 332 tests must run after annotation refresh.

### Route-selection helper preview validated

Recovered `00056790` as `h2_network_game_select_routes`, preserving signed
capacity checks, reserved last slot, local-ID exclusion and ordered writes to
selected/pending/count outputs. Complete original instructions reviewed; Xita
corroborates write order. Normal and UBSan previews each passed 2,048 full-memory
comparisons (4,096 total), with 3,217 selected writes, 214 deferral decisions and
683 aliased-pointer fixtures per suite. Reports:
`analysis/network-game-route-select-preview{,-ubsan}.json`; provenance:
`analysis/xita-engine-game-route-select-reference.json`.

This helper remains outside the integrated 332 build while full regression 5205
runs. Inspection also established `00054f20` only returns EAX (not an EDX:EAX
64-bit value suggested by an unannotated caller). Routing composition therefore
requires original instruction review rather than relying on that pseudocode.
Session-overlap helper `00053c70`, whole activity query and playable Linux
execution remain unfinished.

### Session overlap and kind previews validated

Recovered `00053c70` session overlap and `00054f20` kind getter in
`network_game_overlap.c/.h`. Original instructions reviewed; Xita corroborates
peer lookup and wrapped overlap bits. Normal and UBSan previews each passed
2,048 comparisons (4,096 total), with actual session getters and peer matching,
3,277 peer searches and 2,059 successful matches per suite. Tests cover gates,
failed getters, invalid A descriptor, signed counts, absent/repeated identities,
and up to 40 B peers to exercise output-bit wrapping. Successful getters require
a valid B descriptor; invalid B fault behavior is outside scope. Eight disjoint
guest scratch bytes replace two stack outputs and are excluded from persistent
memory comparison. Reports: `analysis/network-game-overlap-preview{,-ubsan}.json`;
provenance: `analysis/xita-engine-game-overlap-reference.json`.

Both routines remain outside the integrated 332 build during full regression
5205. Routing wrapper `000565c0` can now be reconstructed from recovered
callees, but whole activity query, observer controller and playable Linux game
remain unfinished.

### Routing composition preview validated

Recovered `000565c0` as `h2_network_game_build_routes`, composing actual routing
queries, session overlap and route selection. Original instructions and Xita
confirm that `00054f20` returns the kind in EAX while preserving the previously
computed peer mask in EDX; the raw caller's apparent 64-bit return was misleading.
Normal and UBSan previews each passed 1,024 routing-wrapper comparisons plus
1,024 kind-getter comparisons (2,048 wrapper comparisons total). Each suite
executed 252 selection calls and 647 peer searches. Full persistent memory is
compared for the void wrapper; EAX is separately checked for the kind getter.
Tests include reserve modes, capacity, masks and output aliasing the table-enable
byte. Twenty-four disjoint guest scratch bytes replace stack locals and are
excluded from persistent comparison; valid B descriptor remains required.
Reports: `analysis/network-game-routes-preview{,-ubsan}.json`; provenance:
`analysis/xita-engine-game-routes-reference.json`.

This preview remains outside the integrated 332 build during full regression
5205. Wrapper `00056590` and activity predicate `00054890` still need composition
and verification before the top-level observer controller can use them. Full
engine recovery and playable Linux execution remain unfinished.

### Member routing wrapper preview validated

Recovered `00056590` as `h2_network_game_member_routes`, preserving output clear
order and the post-clear table-enable check, then composing actual member-to-peer
conversion and routing. Complete original instructions and Xita reviewed. Normal
and UBSan previews each passed 1,024 wrapper comparisons plus 1,024 kind-getter
checks (2,048 wrapper comparisons total), with 82 selection calls and 289 peer
searches per suite. Full persistent memory verifies the void wrapper; the kind
getter separately checks EAX. Fixtures include output aliasing the enable flag;
24 disjoint scratch bytes replace nested stack locals. Valid B descriptor domain
remains required. Reports: `analysis/network-game-member-routes-preview{,-ubsan}.json`;
provenance: `analysis/xita-engine-game-member-routes-reference.json`.

The wrapper remains outside the integrated 332 build during regression 5205.
All direct dependencies of activity predicate `00054890` now have recovered
implementations, but the predicate and top-level observer still require
composition and original-XBE verification. Full recovery/Linux gameplay remain
unfinished.

### Full peer-activity predicate preview validated

Recovered `00054890` as `h2_network_game_peer_active`, composing all actual
session/member/routing callees. Original instructions and Xita corroborate the
routed-success branch at `00054977`, incorrectly removed from raw Ghidra output.
Normal and UBSan previews each passed 2,048 activity comparisons plus 2,048
separate kind checks (4,096 activity comparisons total). Each suite exercised
257 member-route calls, 102 route selections and three routed-success returns,
as well as the direct ID-match shortcut. Full persistent memory and AL are
compared; 28 disjoint scratch bytes replace predicate and nested stack locals.
Valid descriptors remain a precondition; no fault-emulation claim. Reports:
`analysis/network-game-activity-preview{,-ubsan}.json`; provenance:
`analysis/xita-engine-game-activity-reference.json`.

The activity predicate remains outside the integrated 332 build during full
regression 5205. It can now serve as an actual dependency of `00078ac0`; the
remaining top-level observer implementation must preserve consumer virtual calls,
allocation, priority sorting and probe/bandwidth composition. Full engine
recovery and playable Linux execution remain unfinished.

### Top-level observer bandwidth controller implemented; initial oracle passes

Implemented `00078ac0` as `h2_network_observer_control_bandwidth` after reviewing
its complete instruction sequence. It composes actual allocation, priority sort,
probe update, activity predicate, reduction and bandwidth commit routines, with
explicit virtual-call and clock boundaries. Initial 128-case original-XBE suite
passed full persistent-memory and callback-snapshot comparison, executing 1,020
consumer callbacks, 1,292 clocks, 765 priorities/probe updates and 213 commits.
Disjoint 152-byte native scratch replaces original and nested stack locals.

Coverage is intentionally recorded as incomplete: allocation, game-session
virtual lookup/activity, more probe/reduction paths and UBSan verification still
need work before integration. Report `analysis/network-observer-control-preview.json`;
reference `analysis/xita-engine-observer-control-reference.json`. Main 332
regression session 5205 remains active. Full engine/gameplay goal is unfinished.

### Expanded controller oracle and UBSan passed

Expanded `network_observer_control_oracle.py` to 384 cases covering allocation,
game-session virtual lookups and the actual activity predicate via its ID-match
shortcut, plus reduction. Both normal and UBSan previews passed (768 controller
comparisons total). Each suite exercised 497 allocations, 2,618 session lookups,
1,694 activity calls, 23 reductions, 2,306 probe updates/priorities, 640 commits,
3,071 consumer callbacks and 5,424 ticks. Full persistent memory and callback
snapshots match the original XBE, including consumer-mask mutations affecting
later slots. Scratch remains disjoint/excluded. Routed activity is separately
tested, while integrated live virtual implementations and whole-game behavior
remain unverified. Reports `analysis/network-observer-control-preview{,-ubsan}.json`.

This resolves the initial allocation/session/UBSan coverage gap for the controller
preview, not the full engine goal. Main 332 regression 5205 remains active;
controller and post-332 activity/routing previews await integration. More probe
states and routed activity within the controller can further strengthen coverage.

### Controller probe lifecycle and routed activity coverage expanded

Expanded the controller oracle to 832 cases; normal and UBSan both passed
(1,664 controller comparisons). Each suite now covers 476 probe starts, 766
result evaluations, 358 successes, 431 restorations and 38 routed-activity
successes within the complete controller. It also executes 1,072 allocations,
3,763 activity predicates, 5,798 session lookups, 4,984 probe updates, 1,386 commits
and 23 reductions. Full persistent memory and clock/virtual-call snapshots match
the original XBE. This closes the prior probe-state and routed-activity fixture
gaps while retaining controlled virtual implementations and clock boundaries.
Reports remain `analysis/network-observer-control-preview{,-ubsan}.json`.

Controller and post-332 previews still await integration. Full 332 regression
session 5205 was polled and remains running. Live network integration, full
engine recovery and playable Linux gameplay remain unfinished.

### Observer route-mode finalizer preview

Recovered `0007a4a0` as `h2_network_observer_update_route_mode`, the final step
called by outer observer frame `00075da0`. Complete original instructions were
reviewed; Xita corroborates the gated global write. Normal preview passed 1,536
full-memory comparisons covering all fifteen slots, noncanonical nonzero flag
bytes, active/enabled filtering, all three route modes and disabled global writes.
Reports use `analysis/network-observer-route-mode-preview{,-ubsan}.json`; provenance
is `analysis/xita-engine-observer-route-mode-reference.json`. The outer frame
still needs composition with retry/release/refresh/slot/tick/timeout/async and
bandwidth/controller calls. Main 332 regression 5205 remains active; full engine
recovery and playable Linux execution remain unfinished.

### Audited 332 checkpoint and integrated observer frame (341 routines)

Full regression session 5205 exited 0. Audited all 202 reports against the current
source files, XBE, Release/UBSan libraries and host binaries; the ABI catalogs
contain 332 unique addresses, Ghidra annotated 332 routines, and mapping passed.
Evidence is `analysis/engine-checkpoint-332.json`. This supersedes the earlier
312 checkpoint and the preceding statements that regression 5205 was running.

Recovered outer observer frame `00075da0` using complete original instructions
and Xita `code_015.c:f_00075DA0`. The native context connects the actual recovered
retry, release, refresh, slot, tick, timeout, async, bandwidth, controller and
route-mode routines. It rechecks slot state after retry/release, then preserves
the five-call sequence without inserting intermediate caller state checks.

The frame preview passed 1,088 comparisons in each of Release and UBSan (2,176
total): 256 waiting/retry/release/clock-mutation fixtures and all 832 active
controller fixtures executed through the outer frame. Each build exercised
765 slot releases, 1,072 bandwidth allocations, 476 probe starts, 766 probe
results, 431 restorations and 38 routed-activity successes. Full persistent
memory and SDK/virtual callback snapshots match original execution. Disjoint
replacement stack scratch is excluded. The connected-transport fixtures keep
the preceding bandwidth estimator on cooldown; async task work and connection
transitions still need validation through this outer entry point. This is not
live networking or gameplay evidence.

Integrated these nine routines across eight source/test groups: route selection,
session kind/overlap, route construction, member routing, peer activity,
bandwidth controller, route-mode finalizer and observer frame. Main CMake,
original-ABI catalog, README and Release/UBSan regression commands now cover
341 routines. The Release build succeeds. Frame provenance is
`analysis/xita-engine-observer-frame-reference.json`; original preview reports
are `analysis/network-observer-frame-preview{,-ubsan}.json`. Earlier route-mode
preview also passed both Release and UBSan, 1,536 comparisons each.
The 341 build needs its own full regression before becoming an audited checkpoint.
Full engine recovery and playable Linux execution remain unfinished.

Ghidra refresh completed: 341 ABI annotations, 1,481 invalidated exports, mapping
verification passed. Full 341 Release/UBSan regression is running as session
3852, logging to `analysis/engine-validation.log`; expect 218 suite reports on
successful completion. Poll that session rather than restarting on observation
timeouts. No latest-work GitHub push was performed.

### Parent network update: nine additional preview routines

Previous goal turn was concrete progress (341 build integration and regression
launch). Regression session 3852 was revalidated live and is now in its UBSan
portion; do not restart it. The last fully audited integrated checkpoint remains
332. New work is isolated in preview sources/libraries, leaving that run intact.

Traced observer frame `00075da0` to its caller `0008dfc0`. That parent updates
three session objects (`0005a090`), runs the observer frame, conditionally flushes
replicated object changes (`0008a090`), updates endpoint connections (`00093090`)
and flushes the message writer. The session and connection update paths still
have missing callees, so no placeholder parent implementation was added.

Recovered and checked three new groups:

- `network_replication_changes`: `00089710` marks change masks across fifteen
  peer records; `0008a090` scans 1,024 object records and filters pending masks
  through virtual +0x50 before propagation. Full-memory and callback snapshots
  cover signed type lookup, duplicate peer pointers, zero-mask counter effects,
  counter wrap and callback mutation of handle, manager and future records.
  Each build passed 1,024 marking and 256 flush cases; 3,104 virtual calls and
  1,832 actual propagation calls were observed in the flush fixtures.
- `network_connection_iteration`: `000891e0` walks inline/provider components;
  `00088d70` writes connection timestamps. Each build passed 4,004 iterator calls
  and 1,024 timestamp cases, including exhausted-cursor restart, signed cursor
  boundaries, aliased outputs, wrapping slot arithmetic and mutating SDK clocks.
- `network_stream_events`: `000966d0` record lookup, `001a4840` queue advancement,
  `00096b00` completion, `000965e0` event polling and `00096ce0` retirement. Each
  build passed 1,024 cases per routine, with acknowledgment, timeout, out-of-order
  notification and retirement paths, signed remainders, wrapping arithmetic,
  aliased output writes and SDK clock mutation. Valid mapped queues and
  nontrapping divisors are prerequisites, as for original execution.

All nine preview routines passed Release and UBSan: 22,856 comparisons total.
Final audit matched current sources, preview libraries, engine libraries and XBE
hashes in all six reports. Evidence is
`analysis/engine-preview-network-events-audit.json`, individual
`analysis/network-{replication-changes,connection-iteration,stream-events}-preview{,-ubsan}.json`
and the corresponding `analysis/xita-engine-*-reference.json` files. Original
instructions were reviewed; Xita references corroborate ABI and operation order.
The UBSan dependency was refreshed by the ongoing main regression, so the first
two preview groups were rerun against its current library before the final audit.

These nine routines are not yet in CMake, the ABI catalog or test-engine.sh;
integrate after the 341 regression completes and is audited. No current-preview
process remains active. Session 3852 is the one ongoing regression. Full engine
recovery and playable native Linux execution are still incomplete.

### Audited 341 checkpoint and integrated network event dispatch (353 routines)

Regression session 3852 exited 0. All 218 reports passed and matched current
source, XBE, Release/UBSan libraries and host binary hashes; the ABI catalog has
341 unique routines, with 341 annotations and mapping verification passed.
`analysis/engine-checkpoint-341.json` is the new audited integrated checkpoint.
This supersedes earlier notes that session 3852 remained live.

Recovered `00088db0` as `h2_network_connection_dispatch_events`. It drains eligible
stream records, polls events, updates connected state/timestamps, walks actual
inline/provider components and invokes the original observer/component callback
slots. It retains the initially selected stream across callbacks that replace
global pointers. Both builds passed 1,024 complete dispatcher comparisons each:
full persistent memory, all 72 original stack-local bytes and callback snapshots.
This includes raw boolean-word padding, component/provider and observer mutation,
acknowledgments, out-of-order events, timeout feedback, signed timing thresholds
and SSE/x87 rounding, including infinities and NaNs. SDK clock and virtual method
implementations are controlled; no live networking or whole connection-update
claim is made.

Recovered `00096510` stream reservation and `00096810` byte accounting in
`network_stream_reserve`. Both builds passed 1,536 cases per routine (6,144 total),
with actual forced retirement/queue/lookup callees. Virtual blocked checks,
callback mutation, capacity and sequence-distance limits, retired-slot reuse,
original eight-byte scratch and wrapped accounting match original execution.
Valid mapped queues and existing record handles remain prerequisites.

Integrated these three routines and the prior nine previews: replication
changes, component iteration/timestamps, stream events, connection dispatch and
reservation. All 12 routines passed 31,048 pre-integration comparisons across
Release and UBSan, with current hashes audited in
`analysis/engine-preview-network-dispatch-audit.json`. The main CMake build, ABI
catalog, README and regression script now contain 353 routines and 114 test suites
per configuration. Release builds successfully. New Xita evidence is in
`analysis/xita-engine-connection-events-reference.json` and
`analysis/xita-engine-stream-reserve-reference.json`.

The original packet construction `00088980` remains the missing substantial
callee of connection update `000883c0`; it needs endpoint packet assembly/send
`000931a0` and its diagnostic boundary plus the recovered bitstream, iterator and
reservation routines. Complete connection update, endpoint update `00093090`,
session update `0005a090`, and enclosing network frame `0008dfc0` remain unfinished.
The full objective is still incomplete; there is no playable native Linux game.

Ghidra refresh completed with 353 annotations and mapping passed. Full353
Release/UBSan regression is running as session34612, logging to
`analysis/engine-validation.log`; expect228 reports when it finishes. Poll that
handle rather than restart on observation timeouts. No other test is running.
The public-repo publication remains blocked by the GitHub tool's required
approval under session policy `never`; the prepared local Git bundle is refreshed
with current source and progress without attempting to bypass that restriction.

Recovered packet assembly `000931a0` as a standalone preview in
`src/network_connection_packet.c`. Release and UBSan each passed 1,536 comparisons
against original XBE execution (3,072 total). Tests compare persistent memory,
the full packet, packed bytes and SDK callbacks across primary/secondary payload
limits, inactive states, loopback routing, send failures, callback mutation and
output aliasing. Actual recovered submission and accounting callees execute.
The complete Xita `f_000931A0` translation corroborates the implementation;
local provenance and report hashes are recorded in
`analysis/xita-engine-connection-packet-reference.json`.

This preview is not yet part of the 353-routine main build or ABI catalog.
To build and run its Release check after building the engine library:

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_connection_packet.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_connection_packet_preview.so
.tools/venv/bin/python tests/network_connection_packet_oracle.py
```

Full integrated regression remains in progress. Packet construction `00088980`
and its enclosing connection/frame routines remain unfinished. No playable
Linux game is claimed. Publication remains pending because the GitHub write tool
requires approval and this session's approval policy is `never`.

Recovered packet construction `00088980` and diagnostic formatting wrapper
`000b66f0` as standalone previews in `network_connection_build` and `format_string`.
The builder now runs actual sequence reservation, two-pass component iteration,
bitstream writers, packet assembly/submission and byte-accounting callees.
The formatter calls a controlled CRT boundary, forces the final terminator and
returns the destination pointer. It preserves the original cdecl convention.

Release and UBSan each passed 1,536 builder cases and 512 formatter cases (4,096
comparisons total). Builder tests compare all persistent memory, the full
0x74c-byte original local frame, callback arguments/order and state snapshots.
They cover insufficient budgets, blocked/reservation failures, inline/provider
components, provider removal during callbacks, alignment changes, payload fill,
raw boolean padding, observer changes and aliased optional outputs. Formatter
tests cover zero/short/full output and ignored CRT error returns. These results
are scoped to controlled virtual/SDK/CRT callbacks and empty socket endpoints;
oversized padding beyond the original local buffer and live networking are not
covered. The underlying packet preview separately covers send/error paths.
Complete original instructions and Xita translations were reviewed; local
provenance/report hashes are in
`analysis/xita-engine-connection-build-reference.json`.

Build and run this preview after building the main engine:

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/format_string.c src/network_connection_build.c \
  src/network_connection_packet.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_connection_build_preview.so
.tools/venv/bin/python tests/network_connection_build_oracle.py
```

Main integrated count remains 353; the packet assembler, builder and formatting
wrapper are three additional previews. Full353 regression session34612 remains
live and must finish/audit before integrating these previews. Next recovery is
connection update `000883c0`, then endpoint update `00093090`; session update and
the enclosing network frame still remain. The overall game remains incomplete.

Recovered connection update `000883c0` and endpoint update `00093090` in
`network_connection_update`. Connection update runs actual handshake, close,
component iteration, packet construction, timestamps and stream-event dispatch.
It preserves state checks across callbacks, observer-selected payload limits,
boolean-word padding and unconditional timestamp updates after builder returns.
Endpoint update retains the selected connection through callbacks, reloads the
route count and pool for iteration, and processes deferred closes with reason9.

Release and UBSan each passed 1,024 connection and 1,024 endpoint cases (4,096
total). Tests compare full persistent memory, the original0x864 parent frame
(normalizing its local buffer pointer), and callback arguments/order/state.
They exercise handshakes, timeouts, component closes, activity queries, observer
planning, packet construction, sequence reservation, acknowledgments/out-of-order
stream events, callback state changes, signed/reloaded route counts, duplicate
connection entries and deferred closes. Nested local seeds and virtual/SDK
boundaries are controlled. Native message codec dispatch runs with socketless
endpoints. This does not verify live networking or the complete game.
Original instructions and complete Xita translations were reviewed; local evidence
is `analysis/xita-engine-connection-update-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/format_string.c src/network_connection_build.c \
  src/network_connection_packet.c src/network_connection_update.c \
  -Lbuild -lhalo2_engine '-Wl,-rpath,$ORIGIN' \
  -o build/libhalo2_connection_update_preview.so
.tools/venv/bin/python tests/network_connection_update_oracle.py
```

The main build still has353 routines; these two routines and the previous three
are previews awaiting integration after the full353 regression finishes/audits.
The outer network frame `0008dfc0` now has an endpoint-update implementation;
its remaining substantial missing dependency is session update `0005a090`.
That state machine still needs `000617c0`, `000618d0`, `00061910`, `00061ac0`,
`00061e00`, `00061ef0`, `00062de0`, `0005fda0`, `00062ab0`, `00062990`,
`00062240`, `00062640` and `000627e0` reviewed/recovered as applicable.
Whole-game execution remains unverified and incomplete.

Full353 regression session34612 exited0. All228 reports passed and matched
current source, pinned XBE, Release/UBSan libraries and native host hashes.
The combined ABI catalogs have353 unique addresses, Ghidra annotations353 and
mapping verification passed. The new integrated checkpoint is
`analysis/engine-checkpoint-353.json`. This supersedes earlier running-regression
notes. The five preview routines can now be integrated and the expanded suite
run; those previews are not part of this checkpoint.

Integrated the five packet/connection previews into CMake, the Xbox ABI catalog
and regression script. The main library now has358 recovered routines and117
suites per configuration. All11,264 standalone comparisons passed a preintegration
source/library hash audit in `analysis/engine-preview-connection-path-audit.json`.
The catalog excludes native contexts and replacement scratch; the bounded
formatter is marked variadic with caller cleanup. Full358 validation is pending;
353 remains the most recent audited integrated checkpoint. Session update and
the outer network frame remain incomplete, as does the playable game objective.

The358 Release library and host built successfully. Ghidra refresh annotated358
routines, invalidated1495 exports and passed mapping verification. Expanded
Release/UBSan regression is running as session13740, logging to
`analysis/engine-validation.log`; expect234 reports. Poll this handle rather than
restart on observation timeouts. The353 audited checkpoint remains authoritative
until the expanded regression exits and its report hashes are audited.

Recovered session timeout handlers618d0/61910 as standalone previews in
`network_session_timeouts`. They retain the previous timestamp across SDK clock
callbacks, reload the timeout limit afterward, use signed wrapped elapsed time,
and select actual resend or recursive cleanup on a strict greater-than test.
Release/UBSan each passed1,024 cases per routine (4,096 total), including exact
boundaries, cached/SDK time, callback mutation, actual message codecs/send,
reliable queue allocation, registration release, peer detach and local scratch.
The fixture covers valid join-abort/leave states2/4 with SDK/virtual boundaries
controlled, not live networking.

Recovered observer message deferral768b0/76930 in
`network_observer_message_gate`, dependencies of snapshot broadcasts62640/627e0.
Release/UBSan each passed2,048 cases per routine (8,192 total), comparing original
instructions with no hooks. Coverage includes missing/inactive connections,
existing/new message flags, both capacity thresholds, signed/wrapped capacity,
low-byte64-bit shift counts (including64..255 zero masks) and full persistent
memory. The actual connection-capacity callee executes.

All12,288 new comparisons matched current source/library hashes. Complete Xita
translations corroborate original-instruction review; local evidence is
`analysis/xita-engine-session-timeouts-reference.json` and
`analysis/xita-engine-observer-message-gate-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_timeouts.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_timeouts_preview.so
.tools/venv/bin/python tests/network_session_timeouts_oracle.py
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_observer_message_gate.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_observer_message_gate_preview.so
.tools/venv/bin/python tests/network_observer_message_gate_oracle.py
```

Main count remains358 with four additional tested previews. Full358 regression
session13740 is still running; expect234 reports. These previews are not part of
its build/catalog and must wait for that checkpoint audit before integration.
Next session dependencies include join-request resend62300 and join-state617c0,
plus snapshot constructors60400/609e0 for broadcasts62640/627e0. Session update
5a090, outer frame8dfc0 and whole-game execution remain unfinished.

Recovered join-request resend62300 in `network_session_join_retry`. It runs actual
observer/address query, constructs the original0x1b8 payload, enqueues type8
through the native join-request codec, and updates count/time in original order.
Release/UBSan each passed1,536 comparisons (3,072 total), covering query/address
gates, signed timing, callback mutation, counter overflow, queue flush and
send/error results. Full persistent memory, original payload and SDK snapshots
match; disjoint query/packet scratch is restored. No live session join is claimed.

Recovered status request62990 and connected-state entry612c0 in
`network_session_status`. Status sends retain the original selected peer through
clock callbacks, apply both timing gates and shutdown guard, and send type24
through actual observer/codec/flush/send callees. State entry captures time,
increments generation with wrap, clears temporary state, sets state3 and requests
status. Release/UBSan each passed1,024 cases per routine (4,096 total), including
explicit generation overflow, full persistent memory, original28-byte message,
nested dispatcher scratch and callback snapshots. The name `send_status_request`
distinguishes it from the existing status-query routine.

The main regression rebuilt UBSan during preview validation; both affected suites
were rerun against the current library. All7,168 final comparisons passed the
source/library hash audit. Complete original instructions and Xita translations
were reviewed; local evidence is
`analysis/xita-engine-session-join-retry-reference.json` and
`analysis/xita-engine-session-status-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_join_retry.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_join_retry_preview.so
.tools/venv/bin/python tests/network_session_join_retry_oracle.py
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_status.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_status_preview.so
.tools/venv/bin/python tests/network_session_status_oracle.py
```

Main count remains358 with seven tested previews. Full358 regression session13740
is still running; expect234 reports. Join-state617c0 now has recovered resend and
connected-entry dependencies; its composed implementation/test is next. Session
update5a090, outer network frame8dfc0 and playable Linux Halo2 remain incomplete.


Recovered join-state controller `000617c0` as the standalone
`network_session_join` preview. It composes the recovered observer query,
connected-state entry/status request, join retry, shutdown/join-abort, reliable
queue and message codec/send routines. Both timeout phases preserve the original
signed elapsed-time checks and callback ordering. Confirmation type 21 uses the
original eight-byte identity payload; the final retry checks the current state.

Release and UBSan each passed 1,536 original-instruction comparisons (3,072 total).
Both reports were audited against current source and dependency-library hashes.
Tests explicitly exercise connected entry, retry, shutdown and join-abort,
compare persistent memory and callback snapshots, and check original stack
payloads against caller-provided scratch. SDK and virtual callbacks are controlled;
these tests do not establish live networking or playable startup. Xita remains a
reference, with original XBE execution authoritative. Local provenance and report
hashes are in `analysis/xita-engine-session-join-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_join.c src/network_session_join_retry.c \
  src/network_session_status.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_join_preview.so
.tools/venv/bin/python tests/network_session_join_oracle.py
```

There are now 358 routines in the main build and eight additional tested previews.
The expanded main regression is still running as session 13740; the audited
353-routine checkpoint remains the last complete regression checkpoint. Integration
of the previews awaits the expanded regression audit. Remaining session work
includes migration, snapshot construction/broadcast, session update `0005a090`,
and outer network frame `0008dfc0`. The game is not playable yet.


Recovered migration payload builder `00062b70` in
`network_session_migration_payload`, a dependency of migration entry `000616e0`.
It builds the 192-byte identity/peer payload with original forward word-copy
semantics, index reloads, unaligned identity fields and final local-index return.
Complete original instructions and Xita translation were reviewed. Release and
UBSan each passed 768 original-instruction comparisons (1,536 total) with no
hooks, covering all 16 host/local indexes, same/different peers, randomized data,
unaligned output and overlapping identity buffers. Full memory, return and stack
purge match. Current source/library hashes were audited; local provenance is
`analysis/xita-engine-session-migration-payload-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_migration_payload.c -Lbuild \
  -Wl,--no-as-needed -lhalo2_engine '-Wl,-rpath,$ORIGIN' \
  -o build/libhalo2_session_migration_payload_preview.so
.tools/venv/bin/python tests/network_session_migration_payload_oracle.py
```

Main build remains at 358 routines, with nine additional tested previews.
The main regression session 13740 is still running. Migration state entry and
update remain to be recovered; this payload builder does not establish working
migration or playable Linux startup.


The full 358-routine regression completed successfully (session 13740, exit 0).
All 234 Release/UBSan reports passed the current source, library, host and XBE
hash audit where those hashes apply. Both ABI catalogs together contain 358
unique addresses; Ghidra reports 358 annotations, and mapping verification passed.
The new authoritative checkpoint is `analysis/engine-checkpoint-358.json`, with
report, library, validation-log, annotation and mapping hashes. This supersedes
the earlier running-regression notes and the 353-routine checkpoint.

Nine standalone previews remain outside the main build. Before integration,
refresh any preview whose dependency-library hash predates the main rebuild.
The next migration transition is `000616e0`: original instruction review confirms
callee-purged session argument, two independent clock reads, a 280-byte temporary
state containing the recovered migration payload, masked peer bit shifts,
generation increment/reset and final state 9. Implementation and differential
validation of that transition remain outstanding. No game startup is claimed.


Recovered migration entry `000616e0` as `network_session_migration_start`.
It uses the actual recovered migration payload builder, two independent cached/SDK
clock reads, the original 280-byte temporary state, masked peer shifts, generation
increment/reset, and final state 9. Complete original instructions and Xita
translation were reviewed. Release/UBSan each passed 768 original-instruction
comparisons (1,536 total), including callback changes to clock override, peer
indexes and generation, generation overflow, and wide shift counts. Full persistent
memory, callback snapshots, temporary stack state and stack purge match. Current
source and dependency-library hashes were audited; local provenance is
`analysis/xita-engine-session-migration-start-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_migration_start.c \
  src/network_session_migration_payload.c -Lbuild -Wl,--no-as-needed \
  -lhalo2_engine '-Wl,-rpath,$ORIGIN' \
  -o build/libhalo2_session_migration_start_preview.so
.tools/venv/bin/python tests/network_session_migration_start_oracle.py
```

The audited main checkpoint remains 358 routines/234 reports, with ten additional
standalone previews. Migration entry now supplies a dependency for disconnected
session handling `00062ab0`; migration update `00061ef0`, other session states and
outer network frame remain incomplete. No live migration or playable startup is
claimed by these differential tests.


Integrated all ten session/migration/message-deferral preview routines into CMake,
the original Xbox ABI catalog and the regression script. The main build now has
368 routines and 124 suites per configuration. Before integration, refreshed the
two stale UBSan suites against the current library and audited all
25,600 standalone comparisons, source hashes and library hashes.
Evidence is `analysis/engine-preview-session-path-audit.json`.

Expanded regression is running as session 27801, writing
`analysis/engine-validation.log`; expect 248 reports. Poll that session rather
than restart it on observation timeouts. Ghidra annotation refresh is also running,
writing `analysis/annotate-368.log`. The 358-routine checkpoint remains the last
fully audited integrated checkpoint until both runs and their hash audits finish.
No game startup or live networking is established. Next recovery work includes
disconnected-session handling `00062ab0` and migration update `00061ef0`.


Recovered disconnected-session handler `00062ab0` as a standalone preview.
Original instructions and complete Xita translation show that only state 3 with
valid identity and signed peer count greater than one reaches observer close and
migration entry. All other paths enter actual session cleanup. Release/UBSan
passed 1,024 comparisons each (2,048 total), covering valid states 0..10,
identity/count gates, missing/inactive/established connections in states 2/3,
clock callbacks, recursive cleanup, registration and migration scratch. Original
engine callees execute; SDK/virtual boundaries are controlled. The fixture has
no connection-close callback and does not cover connected state 5 close-message
sending. These are explicit composed-test limitations, not a live migration claim.
Current source and dependency-library hashes passed audit; local provenance is
`analysis/xita-engine-session-disconnect-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_disconnect.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_disconnect_preview.so
.tools/venv/bin/python tests/network_session_disconnect_oracle.py
```

The UBSan preview also links migration_start and migration_payload source while
its dependency library remains at the preceding checkpoint. Reaudit dependency
hashes after the main regression rebuilds UBSan. Main regression session 27801
remains running. Ghidra refresh session 59674 exited 0, with 368 annotations and
1,500 invalidated exports. Main count remains 368 plus this one preview; the last
fully audited integrated checkpoint remains 358. Migration update and playable
Linux startup remain incomplete.


Recovered `00063ba0` as `network_session_peer_lookup`, a dependency of migration
update `00061ef0`. It captures the signed count and six-byte identity, scans the
packed identity table, and returns the last matching index or UINT32_MAX.
Complete original instructions and Xita code_013 translation were reviewed.
Release/UBSan each passed 1,024 original-instruction comparisons (2,048 total),
without hooks, covering empty/negative counts, bounded positive counts, missing,
unique and duplicate matches, unaligned data and aliased input. Full persistent
memory, return and stack purge match. Source/library hashes were audited in
`analysis/xita-engine-session-peer-lookup-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_peer_lookup.c -Lbuild \
  -Wl,--no-as-needed -lhalo2_engine '-Wl,-rpath,$ORIGIN' \
  -o build/libhalo2_session_peer_lookup_preview.so
.tools/venv/bin/python tests/network_session_peer_lookup_oracle.py
```

Main count remains 368 plus two previews (disconnect and peer lookup). Regression
session 27801 is still running; recheck preview dependency hashes after its UBSan
rebuild. The migration update also requires transition `00061570`, whose remaining
dependencies include `00061390`, `00060fa0` and `00062550`. No playable startup or
live migration is established.


Recovered snapshot reset `00060fa0` as `network_session_snapshot_reset`, a shared
dependency of host entry `00061390` and migration transition `00061570`.
Complete original instructions and Xita translation were reviewed. The native
routine preserves the three clear ranges, invalid-version sentinels, per-peer
flags/version resets, signed count handling and optional generation increment.
Release/UBSan each passed 1,024 comparisons (2,048 total) without hooks, comparing
full persistent memory and stack purge. Tests cover negative/empty/valid peer
counts, unaligned sessions, raw stack arguments with low-byte flag semantics,
random adjacent state and generation wrap. Source/library hashes were audited;
local evidence is `analysis/xita-engine-session-snapshot-reset-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_snapshot_reset.c -Lbuild \
  -Wl,--no-as-needed -lhalo2_engine '-Wl,-rpath,$ORIGIN' \
  -o build/libhalo2_session_snapshot_reset_preview.so
.tools/venv/bin/python tests/network_session_snapshot_reset_oracle.py
```

Main build remains 368 routines, with three standalone previews. Regression
session 27801 remains running; preview dependency hashes must be rechecked after
its UBSan rebuild. Host entry now has its reset dependency; transition `00061570`
also needs request sender `00062550`. Migration update and playable Linux startup
remain incomplete.


Recovered host-state entry `00061390` in `network_session_host_entry`, composing
the actual snapshot reset `00060fa0`. It preserves existing host states 5..8,
otherwise resets snapshots, copies raw active-peer flags, captures version/time
when any peer is active, reloads the local peer after the clock callback, clears
temporary state and enters state 5. Original instructions and complete Xita
translation were reviewed. Release/UBSan each passed 1,024 comparisons (2,048
total), including full persistent memory, stack purge, clock callback snapshots,
raw flags, signed count gates, generation wrap and callback mutation of peer,
version and state. Source/library hashes were audited; local evidence is
`analysis/xita-engine-session-host-entry-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_host_entry.c \
  src/network_session_snapshot_reset.c -Lbuild -Wl,--no-as-needed \
  -lhalo2_engine '-Wl,-rpath,$ORIGIN' \
  -o build/libhalo2_session_host_entry_preview.so
.tools/venv/bin/python tests/network_session_host_entry_oracle.py
```

Main count remains 368 with four tested previews. Regression session 27801 is
still running; preview library hashes need rechecking after the UBSan rebuild.
Host entry completes another dependency of transition `00061570`; request sender
`00062550` remains before that transition can be composed. This does not establish
live hosting, migration or playable Linux startup.


Recovered migration request sender `00062550` as `network_session_migration_send`.
Complete original instructions and Xita translation were reviewed. It preserves
masked peer-bit operations, signed elapsed/limit comparison, captured previous
time across clock callbacks, selected-host gating, active/connected peer checks,
actual reliable observer type-18 sends, and post-send mask reload/update.
Release/UBSan each passed 1,024 comparisons (2,048 total), including full persistent
memory, callback snapshots, the original eight-byte payload, nested observer
scratch and reliable-queue scratch. Current source/library hashes passed audit;
local evidence is `analysis/xita-engine-session-migration-send-reference.json`.
SDK/virtual boundaries are controlled; live network delivery is not established.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_migration_send.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_migration_send_preview.so
.tools/venv/bin/python tests/network_session_migration_send_oracle.py
```

Main count remains 368 with five tested previews. Regression session 27801 remains
running. Migration transition `00061570` now has recovered reset, host-entry and
request-sender dependencies; its composed implementation and validation are next.
Whole-session update, migration update and playable Linux startup remain incomplete.


Recovered migration transition `00061570` in
`network_session_migration_transition`. Original instructions and complete Xita
translation were reviewed. It captures the previous host before reset, falls back
to actual host entry for signed count <=1, preserves existing host states, captures
clock/local mask, enters state 8, requests eligible observer connections and calls
the recovered migration request sender. Release/UBSan each passed 1,024 comparisons
(2,048 total), with full persistent memory, stack purge, callback snapshots and
original/nested message scratch. Raw stack flag values exercise low-byte behavior.
Current source/library hashes passed audit; local provenance is
`analysis/xita-engine-session-migration-transition-reference.json`.

The observer request branch executes its actual callee but uses absent connection
identifiers in this fixture; establishing a live connection is not covered.
SDK/virtual boundaries are controlled. This remains a standalone preview.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_migration_transition.c \
  src/network_session_snapshot_reset.c src/network_session_host_entry.c \
  src/network_session_migration_send.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_migration_transition_preview.so
.tools/venv/bin/python tests/network_session_migration_transition_oracle.py
```

Main count remains 368 with six tested previews. Full regression session 27801
remains running. Migration update `00061ef0` now has its previously missing peer
lookup and transition dependencies recovered; composing and validating that larger
controller is next. Whole-session update and playable Linux startup remain incomplete.


Recovered migration controller `00061ef0` in `network_session_migration_update`.
Complete original instructions and Xita translation were reviewed. It composes
actual peer lookup, candidate payload rebuild, migration transition, type-22
broadcast and recursive cleanup. Signed wrapped timeout checks preserve captured
previous values and reload limits after clock callbacks; peer loops reload count.
Release/UBSan each passed 1,024 comparisons (2,048 total), including full persistent
memory, callbacks, original 200-byte payload and nested scratch. Explicit coverage
checks require transition, candidate rebuild, lookup, broadcast and cleanup paths.
Source/library hashes passed audit; local provenance is
`analysis/xita-engine-session-migration-update-reference.json`.

The fixture uses bounded peers and inactive connection-request states with SDK
and virtual boundaries controlled. It does not establish live migration or game
startup. The UBSan preview explicitly links migration_payload while its main
library is still at the preceding checkpoint; reaudit after the main rebuild.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_migration_update.c \
  src/network_session_migration_transition.c src/network_session_migration_send.c \
  src/network_session_host_entry.c src/network_session_snapshot_reset.c \
  src/network_session_peer_lookup.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_migration_update_preview.so
.tools/venv/bin/python tests/network_session_migration_update_oracle.py
```

Main count remains 368 with seven tested previews. Full regression session 27801
remains running. Session-update dependencies still include handoff states
`00061ac0`/`00061e00`, snapshot construction/broadcast and maintenance. Whole-session
update, outer frame and playable Linux startup remain incomplete.


Recovered handoff candidate removal `00061950` as `network_session_handoff_remove`.
Original instructions and complete Xita translation were reviewed. The routine
clears the masked peer bit and, only for the selected peer, clears handoff flags,
invalidates the selected index and refreshes time. Release/UBSan each passed
1,024 comparisons (2,048 total), checking full memory, stack purge and SDK clock
snapshots. Tests cover selected/other peers, wide shift counts, cached/SDK clock,
unaligned sessions and callback mutation of selection/mask/state. Current source
and library hashes passed audit; local evidence is
`analysis/xita-engine-session-handoff-remove-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_handoff_remove.c -Lbuild \
  -Wl,--no-as-needed -lhalo2_engine '-Wl,-rpath,$ORIGIN' \
  -o build/libhalo2_session_handoff_remove_preview.so
.tools/venv/bin/python tests/network_session_handoff_remove_oracle.py
```

Main build remains 368 routines with eight previews. Regression session 27801
remains running. Handoff controller `00061ac0` also needs candidate comparison
`000619b0`, which depends on `00063ca0` and an x87 math boundary. Remaining handoff,
snapshot and maintenance paths still prevent whole-session update and game startup.


Recovered `00063ca0` as `network_peer_mask_count`, a dependency of handoff ranking.
Complete original instructions and Xita code_013 translation were reviewed.
Release/UBSan each passed 1,024 comparisons (2,048 total), including empty/full and
alternating masks, all single set/clear bits, random masks, full memory, EAX and
stack purge. Python bit_count supplies an additional independent result check.
Source/library hashes passed audit; local evidence is
`analysis/xita-engine-peer-mask-count-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude src/network_peer_mask_count.c -Lbuild -Wl,--no-as-needed \
  -lhalo2_engine '-Wl,-rpath,$ORIGIN' -o build/libhalo2_peer_mask_count_preview.so
.tools/venv/bin/python tests/network_peer_mask_count_oracle.py
```

Original instruction review of candidate ranking `000619b0` confirms ECX session,
EDX candidate, EAX incumbent and stack peer-count index (ret4, AL result). It
compares population counts at record+0x9c and signed values at +0xf8, then uses
capped signed rates, wrapping differences, SSE float operations and x87 call
`00372d48` before a final float comparison. The math boundary and rounding need
validation before implementing ranking; the Ghidra pseudocode alone is insufficient.
Main build remains 368 with nine previews; regression session 27801 remains running.
Handoff controller, whole-session update and playable Linux startup remain incomplete.


Identified handoff ranking's CRT boundary `00372d48` as power with ST1 base and
ST0 exponent. Added reproducible `scripts/probe-handoff-math.py`, which runs all
original CRT instructions for eight representative finite cases from a clean x87
state and checks return/stack completion. It records exact double bytes alongside
host math results in `analysis/handoff-math-probe.json`. The original returns
3.0000000000000004 for 9^0.5 in this probe, demonstrating why host pow must not be
assumed bit-identical. This is original-code investigation, not a recovered native
routine or proof of ranking fidelity. Run with:

```sh
.tools/venv/bin/python scripts/probe-handoff-math.py
```

Ranking uses SSE conversion/multiplication followed by this x87 boundary, extended
addition/subtraction and a float store before its final comparison. Next work must
validate the combined rounding behavior, including values near the final threshold.
Main count remains 368 with nine previews. Regression session 27801 is confirmed
live; whole-session update and playable Linux startup remain incomplete.


The full 368-routine regression completed successfully: session 27801 exited 0.
All 248 reports passed current source/library/host/XBE hash checks where recorded.
Both ABI catalogs contain 368 unique addresses; Ghidra has 368 annotations and
mapping verification passed. `analysis/engine-checkpoint-368.json` records report,
library, log, annotation and mapping hashes and supersedes the running notes.

Four standalone previews have stale UBSan dependency hashes following the rebuild:
disconnect, peer lookup, snapshot reset and host entry.
A sequential refresh is running as session 9559 via `/tmp/refresh_368_previews.py`, writing
`analysis/preview-refresh-368.log`. Do not integrate them until that run and the
new report/source/library audit succeed. No native ranking implementation or
playable startup is claimed by this integrated checkpoint.


The four stale UBSan previews completed their refresh successfully (session 9559,
exit 0). All nine standalone routines then passed a current source/library audit:
18,432 comparisons, recorded in `analysis/engine-preview-migration-path-audit.json`.
Integrated them into CMake, the Xbox ABI catalog and the regression script, bringing
the main count to 377 routines and 133 suites per configuration. Original register
and stack ABI entries exclude native platform contexts and replacement scratch.

Expanded regression session 20948 is running with output in `analysis/engine-validation.log`;
expect 266 reports. Ghidra refresh session 2360 is running with output in
`analysis/annotate-377.log`. The 368-routine checkpoint remains authoritative until
the new runs and report-hash audit finish. Handoff candidate ranking remains under
investigation; no whole-session update or playable Linux startup is claimed.


Added `scripts/probe-handoff-ranking.py` to execute the complete original ranking
routine and CRT callees against a host-power hypothesis. It ran 768 finite
arithmetic tie-break cases with thresholds at and adjacent to the host float
score, clean x87 state and default MXCSR. Both power branches execute (402 positive,
366 negative); integer early-return ranking is deliberately outside this probe.
Three score comparisons differed and one final peer-selection decision differed.
Exact inputs are recorded in `analysis/handoff-ranking-probe.json`.

The counterexample has candidate/incumbent latency 3901/3044, rates -94/255,
cap 490, both scales equal float32(0.0001), and exponent 1. Original score is
-0.12059999257326126; the host hypothesis gives -0.12060000002384186. At the latter
threshold, original AL is 1 and host prediction is 0. Thus even finite exponent-1
cases cannot assume a direct host pow substitution preserves ranking decisions.
This is investigation evidence, not a recovered ranking implementation.

```sh
.tools/venv/bin/python scripts/probe-handoff-ranking.py
```

Both math probes now place their injected entry stub at STOP+0x600, away from the
shared harness allocator callback at STOP+0x100. The original eight-case power
probe was rerun successfully after that fixture correction. Next implementation
work must reproduce the CRT/x87 result or provide a separately validated boundary;
the counterexample must remain in its regression cases.

Ghidra refresh session 2360 completed successfully. Main regression session 20948
is still running; the audited baseline remains 368 routines. Main build has 377
routines, and the full playable Linux objective remains incomplete.


Correction to the ranking-rounding interpretation above: the prior “original”
results mean original instructions executed by Unicorn, not measurements from Xbox
hardware. Added `scripts/probe-native-handoff-math.py` and diagnostic-only
`tests/native_x87_power_probe.c` to compare the positive-normal x87 arithmetic on
this host CPU. The script verifies that the 20 arithmetic opcode bytes match XBE
`00327f84` exactly (including FSUBR's direction), then compares seven positive-base
samples with the earlier emulation report. For 9^0.5, native x87 produces 3.0 while
Unicorn produces 3.0000000000000004. Six other representative samples match.

This identifies an emulator/hardware numerical discrepancy. Consequently, the
ranking counterexample does NOT by itself prove that host pow differs from Xbox
hardware peer selection. It remains a useful emulator regression case, but must
not drive an implementation that deliberately reproduces emulator error. The
native probe is not full CRT recovery and does not cover special-value or error
paths; no Xbox-hardware equivalence is claimed. Exact evidence is in
`analysis/native-handoff-math-probe.json`.

```sh
.tools/venv/bin/python scripts/probe-native-handoff-math.py
```

Next numerical work should compare the complete ranking path on native x87 and
clarify the supported floating-point environment, with emulator comparisons
qualified where transcendental results disagree. Main regression session 20948
remains live; main count 377, audited checkpoint 368. Playable startup is incomplete.


Recovered candidate-ranking engine logic `000619b0` in
`network_session_candidate_rank`, with an explicit CRT power callback returning
an extended result. There is no default host-pow implementation. Original
instructions and complete Xita translation were reviewed. Native code preserves
population-count and signed-priority comparisons, capped signed rates, wrapped
differences, float conversion/multiplication, power arguments, extended combination
and final float comparison. Compile with `-ffp-contract=off`.

Release/UBSan each passed 1,024 original-instruction comparisons (2,048 total)
with the CRT boundary controlled using exact finite outputs. Full memory, AL,
stack purge and power arguments match. Both integer and arithmetic paths and both
boolean outcomes execute. Current source/library hashes passed audit; evidence is
`analysis/xita-engine-session-candidate-rank-reference.json`. This validates engine
logic around the boundary, not a production power provider, exceptional FP inputs,
all rounding environments or live handoff. The UBSan preview links the population
count source while its main library is at the previous checkpoint.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -ffp-contract=off \
  -fPIC -shared -Iinclude -Isrc src/network_session_candidate_rank.c \
  -Lbuild -lhalo2_engine '-Wl,-rpath,$ORIGIN' \
  -o build/libhalo2_session_candidate_rank_preview.so
.tools/venv/bin/python tests/network_session_candidate_rank_oracle.py
```

Main count remains 377 plus this preview, with integrated regression session 20948
still running. The handoff controller can now compose ranking through the explicit
math interface, but runtime math fidelity remains an outstanding requirement for
playable Linux startup.


Drafted `network_session_handoff_update` for original `00061ac0` after full original
instruction review. It composes ranking at session+0x58, snapshot-version and
connectivity eligibility, type-15 offer broadcast, type-17 selected-peer confirmation,
timeout candidate removal, host fallback and forced shutdown. The draft compiles
with strict warnings and `-ffp-contract=off`, but has NOT passed differential tests
and is NOT integrated or counted as a recovered routine. The header/source mark
this status explicitly. Complete Xita cross-review also remains pending.

Required composed verification: no candidate vs selected candidate, eligibility
and ranking paths, local-host readiness, original 46-byte offer and eight-byte
confirmation buffers, acknowledgement completion/timeout, candidate removal,
clock/send callbacks mutating flags/selection/count, captured shutdown flag through
host entry, actual reliable queue/codec/broadcast callees, and controlled CRT power.
Do not count compilation as engine equivalence or playable functionality.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -ffp-contract=off \
  -fPIC -shared -Iinclude -Isrc src/network_session_handoff_update.c \
  src/network_session_candidate_rank.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_handoff_update_draft.so
```

Main remains 377 integrated routines, one tested ranking preview, and this unvalidated
handoff draft. Regression session 20948 is confirmed live; audited baseline368.
The production CRT math provider and playable Linux startup remain unresolved.


Handoff-controller preview verification: Release and UBSan each passed 1,024
composed original-instruction comparisons (2,048 total). The fixture compares
persistent memory, callback snapshots, stack cleanup, and original 46-byte offer
and eight-byte confirmation buffers. Each run exercises 416 offers, 231
confirmations, 439 candidate removals, 150 host entries, and 32 ranking calls.
SDK and virtual callbacks are controlled. The fixture supplies a controlled CRT
power boundary, but these cases do not reach it: arithmetic ranking coverage is
provided by the separate candidate-ranking suite, not this controller suite.

The controller remains a draft outside the 377 integrated routines. Complete
Xita cross-review and targeted callbacks mutating selection/acknowledgement flags
remain pending. The production math provider and playable Linux startup are still
unresolved. Local evidence: `analysis/network-session-handoff-update-preview.json`
and `analysis/network-session-handoff-update-preview-ubsan.json`.

Reproduce after building the draft library with the command above:

```sh
.tools/venv/bin/python tests/network_session_handoff_update_oracle.py
```

GitHub publication remains pending: the connected GitHub write was rejected because
it requires approval while this session's approval policy is `never`. The prepared
Git repository, complete bundle, and patch are maintained under
`/tmp/halo2-publish/`; these local artifacts do not mean GitHub has been updated.


Completed the full Xita `f_00061AC0` cross-review, including eligibility gates,
ranking argument base, captured/reloaded clock state, offer/confirmation scratch,
acknowledgement handling, removal, host fallback, and captured shutdown flag.
Expanded the controller fixture to 2,048 cases per build: the original 1,024 cases
plus callbacks mutating selection/acknowledgements, offer/confirmation flags, local
peer/count, and timeout configuration. Dedicated eligible ties now execute the
arithmetic ranking path through the controlled CRT power result (512 calls per
build). This supersedes the earlier note that the controller fixture did not
reach the math boundary. It does not establish production power fidelity.

Release and UBSan each pass all 2,048 cases, including full memory, callback
snapshots, scratch messages and stack cleanup. Per-build coverage includes 821
offers, 428 confirmations, 876 removals, 339 host entries and 576 ranking calls;
all five callback mutation modes execute. Current report, source, library and
Xita translation hashes are recorded in
`analysis/xita-engine-session-handoff-update-reference.json`.
The controller remains outside main integration while the production math provider
is unresolved. Main count is 377; the last fully audited checkpoint is 368, and
the existing full regression continues under session 20948. No playable startup.


Recovered session connection maintenance `00062240` as
`h2_network_session_maintain_connections` in a standalone preview. Reviewed the
complete original instructions and Xita translation. The routine preserves the
initial inactive-state gate, signed peer-count loop with post-callback reload,
active-peer filtering, host-state bypass, actual shutdown guard, identity and
connectivity checks, and observer-state-one skip before the actual recovered
request/tick path.

Release and UBSan each pass 4,096 original-instruction comparisons (8,192 total).
Tests cover session states 0..10 and signed edge values, empty/negative/bounded
counts, identity/activity gates, and callbacks mutating session state/count.
Actual resolution, retries, observer transitions, connection open, handshake
queue, stream reset and inactive storage clearing execute. Each build reaches
53 connection opens and 105 recursive ticks. Persistent guest memory, callback
order/arguments and scratch match; SDK/virtual boundaries are controlled. The
fixture uses a fresh writer and inactive storage, with no live socket or playable
session claim. Evidence: `analysis/xita-engine-session-maintenance-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_maintenance.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_maintenance_preview.so
.tools/venv/bin/python tests/network_session_maintenance_oracle.py
```

This preview remains outside the 377-routine main build while its existing full
regression runs (session 20948). Fully audited baseline remains 368. Session
broadcast constructors and other update dependencies, production ranking math,
and playable Linux startup remain outstanding.


Recovered reservation expiration `00062de0` as the standalone
`h2_network_session_expire_reservations` preview after reviewing original
instructions and the complete Xita translation. It scans all sixteen 36-byte
slots, skips inactive/infinite-duration entries, captures the prior timestamp,
reads cached or SDK time, reloads the duration after callbacks, and clears only
the active byte when unsigned wrapped elapsed time strictly exceeds the duration.
This removes another missing dependency of the session-update host path.

Release and UBSan each pass 1,024 original-instruction comparisons (2,048 total).
Full guest memory and clock snapshots match across inactive/noncanonical active
bytes, infinite durations, equality boundaries, high-bit timestamps and wraparound.
Reentrant clocks mutate timestamps/limits and switch remaining slots to cached
time. Current hashes and Xita reference are audited in
`analysis/xita-engine-session-reservation-expiry-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_reservation_expiry.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_reservation_expiry_preview.so
.tools/venv/bin/python tests/network_session_reservation_expiry_oracle.py
```

The routine remains a preview outside the main 377 while full regression session
20948 continues. Fully audited checkpoint remains 368. Peer eviction and snapshot
broadcast construction are still missing dependencies; production math and
playable Linux startup remain unresolved.


Recovered peer eviction `0005fda0` as standalone
`h2_network_session_evict_peer`, following complete original-instruction and Xita
review. The routine captures the session identity in eight-byte scratch, checks
peer activity, sends a reliable type-13 notification only for observer state seven,
then sends an unreliable notification with reloaded routing fields, and invokes
the actual recovered peer-removal path. Caller supplies disjoint notification and
player-removal scratch.

Release and UBSan each pass 1,024 composed comparisons (2,048 total). Per build:
292 reliable notification calls, 877 unreliable notification calls, 1,024 actual
peer/player removals and 1,366 memmoves. Full guest memory, callback snapshots,
captured notification and nested scratch match. Cases use three peers/players,
active/inactive peers, observer states six/seven, and callback mutation of identity
and observer-slot routing. Actual codecs, reliable allocation, detach, player
removal and compaction run; SDK/virtual boundaries remain controlled and the writer
is fresh. No live socket/session or gameplay claim. Hash audit and Xita provenance:
`analysis/xita-engine-session-eviction-reference.json`.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_eviction.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_eviction_preview.so
.tools/venv/bin/python tests/network_session_eviction_oracle.py
```

Main remains 377 while existing regression session 20948 continues; audited
checkpoint remains 368. The new eviction, maintenance and reservation-expiry
routines are tested previews. Snapshot constructors/broadcasts still block full
session-update composition, and production math/playable Linux startup remain
unfinished.


The full 377-routine regression (session 20948) exited successfully. All 266 reports
passed current source, library, host and input hashes where recorded; 377 unique
ABI entries and 377 Ghidra annotations match, and mapping verification passes.
Evidence is `analysis/engine-checkpoint-377.json`.

Integrated connection maintenance, reservation expiry and peer eviction after
re-auditing all 12,288 Release/UBSan standalone comparisons against current source
and dependency hashes (`analysis/engine-preview-session-maintenance-audit.json`).
Main now contains 380 routines. CMake, custom ABI catalog, test defaults and full
regression script include the additions (136 suites per configuration).
Handoff candidate ranking and controller remain previews with unresolved production
math. Snapshot construction and playable Linux startup remain incomplete.

Expanded 380-routine regression started as session 7210; Ghidra ABI/mapping refresh
started as session 97361 with workspace-local configuration/cache. The 377 checkpoint
remains the last fully audited result until these complete and their reports pass
a fresh audit. Integration build completed and initial suites are passing.


Recovered the smaller session parameter snapshot constructor `000609e0` as
`h2_network_session_build_parameters_snapshot`, a standalone preview. Complete
original instructions were reviewed; the Xita translation is located and hashed,
with full cross-review still pending. The constructor writes a 0x14d8-byte delta
from a 0x14ac-byte current parameter block and optional baseline. It preserves all
25 change flags, tagged union selection, conditional payload copying, bounded
narrow-string comparisons/copies and Xbox UTF-16 comparisons/copies. Output must
be disjoint from all inputs; baseline may alias current.

Release and UBSan each pass 2,048 original-instruction comparisons (4,096 total).
Original CRT callees execute without hooks. Full memory and stack cleanup match;
all 25 flags are both set and clear across absent/equal/current-aliased baselines,
individual field and sparse changes, six union tags, early/boundary terminators,
unterminated fields, and nonzero string tails. Current report/source/library hashes
are audited in `analysis/xita-engine-session-parameters-snapshot-reference.json`.
This tests construction, not live snapshot broadcasting or game startup.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_parameters_snapshot.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_parameters_snapshot_preview.so
.tools/venv/bin/python tests/network_session_parameters_snapshot_oracle.py
```

Ghidra refresh session 97361 completed successfully with 380 annotated routines.
The main 380 regression remains in session 7210; fully audited baseline377.
The larger membership snapshot constructor and broadcast composition remain
outstanding, along with production handoff math and playable Linux startup.


Completed the full Xita `f_000609E0` cross-review for the parameter snapshot
constructor, including flag gates, copy extents, tagged union cases, and narrow/
UTF-16 comparisons, padding and truncation. Re-audited the existing 4,096
Release/UBSan comparisons against current source and dependencies; the provenance
report now records the completed cross-review.

Drafted `h2_network_session_broadcast_parameters` for `000627e0` after complete
original instruction review. It filters active, unblocked peers at observer state
seven; chooses full/delta snapshots by revision; invokes the recovered type-33
message deferral gate; suppresses new payloads in session state eight; stamps peer
revisions before actual reliable sends; and copies the current parameter block to
the baseline after callbacks. Two disjoint 0x14d8 scratch buffers replace original
stack payloads. The draft compiles with strict warnings, but has NOT passed
composed differential validation and is NOT integrated or counted as recovered.
Full Xita review of the broadcast itself remains pending.

Required next validation: full/delta/both/no payload masks, active/block/state and
revision gates, actual deferral mask writes, original stack payload equality,
reliable type-33 queue/codec path, callbacks mutating peer count/activity/revision,
and post-send baseline copying. Main remains380 and fully audited checkpoint377;
regression7210 continues. No playable startup.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_session_parameters_broadcast.c \
  src/network_session_parameters_snapshot.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_session_parameters_broadcast_draft.so
```


Built the composed parameter-broadcast test fixture. Its first execution exposed
an additional missing production dependency: type33 (`parameters-update`) uses
encoder `000af890`, which is registered in the descriptor table but absent from
`h2_message_native_can_encode`/the native dispatcher. After registering parameter
messages in the fixture, the send path reached this unsupported encoder and the
native dispatcher aborted. This is not a broadcast equivalence pass.

The test now checks encoder availability up front and fails with an explicit
message instead of aborting. It retains the real constructor, gates, reliable
queue and codec path; no replacement encoder or engine stub was introduced.
The fixture is unfinished and has NOT passed, and broadcast remains a draft.
Recovery of the real encoder is the next dependency before composed validation.
Xita has `f_000AF890` in `code_025.c`; the current Ghidra export has the decoder
`000b0900.c` but no encoder file. Initial instruction inventory finds direct calls
to `00063690`, `0007c5a0`, `0007cc50`, `000b2330`, `000b66f0`, `001955d0` and
`00195720`. These are leads for review, not proven recovered dependencies.
Local gap evidence is `analysis/parameters-encoder-gap.json`.

Main stays380; last fully audited checkpoint377, regression7210 still live.
No live parameter broadcast or playable Linux startup is claimed.


Recovered parameter-block writer `000b2330`, a direct dependency of type33 encoder
`000af890`, after complete original-instruction and Xita review. The 68-byte block
writes a one-bit kind, 64/128/288-bit buffers, then a two-bit mode. Out-of-range
unsigned enums run the existing diagnostic wrapper before encoding; the first
kind remains captured across formatting. Disjoint diagnostic256/arguments8 scratch
replace stack locals and varargs.

Release/UBSan each pass512 original-instruction comparisons (1,024 total). Original
bitstream and formatting-wrapper bodies execute; only the CRT formatter is
controlled. Full memory, bitstream errors/positions, diagnostic scratch, format
arguments and stack balance match. Tests cover all bit offsets0..31, short/full
buffers, sticky errors, valid/invalid/high-bit enum values. Evidence:
`analysis/xita-engine-parameter-block-reference.json`. This is a standalone preview,
not the complete type33 encoder or a validated parameter broadcast.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_parameter_block.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_parameter_block_preview.so
.tools/venv/bin/python tests/network_parameter_block_oracle.py
```

Remaining type33 dependencies include `00063690` and text serializers
`0007c5a0`/`0007cc50`, then the encoder body itself. Main remains380 with
regression7210 running and fully audited checkpoint377. Playable startup remains
unfinished.


Dependency correction: `0007c5a0` and `0007cc50` are structured-record serializers
that include UTF-16 names and additional fields, not merely text serializers.
Initial instruction review shows nested serialization and conditional fields;
full recovery remains pending.

Reviewed all original instructions of `00063690` through its ret8 at `0006396e`
and drafted `h2_network_parameter_lists_write`. Its two signed-count loops encode
64-bit IDs, optional 96-bit identities, raw32 fields, then a second list with96-bit
IDs and five-bit values plus optional seven-/thirty-bit fields. The inline boolean
writer only sets true bits and advances position even when capacity is exhausted;
it must not be replaced by a generic bit writer that clears false bits. Count and
field bounds retain diagnostic calls via the recovered formatter wrapper. Three
256-byte diagnostic buffers and eight-byte varargs scratch replace stack storage.

The draft compiles with strict warnings but is NOT differentially validated or
integrated. Complete Xita cross-review remains pending. Required tests include
empty/negative/bounded counts, counts at diagnostic boundaries, absent/present
identities, optional-value sentinels and bounds, all bit offsets, short buffers,
preexisting true bits on false writes, and diagnostic callback mutation/capture.
No progress count or broadcast-validation claim follows from compilation.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_parameter_lists.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_parameter_lists_draft.so
```

Main380 regression7210 remains live; audited checkpoint377. Full parameter encoder
and live broadcast/playable Linux startup remain unfinished.


Parameter-list writer `00063690` now passes512 Release and512 UBSan original-
instruction comparisons (1,024 total), with complete Xita translation cross-review.
Current source/library/dependency hashes pass audit in
`analysis/xita-engine-parameter-lists-reference.json`. The header now marks a tested
preview rather than an unvalidated draft; it is still outside main integration.

Tests compare full guest memory, stack purge, all768 diagnostic scratch bytes,
and CRT callback arguments/stream snapshots. Original bitstream routines and
formatting wrapper execute; only the CRT formatter is controlled. Cases include
counts0/1/2/15/16/31/32 and signed negatives, optional identities and numeric
sentinels, boundary/invalid values, all bit offsets0..31, short/full buffers,
sticky errors, nonzero output bytes, and callbacks mutating both counts. Fixed
layout arrays can overlap at larger counts; both executions use identical guest
storage and no synthetic bounds clamping. No full parameter-encoder or live
broadcast claim follows from this helper's validation.

```sh
.tools/venv/bin/python tests/network_parameter_lists_oracle.py
```

Main380 regression7210 remains live; audited checkpoint377. Next work is the
structured serializers `0007c5a0`/`0007cc50`, followed by the full type33 encoder.
Playable Linux startup remains incomplete.


Reviewed the complete original `0007c5a0` serializer through ret4 at `0007ca69` and
drafted `h2_network_parameter_record_write`. It writes the bounded32-code-unit
UTF-16 name, nested configuration fields, optional96-bit identity with a second
bounded16-code-unit name, optional signed byte/word/dword fields, then final mode,
positive-signed-byte flag and three-bit value. Inline boolean writes preserve
existing false bits and advance position despite insufficient capacity.

Dependency finding: `0007ee10` is already cataloged as
`h2_message_config_fields_write`, but its current implementation omits original
out-of-range diagnostic calls. This draft retains nested diagnostics using the
existing formatter wrapper and separate256-byte scratch. It does not alter the
integrated implementation while regression is running. Differential tests must
cover both valid fields and diagnostic behavior before choosing shared integration.

The new record serializer compiles with strict warnings but has NOT passed
original-instruction comparisons or full Xita cross-review. It remains a draft
outside main380. Required next checks: original main/nested diagnostic scratch,
reentrant formatting, short buffers/nonzero bits, UTF-16 termination and maximum
length, all optional sentinels, sign extension, and nested bitstream operations.

```sh
cc -O2 -std=c11 -Wall -Wextra -Wpedantic -Werror -fPIC -shared \
  -Iinclude -Isrc src/network_parameter_record.c -Lbuild -lhalo2_engine \
  '-Wl,-rpath,$ORIGIN' -o build/libhalo2_parameter_record_draft.so
```

Main380 regression7210 remains live; audited checkpoint377. Full type33 encoding,
parameter broadcasts and playable Linux startup remain incomplete.


Structured parameter serializer `0007c5a0` now passes512 Release and512 UBSan
original-instruction comparisons (1,024 total). Original nested `0007ee10`,
bitstream routines and diagnostic wrappers execute; only CRT formatting is
controlled. Tests compare full memory, stack purge, both256-byte diagnostic
buffers, callback arguments and stream snapshots. They cover UTF-16 early/max
terminators and nonzero tails, absent/present identities, optional signed-byte,
signed-word and dword sentinels, invalid enum values, short/full bit buffers,
all bit positions0..31, sticky errors and callback mutation of a later field.
Current source/library/dependency hashes are audited in
`analysis/xita-engine-parameter-record-reference.json`.

Full Xita cross-review remains pending (`f_0007C5A0` in `code_016.c`), and the
serializer remains outside main integration. These comparisons establish bounded
serializer behavior, not the full type33 encoder or a live broadcast. The larger
`0007cc50` serializer and type33 encoder body remain unrecovered. Main380 regression
7210 continues; audited checkpoint377. No playable Linux startup.

```sh
.tools/venv/bin/python tests/network_parameter_record_oracle.py
```


2026-10-02: completed full Xita cross-review of parameter-record writer
`0007c5a0` against the reviewed original instructions and native implementation.
The preview covers optional signed fields, preserved false bits, nested diagnostic
buffers, and post-callback field reloads. It remains outside main integration.

Mapped the larger writer `0007cc50`: its direct callees are `000b66f0`,
`00195720`, and the still-uncataloged `001947e0`. The initial tag at record+0x44
controls early exit and an indirect variant dispatch; reachable paths extend
beyond the first return. Original jump-table targets and the packing helper
require verification before recovery. Local dependency evidence is recorded in
`analysis/parameter-large-dependencies.json`; no generated Xita code is published.
Main380 regression7210 remains running; the latest fully audited checkpoint is377.
The full type33 encoder, live broadcast, and playable Linux startup are incomplete.


2026-10-02: main regression session7210 exited0. Audited all272 reports against
current Release/UBSan libraries, host hashes where recorded, source hashes and
pinned XBE. Both ABI catalogs have380 unique routines; Ghidra annotations report
380 and mapping verification passes. Evidence: `analysis/engine-checkpoint-380.json`.

Recovered checked bit writer `001947e0` as an unintegrated preview. Full original
instruction and Xita `code_047.c` review confirms an unsigned value bound check,
a signed width comparison, x86-masked shift and unconditional downstream write.
This is not signed-value packing. Widths including0,31,32,33,63 and negative-bit
patterns, value boundaries, partial buffers and callback changes to stream state
pass2,048 Release plus2,048 UBSan comparisons. Diagnostic scratch, full memory,
callback arguments and ret4 stack behavior match. Only CRT formatting is controlled.
Evidence: `analysis/xita-engine-bitstream-checked-reference.json`.

For `0007cc50`, decoded original instructions at699 Xita-listed addresses; their
mnemonics agree. The original dispatch table contains zero targets for tags5/6
and concrete branches for1/2/3/4/7/8/9. Do not invent default handling for invalid
tags. Full operand/control-flow review and serializer implementation remain next.
The complete type33 encoder and playable Linux game remain unfinished.


Recovered `0007cc50` parameter variant serializer as an unintegrated preview.
All valid tags0/1/2/3/4/7/8/9 pass1,024 Release and1,024 UBSan comparisons.
Original instructions were reviewed through the out-of-line variant paths.
The implementation preserves UTF-16 termination, signed field extension, field
ordering, final tag reload and diagnostics from both inline fields and nested
`001947e0`. Tag8 writes its f2 word before rejoining the f4-word path; tag9 writes
two extra signed words before the tag1 path. Tests compare full memory, parent
256-byte diagnostic scratch, formatter calls, stream snapshots and ret8 behavior,
including callbacks that change the final tag and a later field. Unsupported
tags abort natively; equivalence to original invalid indirect-jump faults is not
claimed. Full translated-Xita C cross-review remains pending.

Evidence: `analysis/xita-engine-parameter-variant-reference.json`. The type33
encoder `000af890` now has tested previews for its four structured dependencies
`00063690`, `0007c5a0`, `0007cc50`, `000b2330`; remaining direct callees are already
recovered. The encoder itself still needs recovery and composed validation before
parameter broadcasts can execute. Main remains the audited380-routine checkpoint;
no playable Linux startup yet.


Drafted full type33 parameter encoder `000af890` and obtained256 Release plus256
UBSan composed original-instruction comparisons. Its four structured callees run
natively; the original executes corresponding engine bodies. Only CRT formatting
is controlled. The test compares full guest memory, both parent diagnostic buffers,
formatter arguments/stream snapshots and ret12 behavior. Mixed flags, short/full
buffers, random strings, valid nested variants, sentinel baseline versions and
callback mutation of a later tagged payload are included. Full field-isolation
and explicit string-boundary coverage remain to add; this initial pass is not a
complete encoder validation claim.

Xita's1,524-instruction listing supplied the control-flow reference; each original
instruction was decoded with mnemonic agreement. Full operand and translated-C
cross-review remain pending, including the variant serializer. The draft is not
registered in native message dispatch, so the broadcast preflight still correctly
rejects type33. Evidence: `analysis/xita-engine-parameters-encode-reference.json`.
Main remains the audited380-routine checkpoint; playable Linux startup remains
incomplete.


Expanded type33 composed encoder validation to2,048 cases per build (4,096 total),
including800 single-top-level-flag/starting-bit combinations (25 flags x32 bits),
all-present and mixed flags, secondary flag gates, early/max/no string terminators,
16-record loops, mask boundaries and diagnostic callbacks mutating future fields.
Each build executes641 list serializers,1,152 variant serializers,10,023 record
serializers and640 block serializers, with197,808 formatting calls. Full memory,
parent scratch and callback comparisons pass in Release and UBSan; current source,
library and dependency hashes audited. Detailed counters are in the refreshed
`analysis/xita-engine-parameters-encode-reference.json`.

Dispatch inspection identified an integration requirement: the current native
codec context provides clock and scratch, but no formatting operations. Type33
must carry the real formatter boundary and1280-byte diagnostic plus8-byte argument
storage through its adapter. Do not register it by silently discarding diagnostics.
Full Xita/operand review is still pending. Main remains the audited380-routine
checkpoint and there is no playable Linux startup.


Connected the parameter encoder to a preview native codec adapter carrying explicit
formatting operations,1280-byte diagnostics and8-byte arguments. Existing message
encoders delegate to main dispatch; type33 invokes the composed native encoder.
The main codec ABI and audited380-routine build are unchanged.

Parameter broadcast `000627e0` now passes1,024 Release and1,024 UBSan comparisons
through actual full/delta constructors, observer gates, reliable queues and type33
encoding. Per build:221 full snapshots,124 delta snapshots,48 deferrals,614 queue
poll/allocation pairs and490 diagnostic formatting calls. Full guest memory,
callbacks, snapshot payloads and reliable/local scratch match. SDK, virtual queue
and CRT formatting boundaries are controlled; engine callees are not stubbed.
Source/library hashes audited in
`analysis/xita-engine-session-parameters-broadcast-reference.json`.

This removes the previous missing-encoder preflight obstacle in the preview
broadcast fixture. Full Xita review, main integration, broader session-state
composition and playable Linux startup remain unfinished. These bounded tests do
not establish a live networking backend or a runnable game.


Completed full Xita translated-C review of tested parameter broadcaster `000627e0`:
captured peer revisions, deferred-message handling, full-before-delta construction,
revision stamping before active-peer recheck, loop count reloads and final0x14b0
copy agree with the native implementation. Existing2,048 composed comparisons
remain current; main integration still awaits the encoder/variant review.

Mapped the next session dependency: state8 completion `00061e00` calls membership
broadcast `00062640` as well as parameter broadcast. Membership broadcast requires
snapshot constructor `00060400` and type25 encoding. Its snapshot constructor uses
peer changes `000602b0`, now recovered as a preview with2,048 Release plus2,048
UBSan comparisons. Null/equal/current-aliased baselines, single-byte/sparse changes,
all five flags both ways, UTF-16 terminator/truncation/tail cases and nonzero output
seeds pass with original CRT routines intact. A first failing case exposed missing
UTF-16 zero padding; corrected and rerun successfully. Unchanged flags and output
bytes are preserved. Full translated-C review remains pending for this helper.
Evidence: `analysis/xita-engine-peer-changes-reference.json`.

The larger membership constructor and type25 encoder remain unrecovered. Main is
still the audited380-routine checkpoint; no playable Linux game yet.


Recovered membership snapshot constructor `00060400` as an unintegrated draft.
The implementation builds bidirectional peer identity maps, emits removals before
new/changed peers, preserves moved-peer indices, delegates changed peer fields to
`000602b0`, and constructs player removal/add/change records with owner remapping.
The output is0x489c bytes; input records and output must be disjoint, peer counts
are bounded to16 and player owner indices must be valid.

1,024 Release plus1,024 UBSan comparisons pass with original peer-change and CRT
callees intact. Full guest memory and ret12 match for null/equal/current-aliased
baselines, reordered peers, identity removal/addition, masks and player payload
changes. All source/library/dependency hashes audited in
`analysis/xita-engine-membership-snapshot-reference.json`. Xita's416-instruction
listing was reviewed and original instruction sites decoded with mnemonic
agreement; full operand and translated-C cross-review remain pending.

Membership message registration identifies type25 encoder `000adef0` and decoder
`000ae7f0`, both separate from type33. Encoder recovery is required before composing
membership broadcaster `00062640` and state8 completion `00061e00`. Main remains
the audited380-routine checkpoint; no playable Linux startup yet.


Drafted type25 membership encoder `000adef0`. Its peer and player loops preserve
signed16-bit count reloads, optional index sentinels, independent diagnostic
buffers, UTF-16 names, structured peer payloads and two nested record serializers
per populated player. The ignored size argument and ret12 match the original ABI.
Scratch requires0xd00 diagnostic bytes and8 argument bytes, disjoint from payload
and bitstream buffers.

512 Release plus512 UBSan composed comparisons pass. They cover zero/short/full
buffers, starting bit positions, sticky errors, signed count boundaries including
negative counts and32 records, enum bounds, optional peer indices and formatting
callbacks mutating both loop counts. Full guest memory,11 parent diagnostic
buffers and callback arguments match; original engine callees run with only CRT
formatting controlled. Current source/library hashes audited in
`analysis/xita-engine-membership-encode-reference.json`.

The720-instruction Xita listing was reviewed and original sites decoded with
mnemonic agreement. Full operand/translated-C review, broader field-isolation
coverage, codec adapter registration and membership broadcast composition remain
pending. Main remains the audited380-routine checkpoint; game startup is incomplete.


Connected type25 through a preview membership codec adapter and recovered
membership broadcaster `00062640`. It preserves full/delta mask selection,
constructor order, peer revision stamps, reloaded peer counts and the final0x2494
baseline copy. Adapter context diagnostics require0xd00 bytes plus disjoint8-byte
arguments; other message types delegate through the existing preview adapter.

1,024 Release and1,024 UBSan composed comparisons pass. Each build exercises221
full snapshots,124 delta snapshots,48 deferrals and2,097 reliable queue poll/
allocation pairs. Actual snapshot constructors and encoder bodies execute; no
engine callees are stubbed. Full memory, payloads, queue/local scratch and callback
snapshots match. The fixture uses bounded peers, fresh writers and controlled SDK/
virtual queue boundaries; no live network claim. Hash audit evidence:
`analysis/xita-engine-session-membership-broadcast-reference.json`.

Main remains the audited380-routine checkpoint. Full Xita review of the membership
path and broader composition remain pending. Both snapshot broadcast dependencies
of state8 completion `00061e00` now have passing composed previews, enabling its
recovery next. Playable Linux startup remains incomplete.


Recovered state8 host completion `00061e00` as a composed preview. It sends
migration requests, checks the completed-peer mask or signed wrapped timeout,
captures shutdown/handoff flags, enters host state, evicts selected nonlocal peers
in reverse index order, broadcasts membership then parameters, and finally follows
the captured shutdown/handoff decision. Full Xita body and previously decoded
original listing reviewed; dependency reviews remain outstanding.

1,024 Release plus1,024 UBSan comparisons pass. Per build:730 host completions,
298 peer removals,232 full/92 delta membership snapshots,70 deferrals,2,505 reliable
queue poll/allocation pairs,1,071 clock calls and430 sends. Full memory, callback
snapshots and nested scratch compare against original execution. The initial
fixture lacked type33 registration; registering both message families fixed the
original's invalid callback fetch. No engine callees are stubbed. Evidence:
`analysis/xita-engine-session-host-completion-reference.json`.

This is still a preview outside the audited380-routine main build. Broader
transition-specific coverage, remaining dependency reviews and main integration
are pending. There is no playable Linux game yet.


Expanded host-completion validation to2,048 cases per build (4,096 total).
Explicit original-instruction coverage now confirms505 shutdown transitions,
333 handoff transitions and742 wait returns per build. Signed deadline edges
include exact equality and wrapped/sign-boundary elapsed values. Queue callbacks
mutate stored shutdown/handoff flags8,746 times after host entry; captured decisions
still match original execution. Eviction indices are checked for descending order.
Full memory, callback and nested scratch comparisons pass in Release and UBSan;
current source/library hashes audited in the refreshed host-completion evidence.

Completed full translated-Xita review of peer-change constructor `000602b0`:
UTF-16 comparison/copy bounds, forced terminators, grouped change flags and baseline
reloads agree with the native implementation and original-execution evidence.
Its prior4,096 comparisons remain current. Main remains the audited380-routine
checkpoint; remaining large serializer/constructor reviews and integration are
still required before the complete session update loop can be assembled.
No playable Linux startup yet.


Completed full translated-Xita review of membership constructor `00060400`,
including both peer mapping arrays, removal-before-addition ordering, last-match
behavior for duplicate identities, owner remapping and both player payload blocks.
No native code correction was required. Expanded the fixture to2,048 cases per
build, adding unequal current/baseline peer counts, duplicate identities, changed
player identities/owner metadata and changes in the second payload block/final
word. All4,096 Release/UBSan comparisons pass; source/library hashes audited in
`analysis/xita-engine-membership-snapshot-reference.json`.

The constructor and its peer-change helper now have full Xita reviews. Large
encoder/variant reviews and main integration remain pending. Main remains the
audited380-routine checkpoint; playable Linux startup remains incomplete.


Integrated reviewed constructors `000602b0` and `00060400` into CMake, native ABI
catalogs and both Release/UBSan test passes. Audited8,192 standalone comparisons
before changing defaults/headers; evidence archived in
`analysis/engine-preview-membership-constructors-audit.json`. Catalogs now contain
382 unique original routine addresses. Expanded full regression session66057 is
running (expected276 reports). Ghidra annotation refresh exited successfully with
382 annotated routines, eight allocator call overrides and five key call overrides.
The previous fully audited checkpoint remains380 until the new run exits and all
reports are checked. Playable Linux startup is still incomplete.


Completed the full Xita/original-instruction review of membership broadcast
`00062640` (136 decoded instruction sites). Confirmed captured peer revisions,
signed/reloaded loop bounds, deferral handling, full-before-delta construction,
delta selection priority, revision writes before active checks and the final
forward snapshot copy. No native correction was needed. The existing 2,048
standalone comparisons remain historical evidence from before the 382-routine
integration; their library hashes do not validate the current build. Large
encoder reviews remain pending before broadcast integration. Main regression
session 66057 remains live; no new fully audited checkpoint is claimed.


Completed the full Xita translated-C and original operand review of membership
encoder `000adef0` (720 instruction sites). Confirmed field layouts and widths,
signed count reloads, UTF16 bounds, optional-word sentinels, false-bit preservation,
captured diagnostic values, all 11 parent diagnostic buffers and nested record
ordering. No native correction was required. Expanded its differential fixture
to 1,024 cases per build, adding 16 isolated field groups at every bit alignment.
All 2,048 Release/UBSan comparisons pass with current source and library hashes
audited in `analysis/xita-engine-membership-encode-reference.json`. The encoder
remains outside the main build; integration and composed-path revalidation are
pending. Main regression session 66057 remains live at this checkpoint.


Expanded parameter variant serializer `0007cc50` to 2,048 cases per build.
Added every valid tag at all 32 bit alignments with zero, field-limit and
overflowing values, retaining the original randomized cases and callback
mutations. All 4,096 Release/UBSan comparisons pass; current source and library
hashes audited in `analysis/xita-engine-parameter-variant-reference.json`.
Rechecked the complete original operand listing against the native field order;
no correction required. Full translated-Xita C review remains pending, so the
serializer stays outside the main build. The 382-routine regression remains live.


Completed the full translated-Xita C review of parameter variant serializer
`0007cc50`, checking all 699 original instruction sites and the original nine-entry
jump table. Confirmed computed enum widths, signed byte/word handling, captured
diagnostic values, tag reloads after callbacks, zero-tag return and all seven
nonzero valid branches. No native correction was needed. Re-audited the existing
4,096 comparisons against current sources and libraries. Unsupported tags remain
outside the fidelity claim. The large type-33 encoder review remains pending;
reviewed serializers have not yet been added to the main 382-routine build.


Completed the original operand review of type-33 encoder `000af890` across
1,524 instruction sites. Confirmed all 25 top-level flags, serialized field order,
signed transforms, string bounds, nested serializer arguments, 16-record loop,
mask/tag reloads after callbacks and two parent diagnostic offsets. No correction
was required. The separate translated-Xita C review remains pending. Earlier
4,096 comparisons remain historical evidence until the composed encoder is
revalidated against the current build. Main regression session 66057 is still live.


Completed the type-33 encoder Xita cross-review, inspecting distinct translated
operations/branches against the previously reviewed original instruction order
and checking immediate PUSH constants. No native correction was required.
Rebuilt the composed encoder against the current main libraries and reran both
suites: all 4,096 comparisons pass, with source/library hashes audited. The
reviewed serializer dependencies now support preparing main integration once the
ongoing 382-routine regression completes. This does not establish live networking
or playable Linux startup.


Prepared an isolated 389-routine integration candidate at
`/tmp/halo2-integration-389`, adding the seven reviewed checked-bitstream and
parameter/membership serializers to CMake and the original ABI catalog. Both
Release and UBSan shared-library/host builds succeeded. Source/header bytes match
the worktree; only candidate CMake and ABI catalogs differ. Seven differential
suites per build are running against these combined libraries (sessions 94647
and 56247). Main remains at 382 while its regression session 66057 runs. The
candidate is not yet integrated or claimed fully validated.


All fourteen serializer suites passed against the isolated 389-routine candidate:
17,408 comparisons in Release/UBSan, with report/source/library hashes audited in
`analysis/integration-389-candidate.json`. The seven serializers therefore pass
as part of one combined engine library. Built the host-completion preview against
that candidate and started its composed differential suite in both configurations
(sessions 7846 and 80091), exercising membership and parameter broadcasts together.
The main 382-routine regression remains live; neither whole-engine regression nor
playable Linux behavior is established by this candidate validation.


The composed host-completion suites also passed against candidate389: 4,096
Release/UBSan comparisons, with current report/source/library hashes audited.
Drafted outer session coordinator `0005a090` from the original instructions and
verified its nine-entry dispatch table. The draft connects recovered join, leave,
cleanup, handoff, host completion, migration, disconnect, status, reservation,
eviction, maintenance and broadcast paths, preserving state/count reloads. It
passes strict C11 syntax checks only; differential validation is still required,
and the handoff math limitation remains. This draft is outside the main build
and ABI catalog. Main382 regression continues in session66057.


Audited all 276 main382 reports against current sources, native libraries, host,
XBE, ABI annotations and mapping. Preserved the exit-code limitation in
`analysis/engine-checkpoint-382.json`. Integrated the seven serializer sources,
ABI entries and both test passes after the isolated candidate's 17,408 serializer
and 4,096 host-completion comparisons. Main now has389 routines. New full regression
session35843 writes `analysis/engine-validation-389.log` and an explicit `.exit`
file on termination; expected290 reports. Ghidra annotation refresh started.
No gameplay or completion percentage is claimed.


The Ghidra389 refresh exited0 with389 annotated routines. Added an isolated
differential fixture for session coordinator `0005a090`: all fourteen engine
callees are controlled equally in the original and native runs. Tested dispatch
order, full persistent memory, callee arguments/snapshots, state changes after
dispatch/disconnect/expiry/maintenance and peer-count changes during eviction.
Both suites exited0 after fixing a missing report-writer import: 8,192 comparisons
pass with current source/library hashes audited. This validates coordinator
control flow only; composed-callee validation and handoff math fidelity remain
pending. The coordinator stays outside main389. Main regression35843 remains live.
