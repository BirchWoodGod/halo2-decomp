# Engine investigation

These are preliminary interpretations of the local retail XBE, supported by
string references and generated pseudocode. Names below are descriptive working
names, not recovered original symbols. Calling conventions and types are still
unverified except the data-array ABI below, which is applied in Ghidra and tested
against original instructions. Addresses refer to the SHA-256 recorded in README.md.

| Address | Working interpretation | Evidence |
| --- | --- | --- |
| `0x001DFAE0` | AI actor storage initialization | Allocates storage labeled `actor`, reserves `0x640` bytes from an arena, and registers `actor firing-position owners` |
| `0x00257D00` | AI command-script storage initialization | Allocates two containers labeled `command scripts` and `joint command scripts` |
| `0x001C2910` | BSP-to-Havok setup | Enters a scope labeled `building havok representation for bsp` and calls into physics-related allocation and object setup |
| `0x001CEC30` | Havok component storage initialization | Allocates a container labeled `havok components` and stores its address globally |
| `0x00188D60` | Scripted dialogue-related initialization | Conditional registrations include `scripted_dialog_player`; exact role needs callers/types |

## First useful shared abstraction

The actor, command-script, and Havok-component candidates share this pattern:

1. Obtain a pointer through an indirect allocator call.
2. Pass the allocation, diagnostic name, and allocator to `0x0016B5F0`.
3. Set bit `0x04` in a byte at allocation offset `0x2A`.
4. Save the allocation in a global.

Instruction inspection of `0x0016B5F0`, its helper `0x0016B650`, and the actor
and command-script callers supports the following initial layout and ABI.
The meaning of the flag remains unresolved.

### Custom calling convention at `0x0016B5F0`

| Input at function entry | Observed use |
| --- | --- |
| `ECX` | Alignment exponent; alignment is `1 << CL` using x86 shift semantics |
| `EDX` | Element stride in bytes |
| `EBX` | Element capacity |
| `[ESP+4]` | Container allocation address |
| `[ESP+8]` | Diagnostic name |
| `[ESP+12]` | Allocator/context pointer |

The function returns with `ret 0xC`. Ghidra's original automatic prototype omitted
`EBX`, hiding important arguments. `AnnotateDataArray.java` now applies custom
parameter storage from `config/data_array_abi.json`, and refreshes direct callers.

The initializer rounds `allocation + 0x4C` upward to the requested alignment,
uses that as the element-storage address, places a bitmap immediately after
`capacity * stride` bytes, and clears `ceil(capacity / 32)` bitmap words.
For the inspected callers, the alignment exponent is zero.

| Container | Capacity (`EBX`) | Stride (`EDX`) | Allocation size |
| --- | --- | --- | --- |
| AI actors | 256 | `0x888` | `0x8886C` |
| Command scripts | 40 | `0xD4` | `0x2174` |
| Joint command scripts | 10 | `0x8C` | `0x5C8` |

All three sizes independently match
`0x4C + capacity * stride + 4 * ceil(capacity / 32)`.
Actor arguments are set at `0x001DFB02`–`0x001DFB09`; command-script arguments
at `0x00257D21`–`0x00257D28` and `0x00257D5A`–`0x00257D61`.

### Initial x86 container header fields

Offsets below come from stores in the helper at `0x0016B650`, which first clears
`0x4C` bytes. This is an incomplete layout, and pointers here are 32-bit guest
addresses, not native host pointers.

| Offset | Size | Observed value/use |
| --- | --- | --- |
| `0x00` | 32 bytes | Copied diagnostic name, terminated at byte `0x1F` |
| `0x20` | 4 | Capacity |
| `0x24` | 4 | Element stride |
| `0x28` | 1 | Alignment exponent |
| `0x29` | 1 | Initially zero; lifecycle meaning unresolved |
| `0x2A` | 1 | Flags; helper sets low two bits, outer initializer clears them |
| `0x2C` | 4 | Constant `0x64407440` |
| `0x30` | 4 | Allocator/context pointer |
| `0x44` | 4 | Element-storage pointer, assigned by outer initializer |
| `0x48` | 4 | Bitmap pointer |

The structure and custom register storage are now modeled in Ghidra. Sixteen
initialization, allocation, lookup, deletion, and iteration routines have native C
implementations in `src/data_array.c`, tested against the original x86 machine
code. A set bitmap bit means an occupied slot during normal operation. Each
element's first 16 bits hold its salt; a handle combines that salt with the
16-bit slot index. Generation rollover skips `0xFFFF` in normal allocation.
Deletion uses the index without checking the supplied salt; lookup validates it.
Free-element fill with `0xBA` is controlled by flag bit `0x08`.

`0x34` is the allocation search start, `0x38` the high-water bound, `0x3C` the
occupied count, and `0x40` the next salt. The rebuild routine reconstructs the
bitmap and counts from nonzero element salts. Explicit-handle allocation accepts
a zero salt, producing a bitmap/salt inconsistency until rebuild; the native code
preserves this edge behavior. These routines assume valid engine allocations and
are not generic checked container APIs.

AI actor initialization also calls `0x0013E1A0` for firing-position ownership.
Its convention is likewise nonstandard and must be recovered before interpreting
the apparent argument list in generated C.

## Port boundary

Retain engine behavior above interfaces for memory, files, scheduling, input,
audio, and rendering. Start by recovering pure data manipulation routines and
their inputs/outputs. Physics integration calls into Havok and may require its
own compatibility work; the engine does not become portable just by excluding
the separate `D3D` section.

Use `analysis/engine-candidates.tsv` to expand these leads and
`analysis/calls.tsv` to inspect known direct callers/callees. Always check the
corresponding instructions before accepting pseudocode types or control flow.

## Startup and engine dispatch

The entry at `0x002D0AEE` passes callback `0x002D0A7A` through the thread-creation
wrapper at `0x002D21C6`. The wrapper calls `PsCreateSystemThreadEx` and also supplies
trampoline `0x002D212E`. The callback performs CRT/XAPI setup before calling
`0x00012190`. That game entry calls initialization (`0x00012000`), main loop
(`0x0012B690`), and cleanup (`0x00012080`). These are working role descriptions.

The main loop initializes subsystem callbacks through `0x00137C20`, then calls
`0x0012B450` repeatedly while byte `0x00547F2B` is zero. On exit it traverses
shutdown callbacks in reverse. Initialization walks `0x00440DD8` at stride `0x24`
for `0x990` bytes: 68 subsystem entries. Shutdown uses the second pointer of each
entry, from `0x00441748` down to `0x00440DDC`. The other seven callback columns
still need call-site and signature analysis.

`DiscoverEngine.java` seeds functions from this bounded table and the observed
thread callbacks. These are concrete engine roots missed by purely direct-call
discovery. The startup path has not executed in a Linux game runtime; it still
depends on Xbox threading/TLS, physical memory, graphics, files, and other services.

### Reviewed function boundaries and switches

Two lifecycle-table callbacks were originally absorbed into predecessor functions
because the predecessor tail-jumps to them. The boundaries at `0x0008DD70`
(jump at `0x0008DD67` from `0x0008D9F0`) and `0x0020A750` (jump at `0x0020A743`
from `0x0020A700`) are now split. Both targets independently occur in the lifecycle
table. The script restricts this repair to those reviewed source/target pairs;
other overlapping bodies remain reportable conflicts.

Two failed decompilations were unguarded enum switches. `0x00068C19` indexes five
pointers at `0x00068DA8`; `0x001E5AFA` indexes six at `0x001E5B30`. Both decrement
the input enum before indexing. The second table's last three entries share a
return epilogue. `RecoverSwitches.java` verifies the exact table contents and
provides the destinations to Ghidra, with pointer data explicitly separated from
instructions. This does not add runtime bounds checks or establish behavior for
out-of-range enum values. The generated C switch default is not evidence that
the original safely handles such values.

After these repairs, all 11,390 currently discovered main-section functions
export pseudocode. That inventory remains incomplete and is not a 100% source
recovery claim. The 16 reconstructed container routines pass 10,510 differential
comparisons in both optimized native and undefined-behavior-sanitized builds.

## Native allocator and first host integration

Four additional original functions now have native implementations:

| Original address | Native function | Verified behavior |
| --- | --- | --- |
| `0x0016B570` | `h2_data_create` | Allocation-size calculation, constructor arguments, owned flag, allocation failure |
| `0x0016B5D0` | `h2_data_dispose` | Saves allocator identity, clears all `0x4C` header bytes, invokes free if identity is nonzero |
| `0x00257D00` | `h2_command_scripts_initialize` | Creates the 40-entry and 10-entry script pools; preserves allocator reread/global-write order and partial failures |
| `0x001CEC30` | `h2_havok_components_initialize` | Creates 512 entries of stride `0xA0` at alignment exponent 4, stores result at `0x0051E9B8` |

The data constructor has `capacity` in `EAX`, allocator object in `EDI`, and
name/stride/alignment at stack offsets 4/8/12; it returns in `EAX` and pops 12
bytes. The disposer receives the array in `ESI`. Their allocator calls use
`ECX=this`, one stack argument, and callee cleanup of four bytes. Eight explicit
call-site prototype overrides correct Ghidra's previous four-byte stack drift.
Without that correction the constructor's generated pseudocode misleadingly
treated the name as a return address. The ABI catalog is `host_bridge_abi.json`.

The Linux heap and image mapper are host implementations, not recovered Xbox
kernel source. They provide a single guest arena with coalescing free spans.
The host accepts only the pinned executable hash, reserves and copies its image,
then runs the three recovered pool initializers using native allocator callbacks.
It does not enter the Xbox thread startup path or run an instruction interpreter.

Verification adds 289 create/dispose comparisons, 3,000 Linux heap stress
operations, and 26 full-memory pool-initialization comparisons covering all
allocation-failure combinations and allocator identity changes. Image mapping is
independently compared with the Python parser; six invalid/repeated load cases
are rejected. Both release and undefined-behavior-sanitized builds pass, as does
the standalone `--probe-pools` executable. This proves only these tested modules.

## Actor initialization, owner tables, and CRC

Ten further routines bring the recovered total to 30:

| Original address | Native function |
| --- | --- |
| `0x001DFAE0` | `h2_actors_initialize` |
| `0x0013E1A0` | `h2_hash_create` |
| `0x0013E210` | `h2_hash_clear` |
| `0x0013E270` | `h2_hash_insert` |
| `0x0013E2D0` | `h2_hash_find` |
| `0x0013E320` | `h2_hash_remove` |
| `0x0025DD20` | `h2_actor_owner_hash` |
| `0x0025DD30` | `h2_actor_owner_equal` |
| `0x00163BA0` | `h2_crc_update` |
| `0x00163C00` | `h2_crc_table_initialize` |

Actor initialization allocates 256 records of stride `0x888`, reserves `0x640`
bytes from the existing engine arena, feeds that reservation size into the arena
CRC, then creates the 256-node firing-position owner table with 1,024 buckets
and four-byte payloads. The native probe supplies the arena explicitly; recovery
of the full arena lifecycle and AI behavior remains outstanding. Allocation
failure, allocator identity changes, and cold/warm CRC state are covered by
16 actor initialization cases within the 26-case pool suite.

The hash header is `0x3C` bytes: name at `0`, bucket count at `0x20`, capacity at
`0x24`, payload size at `0x28`, hash/equality callback addresses at `0x2C/0x30`,
allocator at `0x34`, and free-list head at `0x38`. Bucket pointers follow the
header, then nodes of `12 + payload_size` bytes. A node stores key, cached hash,
next pointer, and payload. Insert allows duplicate keys; lookup/removal select
the newest matching entry. Lookup checks the cached hash before equality;
removal only checks equality within its bucket. The actor callback hashes the
low key byte times four and compares full 32-bit keys. Native callback adapters
currently support those two recovered functions only.

CRC table generation uses reflected polynomial `0xEDB88320`. Update lazily
initializes the global table, performs no initial/final XOR, and skips data for
negative signed lengths while still initializing the table. It is an accumulator,
not an allocator. The host-byte adapter supports the actor initializer's local
four-byte reservation value and is not counted as an additional recovered routine.

`hash_crc_oracle.py` passes 1,299 original/native comparisons, including full
mapped-memory checks, collisions, duplicates, exhaustion, reuse, odd payload
sizes, empty data, and chunked CRC. Release and UBSan builds both pass. Five
indirect key-call overrides and the reviewed register/stack prototypes are saved
in Ghidra. These results establish tested infrastructure behavior, not AI
simulation, game boot, or complete engine equivalence.

## Recovered shared engine arena

Five more original functions are reconstructed in `src/arena.c` (now 79 total):
`00123B30` initializes the arena, `00123D40` reserves rounded space,
`00123D80` reserves aligned space, `00124700` implements the allocator's allocate
method, and `00072C70` is its shared no-op release method. The latter is a shared
return stub; its project name describes this use, not every caller's purpose.

The arena state is base `004E6080`, offset `004E6084`, CRC `004E608C`, initialized
byte `004E3B60`, and startup-state pointer `004E6094`. Initialization requests
`0x3BE000 + 0x40000` bytes, clears `0x3FE000` bytes, calls save-storage preparation,
reserves `0x1288` bytes of startup state and four bytes for the allocator object,
and installs vtable `00453498` at the object stored in `00510C2C`. It preserves an
existing offset; it does not reset that offset to zero. A nonzero initialized
byte skips the entire operation. The two platform calls remain external:
`00214F10` manages Xbox backing memory and `00214F80` prepares save-game files.
Their complete behavior has not been recovered or ported.

Ordinary reservations round `(size + 3)` down to a four-byte multiple. Aligned
reservations consume `(size + (1 << (bits & 31)) + 3) & ~3` bytes and align the
returned pointer. Both feed the consumed size, little endian, into the arena
CRC. Arithmetic wraps as 32-bit x86 arithmetic does. No capacity check or
individual reclamation is introduced: valid callers must keep reservations
within their backing memory. Host heap deallocation and this allocator have
different lifetimes.

The Linux diagnostic now invokes recovered initialization using host backing
memory, then uses the recovered arena allocator for command-script and actor
storage. Havok-component storage still uses its separate host allocator. Save
setup is explicitly omitted in this diagnostic; no game persistence is claimed.
At shutdown the diagnostic releases the entire backing allocation.

`arena_oracle.py` passes 711 comparisons in Release and UBSan. It compares original instructions and native C over the full
16 MiB test mapping. It covers cold initialization, repeated calls, nonzero
starting offsets, alignment exponents, arithmetic wraparound, the allocator
methods, and the combined initialization → command-script/actor allocation →
disposal path. On the original side the allocator vtable executes unchanged;
only the backing-memory and save-storage platform boundaries are controlled.

The arena lifecycle also now includes `00123BF0` (`h2_arena_dispose`) and
`00123C20` (`h2_arena_initialize_for_map`). Shutdown clears the byte at `005020D8`,
calls the save-storage closure boundary, then zeros `0x2540` bytes starting at
`004E3B60`. It does nothing when the initialized byte is zero. It does not itself
release the backing allocation; the diagnostic host owns that allocation.

Per-map initialization requests protection flags `4` over the first `0x3BE000`
bytes and `0x404` over the remaining `0x40000`. It clears transient global state
while preserving arena allocation metadata, initializes the `0x1288`-byte state
header, copies a bounded 256-byte name and 32-byte build string, and copies
`0x1118` bytes of game options from the structure referenced by `004E6948`.
This is state preparation, not map-file loading. Protection and save closure
remain explicit platform callbacks; the original platform implementations have
not been replaced by inferred success in the tests. The diagnostic does not
invoke per-map initialization because it does not yet load real game options.

The expanded arena suite has 711 comparisons, including 24 per-map cases and
72 shutdown cases. Both Release and UBSan pass. Tests cover empty and overlong
names, byte-sized writes adjacent to preserved state, option copying, idempotent
shutdown, full mapped-memory equivalence, and platform call arguments/order.

## Game lifecycle and options drivers

`src/game_lifecycle.c` reconstructs six routines: subsystem startup `00137C20`,
map initialization `00137CA0`, map disposal `00137D00`, structure initialization
`00137D40`, structure disposal `00137DA0`, and options copying `00137DD0`.
Startup invokes arena initialization, reserves/clears `0x1200` bytes of game
state, writes the global pointer at `004E6948`, initializes the structure index
to `0xFFFF`, requests FP control `(0x9001F, 0xFFFFF)`, and calls all 68 startup
slots in ascending order. Map/structure initialization traverses columns 2/4
forward; disposal traverses columns 3/5 backward. Those four columns skip null
callbacks. All slots are read when visited, not cached as a host-side list.

Options copying preserves forward dword-copy order over `0x1118` bytes. It clears
specific state flags, conditionally calls variant validation `0019D650` with
`EBX=state+0x13C`, reloads the global state pointer after validation, and writes
the value at state offset `0x18` through the pointer at `004E7408`. State pointers
are also reloaded at the instruction-reviewed lifecycle boundaries, allowing
callbacks to change them. The full variant validator remains unrecovered.

The native operations interface requires subsystem dispatch, FP control, and
variant validation. These are explicit dependencies, not no-op implementations.
The diagnostic host does not claim to run these drivers to completion: most
subsystem bodies are missing. `game_lifecycle_oracle.py` controls those boundaries
and verifies driver behavior with original x86 execution, full mapped-memory
comparisons, event ordering, state-pointer changes, and real/synthetic tables.
All 144 comparisons pass in Release and UBSan. They establish orchestration
behavior, not subsystem execution, game initialization, or map loading.

`scripts/audit-startup.py` reads the pinned XBE table and compares its direct
entrypoints to the native ABI catalogs. The resulting `startup-coverage.json`
reports 23/68 catalogued initialization slots, 39/68 disposal slots, 13/54
map-initialization slots, 26/54 map-disposal slots, 5/21 structure-initialization
slots, and 14/21 structure-disposal slots. Of these, respectively 20, 38, 12, 26,
5, and 14 slots point to the same shared no-op. Unique catalogued targets and
shared no-op slots are reported separately. This is deliberately not a completion percentage:
entrypoints can depend on other missing code, and many recovered helpers occur
below the direct table entries. The startup entry `0008D690`
now has a native implementation as described below. The return stub `00175F40` and random initializer `00146240` are now recovered;
the next missing startup entry is `0008D9F0`.

## Transport startup

Five routines in `src/transport.c` bring the recovered catalog to 48:
`0008D690` initializes transport, `0007A840` initializes address state,
`0007B3E0` constructs QoS storage, `0008D770` registers callbacks, and `0008D7C0`
checks whether transport is active. Names are project-assigned from usage and
embedded strings. The callback registry has eight slots in four parallel arrays
(start, stop, update, context). Registration preserves the original unchecked
count and individual index reloads; callers must provide valid capacity.

Initialization clears `0x88` bytes at `004D8B18`, initializes `0x144` bytes of
address state at `004CF790`, registers the original address callbacks, and
constructs a 32-entry, eight-byte-stride `transport qos attempts` pool using the
allocator at `00468758`. The QoS globals are cleared before the allocation call.
Allocation failure leaves the pool null but does not stop the link query.
The initialized byte is written before querying `0036C47D`; the result updates
`0055E704` and bit zero gates the tail call to online startup `0008D840`.
Online startup and the SDK query remain explicit required dependencies.

`transport_oracle.py` passes 82 comparisons in Release and UBSan. Cases include
allocation failure, matching/different cached status, link-bit combinations,
all valid callback indices, and noncanonical nonzero active flags. Four combined
cases run the original/recovered game initialization driver with the actual
transport initializer, controlling the other subsystem bodies. Full mapped
memory and network callback snapshots/order match. This replaces the controlled
transport callback in those integration tests; it does not implement network
connectivity, online startup, or full game boot. The standalone host probe still
exercises its documented pool/arena path only.

## Random state and direction selection

`src/random.c` reconstructs initialization `00146240`, seed generation `001462B0`,
direction selection `001462E0`, and the shared empty callback `00175F40`.
Initialization reserves eight arena bytes and publishes the pointer at `004E7408`.
The first word receives `0x78A8`. The second receives the XOR of three values,
obtained in order from CRT/SDK routines `00321AAE(0)`, `00321F75()`, and
`003314B0()`. The global pointer is reloaded after those calls. These source
routines remain external callbacks; a host entropy implementation is not claimed.

Direction selection advances the caller's 32-bit seed with
`seed = seed * 0x19660D + 0x3C6EF35F` modulo `2^32`. It selects index
`((seed >> 16) * 1026) >> 16` from the 12-byte-entry table at `004417F0` and
copies three words in original order, preserving their float bit patterns.
The nearby floating-point random rotation routine `00146320` is not yet recovered.

The 1,127-case random suite tests initialization, entropy call ordering, changes
to the state pointer during entropy callbacks, all 1,026 direction-table entries,
output/seed overlap, the shared return stub, and four combined startup cases.
The integrated cases execute the actual random initializer and shared return
stub; other subsystem bodies remain controlled. Release and UBSan both pass.
The shared stub counts as one recovered routine regardless of how many table
slots use it. These additions do not establish full startup or game playability.

## Network message registrations

Nine callees of `0008D9F0` are reconstructed in `src/network_messages.c`:
`000AC800` (discovery), `000ACB10` (connection), `000ADAB0` (session), `000AF680`
(membership), `000B2220` (parameters), `000B2680` (simulation), `000B2B30`
(synchronous), `000B2CC0` (results), and `000B2DE0` (test). These project-assigned
group names follow embedded message names. Each receives the table in `EAX`.
Together they populate 45 records of 32 bytes, spanning `0x5A0` bytes.

Each record contains an active byte, three untouched reserved bytes, a guest
name pointer, a flags word, two size fields, and three guest callback addresses.
The synchronous-game-state record uses flags 1 and size fields 8/65535, unlike
most records whose size fields match. Callback addresses remain metadata;
these routines do not implement the encoder/decoder bodies or networking.

`config/message_descriptors.json` retains the original instruction listings,
write traces, decoded names, and constants. The extraction script at
`scripts/recovery/extract_message_descriptors.py` reproduces that evidence from
the pinned executable. The original routines are straight-line stores with
register constant setup and stack preservation; they have no calls or branches.
The native implementation expresses the same bounded table updates as constant
descriptors and preserves reserved bytes. It reorders independent stores within
a record; the API assumes a valid ordinary-memory table, without concurrent
observers or aliasing executable code. It does not execute original code.

`network_messages_oracle.py` runs all nine originals without replacement calls
and compares the complete mapped memory against native C over 360 calls. Cases
include the original global table address, unaligned allocations, random prior
contents, and reversed-order re-registration. Release and UBSan both pass.
The catalog now contains 61 routines. The enclosing network startup and its
remaining dependencies still prevent actual startup; this table recovery does
not increase direct lifecycle entrypoint coverage or demonstrate connectivity.

## Endpoint and statistics initialization

Three routines in `src/network_endpoint.c` bring the native catalog to 64:
`00092870` initializes statistics, `00092BF0` opens an endpoint's sockets, and
`00092A90` initializes the endpoint. Their custom ABI is now recorded: statistics
receives `EAX=block, ECX=signed interval`; socket opening receives `ESI=endpoint`;
endpoint initialization receives `EAX=endpoint`. Both endpoint routines return
only the low byte `AL`.

A statistics block clears `0xD4` bytes, stores the signed interval, its quotient
by 20 truncated toward zero, and a single-precision scale computed from the
original constant at `0045DCCC`. Four blocks begin at endpoint offsets `0x228`,
`0x300`, `0x3D8`, and `0x4B0`, each with interval 2000. Their `0xD8` stride leaves
four bytes untouched after each block. Native float comparisons are verified
for the default SSE rounding mode, including signed extremes and zero; other
floating-point modes are not established by these tests.

Socket-open order is `(type=3, port=1000, special=0, output=+0xC)`, then
`(2,1001,1,+0x18)`, `(3,1005,0,+0x10)`, and `(3,1006,0,+0x14)`. The first failure
stops further opens and invokes endpoint cleanup. Complete success sets byte
`endpoint+8` to one; the open routine returns that byte after either path.
The outer initializer always sets `endpoint+0` to one and returns one, regardless
of the open result. This original distinction is preserved, not interpreted as
proof of usable sockets.

`network_endpoint_oracle.py` passes 136 comparisons in Release and UBSan. It
executes the original statistics and wrapper instructions, controlling only
socket creation/configuration `00092AE0` and cleanup `00092C70`. Tests compare
full mapped memory, callback arguments/order and intermediate snapshots, all
16 failure masks, noncanonical cleanup flag values, preserved padding, and 72
signed intervals. Socket creation/configuration remains unrecovered. Endpoint cleanup is now
reconstructed below; the original endpoint suite retains its controlled cleanup
boundary, while the new socket suite adds the combined failure path.

## Socket record allocation and endpoint cleanup

Three more routines in `src/network_socket.c` bring the catalog to 67:
`000B4D50` creates an eight-byte socket record, `000B4F50` closes its handle and
resets the record, and `00092C70` closes/releases an endpoint's four records.
The create routine takes a stack type argument and retains its low 16 bits;
close takes the record in `ESI`; endpoint cleanup takes a stack endpoint pointer.

Creation requires both transport initialized/active bytes to be nonzero. It
requests eight bytes with original allocation arguments `(0,8,0x101000,4)` and
initializes handle `0xFFFFFFFF`, flags zero, and the 16-bit type. Failed
allocation queries the system error function and returns null. This operation
allocates the record, not an OS socket.

Close only calls SDK shutdown/close when the handle is valid and transport is
active. Flag bit zero gates shutdown with argument 2. It reloads the handle
before close, reports each nonzero SDK result through the socket-error boundary,
and then clears the handle and two flag bytes, preserving the type. Endpoint
cleanup visits offsets `+0xC,+0x10,+0x14,+0x18`, skips null slots, closes each
record, releases it with `(record,0,0x8000)`, reports a zero release result, and
clears the slot regardless. It finally clears the endpoint's open byte at `+8`.

`network_socket_oracle.py` passes 464 comparisons in Release and UBSan. Tests
cover active flags, invalid handles, shutdown flags, platform failures, null
slots, preservation of type bytes, and platform callbacks that mutate handles
and transport state. Full memory and callback snapshots/order are compared.
Eight integrated cases execute the recovered endpoint initializer/open wrapper
and real cleanup after partial open failures. Only socket creation/configuration
and SDK allocation/shutdown/close/error operations are controlled in those cases.
The previous broad cleanup substitute is therefore removed from that integration
path. A Linux implementation of these SDK semantics and socket configuration
remains outstanding; no network connectivity or game startup is claimed.

## Socket option mapping and access

`src/network_options.c` adds `000B4DA0` (option mapping), `000B4E00` (get), and
`000B4E70` (set), bringing the recovered catalog to 70 routines. These decode
only the low 16 bits of the option argument. IDs 0–5 map to SDK values
`4, 0x80, 0x20, 0x1001, 0x1002, 0x4001`; other IDs return `0xFFFFFFFF`.
Both accessors require initialized/active transport and a valid socket handle.
They pass level `0xFFFF` and four bytes to the original SDK boundary.

The setter takes the option ID in `ESI`, socket at stack offset 4, and value at
stack offset 8. For ID 5 the value is a guest pointer to four bytes; otherwise
it is a scalar encoded as four little-endian bytes. It returns only `AL`, true
on a zero SDK result. The getter takes socket/option at stack offsets 4/8,
initializes a local value to zero and length to four, then returns that local
value even after a nonzero SDK result. Either accessor queries the error routine
when the SDK reports an error. Getter writes made by the SDK on failure are
therefore preserved. The previous automatic pseudocode's extra register outputs
are not used as the implementation specification; these details were read from
instructions and verified by execution.

`network_options_oracle.py` passes 820 comparisons in Release and UBSan. It
covers the real mapping routine, valid/invalid IDs, high-bit aliases, all
transport gates, invalid handles, SDK failures with/without output writes,
changed output lengths, and scalar versus pointed-to data. Full mapped memory,
return values, SDK arguments, and input bytes are compared. SDK option operations
remain required callbacks; this is not a Linux networking implementation.

## Network address conversion and handle setup

Three routines in `src/network_address.c` bring the catalog to 73:
`000B5470` converts an engine address to an Xbox socket address, `000B5560`
converts back, and `000B53E0` ensures that a socket record has an SDK handle.
The original custom register/stack storage is recorded in the ABI catalog.

Engine addresses occupy 20 bytes: up to 16 address bytes, a 16-bit port at
`+16`, and a 16-bit address width at `+18`. Width 4 maps to Xbox family 2 and
socket-address length 16; width 16 maps to Xbox family 23 and length 28.
Conversion swaps the IPv4 dword or each IPv6 word and the port. It preserves
unwritten destination bytes, including unused IPv4 bytes and IPv6 auxiliary
fields. Forward conversion clears the output length before inspecting the
address width, and returns false for other widths. Reverse conversion selects
its behavior from the supplied length, without validating the family field;
unsupported lengths clear the complete 20-byte engine address. Word/dword
read/write order is preserved, including overlapping-buffer cases.

The handle helper retains an existing non-invalid handle. Otherwise it requests
family 2, 23, or `0xFFFFFFFF` from the address width. Socket record types 2/3/4
select `(type,protocol)` pairs `(2,17)`, `(2,254)`, and `(1,6)`; other record types
pass zero/zero. It stores the SDK result before querying the error function on
failure. On success or reuse it runs the recovered option getter for ID 4 and
ORs flag `0x10` when that result is nonzero. It does not clear that flag on zero.
Transport gating occurs in the getter, not before the helper's create call.
These constants retain Xbox meanings; they are not directly POSIX parameters.

`network_address_oracle.py` passes 592 comparisons in Release and UBSan. The
conversion tests run unmodified originals, compare all mapped memory, and cover
random bytes, overlap, aliased length outputs, unknown formats, and preserved
padding. Handle tests execute the actual recovered option wrapper and compare
SDK arguments, failure snapshots, handle reuse, and transport gating. The SDK
create/get/error boundaries remain controlled. Binding is now reconstructed below. Full endpoint open is reconstructed below;
a Linux SDK implementation remains outstanding.

## Bind wrapper with explicit temporary storage

`000B4ED0` is reconstructed as `h2_network_socket_bind` in `src/network_bind.c`,
bringing the catalog to 74. It gates on both transport flags, runs the recovered
address converter, ensures a socket handle through recovered code, then passes
the current handle and converted address to SDK bind `003CD1D2`. It queries the
socket error boundary and returns false on bind failure; invalid addresses and
handle creation failure return false before binding. The original input ABI is
`EAX=engine address`, stack offset 4 = socket record, with `AL` return and four
bytes of stack cleanup.

The original reserves 28 bytes of stack-local address storage without clearing
it. Its converter leaves some bytes untouched, including IPv6 auxiliary fields.
The native API therefore takes an explicit 28-byte workspace representing those
incoming stack bytes. It preserves them, rather than substituting zeros or
ignoring them during validation. This additional host argument is not an
original XBE parameter. Callers must supply initialized bytes and keep the
workspace separate from guest memory. A local adapter reuses the recovered
converter, with valid 20-byte source addresses, without adding guest allocations.
A future host runtime must establish its workspace policy; full-game equivalence
of such a policy has not been demonstrated.

`network_bind_oracle.py` passes 256 comparisons in Release and UBSan. Original
conversion, handle creation, option mapping/getting, and bind-wrapper instructions
execute unmodified; only SDK create/get/bind/error calls are controlled. Tests
seed the original local buffer and native workspace with identical random bytes,
then compare the complete address supplied to bind, the entire resulting buffer,
all mapped engine memory, callback arguments/order, and return values. Cases
cover both supported address widths, invalid widths, transport gates, existing
handles, creation failure, bind failure, and option-derived socket flags.
This closes the engine bind-wrapper dependency, not SDK binding or OS networking.

## Complete engine endpoint socket-open path

`00092AE0` is reconstructed in `src/network_open.c`, bringing the native catalog
to 75. The routine takes the socket type in `EAX`, then port, special flag, and
output-pointer address at stack offsets 4/8/12. It returns `AL` and pops 12 bytes.
It allocates a socket record, builds an IPv4 wildcard engine address using the
low 16 port bits, binds through the recovered helpers, and conditionally calls
SDK ioctl `003CD1A9(handle,0x8004667E,&one)` when socket flag `0x10` is set.
Successful ioctl clears that flag. A nonzero low byte of the special argument
requests recovered option ID 2 with scalar value one. Higher special-argument
bytes alone do not enable the option.

Only complete success publishes the socket record through the output pointer.
On failure after allocation it invokes recovered socket close, then releases
storage with the original SDK arguments and queries system error on a zero
release result. Allocation failure leaves the output untouched. The routine
rereads transport state after binding, so a callback-driven state change can
skip ioctl; a still-active transport with an invalid handle takes cleanup.
These cases are preserved rather than replaced by a generic failure path.

Host adapters allow the existing bind/conversion/handle code to consume the
routine's stack-local address without inventing a guest allocation. They are
not counted as additional recovered functions. Only the IPv4 word, port, and
width are consumed; native unused engine-address bytes are initialized. The
separate 28-byte bind workspace still preserves incoming original stack bytes.
The differential harness captures those bytes at the original bind entry,
after earlier calls have affected the stack, and supplies them to native code.
No claim is made that a future Linux runtime already reproduces stack history.

`network_open_oracle.py` passes 448 comparisons in Release and UBSan: 432 socket
open cases and 16 combined endpoint initialize/close calls. Original engine
callees are not substituted. The combined path includes the four-socket
initializer, statistics setup, allocation, address conversion, handle setup,
options, binding, ioctl, partial-failure cleanup, and final endpoint cleanup.
Only SDK/kernel calls are controlled. Tests compare full guest memory, every
SDK argument and address byte, error ordering, output publication, and returns,
including injected failures and changes to transport state/handle flags.
This establishes the tested engine path, not OS networking or game startup.

## Network object, shared state, and provider setup

Three routines in `src/network_state.c` bring the catalog to 78:
`00075970` initializes a network state object, `00063D50` initializes shared
state, and `000662F0` invokes provider initialization. Their names describe
recovered behavior; the original object type names are not established.

The object initializer stores four dependencies, clears `0x90` bytes at `+0x14`,
and initializes statistics at `+0x4E30` using the signed interval at configuration
`+0xF8`. It sets status bytes at `+0x4F3C..+0x4F3E`, an invalid index at `+0x4F38`,
and two timestamps at `+0x4F30/+0x4F34`. Each timestamp independently checks the
byte at `00510548`: nonzero selects the word at `0051054C`; zero calls `003314B0`.
A first clock callback can therefore change how the second timestamp is chosen.
Fifteen records at `+0xA8`, stride `0x528`, are zeroed, with words `+0xC` and
`+0x70` set to `0xFFFFFFFF` in each. Byte `+0x4E00` is cleared. Gaps, padding,
and the object's first word remain untouched. The routine returns `AL=1`.

Shared-state setup clears `0x7D8` bytes at `004CD868`, stores the supplied
dependency at `004CE03C`, sets the first byte to one, and sets `004CD900` to
`0xFFFFFFFF`. It also returns `AL=1`, despite the original automatic pseudocode
having described it as void. Provider setup checks pointer `00477058` and its
callback at `+0x10`, calls with the address of that pointer slot, and sets or
clears flag bits `0x2/0x8` in byte `0047705C` based on the callback's low byte.
It reads flags after the callback and preserves adjacent bytes. Null provider
or callback pointers leave flags unchanged.

`network_state_oracle.py` passes 112 comparisons in Release and UBSan. It runs
the original statistics initializer, comparing the entire mapped memory and
clock/provider event snapshots. Tests include unaligned objects, random prior
bytes, signed interval extremes, timing override transitions, null providers,
and callbacks that change flags. Clock and provider implementations remain
external; these routines do not complete network startup or session behavior.

The next constructor on this startup path is `00059AD0`, invoked three times
by `0008D9F0`. Its current pseudocode shows dependency links and several large
state-array resets, with no external calls. Its register/stack ABI and exact
write ranges are now reviewed and implemented as described below.

## Session storage constructor

`00059AD0` is reconstructed as `h2_network_session_storage_initialize` in
`src/network_session.c`, bringing the catalog to 79. It receives the registry
in `EAX`, object in `EDX`, observer in `ECX`, then index, kind, dependency value,
and owner at stack offsets 4/8/12/16. It returns `AL=1` and pops 16 bytes.
Names are descriptive project labels, not recovered original type definitions.

The constructor stores the inputs, publishes the object at `registry[index]`,
then rereads its stored index to link into a 36-byte observer slot. It resets
large buffers at `+0x4C/+0x24E0` (each `0x2494` bytes) and `+0x4978/+0x5E28`
(each `0x14B0` bytes), placing invalid-index words at their heads. Smaller reset
regions and status fields extend through byte `+0x78AC`. It preserves the first
word, gaps between regions, and the trailing bytes of the startup allocation
stride `0x78B8`. It is not a blanket zeroing of the session object.

`network_session_oracle.py` passes 44 comparisons in Release and UBSan with no
replaced original constructor calls. Forty cases vary prior bytes, alignment,
indices, and stored inputs. Four combined calls execute the recovered observer
initializer and the three session constructions using the startup object
addresses, stride, and observed index/kind/dependency triples `(0,1,0)`,
`(1,1,1)`, `(2,2,2)`. Full mapped-memory comparisons verify cross-links, reset
regions, sentinels, and preserved bytes. The observer uses its fixed-time
override, so this test requires no clock substitute. Construction does not
implement the session state machine, networking, or complete game startup.

The setup dependency `00058EE0` and its four helper constructors are now
reviewed and implemented as described below.

## Parameter object construction

Four routines in `src/network_parameters.c` bring the catalog to 83. Names are
descriptive labels; the parameter state machines and original types are unknown.

- `0006DE50` receives the set in EAX and seven stack values, returning void and
  popping 28 bytes. It clears ten words, stores dependencies, and resets three
  status bytes while preserving padding.
- `0006F090` receives the parameter in EAX and set in EDX. It registers object
  number 5 at set offset `0x18` and initializes selected fields and sentinels.
- `00070190` receives the parameter in EAX and set in ECX. It registers object
  number 6 at set offset `0x1C`, initializes selected fields, and advances the
  shared random seed twice. The arithmetic preserves signed 16-bit bounds,
  32-bit multiplication wrap, logical shifts, and sign extension of results.
- `00072C80` receives a dependency in EDX and owner in ESI. It partially resets
  two fixed runtime records, stores the owner, and enables their shared flag.

The last three routines return void without stack arguments. Initialization
preserves all untouched bytes. The random routine caches the seed address before
subsequent writes and preserves the original write order when its first output
aliases the seed. Native arithmetic helpers are not separately counted routines.

`network_parameters_oracle.py` passes 240 original-instruction comparisons in
both Release and UBSan, varying alignment, prior contents, signed bounds, seed
aliasing, and dependencies. Full mapped-memory comparison checks links and
preserved bytes. No original callee is replaced in this suite. The enclosing
network startup and actual parameter behavior remain unfinished. The enclosing
parameter setup is recovered in the following section.


## Complete parameter setup and additional network resets

`00058EE0` is reconstructed as `h2_network_parameters_initialize`. It receives
session in EAX, two dependencies in ECX/EDX, and three values at stack offsets
4/8/12. It returns `AL=1` and pops 12 bytes. Its original instructions establish
the session back-reference at `+0x78A8`, initialize the fixed owner record, call
the recovered set constructor, and link all ten numbered parameter objects.
Parameters 5 and 6 use their recovered constructors; the remaining objects have
partial inline initialization. It then calls the recovered runtime initializer
and sets the shared enabled byte. First words, padding, and untouched payload
fields retain their previous contents. This implements construction only.

The parameter suite now passes 300 comparisons: the previous 240 constructor
cases and 60 enclosing calls with original callees executing unchanged. The new
cases vary dependencies, contents, signed random bounds, and the three session
storage addresses used by startup. Full memory comparison covers all effects;
additional checks confirm the ten-object registry, session back-reference,
dependency ordering, and two random-seed advances.

Two further routines in `src/network_state.c` bring the total catalog to 86:

- `0007F020`, `h2_network_auxiliary_initialize`, accepts EAX/ECX dependencies,
  clears 27 words and selected bytes, installs an invalid-index sentinel and a
  value of 16, and returns `AL=1`. Original pseudocode incorrectly inferred a
  void return; the caller consumes AL and the instruction stream sets it to 1.
- `0008E210`, `h2_network_tracking_reset`, takes no inputs and returns void. It
  fills 32 index words with `0xFFFFFFFF`, then resets four words in each of 32
  20-byte records. The fifth word in every record remains untouched.

The state suite now passes 176 comparisons, including 64 new reset cases with
randomized incoming contents. These two routines require no controlled calls.
Both expanded suites pass in Release and UBSan. The enclosing network startup
`0008D9F0` is still unrecovered. Online-task initialization is now recovered below. Remaining dependencies include
persisted configuration handling
(`0007FA40`/`0007F930`), final state setup (now recovered below), and failure
cleanup (`0008DD70`). These must be recovered before claiming complete startup.


## Online-task pool construction

`0006B3E0` is reconstructed as `h2_online_tasks_initialize` and `0006BFA0` as
`h2_online_address_classify` in `src/online_tasks.c`, bringing the catalog to 88.
Both are void functions without parameters in the original ABI. The native pool
initializer receives the memory view and allocator operations at its host boundary.

The constructor captures allocator identity from `0x468758`, requests `0x230`
bytes, and invokes the recovered data-array initializer with 24 slots of 20 bytes
and the original "online tasks" name. It retains the captured allocator identity
when initializing the header, even if allocation changes the global. It sets flag
bit 2, publishes the pool at `0x4CF78C`, activates and clears it, and invokes the
address classifier. Finally it zeros `0x2580` bytes at `0x4771C8` and installs an
invalid-index sentinel at `0x479748`.

The classifier compares six bytes at `0x4CF7CC` against two six-byte constants
starting at `0x43FF84`, storing exactly 0 or 1 at `0x50944E`. Neighboring bytes
remain unchanged. The project label describes this comparison and does not claim
to recover the original name or the meaning of the two constants.

`online_tasks_oracle.py` passes 90 comparisons in Release and UBSan: 30 classifier
cases and 60 full constructor cases. They include both constant matches, a change
to each byte, random addresses, varied allocation alignment and incoming bytes,
and allocator callbacks that change the global allocator. All original data-array
callees execute unchanged. The allocation boundary is controlled, and the test
compares the entire mapped memory after each call. Allocation failure is outside
this suite: the original dereferences the resulting null pool, while the native
memory bounds check aborts. No graceful failure behavior is claimed.

The Linux `--probe-pools` executable now constructs this pool with the native heap,
allocates a slot, looks it up, deletes it, and releases the pool. Its existing final
live-allocation check also covers this added allocation. This demonstrates native
container use, not online-task execution or a completed game startup.


## Final network startup state construction

Three routines in `src/network_final_state.c` bring the catalog to 91. Names
are descriptive; the original subsystem and structure names remain unknown.

`00056080`, `h2_network_slot_state_initialize`, takes its state pointer at stack
offset 4, returns void, and pops four bytes. It initializes sixteen records at a
stride of `0x170`, storing each index at base `+0x10`, setting a byte at `+4`,
clearing a word at `+8` and a halfword at `+0xC`, and clearing payloads at `+0x14`
(length `0x120`) and `+0x134` (length `0x40`). Record bases in this description
include the four-byte prefix preceding the first record. The complete touched
extent is `0x1704` bytes. It finally enables the first byte of the whole state.
Gaps and padding are retained rather than blanket-cleared.

`00056AE0`, `h2_network_vector_state_initialize`, takes its pointer in EDX and
returns void. It clears eight 64-byte arrays at offsets `4`, `0x44`, `0x84`,
`0xC8`, `0x108`, `0x194`, `0x1D4`, and `0x148`, in that order. It stores the
32-bit representations of -1000 and -80 at `+0x18C` and `+0x188`, then sets bytes
at `+0x190` and `+0`. The purpose of those constants is not yet established.

`00053210`, `h2_network_final_state_initialize`, takes no parameters and returns
void. It clears fixed globals, sets an invalid-index sentinel and flags, calls
both constructors at the original state addresses, and sets the final enabled
byte. Redundant zero stores inside the initial clear have no intervening calls
and are represented by that clear in native C.

`network_final_state_oracle.py` passes 144 comparisons in both Release and UBSan:
48 cases for each constructor and 48 parent calls, varying prior memory contents
and pointer alignment. Original callees execute without replacement. Full mapped
memory comparison verifies untouched gaps as well as all writes; independent
checks cover record indices, sentinels, and flags. No complete network startup
or behavior beyond state construction is claimed. Persisted configuration
handling and the startup failure cleanup path remain unrecovered.


## Persisted network state defaults and validation

Three routines in `src/network_config.c` bring the catalog to 94. The names label
the observed persisted-state path; they are not recovered original symbols.

`0007F930`, `h2_network_config_defaults`, takes no original arguments and returns
void. It writes version 8, zero checksum/count fields, and four absent-index
sentinels at the block beginning `0x4CF970`. It initializes all 350 records at
`0x4CF98C`, stride `0x68`: zero contents with byte `+0x56` set to `0xFF` and four
16-bit sentinels at `+0x58` through `+0x5E`. The original zeroed stack temporaries
and copies have been reduced to equivalent writes to the persistent block.

`00153750`, `h2_network_config_fields_valid`, takes a pointer in EDX and returns
AL. The first four signed bytes accept -1 through 17, the fifth accepts -1 through
3, and the final three unsigned bytes must be less than 64, 32, and 16. Other
negative byte encodings are invalid. The native tests exhaust each byte domain
individually while holding the other fields valid.

`00080660`, `h2_network_config_validate`, takes no original arguments and returns
AL. It checks version 8 and a signed count from 0 through 350. Active records must
have strictly increasing unsigned lexicographic 12-byte keys, valid eight-byte
fields at `+0x4C`, and a word at `+8` whose low two bits are zero and which is not
`0xBAD00000`. Four header indices describe two lists: each pair must either both
be absent or both be in range. For enabled lists it traverses exactly count
records, checking visited bits, first/last sentinels, predecessor links, successor
bounds, and the specified tail. Both absent indices disable that list check even
when the count is nonzero, matching the original. No semantic meaning is assigned
to the key words or field limits beyond these observed checks.

The validator only reads persistent state. Native early returns replace later
read-only checks on failure; scratch stack arrays remain host-local. The suite
executes the complete original validator and its field-validation callee without
substitution, comparing AL and the entire mapped memory. All 2,492 comparisons
pass in Release and UBSan: 16 default resets, 2,048 byte-field cases, and 428 full
validation cases. Cases include both absent and shuffled valid lists, counts at
0/1/350 and out of range, signed boundary indices, duplicate/descending keys,
invalid fields, broken forward/backward links, and randomized structured damage.

This recovers the fallback and post-load validation used by `0007FA40`. Its file
reference, open/read/close helpers and checksum orchestration remain unrecovered,
as does complete network startup and its cleanup path.


## Xbox file-path helpers

Three routines in `src/file_path.c` bring the catalog to 97. They preserve the
original path format; they do not interpret Xbox drive letters as Linux mounts.
All three return void and have no original stack parameters.

`00137320`, `h2_file_path_append`, takes destination in ESI and component in EDI.
An empty component leaves the destination untouched. Otherwise it scans the
existing path, adds a backslash if needed, copies with `strncpy`-style zero
padding to the 256-byte limit, and forces byte 255 to zero. If an existing path
has length 255 without a trailing separator, the original briefly writes the
separator at 255 and a zero at 256 before restoring byte 255 to zero. Native code
preserves that extra write; callers must supply storage for it. The tested input
contract is disjoint source/destination buffers and an existing path of at most
255 bytes, matching the bounded path use on this startup path.

`001373C0`, `h2_file_path_parent`, takes its path in ECX. It scans backward from
the string terminator to the last backslash and replaces that backslash with zero.
Without a backslash it clears the first byte. The original converts the string
length to signed 16 bits before the backward scan; the native implementation
preserves this, including writes before the path for negative truncated lengths.
Such oversized paths are tested in valid mapped storage as instruction-fidelity
cases, not presented as suitable host filesystem inputs.

`001374C0`, `h2_file_path_resolve`, takes destination in ESI and path in EDI.
An ASCII letter followed by colon and backslash is already drive-qualified.
Other paths receive the original `d:\` prefix from the pinned XBE. The copy has
zero-padding semantics and always terminates at destination byte 255. Append
and resolve tests use nonoverlapping buffers; overlap equivalence is not claimed.

`file_path_oracle.py` passes 534 comparisons in Release and UBSan: 192 append
cases, 269 resolution cases, 68 parent cases, and five signed-length boundary
cases. It executes the original CRT copying routine unchanged and compares the
entire mapped memory, checking padding and neighboring bytes as well as text.
Actual file reference handling, stat/open/read/close operations, and Linux host
path translation remain outstanding dependencies of persisted-state loading.


## Engine file read, write, and close wrappers

Three routines in `src/file_io.c` bring the catalog to 100. The native interface
uses an explicit SDK boundary (`h2_file_platform`) whose nonzero results mean
success. Handles remain 32-bit values, buffers remain guest addresses, and the
transferred-count output is native-local storage corresponding to the original
stack local. The boundary does not imply a working Linux file backend.

`00136CA0`, `h2_file_read`, receives the file reference in ESI, buffer in ECX,
count in EDI, and a byte-valued error-suppression flag at stack offset 4. It
returns AL and pops four bytes. SDK read uses the handle at reference `+0x108`.
Only a successful read reporting exactly the requested count succeeds. A short
successful read first sets error `0x26`; it does this even when later error
handling is suppressed. It then adds the reported count to the current position
at `+0x10C`, with 32-bit wrap. An unsuccessful result with a zero suppression
byte calls get-last-error and then set-error(0), in that order.

`00136D00`, `h2_file_write`, uses the same three registers, no stack argument,
and returns AL. It also requires a successful exact-length transfer, advances
the stored position by the reported count, and calls get-last-error followed by
set-error(0) on failure. It has no read-style short-transfer error `0x26`.

Both original routines initialize the transferred-count local with the incoming
buffer address. Native code preserves that value if the platform callback does
not write the output, including on failure. It also rereads the stored position
after I/O and, for short reads, after setting error `0x26`; callback-visible
mutations must occur before the position addition.

`00136BB0`, `h2_file_close`, takes the reference in ESI and returns AL. Successful
SDK close clears both handle and position. Failed close preserves them except
for platform side effects and invokes get-last-error followed by set-error(0).

`file_io_oracle.py` passes 498 comparisons in Release and UBSan: 384 reads,
96 writes, and 18 closes. Tests compare the entire mapped memory, AL, SDK call
arguments and order, and intermediate handle/position snapshots. They vary SDK
success values, requested and reported counts, omitted count writes, low-byte
suppression flags, callback mutations, buffer overlap with position storage,
and invalid handle values. Original engine instructions execute unchanged;
only SDK entrypoints are controlled. Opening, metadata lookup, seeking, and
actual Linux filesystem operations remain outstanding.


## File seek and set-end wrappers

`00136BF0` and `00136C40` are recovered in `src/file_io.c`, bringing the catalog
to 102. Both receive the file reference in ESI and requested position in EAX,
and return AL. Seek additionally receives a suppression byte at stack offset 4
and pops four bytes; set-end has no stack arguments.

`h2_file_seek` returns success without a platform call when the cached position
already equals the request, including the `0xFFFFFFFF` bit pattern. Otherwise
it invokes the SDK seek boundary with high-word pointer zero and origin zero,
stores the returned position, and treats `0xFFFFFFFF` as failure. Unsuppressed
failure queries the last error and then sets error zero. The returned position
may differ from the request and is stored unchanged.

`h2_file_set_end` performs the same seek check, then invokes SDK entrypoint
`002D2404` with the current handle. That SDK routine queries file position and
sets end/allocation information; the project labels it set-end. If seeking
fails, the original performs two get-last-error/set-error(0) pairs. Both pairs
are preserved. A failed set-end after successful seek performs one pair. The
native helper reuses recovered seek logic; the original has that logic inlined.

The expanded file-I/O suite passes 678 comparisons in Release and UBSan. Its
180 new cases cover skipped seeks, returned positions differing from requests,
failure sentinels, low-byte suppression, handle changes during SDK calls, and
repeated error handling. Full memory and callback snapshots match original
instructions. SDK calls remain controlled boundaries; opening, metadata lookup,
and actual Linux file operations are still outstanding.


## File existence and size lookup

`001368F0` and `00136E90` are reconstructed in `src/file_io.c`, bringing the
catalog to 104. Both return AL and take a file reference at stack offset 4.
Existence pops four bytes. Size lookup also takes an output pointer at stack
offset 8 and pops eight bytes. Each resolves the path at reference `+8` into a
local 256-byte buffer using the recovered Xbox path rules.

`h2_file_exists` invokes the SDK attributes query and treats every result except
`0xFFFFFFFF` as success. Failure first queries last-error and returns quietly
if that result is 2. Otherwise it queries again and returns quietly if the second
result is 3. Otherwise it performs a third query followed by set-error(0). The
queries remain distinct because a boundary callback can return different values.

`h2_file_size` queries SDK metadata at information level zero. On success it
copies only the little-endian word at information offset 32 to the output; the
high-size word is ignored. On failure it leaves the output untouched and performs
get-last-error/set-error(0). A successful platform query must initialize its
36-byte information record, consistent with the SDK boundary used here.

The host-stack path adapter `h2_file_path_resolve_buffer` does not count as a
separate recovered routine. It avoids putting local path bytes into persistent
guest storage. The new suite compares all 256 bytes presented to the SDK against
the original resolver, including zero padding and truncation.

`file_metadata_oracle.py` passes 280 comparisons in Release and UBSan: 112
existence cases and 168 size lookups. Tests execute the original path resolver
and CRT copy unchanged, controlling only SDK operations. Cases include relative
and drive-qualified paths, non-letter drive prefixes, long paths, changing error
query results, high-bit success values, varied low/high size words, and outputs
aliasing the input path. Full mapped memory, AL, callback arguments and order
match. File opening and the Linux filesystem backend remain outstanding.


## Engine file opening

`00136970`, `h2_file_open`, is recovered in `src/file_io.c`, bringing the catalog
to 105. The original receives its file reference in EBX, flags at stack offset 4,
and an error-output pointer at stack offset 8; it returns AL and pops eight bytes.
It clears the error output before resolving the path, preserving alias effects.

Flags 1 and 2 select SDK read/write access bits. Sharing is 1 unless write access
is requested without flag 8. Attributes start at `0x80`, then flags `0x20`, `0x40`,
`0x80`, and `0x100` successively select `0x100`, `0x04000000`, `0x10000000`, and
`0x08000000`; the last present flag wins. Security/template values are zero and
the SDK disposition is 3. The original 256-byte resolved path is passed intact.

An SDK handle of `0xFFFFFFFF` fails. The first error query maps codes 2/3/5/15/32
to engine outputs 1/3/2/4/5, with other values mapping to 6. Unless flag `0x10`
suppresses it, failure then queries the error again and sets error zero.

Successful open publishes the handle and resets the cached position. Flag 4
requests a seek with zero displacement and origin 2. A failed seek causes a close
of the current stored handle, then clears handle and position regardless of the
close result. It returns failure and performs the same optional final error pair.
The mapped error output remains zero on this path unless it aliases other fields.

The file-open suite passes 840 comparisons in Release and UBSan. It exhausts all
512 low-nine-bit flag combinations, checks SDK errors 0 through 131 plus signed
boundary patterns, and varies failed-seek cleanup, close results, callback handle
mutations, and error outputs aliasing path/handle/position. Original path and CRT
code execute unchanged. Full mapped memory, AL, path bytes, SDK arguments/order,
and intermediate handle/position/error snapshots match. SDK operations remain
controlled; actual Linux opening and the enclosing configuration loader are not
yet implemented.


## Complete persisted-configuration loader

`0007FA40`, `h2_network_config_load`, is reconstructed in `src/network_config.c`,
bringing the catalog to 106. It has no original arguments and returns AL. The
native host supplies a `0x114`-byte temporary guest-addressable workspace: a
scratch word followed by the `0x110`-byte file reference that was originally on
the x86 stack. This storage must not overlap engine globals, source paths, or
other live objects. It is caller-owned temporary storage, not a recovered global.

The loader clears the file reference, installs signature `0x66696C6F`, reference
flags and sentinels, and appends the original filename at `0x450C68`. It calls
recovered existence and size wrappers, requiring exactly `0x8E4C` bytes, then
opens with flag 1 and reads that many bytes into `0x4CF970`. Successful exact
reads compute the recovered raw CRC over `0x8E44` bytes at `0x4CF978` with seed
`0xFFFFFFFF`, compare it to the stored checksum, and call the full recovered
state validator. Once opening succeeds, all paths close the file. Close failure
does not override a successful validation result. Failed/partial reads and failed
validation do not roll back the loaded global bytes. The enclosing startup code
is responsible for selecting the recovered defaults on failure.

The native implementation composes the existing path, file, CRC, and validator
routines. It does not replace those engine dependencies with test callbacks.
The unreachable parent-path branch after zero initialization is omitted.

`network_config_load_oracle.py` passes 44 comparisons in Release and UBSan,
covering four record counts (0/1/7/350) and eleven outcomes: valid data, missing
file, metadata failure, wrong size, open failure, read failure, short read, CRC
mismatch, invalid version, invalid fields/count, and close failure. Original
engine and CRT callees execute unchanged; only SDK entrypoints are controlled.
Tests compare AL, all persistent mapped memory, SDK arguments/order, and the
file-reference bytes at callback boundaries. The native workspace is compared
against the original stack-local reference and initialized scratch word, then
excluded from the persistent-memory comparison. This explicit exclusion avoids
mistaking temporary storage for persistent game state while still checking its
contents. CRC cold initialization is included.

This establishes the engine loading path against controlled I/O. A real Linux
filesystem backend, complete network startup, and cleanup remain unfinished;
no successful load from a real host file or playable game is claimed here.


## Native Linux file backend and configuration probe

`src/host/files.c` implements the `h2_file_platform` boundary for Linux and is
host adaptation code, not recovered game code. The original-routine count stays
106. The host mounts existing directories at selected Xbox drive letters through
`h2_host_files_mount`; the configuration probe mounts its directory as Z.

Paths are resolved relative to mounted directory descriptors. Backslashes are
translated to separators, exact case is preferred, and otherwise a unique
ASCII-insensitive name match is required. Parent components stay inside the
mount; symlinks and ambiguous case matches are rejected. Unmounted drives have
an explicit failure instead of falling through to the host working directory.

The backend opens existing regular files and maintains a 256-entry handle table.
It implements the access/sharing combinations emitted by recovered opening,
read/write counts and EOF, seeking, truncation, file attributes and low/high size
metadata, closing, last-error storage, and delete-on-close. Sharing conflicts are
checked by device/inode within the context. Sequential/random flags become
Linux access hints; the temporary-file attribute is only a hint. Delete-on-close
checks file identity before unlinking so a replacement pathname is not deleted.
Destroying the backend closes outstanding files and mount descriptors.

The new `--probe-config XBE CACHE_DIRECTORY` command loads the pinned XBE, mounts
Z, supplies the loader workspace, and runs recovered existence/size/open/read,
CRC, validation, and close against the actual file named by the XBE. Validated
configuration returns exit zero and reports its version and record count.
Missing or rejected data returns exit one. No fallback configuration is silently
substituted by this probe, and it does not boot the game.

`host_files_test.py` uses real temporary directories and the native backend,
without SDK callbacks or original instruction execution. Tests exercise case
lookup, exact/short reads, position changes, writes, truncation, seek-to-end,
shared readers and conflicting writers, mount bounds, parent components,
symlink/ambiguity rejection, deletion and pathname replacement, a sparse file
larger than 4 GiB, invalid handles, access denial, all 256 handle slots, and cleanup.
They load a valid on-disk configuration and reject missing, wrong-sized,
CRC-damaged, and invalid-version data, checking that no handle remains open.
The standalone executable is tested against valid and invalid files as well.
Descriptor counts before and after backend destruction match, including when
one file is deliberately left open. Both Release and UBSan pass these checks.

This proves real Linux I/O for the currently recovered configuration path, not
full SDK equivalence. Metadata timestamp fields are zero and have not been
recovered for consumers that need them. The backend is single-threaded with
context-local error state; cross-process sharing enforcement, TLS error state,
and Windows deletion semantics after rename remain incomplete. The high-word
seek-pointer form and open dispositions other than the recovered value 3 are
unsupported. These limits must be addressed as more engine consumers are linked.
Complete network startup, cleanup, map loading, rendering, audio and gameplay
remain unfinished.


## Online-task lookup dependencies for shutdown

`0006B890` and `0006B910` are recovered in `src/online_tasks.c`, bringing the
catalog to 108. These are dependencies of the remaining online-task cancellation
and shutdown path, not a completed cleanup implementation.

`h2_online_task_find` (`0006B890`) receives owner in EBX and kind at stack offset
4, pops four bytes, and returns a full EAX boolean. It walks the pool's active
bitmap below the signed high-water bound, compares kind at entry `+4` and owner
at `+8`, and accepts owner `0xFFFFFFFF` or `0xFF` as wildcards. It does not use
entry salts. A computed zero entry address terminates the search with false.

`h2_online_task_get` (`0006B910`) receives a handle in EAX and returns an entry
address or zero. It rejects the absent handle and out-of-range indices, then
requires a nonzero 16-bit entry salt matching the handle's upper half. Both
halves are sign-extended by the original before comparison; equality is
preserved by comparing their 16-bit representations. It does not consult the
active bitmap, which is deliberately different from the search routine.

The online-task suite now passes 810 comparisons in Release and UBSan, including
240 searches and 480 handle lookups in addition to its 90 setup cases. The new
cases vary signed high-water limits, stride, sparse bitmap words across 32-bit
boundaries, task kinds, wildcard owners, zero/high-bit salts, and invalid indices.
Original lookup instructions execute without replacement; full mapped memory
and EAX match. SDK task-status polling, task cancellation, and enclosing shutdown
still need recovery before the network subsystem has a complete lifecycle.


## Online status and continuation

`0006CD50` and `0006C670` are recovered in `src/online_tasks.c`, bringing the
catalog to 110. The status routine takes a handle in EAX; continuation takes a
task pointer in ESI. Both return full EAX values with no stack arguments.

Status uses the recovered lookup. Invalid handles return the existing global
status; kind 1 or flag bit `0x20` returns the record's cached status. Invalid SDK
handles update only global status to 10. Inactive transport marks the task with
flag `0x20` and status 5. Otherwise the SDK status result maps terminal errors
to values 2 through 8 or 10, updating both task and global status. Result zero
updates only global status to 0, and `0x1510F0` updates only global status to 1.
Result `0x1512F0` also sets the byte at `0x50944F`. Existing flag bits survive,
including SDK callback changes made before a terminal result is processed.

Continuation rejects null tasks and zero/absent SDK handles with `0x80004005`.
Kind zero on active transport bypasses login polling. Other tasks require a
non-absent login handle whose recovered status is 1, otherwise returning
`0x80151000`. The SDK continuation call receives the current stored task handle,
reloaded after status polling so intervening callback changes are preserved.

`online_poll_oracle.py` passes 215 comparisons in Release and UBSan. Cases
cover all observed status mappings and unknown results, cached/invalid handles,
transport combinations, the direct continuation path, and callbacks modifying
flags and task handles. Original lookup, transport-active, and nested status
callees execute unchanged. Full memory, EAX and callback snapshots match; only
SDK status/continuation entrypoints are controlled. This does not implement an
online service or finish task cancellation and network cleanup.


## Online task cancellation

`0006B640` and `0008C550` are recovered in `src/online_tasks.c`, bringing the
catalog to 112. The cancellation routine receives its handle in EDI; the kind-33
helper receives it in EDX. Both return void with no stack arguments.

Cancellation validates the salt/index, then dispatches valid SDK handles by task
kind. Kind 2 continues until result `0x1500F2` or a negative result, preserving the
original potentially unbounded loop. Kind 3 calls the SDK preparation boundary
and continues once only for a nonnegative result. Kind 33 calls its helper, which
requires a valid task and login status 1 before the SDK operation. Other kinds
skip those steps. All valid SDK handles are then closed, the global pool pointer
is reloaded, and the old task's SDK-handle field is cleared before data deletion.
Zero/absent SDK handles skip closing but still delete the entry from the initially
captured pool. SDK return values from close and kind-33 cancellation are ignored.

`online_cancel_oracle.py` passes 399 comparisons in Release and UBSan with
original lookup, status, continuation, and data-deletion callees intact. Only SDK
calls are controlled. Cases include completion/error sequences, failed prepare,
invalid handles, login gating, callback changes to task handles and the global
pool pointer, and the data-array poison-on-delete flag. Full mapped memory and
intermediate callback snapshots match. Completion of this routine does not
establish full online-task draining, pool disposal, or network shutdown; those
remaining callers still need recovery.


## Online-task draining and pool disposal

`0006B950` and `0006B450` are recovered in `src/online_tasks.c`, bringing the
catalog to 114. Both have no original arguments and return void.

The drain routine repeats bitmap scans while the signed live count is positive.
Kind 0 waits until only one task remains; kinds 1, 2 and 33 wait for counts at
most 2, 3 and 4. Kind 11 waits until no kind-12 task exists, using wildcard owner
255. Other kinds may be cancelled immediately. Each scan retains its original
pool for entry lookup while cancellation can replace the global pool used for
count checks. The next outer scan adopts that new pool. The native routine
preserves this distinction and the original potentially unbounded behavior for
inconsistent pools or nonterminating SDK tasks.

Disposal drains first, clears the 0x4C-byte pool header and invokes its stored
allocator release method. It then reads the pending handle at `0x479748`, cancels
it if non-absent, and stores the absent sentinel. The pool global itself is not
cleared by the original. The native implementation composes recovered drain,
data-array disposal, and cancellation; only SDK and allocator methods remain
host boundaries.

The new suite passes 72 comparisons in Release and UBSan: 48 drains with shuffled
dependency order and 24 disposals. Tests cover empty pools, poison-on-delete,
SDK callbacks replacing the global pool, absent allocators, and allocator release
callbacks supplying a different pool and pending handle. Original engine callees
execute unchanged. Full mapped memory and intermediate callback snapshots match,
including the cleared header observed at release.

The Linux pool probe now calls the recovered disposer after deleting its only
probe task. That empty-pool path performs no online SDK calls, and the existing
native allocation-leak check still passes. This completes the online-task pool
lifecycle for the tested paths; the wider network subsystem still has unrecovered
cleanup dependencies.

## Parameter runtime cleanup

Recovered `00072D30` as `h2_network_parameter_runtime_dispose`, bringing the
native catalog to 115 routines. It cancels four pending task handles in order,
resets their slots to the absent sentinel and clears three runtime flags.
Cancellation uses the recovered task code; SDK operations remain callbacks.
Slots are read immediately before cancellation so earlier callbacks may change
later tasks. Flag writes preserve the original ordering and unrelated state.

The online drain suite adds 64 original-instruction comparisons covering all
16 pending-slot combinations, duplicate handles, invalid salts, and callback
mutation of a later slot. Callback snapshots include runtime state as well as
pool headers; the harness compares all persistent guest memory. This recovers
a dependency of parameter shutdown, not its complete enclosing routine or
network shutdown.

The ABI refresh annotates all 115 routines. It exposes a Ghidra input-varnode
export error in `0006D080`, leaving 11,389 of 11,390 discovered functions exported.
This unresolved pseudocode issue is separate from native differential validation.

## Asynchronous task release and idle query

Recovered `0007B650` and `0007B6C0` in `src/async_tasks.c`, bringing the native
catalog to 117 routines. This separate task pool at `004CF8D8` is guarded by
`004CF8D4`. Both routines validate the signed high-water bound and entry salt;
they do not consult the active bitmap. The idle query returns true for absent
or stale handles, otherwise tests the SDK object's word at offset four.

Release invokes the SDK boundary `003CD172`, clears the entry's SDK pointer only
on a zero result, then reloads the global pool and deletes the entry regardless
of SDK success. The implementation preserves this ordering, including pool
replacement during the callback. Names describe observed behavior, not recovered
original symbols. The SDK service itself remains unimplemented.

The new suite has 135 comparisons: 108 release cases and 27 idle queries, covering
disabled state, absent handles, signed bounds, zero/mismatched/high-bit salts,
SDK errors, pool replacement and deletion poisoning. All original engine callees
remain intact; only SDK release is controlled. These routines support remaining
parameter shutdown work, not complete network shutdown or game boot.

## Parameter operation cleanup

Recovered `00090C80` as `h2_network_parameter_operation_dispose`, bringing the
native catalog to 118 routines. The original accepts one stack pointer and returns
void. State 1 changes to 2 before cancellation. It cancels the online task at
`+70`, releases asynchronous tasks at `+74` and `+78`, then releases buffers at
`+90`, `+8C`, and `+A0` in that order. It resets task slots and buffer pointers
and clears the active byte while preserving unrelated fields.

Buffer virtual methods remain controlled platform boundaries. The query's output
is written to a dead stack slot by the original and discarded; the native query
callback therefore exposes only identity and buffer. Release receives flags
`FFFFFFFF`. The allocator wrapper is reloaded after query but captured across
release, and its stored count decrements with 32-bit wraparound.

The drain suite adds 192 cases (64 presence combinations in three callback modes),
comparing original engine calls, all persistent memory and boundary snapshots.
Callbacks replace the allocator wrapper and alter a later buffer; state values
0, 1, 2 and FFFFFFFF and counter underflow are covered. This is another complete
shutdown dependency, not complete parameter/session shutdown or game boot.

## Pending request removal

Recovered `0006DDB0` as `h2_network_parameter_request_remove`, bringing the native
catalog to 119 routines. Owner is passed in EBX, request in ESI; there are no
stack arguments or return value. It traverses the singly linked list at owner
`+0C`, unlinks a matching record before querying/releasing it, then decrements
the captured allocator wrapper's count and the owner's current count at `+10`.
An absent non-null request leaves memory unchanged. Null requests are not valid
inputs: the original can dereference address zero at the end of the search.

The existing buffer boundary preserves query/release ordering and reloads the
allocator wrapper after query. The 84 new comparisons cover list sizes zero
through five, every removal position, absent records, allocator replacement,
freed-record overwrites and counter changes during callbacks. The original
instructions execute unchanged apart from controlled virtual buffer methods.
The enclosing request-drain function still needs session admission and response
routines; this is not complete network shutdown.

## CRT stack-probe analysis correction

The previously recorded `0006D080` export failure is resolved. `00320560` probes
stack pages and changes caller ESP by the size passed in EAX. Its old ordinary
call model misplaced local variables over the return-address area. The ABI
annotation script now verifies all 65 helper bytes and applies Ghidra's x86
Windows `alloca_probe` injection. Its callers are invalidated and re-exported.
All 11,390 discovered main-section functions now export successfully again.
This is an analysis-model correction, not an additional recovered engine routine
or proof that the exported pseudocode is correct buildable source.

## Session shutdown guard, peer lookup and capacity checks

Recovered `00058D90`, `0005F760`, and `0005AF70` in `src/network_session.c`,
bringing the native catalog to 122 routines. These are dependencies of parameter
shutdown and request admission; the enclosing state transitions remain unfinished.

The shutdown guard returns one in states 2, 4 and 6, the original flag byte at
`+7420` in states 7 and 8, and zero otherwise. It does not normalize that flag.
Peer lookup rejects state zero or an absent `+4C` marker and scans the signed
count at `+54`, comparing 36 identity bytes in records of stride `10C`. The first
match wins; absent matches return FFFFFFFF. Capacity checking applies only in
states 3 through 8. It adds the proposed peer/player counts with 32-bit wrapping
and compares them as signed values against the two stored limits.

The session suite adds 1,136 comparisons: 590 guard cases (all 256 flag values
for both conditional states), 30 peer search cases, 36 individual identity-byte
mismatches, and 480 capacity cases including signed overflow. All original
instructions run without substituted calls. Tests compare persistent memory and
AL/full-EAX as appropriate; these functions do not demonstrate session startup.

## Reservation-aware request admission

Recovered `00062F40`, `0005AFC0`, and `00062FE0` in `src/network_session.c`;
the native catalog now has 125 routines. Reservation lookup scans sixteen
36-byte records at session `+7668`, requiring an active byte and matching the
12-byte identity at record `+0A`. The first match optionally writes its guest
address; failure leaves the output untouched.

Reservation capacity counts matching proposed identities unless the input flag
is nonzero. It counts active, unconsumed reservations separately and evaluates
the signed requested count against `limit - current - reserved + matches`, with
32-bit wrapping arithmetic. Duplicate proposed identities are counted separately,
matching the original. Negative requested counts skip the lookup loop.

Request status returns code 3 outside states 5 through 8, code 2 for a signed
`+498C` value greater than one, and code 3 for states 6 through 8 after that test.
In state 5 an existing peer succeeds immediately. Otherwise it composes the
recovered peer/player capacity and reservation-capacity checks, returning 0
for acceptance or 4 for rejection. Code meanings beyond these observed branches
remain project interpretations; no original symbol names were recovered.

The session suite adds 516 cases: 68 reservation searches (all slots, missing
records, duplicate matches, null outputs and output/identity aliasing), 160
reservation-capacity cases, and 288 composed admission cases. Original engine
callees run unchanged and persistent memory/returns are compared. This supplies
another request-drain dependency; response transmission and the enclosing drain
are still unrecovered.

## Bitstream word read/write

Recovered `001959C0` and `00195720` as `h2_bitstream_read_bits` and
`h2_bitstream_write_bits` in `src/bitstream.c`. The native catalog contains
127 routines. Stream fields are data pointer at zero, byte capacity at four,
and bit position at `+10`. These routines underpin response serialization.

Both select the signed minimum of requested width and remaining bits, process
only a positive selected width, and advance by the original requested count.
The reader combines up to two little-endian words and masks the result. The
writer ORs into the first word but assigns the second word on crossing, including
clearing its higher bits. It reloads the position after stores, which matters
when the buffer overlaps the stream header. Native shifts explicitly reproduce
x86 masked shift counts and arithmetic right shifts without C undefined behavior.

The 3,036 comparisons cover each starting alignment with widths 0 through 33,
random short/empty capacities, signed and wrapping count cases, nonzero buffer
contents, and position-field aliasing. Original instructions run unmodified.
Fixtures provide mapped word padding: the original can read or write a full word
beyond the declared byte boundary. This does not make arbitrary invalid guest
pointers safe or establish complete message serialization/transmission.

## Bitstream checkpoint rollback

Recovered `00194710` as `h2_bitstream_pop_checkpoint`, bringing the native catalog
to 128 routines. It decrements checkpoint depth at `+18` and loads the saved
position from `+1C + depth*4`. A zero rollback byte only pops the checkpoint.
Otherwise it restores the saved position. In write mode (`+0C == 1`), when the
saved position is signed-less than the current position, it records the discarded
bit count at `+2C`, increments `+30`, masks the first affected byte and clears
the remaining buffer bytes. Signed division/remainder and wrapped arithmetic
match the x86 instructions, including negative-position cases with mapped padding.

The bitstream suite adds 512 cases covering four checkpoint depths, zero and
nonzero rollback flags, five stream modes, position ordering, byte boundaries,
short buffers and counter wraparound. Original instructions execute unmodified;
all persistent memory is compared. Checkpoint-stack validity and mapped writable
buffer storage remain caller requirements. Message framing and response
transmission still need recovery.

## Message header framing and stream error check

Recovered `000937E0`, `00093860`, and `001946F0`, bringing the native catalog
to 131 routines. Header writing emits an eight-bit type and sixteen-bit size
through the recovered bit writer. Out-of-range values still encode their low
bits. The original formats a diagnostic into an unused 256-byte local stack
buffer in those cases; the native implementation omits that discarded local
text. Differential tests execute the original formatter and CRT unchanged and
compare all persistent guest memory, including oversized values.

Header reading writes type and size outputs before validation. It checks the
stream error byte and signed position/capacity comparison, rejects type values
outside 0 through 44, requires an enabled descriptor, and checks signed size
bounds at descriptor offsets 12 and 16. It then calls the recovered stream-error
query. The implementation preserves output aliasing, reloads and early returns.
The standalone error query returns a normalized byte, preserving the original
signed comparison of bit position with wrapped byte-capacity-times-eight.

The bitstream suite adds 576 cases: 128 writes, 320 reads and 128 error queries.
It covers oversized headers, partial capacities, disabled descriptors, invalid
types, signed bounds and outputs overlapping stream/descriptor fields. Engine
and CRT callees execute unchanged; transient stack contents are outside the
persistent-memory comparison. Full message-body dispatch and transmission
remain unfinished; header framing alone does not establish network operation.

## Bulk bitstream I/O and join-refusal payloads

Recovered `001955D0`, `00195820`, `000AD230`, and `000AD290`, bringing the native
catalog to 135 routines. Bulk bitstream transfers preserve separate byte-aligned
and unaligned paths. Aligned transfers use forward word copies then byte copies,
including their overlapping-buffer behavior. Unaligned writes merge the first
word, construct later words and mask the final word. Unaligned reads preserve
padding bytes beyond the last partial output byte. Both advance by requested
width even when fewer bits fit. Mapped word padding is still required.

Join-refusal encoding transfers the first 64 payload bits, then the low four
bits of the reason at payload `+8`. Decoding writes those same fields and returns
the inverse stream-error status. The size argument is unused in both originals.
The encoder's out-of-range reason diagnostic only formats discarded stack text;
the original formatter/CRT run unchanged in comparison tests.

The bitstream suite adds 1,216 comparisons: 448 bulk reads, 448 bulk writes,
160 refusal encodes and 160 refusal decodes. It covers all bit alignments, partial
bytes/words, empty and short buffers, overlapping source/destination regions,
ignored size values, stream errors and oversized reasons. All original engine
callees remain intact. This recovers the payload used by request rejection,
but the surrounding message queue and packet transmission remain unfinished.

Annotating the bulk-transfer entrypoints adds two functions to the discovered
main-section inventory: all 11,392 now export. Function discovery remains
incomplete, and this export count is not a whole-game recovery percentage.

## Packet packing, unpacking and size accounting

Recovered `00093590`, `00093610` and `000936C0` in `src/network_packet.c`,
bringing the native catalog to 138 routines. Type 3 copies the primary payload
without a prefix. Other types use a little-endian 16-bit primary-length prefix,
followed by primary and secondary payloads. The packet stores lengths at `+1C`
and `+620`, with payloads at `+20` and `+624`.

Unpacking bounds primary data to 0x600 bytes and secondary data to 0x200. For
non-type-3 packets, parsing writes both length fields before validating them;
failed validation preserves those writes. Type 3 rejects oversized input before
writing its length and leaves the secondary fields alone. Packing trusts caller
lengths. Copies preserve original forward word/byte behavior, including overlap.

Accounting rounds a positive signed primary length upward to an eight-byte
boundary, then adds the secondary length and 44 bytes for type 3 or 45 otherwise.
Negative signed lengths are not rounded; all additions wrap at 32 bits. This
function's arithmetic is recovered without assigning undocumented meanings to
the overhead constants.

The new suite has 704 comparisons: 192 pack, 384 unpack and 128 accounting cases.
It executes original instructions without substituted calls, compares all guest
memory/returns, and covers limits, malformed prefixes, partial metadata writes,
overlapping copies, output aliasing and signed/wrapped size calculations. Packet
submission still requires its transport and scheduling dependencies.

## Datagram send wrapper

Recovered `000B5110` as `h2_network_socket_send_to`, bringing the native catalog
to 139 routines. ESI carries the engine address; socket object, data pointer and
16-bit length occupy three stack slots. The return is AX, not full EAX. Ghidra
annotation now explicitly supports word parameters and AX returns.

The wrapper requires both transport-active bytes, converts the original address,
then calls the SDK sendto boundary with flags zero and a sign-extended 16-bit
length. It does not create or validate a socket handle. Only a return whose low
word is FFFF triggers error lookup: 2733 maps to FFFE, 2751 to FFFF, and others
to FFFD. Disabled transport and conversion failure return FFFD without SDK calls.
A host-supplied 28-byte workspace preserves uninitialized stack address bytes,
following the same convention as recovered bind. It must not alias guest memory.

All 512 comparisons execute the original wrapper and address converter intact;
only SDK sendto and error retrieval are controlled. Tests compare AX, persistent
memory, complete address workspace, call arguments/order and callback mutations.
They cover address widths, transport states, negative lengths, high return bits
and all error mappings. This is an SDK boundary, not a Linux socket backend or
a demonstrated live datagram transmission.

## Traffic-statistics window and sample rings

Recovered `000928E0`, `000929D0`, and `00092A30`, bringing the native catalog
to 142 routines. All use the existing clock override (`00510548`/`0051054C`)
or the SDK tick boundary `003314B0`. Native APIs reuse the tick callback from
`h2_network_state_operations`; the other callback is not used here.

The statistics update advances a 20-bucket ring, replacing expired values with
the pending counters and updating wrapping totals. Gaps exceeding 20 periods
clear bucket storage and totals and set the timestamp to now; pending counters
and the ring index are preserved in that branch. Timestamp comparisons retain
the original unsigned behavior, while the quotient threshold is signed.

The separate sample reset timestamps each configured slot and clears its values,
index, total and elapsed fields. Sample insertion removes the replaced value
from the total, records the current timestamp/value, computes elapsed ticks and
advances the index modulo the configured slot count. All arithmetic and stores
retain original ordering. Valid mapped ring indices and nonzero divisors are
caller requirements, as in the original code.

The endpoint suite adds 528 comparisons: 240 window updates, 128 resets and
160 sample insertions. Tests execute original engine instructions, controlling
only SDK time; clock overrides, callback mutations, multiple period boundaries,
long gaps, ring wrap, tick wrap and counter overflow are included. These supply
packet-submission accounting dependencies, not complete networking or gameplay.

## Endpoint route lookup and send dispatch

Recovered `00092E50`, `00092EF0`, and `00093730` in `src/network_routing.c`,
bringing the catalog to 145 routines. Route lookup scans the captured signed
entry count, compares positive signed address widths and the corresponding
address bytes, and returns the first eligible index. Kinds 1 and 2 additionally
require connection state greater than two and flag 80 or 40 respectively; other
kinds have no such filter. Connection lookup returns the matching connection ID.

Send dispatch copies the address to a local record and selects port 1000, 1005,
1006 or 1001 for kinds 0 through 3. A null socket slot returns immediately. It
composes the recovered send wrapper via a host adapter for the local address.
Only signed result -1, unequal to the original full size, triggers route lookup
and setting the matching failure byte. Other errors and short writes leave that
byte alone. The original jump table requires a valid kind from 0 through 3.

The send suite adds 640 comparisons: 192 route searches, 192 connection searches
and 256 sends. All engine callees are original instructions; only SDK send/error
are controlled. Full memory, return values, port selection and callback arguments
are compared. The full temporary sockaddr buffer is compared at the send boundary;
later route lookup reuses that dead stack storage, so its final contents are not
a persistent-state requirement. A live Linux socket backend is still absent.

## Composed packet submission and raw datagrams

Recovered `000932F0` and `00093100`, bringing the native catalog to 147 routines.
Submission packs the packet first, skips accounting for the exact IPv4 loopback
address, otherwise updates two statistics records and their wrapping 64-bit
packet/byte totals. The primary byte count is captured before the first clock
callback; accounted size is calculated afterward and captured before the second.
Only packed sizes 1 through 0x518 are dispatched. The packet's destination and
kind are read after accounting, matching the original callback-sensitive order.

Raw-datagram construction clears a 0x824-byte packet, copies the destination,
sets type 3 and copies at most 0x600 payload bytes. It then submits the packet and
optionally writes its accounted size. Oversized payloads produce output zero.
The reported size does not indicate successful SDK transmission.

Native scratch storage models temporary guest-addressable stack data: 0x1004
bytes for submission, or 0x1828 bytes for datagram construction plus submission.
It must be disjoint from persistent inputs/state. Tests compare defined scratch
bytes against the original stack and restore native scratch before comparing
persistent memory. Address workspace is observed at original send entry, since
intervening calls reuse the stack; this observation does not replace execution.

The new suite adds 288 comparisons (192 submission, 96 outer datagram cases).
Every engine callee runs unchanged in the oracle; only SDK ticks, sendto and
error retrieval are controlled. Payload bytes, SDK argument snapshots, statistics,
loopback handling, size gates, mutation ordering and send failures are checked.
The complete engine datagram path now reaches the SDK boundary, but a live Linux
socket backend, message-queue integration and game boot remain unfinished.

## Message-writer flush

Recovered `0007B330` as `h2_message_writer_flush`, bringing the native catalog
to 148 routines. Inactive writers return immediately. An active writer advances
the bit position by one, computes the byte count with the original signed
arithmetic, rounds it using the stream's alignment divisor, and sets mode two.
It then calls recovered raw-datagram construction/submission and clears the
active byte after return, regardless of the SDK send result. No explicit
terminator-bit store occurs in this routine.

The flush API reuses the datagram caller's 0x1828-byte scratch and address
workspace requirements. A nonzero alignment divisor is required for active
writers; the original faults on zero. Tests also cover signed alignment and
position edge cases without claiming those are normal game inputs.

The submission suite adds 160 flush comparisons. All engine callees run intact,
including datagram construction, packing, accounting, routing, conversion and
send semantics. Only SDK ticks/send/error are controlled. Tests cover inactive
writers, alignment/size limits, position wrap, loopback and failures, including
a send callback that changes the active byte before the final unconditional
clear. Defined scratch bytes are compared against observed original stack
frames, then excluded from persistent-state comparison by restoration. This
closes another message-writer dependency; enqueue/body dispatch, a live Linux
socket backend and game boot remain unfinished.

## Message enqueue, encoding dispatch and retry

Recovered `0007B140` as `h2_message_writer_enqueue`, bringing the catalog to
149 routines. It flushes an active packet when the destination differs, creates
a fresh stream when needed, saves a checkpoint, emits the message marker/header,
and calls the descriptor's encoder. Successful encoding pops the checkpoint.
Overflow rolls back; an existing packet is flushed and encoding retried in a
fresh packet, while failure in a fresh packet returns zero.

The native codec bridge receives the guest encoder address and must dispatch
to the corresponding recovered implementation. It does not execute arbitrary
x86 or silently substitute unsupported bodies. Join-refusal is currently the
recovered encoder used by these integrated tests; other descriptors still need
native encoders. Fresh initialization writes mode one before any calls, so the
original unreachable alternate-mode setup branches have no native side effects.

The submission suite adds 144 cases: original join-refusal encoding with all
engine callees intact, plus controlled oversized encoder callbacks to exercise
fresh-packet rejection. Cases cover inactive/active writers, equal/different
destinations, exact capacity edges, overflow retry and send errors. SDK calls
remain controlled. Temporary packet/packed-buffer bytes are observed before
return from their owning original routines, since subsequent encoding reuses
that stack storage. Native scratch is then restored for full persistent-memory
comparison. This recovers queue mechanics, not all message bodies, live Linux
networking or complete game startup.


Session control and handoff codecs (000ad5a0, 000ad2e0, 000ad3f0,
000ad320, 000ad390) now have native implementations. The shared session-ID
writer transfers 64 bits; both control readers transfer 64 bits and return
success only if the stream has neither a sticky error nor position beyond its
signed capacity. Handoff transfers 64 identity bits, the low four bits of the
signed 16-bit field at payload+44, then 288 bits from payload+8. Decoding writes
only the two-byte field at +44 before reading the 36-byte block. Size arguments
are unused. The discarded local formatting diagnostic is omitted, as in the
other recovered codecs; the oracle executes the original diagnostic unchanged.

The bitstream oracle adds 192 comparisons for each of these five bodies (960
new comparisons), including all bit alignments, empty/short/exact/ample buffers,
sticky errors, ignored sizes, signed/out-of-range handoff fields, and overlapping
payload/data regions. Native execution composes the recovered bitstream routines;
no original engine callee is replaced in these comparisons. Full mapped guest
memory and decoder AL results are compared. These codecs do not implement the
remaining descriptors or a live Linux transport backend.


Join-abort encoding/decoding (000ad1c0/000ad1e0) transfers two successive
64-bit fields. Host-decline encoding/decoding (000ad430/000ad530) transfers a
64-bit identity and one flag, then conditionally two more flags; the last flag
controls a 288-bit block at payload+12. Absent fields retain previous bytes.
The encoder tests nonzero flag bytes and reloads them after each bit write,
which matters when source and stream data overlap. Its inlined flag writes
OR a byte only when signed remaining capacity is positive, always advancing
the position. They do not use the generic word-oriented bit writer.

The recovered boolean reader (001957d0) reads when signed position is LESS THAN
OR EQUAL to signed capacity*8, including one padding bit at the exact boundary.
It returns zero beyond that boundary and advances position regardless of errors.
The native implementation preserves signed truncating byte indices, x86 shift
masking, and wrapped position updates. Mapped padding remains required.

The bitstream oracle adds 256 direct boolean comparisons and 320 comparisons
for each of the four codecs (1,536 total), with original callees intact. Cases
cover signed/wrapped capacity, negative positions for boolean reads, all bit
alignments, all wire flag combinations, short buffers, sticky errors, ignored
size arguments and overlapping payload/data. Full guest memory and decoder AL
are checked. No live networking or game boot is established by these tests.


Election codecs (000ad5c0/000ad710) transfer the session identity, two 36-byte
identity blocks, scalar fields, a five-bit count, six-byte entries, and two
16-bit masks. The writer loops over the signed full input count, reloading it
after every entry. It truncates the count on the wire but does not clamp the
loop; discarded local range diagnostics do not change encoding. The decoder
accepts counts 0–16 for entry reads. Invalid counts skip entries but still read
both masks before failing. Successful decoding also requires no stream error
and no mask bits above the decoded entry count. No unrelated enum validation
has been added.

Election-refusal codecs (000ad820/000ad8d0) transfer a 64-bit identity, four-bit
reason, one boolean, and an optional 36-byte block at the unaligned payload+13.
The reader writes consumed fields even on failure, retains the optional block
when absent, and accepts only reason values 1–10 after checking stream errors.
The writer rereads the flag after its inlined bit write, preserving overlap
behavior. All four callbacks ignore the supplied structure-size argument.

The bitstream oracle adds 512 cases per body (2,048 comparisons), covering bit
alignments, short and ample capacities, sticky errors, out-of-range encoder
fields, all 32 wire counts, invalid counts, mask rejection, all refusal reasons,
optional blocks and refusal buffer overlap. Election entry storage is supplied
beyond the nominal structure for oversized writer-count cases. Original engine
callees and formatting diagnostics execute unchanged. Full mapped memory and
reader AL are compared. This does not establish a running election state
machine, live network transport, or game boot.


Time-sync messages (000ad940/000ad9e0/000ada90) now have native encoding,
decoding and timestamp clearing. Encoding writes the 64-bit identity and low
mode bit. A zero full 16-bit mode sends SDK ticks; a nonzero full mode sends
payload+8, payload+16, and adjusted session time. The full mode is reread after
encoding its low bit, preserving the original out-of-range behavior. Decoder
mode zero reads one timestamp, stores -1 at +12/+20, and adjusted session time
at +16. Mode one reads three timestamps and samples SDK time into +12 after
the first. Header errors fail early; errors incurred by later timestamp reads
are not checked again before returning success. Clearing writes -1 to the four
timestamp words only and returns one.

Session lookup (00075800) searches three slots in order, requiring nonzero
session state at +741c, an enabled byte at +24, and the matching eight-byte
identity at +1c. Adjusted time (000758c0) uses the table at global 510550;
missing/disabled sessions return zero without SDK calls. A matching session
must also enable +78ac. SDK time is added modulo 32 bits to its offset +78b0,
which is read after the callback, while retaining the captured session pointer.

The bitstream oracle adds 256 cases for each of these five routines (1,280
comparisons). Only SDK ticks are replaced; original engine callees run intact.
Cases include absent tables/slots, first matching sessions, disabled states,
clock wraparound, callbacks changing offsets and table slots, mode truncation,
all bit alignments, short buffers, sticky errors and ignored size arguments.
Full memory, return values and callback snapshots are compared. Real transport,
clock synchronization between hosts, and complete game startup remain absent.


Connection message codecs (000ac8a0/000ac900, 000ac940/000ac9a0,
000ac9e0/000aca00, 000aca40/000acab0) now encode/decode request, refusal,
establishment and closed messages. Request transfers a 32-bit value followed
by eight bits; refusal uses 32+3 bits; establishment uses 32+32 bits; closed
uses 32+32+5 bits. Each field occupies a full payload DWORD. Size arguments
are ignored. Writers reread each field immediately before encoding, preserving
overlapping data behavior. Out-of-range diagnostic formatting is discarded
local text in the original and has no native persistent side effect.

Readers write each field as it is consumed, including on overflow. Request,
refusal and establishment return the inverse stream-error predicate. Closed
also requires the captured decoded reason to be below 18. It does not undo
writes on rejection or substitute an unknown-reason value.

The bitstream oracle adds 256 cases per routine (2,048 comparisons), executing
all original engine callees and original diagnostic formatting. Cases include
all bit alignments, short/empty/ample buffers, sticky errors, nonzero buffers,
out-of-range writer values, all five-bit closed reasons, ignored sizes and
payload/data overlap. Full guest memory and reader AL are compared. This
recovers message bodies, not connection negotiation or a Linux socket backend.


Discovery codecs (000ac490/000ac530, 000ac580/000ac610,
000ac670/000ac6e0) implement ping, pong and broadcast-search message bodies.
All transfer a 16-bit first field while preserving payload padding at +2/+3.
Ping then transfers a 32-bit field at +4 and a boolean at +8, with its decoder
writing only that one byte. Pong transfers a 32-bit field and two-bit value,
storing the latter in a full DWORD at +8; only values 0–2 pass validation.
Broadcast search transfers a 64-bit block from +4 after the first field.
Writers preserve the original field read order and OR-oriented bit behavior;
size arguments are unused. Pong's discarded out-of-range formatting diagnostic
is omitted from native code. The original's first-field diagnostic is unreachable
because its 16-bit value is zero-extended before comparison with 65536.

The bitstream oracle adds 256 cases per routine (1,536 comparisons), including
all alignments, short/empty/ample buffers, sticky errors, nonzero padding,
reserved pong values, non-boolean ping input bytes, out-of-range pong input,
ignored sizes and payload/data overlap. Original callees execute intact;
full memory and decoder AL are compared. Broadcast replies still require the
larger session-description codecs at 0007ba10 and 0007c110; no live discovery
or completed session startup is claimed.


Broadcast-reply dependency recovery adds compact configuration codecs
(0007ee10/0007efa0) and text conversion (001405a0/00140650/00140440).
The compact writer encodes four signed bytes plus one with widths 5/5/5/5,
then a signed byte plus one in three bits, two unsigned six-bit bytes and one
four-bit byte. The reader zeroes all 16 output bytes first, reads/debiases the
eight fields, then tail-calls the recovered configuration validator. It does
not substitute the stream-error predicate for that validation result.

Text encoding uses one through four UTF-style bytes for values through 1fffff,
returns the required width even when output capacity is short, and returns zero
without writing for larger values. String encoding treats each 16-bit input
unit separately; surrogate pairs are not combined. It scans through the source
after output fills, terminates in available space or replaces the final output
byte with NUL, and can therefore retain an incomplete encoded sequence.
Decoding checks continuation-byte form but accepts overlong sequences and
surrogate values. Four-byte results are truncated to one 16-bit unit. Invalid
sequences advance one source byte without emitting a replacement character.
The source scan continues after destination capacity fills. The final output
unit is replaced by zero when full. Negative capacities use original signed
comparisons; no standard Unicode conversion semantics are substituted.

The oracle adds 768 compact-field comparisons, 126 single-character encodings,
420 string encodings and 444 string decodings (1,758 total). Original helper
callees execute intact. Cases cover field/data overlap, signed fields, short
streams, malformed and truncated byte sequences, surrogate inputs, capacity
edges and negative capacities. Text buffers are disjoint and padded for the
original reads; full mapped memory and defined return values are compared.
These helpers are prerequisites for the still-unrecovered session-description
codec and do not make broadcast discovery or game startup functional.


Session-description validation (0007b880) and decoding (0007c110) are native.
The validator retains its original second-ID upper-bound quirk: after checking
that the second ID is positive or -1, it compares the first ID again against
65534. Other range checks remain signed as in the executable; fields not tested
by the original are not given new validation rules.

The decoder consumes scalar fields, name text, identity blocks, two player
counts, player records, two masks, mask-selected values and an optional 12-byte
block. Counts must satisfy 0 <= stored <= transmitted <= 16; invalid counts
skip the player loop but still consume trailing fields. Extra transmitted
players are decoded into temporaries and discarded. The stored count is reread
before each player copy. The configuration helper's return value is ignored,
matching the original. Mask values are consumed according to the transmitted
mask and stored only if the description's mask also selects them. Absent
optional data is zeroed. Successful return requires valid counts, no stream
error, and the recovered description validator. Failed decoding retains writes.

A 76-byte caller-owned guest workspace represents the original local identity,
configuration and text buffers, including their overlap/reuse. Its incoming
contents can matter on short reads. The test seeds the original and native
scratch with matching zero or nonzero bytes and text terminators, compares all
76 final bytes, then restores the native temporary region before comparing
persistent guest memory. Inputs/output/workspace are disjoint in these cases.

The new session-description oracle adds 173 validator and 384 decoder
comparisons (557 total), with no original engine callee replaced. Coverage
includes field boundaries, ID validation quirks, all bit alignments, count
relationships, discarded players, optional data, differing masks, text,
short/empty buffers and sticky errors. The suite runs in Release and UBSan.
The description encoder and enclosing broadcast-reply codecs remain incomplete;
this does not establish discovery, session startup or gameplay.


Session-description encoding (0007ba10) and broadcast-reply wrappers
(000ac730/000ac7a0) are now native. Encoding converts the session name before
writing scalar fields, emits signed short fields with original low-bit
truncation, and writes both count and mask copies with the original rereads.
The second count is captured for the player loop, while each iteration rereads
the current count to choose real or zero/default record data. Player identity,
name, scalar, index and compact configuration fields use recovered helpers.
The second mask is captured for deciding which values to transmit, while each
value is selected using the current source mask. Optional trailing data uses
the original byte-oriented flag write and flag reread.

The writer takes 64 bytes of disjoint guest scratch: 12-byte identity, 16-byte
configuration, four-byte captured count, and 32-byte name buffer. Original
name conversion leaves bytes after its terminator unchanged, and those bytes
are transmitted in fixed-size blocks. Initial name-tail contents must therefore
be supplied, not silently zeroed. For player names the original first copies
32 bytes of the UTF-16 source into that name buffer before conversion; native
code preserves this ordering. Range diagnostics only format discarded text in
a separate stack buffer and are omitted.

Broadcast wrappers transfer a 16-bit field and 64-bit identity, then call the
full description codec at payload+12. The reader retains partial writes and
requires both successful description decoding and no stream error. Size
arguments are ignored.

The description suite adds 256 direct encoder, 256 broadcast encoder, and 384
broadcast decoder comparisons (896 new cases; 1,453 suite total). All engine
callees execute unchanged. Scratch is seeded at the description routine entry,
after wrapper header calls have reused stack space, compared on return, and
restored before persistent-memory comparison. Cases include nonzero name tails,
all alignments, empty/short/ample buffers, signed counts, player records, masks,
optional data, malformed decode counts and sticky errors. Stream, description
and temporary storage are disjoint in these comparisons. This establishes
broadcast message serialization, not live discovery or playable game startup.


Join-request codecs (000acc20/000acfa0) are native. The wire starts with a
16-bit field and identity/address blocks from payload offsets +4, +18c, +150
and +194, followed by a five-bit player count. Each player transfers a 12-byte
identity plus eight-bit and 31-bit values biased by +1 on write and -1 on read.
Both loops reread the full count after each entry; the writer uses the signed
input count even when its wire representation truncates. The decoder does not
clamp counts to 16, so larger counts retain the original overlapping field
writes inside the structure.

A boolean controls the four-byte field at +15c; absent data is left unchanged.
The two-bit mode field controls the larger block only when its full source
value is exactly two on write, or decoded value equals two on read. That block
contains three seven-bit values, four four-byte blocks in original order
(+164,+168,+170,+16c), and an optional 12-byte identity. The writer compares
this last identity against guest constant 440070; the reader zeroes it when
absent. Fields outside the selected mode remain untouched. Readers retain
partial writes and return success only without stream error and with a
nonnegative final count. Discarded local range diagnostics are omitted from
native writes; original diagnostics execute intact in comparison tests.

The bitstream oracle adds 512 encoder and 512 decoder comparisons (1,024 total).
Cases include every five-bit wire count, signed/out-of-range writer counts,
all alignments, overlapping record arrays, sentinel limits, every decoded mode,
mode truncation on writes, absent optionals, short/empty/ample streams and sticky
errors. Full mapped memory and reader AL are compared. Stream and payload buffers
are disjoint. This recovers the message bodies, not session admission, network
transport or playable Linux startup.


Native message dispatch (src/message_dispatch.c) connects the recovered codecs
for all 25 discovery, connection and session message descriptors (indices 0–24).
Guest callback addresses identify native routines; the bridge never executes
them as x86 code. Shared Xbox callback addresses map to one recovered body.
Clock operations are forwarded to time-sync codecs, and caller-owned scratch
is forwarded to broadcast-reply codecs under their existing contracts.

h2_message_native_encode returns one when handled, zero for an unsupported
address. h2_message_native_decode returns the recovered 0/1 validity result or
-1 when unsupported. Unsupported direct calls leave guest memory unchanged and
do not invoke clock callbacks. h2_message_native_can_encode supports preflight.
The C queue adapter retains a caller-owned memory/clock/scratch context and
fails fast on an unsupported address because the original queue callback has
no return value; it does not silently emit an empty message. Its context and
scratch must remain valid throughout queue use.

The new dispatcher oracle compares 32 encode/decode fixtures for each of the
25 registered descriptors (1,600 original-instruction comparisons). Half the
encoder cases use the C adapter. It checks full guest memory, decoder results,
clock events and description scratch with original engine callees intact.
Twenty unrecovered descriptor pairs and three invalid address pairs verify
unsupported handling without memory or clock side effects. The existing
592-case submission suite now uses the C adapter for join-refusal queue
encoding, retaining its controlled oversized encoder cases. This adds native
integration rather than newly recovered Xbox functions, so the catalog remains
194 routines. No complete network startup, live transport or gameplay is
established by these checks.


Packet message reader (0007afd0) is recovered with explicit engine decode and
delivery callbacks. It initializes stream mode three, resets position/depth/error,
reads a 32-bit debug marker, and sets the sticky error for 64656267. Other initial
values reset position/error again. After the initial error check, it reads a
message marker using the original inclusive-boundary boolean behavior. A zero
marker sets mode five and returns the last decoder byte (initially one), without
an additional overflow check. Thus the original empty-stream/end-marker behavior
is retained rather than tightened.

Each marked message captures the owner's descriptor table, reads/validates the
header, zeroes exactly the declared payload size, and invokes the descriptor's
decoder. Failed header or zero decoder result returns zero with mode three and
partial state preserved. Successful decoding rereads owner+10 for the handler;
when nonzero, delivery represents the still-unrecovered 000938e0 dispatcher.
The owner/table are read again on the next message. Payload storage is reused,
so a delivery implementation must copy any message it retains.

Caller-owned guest scratch is 0x10008 bytes: header type and size followed by
65536 payload bytes. Incoming payload bytes reproduce stack contents beyond the
zeroed size. The oracle seeds original locals after the CRT stack probe (which
itself executes unchanged), compares final header and payload scratch, restores
native temporary storage, then compares persistent guest memory and callback
snapshots. The original stack mapping is extended to accommodate this routine's
64 KiB frame.

The new reader suite runs 384 cases in each build: debug marker, empty/short
streams, multiple messages, malformed/disabled headers, original ping/refusal/
leave decoders, decoder failure, raw nonzero decoder bytes, and handler/table
mutation. Original codec/header callees execute intact through native dispatch
on the native side. The engine delivery dispatcher is a controlled callback;
additional synthetic decoder cases test control flow and mutation explicitly.
This recovers packet parsing, not message-handler bodies, socket receive I/O,
complete session startup or gameplay.


Ping handling (00093f60) now composes recovered message writing. It captures the
input 16-bit identifier and 32-bit timestamp, writes them to a 12-byte local
reply representation, sets the reply's final DWORD to two, and enqueues message
type one through the writer at handler+0c. It ignores the ping flag and enqueue
return value, as the original does. Incoming reply padding at +2/+3 is retained;
the caller supplies disjoint reply scratch and the packet/address scratch
required by existing writer/transport APIs.

The submission oracle adds 144 original-instruction comparisons. Original pong
encoding, enqueue, flushing, datagram construction and transport engine callees
all execute intact; only SDK send/error/time boundaries are controlled. Native
encoding uses the shared C dispatcher adapter. Cases cover inactive/active
writers, destination changes, full-packet retry, send failures and nonzero reply
padding. Reply and packet scratch are compared and restored before persistent
memory comparison. Codec events compare payload bytes rather than original
stack/native workspace addresses. Submission suite total: 736 comparisons per
build. The general 000938e0 handler dispatcher and actual Linux socket backend
remain missing, so this does not establish a live ping exchange or game boot.


Discovery cache updating (000b2fc0) and broadcast-reply handling (000940b0)
are native. The handler requires version two, an enabled search and an exact
match of the reply's eight-byte query identity to globals 4d8ebc/4d8ec0. Its
address argument is unused. Cache update scans the signed count at 4d8ec4,
using 0x784-byte entries from 4d8ec8. It chooses the first matching 36-byte
identity, otherwise the first inactive slot, otherwise the last eligible
replacement. Eligibility preserves the signed short comparison between the
reply's +aa field and each entry's +10e field, with the original nonzero/+20
conditions. No additional eviction policy or count clamp is added.

New/replacement entries are zeroed. Changed descriptions copy 0x714 bytes from
reply+12 to entry+70 using forward DWORD copies, set entry+6c and global dirty
byte 4d8eb5. Identical descriptions retain existing dirty state. The active
byte is set before taking time. Override time sets the recent byte before
storing the timestamp; SDK time stores the timestamp before setting recent.
The selected entry pointer is retained across the SDK callback even if that
callback changes the global table. Empty/disabled/full ineligible searches
perform no update or clock call.

The discovery oracle adds 384 updater and 384 handler comparisons (768 total),
with all original engine callees intact and only SDK ticks controlled. It
checks full memory and callback snapshots for signed counts/ranks, duplicate
matches, first free/last replacement, query mismatch, zero inserts, unchanged
descriptions, dirty flags, timestamp wraparound/override and callback mutation.
Reply/cache regions are disjoint in these cases. The suite runs in Release and
UBSan. Search orchestration, Linux sockets and complete gameplay remain absent.

## Discovery maintenance (`000b2ea0`)

`h2_discovery_update` returns immediately when discovery is inactive. It uses
wrapping 32-bit subtraction interpreted as signed: a delta strictly greater
than 1500 queues type 2, size 12 through the recovered message writer. The
request contains version 2 and the captured 64-bit query identity. Destination
is IPv4 broadcast, port 1001; twelve unused address bytes preserve incoming
stack contents. Native callers supply a disjoint 32-byte local workspace.
Enqueue failure is ignored; a fresh clock value is stored after enqueue. A
search that is not due leaves the last-send global untouched.

Cache entries older than 2000 by the same signed subtraction are cleared in
full (0x784 bytes) and set the global dirty byte. Cache base/count are reloaded
for each iteration, while the current entry and timestamp are captured across
the SDK clock callback. Override state is rechecked at every clock read.

The new oracle compares 512 cases against the original instructions, including
actual enqueue and broadcast-search encoding. It checks local padding, full
guest memory and clock snapshots under boundary timestamps, rollover and
callback mutation. Fresh writers avoid sending in this suite; packet flushing
and SDK send boundaries retain their existing independent oracle coverage.
No Linux socket backend or playable startup is supplied by this change.

## Discovery activation and query identities

`0007ad80` (`h2_random_bytes`) checks the byte at 4cf790 once. If set it calls
the SDK random-byte provider with the original output/count and ignores its
return. Otherwise it acquires time, CRT random, then ticks, XORs those values,
and emits the high byte of each LCG step (`seed * 0x19660d + 0x3c6ef35f`,
modulo 2^32). Zero and negative signed counts still acquire all three values
but write no bytes. The original instructions return no meaningful result.

`0007ad50` (`h2_random_identity`) requests eight bytes until they differ from
the two-DWORD sentinel referenced by 46725c. The sentinel pointer is fetched
after each random call, so callbacks can change it. This preserves the
original retry loop without an arbitrary retry limit.

`000b2e30` (`h2_discovery_start`) retains the raw active byte if already active
or transport flags 4d8b18/19 do not allow startup. Otherwise it sets active,
clears dirty and last-send time, generates the query identity, publishes the
captured cache pointer/count, and zeros `(count * 0x784) mod 2^32` bytes. It
returns the current active byte, including changes made during entropy calls.
The native platform boundary is `h2_random_bytes_platform`; existing
`h2_random_sources` supplies the fallback entropy calls.

The new oracle checks 256 random-byte, 256 identity and 256 startup cases
against original x86 instructions, with only CRT/SDK entropy controlled.
Cases include signed count boundaries, SDK/fallback switching between retries,
changing sentinel pointers, return-byte mutations, and wrapped zero sizes.
Another 64 comparisons carry state through sixteen start/query/reply/expiry
sequences with the actual queue, encoder and cache handlers. This establishes
engine integration in mapped memory; it does not establish live socket
discovery or playable Linux startup.

## Discovery cancellation and stop

`000b31b0` (`h2_discovery_cancel_tasks`) cancels online handle 4d8ef0, then
reloads async handle 4d8ef4 and releases it. Each non-sentinel handle is reset
after its call, including invalid handles. Finally it clears the byte at
4d8ecc and DWORDs 4d8ef8/4d8efc, preserving adjacent bytes. Original online
and async cancellation implementations are reused without substituting their
engine bodies. Callback changes to the later handle remain observable.

`000b3670` (`h2_discovery_stop`) chooses task cancellation when byte 4d8f08
is nonzero; otherwise it clears local discovery's active byte. It then reloads
the allocation at 4d8f18. Nonzero allocation invokes the allocator's second
virtual method using identity 4d8f10, followed by clearing 4d8f18 and 4d8f14.
No allocation leaves the latter field untouched. The native bridge uses the
existing `h2_allocator` release contract; the oracle controls this virtual
method, not its underlying allocator implementation.

The new suite compares 384 direct cancellation and 384 stop cases with original
x86, checking full memory and callback snapshots through SDK errors, task
kinds, stale handles, poisoned deletion, local/online mode, changes to later
handles/allocation during callbacks, and writes after allocation release.
This supplies two dependencies of the larger networking shutdown path;
it does not complete network shutdown or game boot.

## Registration release and endpoint route removal

`000b3b10` (`h2_network_registration_release`) does nothing when 5107dc is
FFFFFFFF. Otherwise it captures the entry address `510588 + index * 0x4a`
with wrapping 32-bit arithmetic. A nonzero 5107e0 is sent to SDK 003cd344,
then cleared; SDK 003cd0e1 receives the captured entry+30 even if the first
callback changed the index. Both results are ignored. The routine decrements
the current 5107e4, resets index to FFFFFFFF, and clears 5107e0 again.
The host API labels these two external boundaries release_address/release_key
descriptively; it does not implement a Linux registration service.

`00092e00` (`h2_network_endpoint_remove_route`) takes endpoint in EAX and
connection ID in EBX, returning AL. Nonpositive signed route count does
nothing. The first matching ID in the 32-byte entries beginning at +24 is
removed: decrement +20, then copy the final entry over the removed entry if
it was not already last. The old final entry is retained. The native copy
preserves the original forward DWORD order.

The combined oracle adds 384 registration-release cases, 384 repeated calls
(which must observe the sentinel), and 384 route-removal cases. It compares
full guest memory and SDK snapshots, including callback changes, SDK errors,
counter underflow, wrapped key arguments, duplicate routes and signed counts.
Invalid key pointers are observed at the controlled SDK boundary rather than
dereferenced. These routines are dependencies of connection/network cleanup;
the enclosing shutdown and game boot remain incomplete.

## Connection close and endpoint-wide close

`00088650` (`h2_network_connection_close`) queues a type-7, 12-byte message
only when connection+54 equals 5 and reason is not 6. The payload captures
+50, +4c, then the reason, using a caller-supplied disjoint 12-byte workspace.
The actual recovered queue and closed-message codec are used. Queue failure
is ignored. A nonzero callback record at +3c invokes its function at +8 with
the argument at +4; the native bridge preserves that function/argument pair.

After callback return, close reloads endpoint and connection ID and removes
the route. It copies the 20-byte current address from +70 to +5c in forward
DWORD order, sets state+54 to 2 and reason+58, and invalidates both IDs at
+4c/+50. Thus changes to endpoint, ID and address during callbacks are visible.

`00092f10` (`h2_network_endpoint_close_connections`) scans successive route
slots and reloads global connection base 4d87d4 for each close, using reason 1.
The loop advances even when route removal swaps the final slot into the
current position, and compares its index against the updated signed count.
It then sets the endpoint count to zero. This may leave swapped connections
unvisited; the native implementation preserves the original behavior.

The new 768-case oracle checks original close and endpoint-wide instructions
with original route/queue/codec callees intact, controlling only the connection
callback. It covers no-send branches, signed counts, route swaps, callback
changes and connection-table replacement. Another 144 cases extend the packet
submission oracle through real queue overflow/flush/datagram construction with
SDK send/time/error boundaries controlled. Payload and packet stack scratch
are compared against original bytes and normalized before full persistent
memory comparison. Live Linux networking and full shutdown remain incomplete.

## Queued storage cleanup and connection disposal

`00094bf0` (`h2_network_storage_clear`) walks two circular queues when storage
byte+4 is nonzero. Each uses signed sequence comparisons and signed remainder
with wrapping 32-bit numerator arithmetic. Queue one has 12-byte entries at
+2c, queue two eight-byte entries at +1848. Byte+1 of an entry is subtracted
from the corresponding byte counter before virtual lookup/release. Queue one
performs these operations even for handle zero; queue two skips zero handles.

The provider owner comes from 4d87f8, pointing to an object whose vtable has
release at +0 and lookup at +4. Lookup AL failure stores FFFFFFFF to its local
output. Release receives the captured handle and FFFFFFFF; the owner is
reloaded after lookup and retained across release for the reference decrement.
Queue one retains that owner in stack scratch, while queue two retains it in
a register. Nonzero handles decrement the captured owner's +4 count. Entries
are cleared after callbacks; bounds are reloaded. Both queue indices/counts,
byte counters and the pending byte reset, while their reset flags become 1.
Native callers supply eight disjoint guest scratch bytes, preserving incoming
stack values and callback-visible writes. Division faults are not modeled as
x86 exceptions: invalid zero/overflow divisions abort the native process.

`000886e0` (`h2_network_connection_dispose`) closes states signed-greater-than
2 with reason 3, clears +40, and disposes the indexed 0x2850-byte storage slot
via the recovered clear routine. The captured slot then loses its active byte
and owner, and the connection slot index becomes FFFFFFFF. The second slot
index is reloaded afterward; a present 0x97c-byte slot loses its active byte
and owner as well. The final connection state is zero.

The new oracle compares 512 direct cleanup and 512 disposal cases, including
actual close/queue/codec/route-removal callees. Virtual provider methods are
controlled and all other engine instructions execute intact. It checks full
memory, callback snapshots, local scratch, signed ranges/remainders, circular
wrap, zero handles, lookup AL failure, unchanged lookup outputs and callback
changes to owner/counters/bounds or the next slot index. Message scratch is
captured before the original stack is reused for storage cleanup. These
tests do not supply the virtual allocator bodies or complete game startup.

## Observer detach and address helpers

`0007aec0` (`h2_network_address_registered_ipv4`) accepts a nonnull address
with a nonzero IPv4 value and width 4, writes the byte-swapped value, and
returns AL=1 only when the original high byte is zero. A nonzero high byte
still writes output but returns zero. Width FFFF and IPv6 width 16 are checked
for nonempty address data but do not produce output. Other widths, null and
empty addresses return zero. Output may alias input; captured values preserve
the original order.

`0007b390` (`h2_message_writer_flush_address`) flushes an active writer only
when its cached address width is a positive signed short equal to the supplied
width and all that many address bytes match. Port is outside ordinary IPv4/IPv6
comparison. The existing native flush/datagram implementation is reused.

`000784a0` (`h2_network_observer_detach`) selects observer+a8+index*528.
A present connection with signed state greater than 2 is closed with the
supplied reason. It then validates the entry's current address at +5c, flushes
its observer writer if matching, and, when the mark argument's low byte is
nonzero and +3c lies in 0..3, sets the corresponding +38 bit. Registered IPv4
conversion reuses the original first stack argument; successful conversion
calls SDK 003cd344, ignoring its result. All 20 address bytes are then cleared.
Invalid/empty addresses return before flush, marking, release or clearing.
Connection callbacks can change the address and bit index before these steps.

The new observer oracle contributes 512 full-memory comparisons with original
close/queue/codec/route/helper callees intact; only connection callback and SDK
address release are controlled. Its queues are inactive or target a different
address at the conditional flush. Another 160 cases extend the packet oracle
through matched/mismatched flush and actual datagram construction, controlling
SDK time/send/error. The address suite adds 384 conversion/alias comparisons.
Native scratch includes 12 close-message bytes and four bytes corresponding
to the original reused argument, checked separately before normalization.
Complete observer disposal/state transitions and game boot remain unfinished.

## Observer slot release and observer disposal

`00076ef0` (`h2_network_observer_release_slot`) captures the selected slot at
observer+a8+index*528, detaches with mark 0/reason 14, then reloads its connection
index. A present connection is disposed through the recovered native routine
and the slot index reset. The async handle at +70 is then reloaded and released
if non-sentinel. Finally all 528 bytes are zeroed, with +0c/+70 restored to
FFFFFFFF. Callback changes before either reload therefore affect later cleanup.

`00075a40` (`h2_network_observer_dispose`) examines fifteen successive slots
and releases each whose current first DWORD is nonzero. Inactive slots retain
their contents; callbacks may activate a later slot before it is examined.
The routine then clears 90 bytes at observer+14 and the DWORDs at +10/+0c/+04,
preserving +00/+08 and other bytes outside those regions.

The new 512-case oracle runs original engine callees throughout the complete
slot/dispose chain, controlling only connection callbacks and SDK address/task
release. It checks full memory, callback snapshots, zero/invalid handles,
shared connections, SDK failures, poisoned task deletion and pool replacement.
The integration uses empty storage queues and inactive/nonmatching writer
flushes; nonempty queue cleanup and actual datagram submission have separate
oracles. Scratch snapshots follow repeated close calls and the original's
reused argument/stack locations. These routines close another main shutdown
dependency, but observer transitions and full network shutdown remain missing.

## Observer state setting, updating, and connection cleanup

`00077330` (`h2_network_observer_set_state`) changes and timestamps a slot
only when its state differs. It rechecks the state after the clock call;
state 1 notifies consumers through vtable+10 with the slot index. Each of
four consumers is selected by the current byte at slot+9, reloaded before
each call, as are the consumer object and vtable method.

`00076ff0` (`h2_network_observer_update_slot`) preserves the original state
dispatch table: states 6/8 handle connection success or failure, state 7
handles established-connection loss, and the other valid states continue
to notification handling. Missing connections detach then enter state 1.
Failure reasons 1/2/5 detach with reason 15; reason 9 has the original
intermediate state-2 transition and retry reset before its common branch.
Retry increments wrap at 16 bits. State changes and callbacks may alter
what later checks observe. Invalid table targets abort in native code; no
claim is made for executing the original's arbitrary out-of-range jumps.

A lost/mismatched connection notifies current consumers via vtable+0c with
index, identifier and connected=0, then clears the notification bit and ID.
A newly established state-7 connection resets selected counters and both
sample arrays through the recovered sample reset, records timestamps and
the default floating-point bit pattern, computes the signed-short interval
with fallback 60, subtracts it from the global 64-bit tick count, and notifies
with connected=1. The captured connection pointer survives callbacks;
notification masks, objects and identifiers are reloaded per consumer.

`00078880` (`h2_network_observer_close_connections`) examines fifteen active
slots, closes signed connection states greater than 2 with reason 3, then
updates that slot through the recovered transition routine. It reloads
connection base/index before disposal and resets the slot's index afterward.
The original assumes active slots have valid connection indices; no invented
missing-index guard is added.

The new state suite compares 384 setter and 1,152 updater cases with original
engine callees intact. It checks full memory and callback snapshots, states
0..9, retry reasons/wrap, notifications, sample counts, signed intervals,
64-bit borrow, clock override, and callback changes to state/mask/object/ID.
The existing cleanup oracle adds 256 whole-observer connection-close cases
using real transition/disposal callees, empty queued storage and disabled
consumer masks. SDK calls and virtual consumer methods remain controlled.
The rest of observer/network lifecycle and playable game boot are unfinished.

## Global connection-manager cleanup (`00081f80`)

`h2_network_connections_dispose` first closes connections in the fixed observer
at 5291a0 using recovered engine callees. It resets two vtable pointers in the
object referenced by 4d87e8, clears byte+29 in the objects referenced by
4d87f0/4d87ec, and clears the three connection/storage array globals.

The provider wrapper at 4d87f8 is captured afterward. A nonnull wrapped object
receives virtual method +34 with flags=1; the captured wrapper's first DWORD
is cleared on return. The captured wrapper is then passed to CRT free thunk
00321379, and the global wrapper pointer is cleared. Callback changes to that
global do not redirect the free. Other fields are reset in original order.
Crucially, 4d87e4 is a byte store, preserving the three neighboring bytes; the
pseudocode's apparent DWORD assignment was not used.

The existing observer-disposal oracle adds 256 manager-level comparisons with
the fixed observer address and actual connection/observer/storage callees.
It controls virtual provider destruction and CRT free explicitly, checks full
memory and intermediate snapshots, varies optional resources, and mutates
wrapper/global pointers during callbacks. Callback writes to globals cleared
earlier are preserved unless the original resets them again. Empty queued
storage and nonmatching writer destinations retain the integration fixture's
existing scope. This recovers a main shutdown dependency, not the entire
shutdown: direct calls 0008e0f0, 000590b0 and 0005a520 still need recovery.


## Tracked-task scheduling dependencies

Five routines now have instruction-reviewed native implementations in
`network_tracking.c`: free-record selection (`0008e1e0`), write/read queuing
(`0008e500`, `0008e580`), and write/read start (`00080ff0`, `00080f70`).
The read/write names describe the separate pending lists and CRC-on-write
behavior; original class/type names remain unestablished. These supply the
scheduling dependencies of the unrecovered task completion routine `00081050`,
which is called by tracked-task cleanup `0008e0f0` during network shutdown.

The record scan selects the first empty object pointer among 32 records of
20 bytes. Each pending list has 16 entries and uses -1 as its empty sentinel.
The routines preserve the original behavior on exhausted tables: they still
write using the -1 index, immediately before the corresponding table. Neither
queue helper introduces a capacity guard. Both preserve the fifth record word.
Write queuing for object types 1 and 2 initializes the first data word to -1
and invokes the recovered CRC routine over the same buffer before publishing
record fields. Read queuing returns the selected record index in EAX despite
the earlier unreviewed pseudocode declaring it void.

Start routines return AL and purge four stack arguments. They leave pending
objects unchanged. Otherwise they store the token, three arguments and low
16 bits of flags. Read start can return success without queuing when the type
is nonzero and status bit 1 is set without bit 3. Queued reads set pending=1
and clear status bit 1 except for type 4; writes set pending=2. A -1 record
index is stored and produces failure after the queue helper's writes.

`network_tracking_oracle.py` supplies 2,560 comparisons across all five routines,
with original CRC and all callees running intact, no mocked dependencies.
It compares full mapped memory and meaningful return bits across empty,
occupied and full tables, flag combinations, pending work, CRC lengths, and
buffers aliasing task fields. These tests do not establish task completion,
main networking shutdown, live Linux networking, or game boot.


## Task completion and integrated tracked-task removal

`h2_network_task_complete` (`00081050`, EAX object, ECX reason, void) copies
pending kind to the previous-kind word, stores the low reason word, clears
pending and the record index, and updates status bits according to reason.
Reason comparisons use the full 32-bit input. Reason 7 can restart reads or
writes before invoking completion callbacks. The table at object+0 contains
callback pointers at +0x14 (previous write) and +0x18 (previous read), each
receiving the object on the stack and returning AL. A false callback restores
the captured status word ORed with the current pre-callback bit 2, and bypasses
the reason-1 early return. Subsequent processing honors current flag bit 1,
optionally invokes table+0x10, updates current low-byte bits 1/3, and may restart
again based on the current previous-kind field. Retry counter 0x55e700 wraps.
All scheduling and CRC dependencies run through their native implementations.
The callback bodies remain explicitly supplied by the host integration.

Three resource-release routines support the remaining cleanup branch:

- `002d15da` calls the memory-protection SDK only for a nonzero length; it
  purges all three arguments even on the no-call path. The native platform
  boundary receives address, length and protection bits without reinterpretation.
- `0013d830` captures a 24-byte pool entry before an optional handle callback,
  then reconnects links using the current pool pointer but the captured selected
  entry. Head/tail fields are manager+0x3c/+0x40. It calls recovered data deletion
  with the freshly loaded pool pointer, including original poison behavior.
- `0012d520` captures a 40-byte resource entry using the handle at payload-0x24,
  requests protection 0x404 for the address/length in the header, then clears
  the captured entry's active bit. It reloads the payload links and manager,
  reconnects the buffer list, and invokes the recovered entry deletion. SDK
  protection and optional release callbacks are controlled boundaries, not
  implementations of Linux memory protection or the original callback bodies.

`h2_network_tracking_remove` (`0008e0f0`) now integrates actual online cancellation,
task completion and conditional resource release. Its previously omitted second
stack argument is the completion reason; original return purges eight bytes.
It reloads the tracked object after cancellation and completion. Type 4 with
record index -1 releases a nonnull payload and clears both allocation fields on
the captured object after release. It clears four record words, preserving the
fifth, and removes the index from both pending lists. Compaction moves entries
back by one position whenever the preceding slot is empty, preserving the
original single-pass behavior instead of packing every nonempty entry densely.

The new suites compare 1,536 completion cases and 2,048 protection/release/removal
cases with original instructions. All engine callees remain intact. They compare
full mapped memory and callback arguments/order/snapshots across null callbacks,
reason and flag combinations, retry scheduling, full tables, zero lengths,
poisoned deletion, list endpoints, and callbacks replacing pool pointers,
managers or tracked objects. Coverage assertions require integrated tracked
removal to reach task, SDK-close, protection and resource-release boundaries.
Main networking shutdown still needs session and parameter cleanup (`000590b0`,
`0005a520` and their dependencies); playable startup remains unfinished.


## Session cleanup and join-abort transition

Four routines in `network_session_lifecycle.c` now cover another part of the
session shutdown path. Names describe observed behavior, not recovered symbols.

`0005f970` takes session in EDI and peer index in EDX. It clears the session's
consumer bit in an associated observer entry, zeroes the 20-byte peer record,
and restores its observer index to -1. The original uses an 8-bit shift result
with a count masked to five bits: consumer indices 8–31 produce a zero bitmask,
while index 32 wraps to bit 0. The preceding state-dependent scan reads valid
session peer storage but has no persistent result; the native routine omits that
scan. Full exception behavior for invalid session memory is not claimed.

`0005fb60` takes session in ESI. An inactive registration returns unchanged.
Otherwise it optionally calls SDK `003cd147` with the identity pointer, three
zeros and flag 16, captures the key-record address using the current session
index, and releases an active key through `003cd0e1`. It clears that captured
record's active byte after the callback, then reloads observer and consumer
pointers for unlinking. Session identity, unaligned key fields and active flag
are cleared, preserving adjacent padding. SDK return values are ignored.

`000623e0` takes session in ESI. It captures the retry timestamp before reading
the clock, compares the signed wrapping elapsed time with the freshly read
threshold, and when overdue queues type-9 join-abort data from four session
words. It ignores enqueue failure and reads a fresh clock value for the new
retry timestamp, rechecking the override flag after enqueue/flush callbacks.

`00061180` takes session in EBX and transitions to state 2. It captures 112 bytes
of selected joining-state fields before the clock callback, increments the
membership version, clears membership storage, detaches active peers, installs
the saved state and immediately calls the recovered join-abort update. The
saved clock goes to session+0x7488; the retry timestamp at +0x748c is initially
zero. Incoming fields modified by the clock cannot replace already saved data.
Native guest scratch models the 112-byte saved state and the separate 16-byte
message payload; both must be disjoint from live objects and packet scratch.

`network_session_lifecycle_oracle.py` compares 2,560 cases with original
instructions: 512 each for peer detach, registration release, timer update and
transition, plus 256 each for timer/transition paths with an already-active
writer that must flush. Message descriptors, codec, queue/flush, packet building,
statistics and socket helpers all execute intact. Only SDK clock/send and
registration calls are controlled. It checks full persistent memory, scratch
contents, packed bytes and callback snapshots/arguments/order, including clock
and SDK mutations of pointers, indices and timestamps. Coverage assertions
require both flush modes to reach the SDK send boundary. This is not a complete
session state machine, live Linux networking or playable game startup.


## Reliable-message storage enqueue

`h2_network_storage_enqueue` reconstructs `00095580`, four stack arguments
(storage, type, size, payload), void return, 16-byte stack purge. The routine
uses a 65,535-byte zeroed encoding area and a bitstream whose initialized fields
and retained padding match the original stack frame. It calls the recovered
header writer and the descriptor's encoder, computes the signed byte count and
alignment remainder, sets mode 2, then computes the CRC over its sentinel word
and the encoded bytes. Native scratch is 0x10037 guest bytes, with the stream at
+0, CRC word at +0x34 and encoded data at +0x38. It must not alias live objects.

The queue splits the CRC plus encoded bit count into fragments of at most 256
bits. Before each attempt it calls the storage's virtual poll method with zero;
a nonzero AL cancels. A full ring sets the pending byte and retries. Allocation
uses a captured global provider wrapper and virtual method +0x14(bytes,0,0).
Failure calls collection method +0x28(0), reloads the object through the captured
wrapper, and retries once. Repeated failure sets pending and returns to polling.
There is no invented retry limit: the original virtual protocol controls progress
or cancellation. Successful allocations increment the captured wrapper's current
reference count, even if callbacks replace the global wrapper pointer.

Appending preserves signed sequence comparisons, wrapping counters and signed
remainder indexing. Fragment bytes are copied before the ring descriptor is
zeroed and populated with flag 4 (continuation) or 12 (final), byte count, bit
length, allocation pointer and -1 marker. The byte-accounting counter increases
by the fragment's byte count. Division faults and invalid guest pointers abort
the native process; x86 exception equivalence outside valid queue state is not
claimed. Virtual provider bodies remain host integration boundaries.

`network_storage_queue_oracle.py` runs the original stack probe and all header,
codec, bitstream and CRC instructions. The oracle extends its mapped stack for
the large original frame. It compares complete persistent memory, normalized
stack scratch and virtual-call snapshots/arguments/order. There are 768 cases
with 24 recovered message codecs, 384 explicit synthetic bulk-codec cases at
fragment boundaries and with changed signed alignment, and 86 follow-up clear
calls. Those follow-up cases release every newly generated fragment through the
recovered clear routine and assert zero reference and byte counts. Other cases
exercise cancellation, queues that later drain, collection/retry, wrapper/object
replacement, negative sequence values and wrapping reference counters. SDK ticks
and virtual poll/allocate/collect/lookup/release methods are controlled.

This supplies the reliable branch's storage dependency for observer dispatcher
`00075e80`. That dispatcher, address-resolution helpers, session broadcast and
remaining shutdown state transitions still need recovery before full shutdown.


Address resolution and observer dispatch
----------------------------------------
`src/network_resolution.c` recovers address validity (`0007af40`), key-specific
resolution (`0007adf0`), eight-key fallback (`0007ab10`), SDK preparation
(`0007acc0`), and observer output assembly (`000783d0`). The SDK preparation
return is treated as a status code, without claiming a completed connection.
Scratch preserves incoming stack bytes, including unused address bytes. Outputs
reload the captured consumer slot after callbacks, matching the instructions.

`src/network_observer_send.c` recovers `00075e80`: cached or resolved datagrams
execute the recovered writer, codecs and packet flush; reliable messages execute
the recovered storage queue. Signed connection states and the original 64-bit
message-mask shift behavior are preserved. The resolution suite supplies 3,328
comparisons, including 256 cases with an already queued message requiring flush.
The storage queue suite adds 512 reliable dispatcher cases (1,750 total).
Callbacks control SDK resolution/preparation/send and allocator/provider methods;
these comparisons do not demonstrate live Linux networking or game startup.


Session send/leave/disband
-------------------------
`src/network_session_send.c` and `include/halo2/network_session_send.h` implement
`00062d20`, `00062da0`, `00062480`, `00061330`, and `00061450`. The routines are
included in the native library and original ABI catalog. Run the focused suite:

```sh
.tools/venv/bin/python tests/network_session_send_oracle.py
```

The 1,280-case suite executes actual recovered callees through SDK send and
virtual allocation boundaries, with both reliable and unreliable delivery.
Broadcast reloads the signed peer count after callbacks. Leave retry captures
its timestamp before the clock callback and reloads the timeout afterward;
state transitions preserve the original clear/send order. The host context
supplies platform callbacks and disjoint reusable scratch. Message, dispatcher
and normalized reliable scratch are compared before restoration. Packet scratch
has separate coverage in the observer dispatcher oracle. The suite participates
in both Release and UBSan validation. Live Linux networking and game startup
remain unfinished.


Recursive session control
-------------------------
`src/network_session_control.c` implements shutdown request `0005a400`, cleanup
`0005a520`, and handoff initialization `000614a0`. Original recursive engine
calls remain intact; the only new host callback is the optional virtual method
at the session owner object's vtable offset 8 (ECX object, no stack arguments).
Cleanup reloads callback-modifiable fields and preserves memory the instructions
do not reset. Handoff preserves the incoming flag byte and original masked
32-bit shifts, including clock mutation between the count guard and mask setup.

All three routines are in the main library and ABI catalog. The 1,536-case
`tests/network_session_control_oracle.py` suite participates in Release and
UBSan validation. It compares valid states, recursion, actual message transport
helpers, SDK/virtual callback mutations and scratch. Unknown original jump-table
targets abort; equivalence to invalid guest execution faults is not claimed.
Full networking shutdown and playable Linux startup remain unfinished.


Session task cancellation
-------------------------
`src/network_session_tasks.c` recovers `0006f0f0` (ESI object, no stack arguments).
It captures the session through object+8 before callbacks, conditionally sets
object+0x104 to 16, cancels the online handle, reloads and releases the async
handle, and invokes actual session shutdown on the captured session. Final
individual byte/DWORD resets preserve the remaining object fields.

The 512-case `tests/network_session_tasks_oracle.py` suite runs in both Release
and UBSan. Task kinds 0/2/3/33, sentinel/invalid/live handles, poisoned pool
deletion and callback replacement of provider/session pointers are included.
Both engine cancellation and recursive session-control callees execute intact;
SDK operations remain controlled boundaries.

Admission identity helpers
--------------------------
`src/network_session_identity.c` recovers machine lookup `0005f6f0`, player
lookup `0005f890` and queued identity insertion `00062eb0`. Machine lookup
captures a signed count and copies each six-byte identity to scratch before
comparison. Player lookup captures a 16-slot membership mask. Queue insertion
retains sequential unaligned writes and reloads owner identity after the clock
callback, then invokes actual player lookup. Inputs may overlap queue entries;
the machine scratch must be disjoint.

The 1,536-case `tests/network_session_identity_oracle.py` suite runs in both
Release and UBSan. The four routines are included in the main library and ABI
catalog. Complete admission still requires observer and membership routines;
main network shutdown and playable Linux startup remain unfinished.


Observer close and membership
-----------------------------
`src/network_observer_admission.c` recovers `00075e40`, which closes a selected
observer connection with reason 17 only when its signed state exceeds 2. Actual
connection close handles message serialization, callbacks and route removal.
Its 512-case suite is `tests/network_observer_admission_oracle.py`.

`src/network_session_membership.c` recovers attachment `0005f900` and insertion
`0005fbd0`. Insertion retains initialization before identity copies and calls
actual attachment; attachment retains incoming flag bytes and writes its captured
peer timestamp after SDK callbacks. Native 16-bit string copying reproduces the
original CRT bounded copy and explicit termination. The 1,024-case membership
suite compares original CRT execution, synthetic default-name lengths, aliases,
wrapping counters and callbacks.

Membership removal
------------------
`src/network_session_removal.c` recovers player removal `00060200`, peer removal
`0005fe20` and peer-flag refresh `0005a2e0`. Removal retains actual reservation
lookup and peer detach calls. It captures the number of shifted peers before
child calls, preserves sequential owner-index adjustments and overlapping
memmoves, reloads the count for tail clearing, then updates revisions and flags.
The reused player-index stack argument becomes a reservation pointer or the
session state, matching the original instructions.

All six routines are included in production CMake and the ABI catalog. The
removal suite adds 1,536 comparisons with original CRT memmoves, full persistent
memory and argument scratch. Inputs model valid peer membership bounds. All
three suites participate in Release and UBSan validation. Full admission and
playable startup are still unfinished.


Observer SDK query and retry
---------------------------
`src/network_observer_query.c` recovers `0007acf0`, `00078580` and `00076f50`.
The host query callback represents SDK `003cd35a`; results 0..3 pass through and
other values map to 4. Invalid observer addresses return 0 before SDK conversion.
Refresh preserves the original state-specific detach reasons, state changes and
retry-word increment/reset, with actual detach and set-state callees.

Its 1,536-case suite includes explicit state 3 coverage for every SDK result
class. Query/release/ticks callbacks can mutate fields; full memory, returns and
temporary bytes are compared. Connections in this fixture have state 2 and
writers are inactive, avoiding close/flush, which have separate coverage.

`src/network_observer_retry.c` recovers `00075890`, `00089070` and `00077580`.
Capacity arithmetic wraps exactly as the DWORD instructions do; the caller uses
its signed value. Retry eligibility preserves both timestamp captures and clock
calls even when an earlier timeout already makes the final result true. Actual
connection close, message serialization and route removal remain intact.
Its 1,536-case suite explicitly checks clock and connection-close coverage.
Fresh writers avoid packet flush, which has separate coverage.

All six routines are included in the main library and ABI catalog, and both
suites participate in Release/UBSan validation. Full observer admission and
playable startup remain unfinished.


Connection setup, routes and handshake
-------------------------------------
`network_connection_setup.c` recovers timer reset `00088d20` and stream reset
`00095cf0`. `network_route_insert.c` recovers `00092d10`, including actual
route lookup, replacement disposal and callback-sensitive capacity checks.
`network_handshake.c` recovers `000890b0`: signed timeout checks, actual close
and encoded request enqueue, plus retry timestamp updates after callbacks.
All four routines participate in the main library and original ABI catalog.
Three suites add 3,072 comparisons per build with full guest-memory checks.
Setup covers clock override changes and wrapping sequence arithmetic. Route
fixtures use no allocated storage; handshake uses fresh writers, with actual
codecs and queue writes but no flush. Dependency suites cover storage/flush
separately. Combined connection opening and playable startup remain unfinished.


Observer connection progression
------------------------------
`network_connection_open.c` recovers88220, `network_observer_selection.c`
recovers78330, and `network_observer_tick.c` recovers776a0/76a40. The latter
retains the captured connection pointer across callbacks, captured retry
schedule/count, all consumer calls, recursive state1 restart followed by
outer state rechecks, and signed retry/time comparisons. Its shared context
provides recovered callees, disjoint scratch and the consumer request method.
Three integrated suites add5,120 comparisons per build. Connection opening
covers actual queued storage releases; selection covers all four consumers.
Tick/wrapper cases explicitly open from states5/9 with handshake requests,
stream/inactive-storage resets, mutable clocks and recursive retries. Fresh
writers avoid flush in these suites; dependency suites cover packet sending.
Full admission, live networking and playable startup remain unfinished.


Connection and backing-slot allocation now includes four native routines:
820f0/82150 in network_slot_alloc.c and88110/82060 in
network_connection_allocate.c. Allocators retain the selected slot across
callbacks, honor signed pool counts and enable gates, and return UINT32_MAX
when unavailable. Initialization builds the stream/storage/inline descriptors
selected by flags8/16/32 and disposes the partial connection on allocation
failure. The outer allocator stops after the first initialization failure.

Xita's generated translations corroborate these call paths and ABI details
(reference hashes in analysis/xita-engine-allocation-reference.json). Correctness
is checked against original XBE instructions, not against translated C alone.
The integrated suites perform3,072 comparisons per build, including full guest
memory, return values, callback order/mutation, free-slot scans and failure
cleanup. Fixtures use incoming slot indices-1 and initially inactive storage;
they do not exercise queued releases or close packets in this constructor path.
Full observer admission remains pending. Integrated native count is276;
full regression and annotation refresh are tracked in PROGRESS.md.


Observer admission76aa0 and timeout checking773a0 are now native, along with
their text-format wrapper dependencies11c9c0/11c9e0, bringing the integrated
count to280. Admission matches existing identities or chooses/reclaims a slot,
allocates a connection, resets timing/sample windows, and notifies the consumer.
Timeout checking preserves the captured connection/start time, signed elapsed
comparisons and callback-sensitive state/config reloads before reason16 close.

The formatting wrappers retain guest varargs and forced buffer termination;
CRT321980 remains an explicit platform callback. They are not an implementation
of the CRT format engine. ABI metadata records their register parameters,
cdecl cleanup and variadic signatures; annotation now supports those fields.

The three suites add4,096 comparisons per build:1,024format-wrapper,
1,024admission and2,048timeout. Admission includes actual state1connection
disposal, stream/inactive-storage ownership cleanup, task-pool deletion and
registered-address release; SDK/CRT boundaries are controlled. Timeout uses
actual close-packet queueing/native codecs and route removal, with clock and
consumer callbacks mutating state/config. These suites use fresh/inactive
writers, so live packet flush and network transport remain outside their scope.
The276checkpoint was fully audited before this integration; the280full
regression and annotation refresh are tracked in PROGRESS.md.

Task creation (`0007b4c0`), task-result decoding (`0007b7b0`), and observer asynchronous maintenance (`00077480`) bring the native catalog to 283 routines. Xita translations corroborate the original instruction flow. Creation preserves signed count clamping, default-option tables, three guest pointer arrays, SDK failure handling, actual pool allocation and cleanup. Result decoding preserves output aliasing and instruction order. Observer maintenance selects a consumer, creates or polls a task, records results and releases completed tasks. SDK create/release are explicit platform boundaries; per-invocation temporary guest memory must be disjoint from engine allocations. The observer oracle executes actual recovered engine callees, including allocation/deletion, and covers 83 create-then-complete sequences. These routines do not provide a live SDK task service.

Observer polling, bandwidth updating, measurement recording and four rate helpers bring the catalog to290 routines. Xita translations and original instructions establish the float/XMM calling conventions where raw pseudocode omitted arguments or results. Differential tests compare full memory, clock snapshots, exact XMM0 result bits and integer results, including counter/clock wraparound, arithmetic shifts, NaNs, infinities and rounded conversion overflow. These floating calculations currently assume the default nearest-even environment; contraction is disabled and libm provides rounding. SDK clock and consumer callbacks remain platform boundaries. This does not supply a complete observer update loop or playable engine.
