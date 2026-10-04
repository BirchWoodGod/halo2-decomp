# Halo 2 engine decompilation

Initial static analysis of the original Xbox Halo 2 engine as 32-bit x86.
The focus is gameplay, AI, physics, scripting, objects, and world management.
Xbox rendering and platform services are dependencies to isolate for a later port.
389 recovered engine routines build as a native Linux shared library.
A native callback dispatcher connects the recovered codecs for message types 0–24.
The Linux host maps the pinned XBE and runs engine pool and configuration probes.
There is no runnable game yet, and the rest of the engine remains incomplete.

Current validation: the 382-routine checkpoint passed a 276-report source/build
hash audit; its process exit code was unavailable after the session ended.
The main build now includes 389 routines after integrating seven reviewed
serializers. Their isolated combined build passed 17,408 comparisons, plus 4,096
composed host-completion comparisons. The expanded main regression is running.
Handoff ranking/controller previews use a controlled CRT power boundary;
production math fidelity remains unresolved.
See [PROGRESS.md](PROGRESS.md) for evidence and remaining work.
Routine counts are not a percentage of game completion.

This repository contains recovery code, tools, and tests. It does not include
the Halo 2 executable, game assets, or generated decompiler exports. Supply your
own matching `default.xbe` locally to run the analysis and differential tests.
Xita is used as a reference alongside the original executable's instructions;
the separate Xita runtime experiments are documented in [runtime/xita-linux](runtime/xita-linux/README.md).
Vendored components retain their license and attribution files.

We also cross-reference [kirklandsig/halo2-decompiled](https://github.com/kirklandsig/halo2-decompiled),
which targets the same XBE and uses original-compiler matching. The pinned
comparison in [config/upstream_reference.json](config/upstream_reference.json)
finds 16 shared routines and 338 upstream-reported game matches outside our
389-routine catalog. These are references for further recovery, not additional
locally validated routines. See the upstream comparison section in ENGINE.md.

See [ENGINE.md](ENGINE.md) for the first engine findings, including the shared
AI/script container layout and its custom x86 register calling convention.

## Build and verify recovered engine code

```sh
python3 -m venv .tools/venv
.tools/venv/bin/pip install -r requirements-test.txt
bash scripts/test-engine.sh
```

Requires a C11 compiler, CMake, Ninja, and OpenSSL development headers/libraries.
This builds `build/libhalo2_engine.so` and `build/halo2-engine-host`. Tests compare
native C with original XBE instructions, including allocation failures and the
ordering of global writes. The 16 core data-array routines use an unmodified x86
oracle; constructors/disposal and four pool initializers control the allocator boundary.
Hash tables and CRC updates add 1,299 comparisons against original instructions.
The Linux heap is separately stress-tested for overlap, reuse, exhaustion, and
coalescing. The suites and native probe repeat with undefined-behavior checks.
Unicorn is a test dependency only; the library and host do not depend on it.
The ABI catalogs in `config/` cover all 382 recovered routines.

Run the native host probe directly:

```sh
build/halo2-engine-host --probe-pools default.xbe
```

It verifies the full executable SHA-256, copies the original image at its guest
addresses, and runs recovered arena, command-script, Havok-component, actor, and online-task pool startup.
Command-script and actor allocations use the recovered arena allocator; save-file
preparation is explicitly unimplemented in this diagnostic.
It exercises allocation, lookup, deletion, and cleanup in native C. The XBE's
instructions are not executed by this host. This diagnostic is not game boot,
Havok simulation, a renderer, or a playable Halo 2 build.

The configuration probe reads `player_configuration_cache.dat` from a directory
mounted as Xbox drive Z and runs the recovered loader, CRC, and validation:

```sh
build/halo2-engine-host --probe-config default.xbe /path/to/cache-directory
```

It returns success only for accepted configuration data. This uses real Linux
file I/O and does not boot the game. `tests/host_files_test.py` creates temporary
valid and invalid fixtures and checks both the library and this executable.
The backend covers the file operations used by this loader; SDK timestamp,
threading, and cross-process sharing fidelity remain incomplete.

The API preserves 32-bit guest addresses and little-endian engine memory while
running native host C. It assumes valid mapped engine allocations. The Linux
heap currently supports one arena with 16-byte alignment and no thread safety;
Xbox physical aliases, page protection, TLS, and scheduling remain unimplemented.
Tests do not establish full game correctness.

## Input

`default.xbe` was copied from the existing local
`../xboxvita/local/halo2/disc/default.xbe`, preserving the original.

- Title: Halo 2; title ID `4D530064`; certificate version 3.
- SHA-256: `03215919bb7163259257d361f4c7bf802a7ab12aa85e2689436369b5c427935d`.
- Entry: `0x002D0AEE`; image base: `0x00010000`.
- 33 sections and 152 kernel import slots.

The binary, generated output, and tools are ignored by Git. This directory was
empty and was not a Git repository when this work started.

## Reproduce

Requires Python 3, Java compatible with Ghidra 12.1.4, curl, and unzip.
This machine's OpenJDK 26 was used. Ghidra is installed locally, with its official
release archive SHA-256 checked by the setup script.

```sh
bash scripts/setup-ghidra.sh
python3 scripts/prepare.py
bash scripts/analyze.sh > analysis/headless.log 2>&1
```

The prepare step creates `analysis/` before shell redirection.
Set `GHIDRA_HOME` to use another Ghidra installation.
Analysis is capped at 600 seconds per file; check the log for timeouts.

To regenerate indexes and export missing functions from an existing project:

```sh
bash scripts/analyze.sh --resume > analysis/resume.log 2>&1
```

To discover engine callbacks from the reviewed subsystem lifecycle table and
rerun analysis, use `--recover` instead. Fresh imports do this automatically.
The table at `0x00440DD8` has 68 entries of nine pointer slots, independently
bounded by the initialization loop at `0x00137C20` and shutdown traversal at
`0x0012B690`. Discovery reports overlap conflicts instead of overwriting other
function bodies. Other unidentified indirect-call targets remain outstanding.

Existing successful C files are retained, except the 358 annotated engine
functions and their direct callers, which are refreshed. Remove a function's C file before
resuming if its Ghidra types, names, or body have changed and need re-exporting.
Do not run headless scripts while the same project is open in the GUI.

Open `analysis/ghidra/Halo2.gpr` with `.tools/ghidra_12.1.4_PUBLIC/ghidraRun`.

## Outputs

| Path under `analysis/` | Purpose |
| --- | --- |
| `decompiled/<address>.c` | Unreviewed Ghidra pseudocode for functions in `.text` |
| `functions.tsv` | Function addresses, provisional names, sizes, export status |
| `disassembly.asm` | x86 disassembly of exported function bodies |
| `calls.tsv` | Ghidra-resolved function call edges; indirect calls may be missing |
| `engine-candidates.tsv` | Subsystem candidates supported by direct string references |
| `imports.tsv` | Xbox kernel import slots and ordinal names |
| `xbe.json`, `sections.tsv` | Executable metadata and exact memory layout |
| `export-summary.json` | Actual export counts and failures |
| `mapping-verification.json` | Byte-for-byte verification of the Ghidra memory mapping |
| `decompiler-errors.tsv` | Functions that failed to export |
| `engine-discovery.tsv` | Reviewed callback seeds and discovery conflicts |
| `lifecycle-table.json` | The 68 engine lifecycle entries and their nine pointer slots |
| `data-array-tests*.json` | Native versus original x86 comparison results and input hashes |
| `allocator-tests*.json` | Create/dispose boundary comparisons and Linux heap stress results |
| `network-task-complete-tests*.json` | Task completion, retry paths, and callback mutations |
| `resource-release-tests*.json` | Resource release and integrated tracked-task removal |
| `network-tracking-tests*.json` | Tracked-task scheduling, capacity exhaustion, and integrated CRC |
| `network-session-tasks-tests*.json` | Task cancellation through pool deletion and recursive session control |
| `network-session-identity-tests*.json` | Identity lookup and queued insertion, aliases and clock mutation |
| `network-observer-query-tests*.json` | Address/observer SDK status, conversion and retry state changes |
| `network-observer-retry-tests*.json` | Elapsed time, queue capacity and retry eligibility with actual close |
| `network-observer-admission-tests*.json` | Established connection close with actual close/codec/route callees |
| `network-session-membership-tests*.json` | Peer attachment and insertion, aliases and clock callbacks |
| `network-session-removal-tests*.json` | Player/peer removal, index shifts, reservations and flag refresh |
| `network-session-control-tests*.json` | Recursive shutdown, cleanup and handoff, callback mutation and scratch |
| `network-session-send-tests*.json` | Peer/broadcast sends, leave/disband transitions, reliable queues and datagram flush |
| `network-resolution-tests*.json` | Address resolution and observer datagram dispatch, including packet flush |
| `network-storage-queue-tests*.json` | Reliable message encoding, fragmentation, retries, and subsequent cleanup |
| `network-session-lifecycle-tests*.json` | Peer and registration cleanup, join-abort transition and message flush |
| `network-session-tests*.json` | Session storage, shutdown guard, peer lookup and capacity checks |
| `network-parameter-tests*.json` | Parameter constructors and full setup, signed random bounds, links, and preserved bytes |
| `network-state-tests*.json` | Network object/global/provider setup with tick and provider boundaries controlled |
| `network-open-tests*.json` | Complete engine endpoint open/initialize/cleanup path; SDK calls controlled |
| `network-bind-tests*.json` | Binding with recovered helpers and exact temporary bytes; SDK calls controlled |
| `network-address-tests*.json` | Address conversion and socket handle creation; SDK calls controlled |
| `network-option-tests*.json` | Socket option mapping/get/set; SDK values and errors controlled |
| `network-socket-tests*.json` | Socket records, cleanup, and partial-open integration; SDK calls controlled |
| `network-endpoint-tests*.json` | Endpoint failure paths and SSE statistics initialization; socket boundaries controlled |
| `network-message-tests*.json` | Nine network descriptor registrations, 45 records; original instructions unmodified |
| `random-tests*.json` | Random-state initialization and all 1,026 direction-table entries |
| `transport-tests*.json` | Transport initialization/helpers and integrated startup; network boundaries controlled |
| `game-lifecycle-tests*.json` | Six lifecycle/options drivers; subsystem calls are controlled boundaries |
| `startup-coverage.json` | Direct lifecycle entrypoint inventory; not transitive boot coverage |
| `arena-tests*.json` | Arena startup, reservation, allocator, and combined engine allocation checks |
| `hash-crc-tests*.json` | Original/native hash table, actor key callback, and CRC comparisons |
| `host-file-tests*.json` | Real Linux file I/O, engine integration, configuration CLI and descriptor cleanup |
| `network-config-load-tests*.json` | Complete persisted-state load path, failures, CRC, validation and close |
| `file-open-tests*.json` | Open flags, error mapping, initial seek and cleanup |
| `file-metadata-tests*.json` | File existence/size queries, resolved paths, error sequencing and output preservation |
| `file-io-tests*.json` | File read/write/close/seek/set-end, position updates and error ordering |
| `file-path-tests*.json` | Xbox path append, parent and drive resolution, including buffer boundaries |
| `network-config-tests*.json` | Persisted-state defaults, byte-field domains, sorted records, index bounds and linked lists |
| `network-final-state-tests*.json` | Final network state construction, record indices, partial resets and preserved gaps |
| `online-drain-tests*.json` | Task draining, dependency order and pool disposal |
| `network-submit-tests*.json` | Datagram construction through the SDK send boundary |
| `network-send-tests*.json` | Send wrapper, address bytes and SDK error mappings |
| `network-packet-tests*.json` | Packet layouts, bounds and size accounting |
| `bitstream-tests*.json` | Bit-level read/write, bounds, alignment and aliasing |
| `async-task-tests*.json` | Separate task-pool release and idle queries |
| `online-cancel-tests*.json` | Task cancellation, SDK call ordering and pool deletion |
| `online-poll-tests*.json` | Login-status mapping, cached state and task continuation |
| `online-task-tests*.json` | Online-task pool startup, address classification, and retained allocator identity |
| `engine-pool-tests*.json` | Original/native pool initialization and independent XBE mapping checks |

Ghidra maps the header and all sections at their original virtual addresses,
preserves section permissions, and zero-fills virtual tails. This is a static
view, not an implementation of Xbox section loading. Kernel ordinal values
remain unchanged and are labeled as external dependencies without invented
signatures. The analysis uses the x86 Windows compiler specification as an
initial ABI assumption; Xbox/LTCG calling conventions need manual verification.

Exports omit functions starting in separate SDK/middleware sections such as
`D3D`, `DSOUND`, `XNET`, and `BINK`. The main `.text` section also contains
rendering, runtime, and middleware code: inclusion is not proof that a function
is engine gameplay code. String categories are navigation hints, not verified
function identities. Engine code without relevant strings will not appear in
the candidate index. Automatic function boundaries, recovered types, indirect
calls, and decompiler warnings require review. Successful export does not prove
correctness, reachability, or completeness.

## Existing work and next steps

The prior `../xboxvita/docs/halo2.md` records an instruction-to-C translation
experiment, including suspected data decoded as instructions and no successful
Halo 2 boot. Its generated C is not treated as recovered engine source here.
Only the XBE parser and kernel ordinal names were reused; provenance and the
source repository's license are in `scripts/vendor/`.

Start from `engine-candidates.tsv`, validate a subsystem's call graph against
x86 instructions, recover its structures and signatures, then rewrite and test
small engine routines. Introduce interfaces for rendering, audio, input, files,
threads, and time at observed boundaries. A playable x86 host will require
those interfaces plus game data; a later device port also needs ABI, alignment,
endianness, floating-point, and performance validation.

Tool source: https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build

Run `python3 scripts/audit-startup.py` after preparation to inventory unrecovered
subsystem entrypoints. Catalogued routines can still depend on unrecovered code;
this report does not measure the percentage of a working game.

## License

The recovery code, headers, configuration, tests, tools and documentation in
this repository are dedicated to the public domain under
[CC0 1.0](LICENSE), the same terms as
[kirklandsig/halo2-decompiled](https://github.com/kirklandsig/halo2-decompiled)
and the Halo CE decompilation. Take whatever helps.

Two vendored parts keep their own license, GPL-3.0, in their folders:
`scripts/vendor/` (Xita tooling, `LICENSE.xboxvita`) and `runtime/xita-linux/`
(`COPYING`). The engine library and host in `src/` do not depend on them.

Halo 2 and its executable, maps and other content belong to Microsoft and are
not included.
