# Experimental Xita Linux frontend

This SDL2 adapter presents Xita's CPU scanout and adds keyboard input. It links
with retained Xita objects outside this project. It does not link the recovered
`libhalo2_engine` and is not a complete native decompilation. The resulting
combined executable is GPLv3; see COPYING and the referenced Xita source tree.

Build and run from the project root:

```sh
python3 scripts/build-xita-linux.py
bash scripts/run-xita-linux.sh
```

Requires SDL2 development files, a C compiler, and the existing local Xita stage.
`XITA_REFERENCE_ROOT` can select another compatible stage with the same layout.
The build derives the object list and original link wrappers from Xita's build
recipe. It preserves the reference objects, but compiles a local copy of
menu_render.c with repeated framebuffer dumps gated by XV_LINUX_DUMP_EVERY
(default 0). Set XV_LINUX_DUMP_EVERY=20 to restore the reference frequency.
Reference and patched source hashes are recorded in build/xita-linux/provenance.json.
Each run copies
base saves into a unique `analysis/xita-host/runs/` directory. Game data stays
external. Default runtime limit is one hour; supply seconds and a unique tag as
the first two arguments. Additional arguments are Xita `NAME=value` knobs.

Controls: Enter=Start, Backspace=Back, Z=A, X=B, C=X, V=Y, Q/E=triggers,
arrows=D-pad, WASD=left stick, IJKL=right stick. Keyboard input is active only
while the window has focus. Closing the window ends the process. Existing
scripted Xita controller input remains available. Audio still uses the retained
host shim; this adapter does not add sound output.

Rendering currently uses Xita's slow software path (`XV_MENU_GXM=0`). The title
scene has been verified in a real X11 SDL window. Full gameplay rendering,
keyboard-driven game interaction, and acceptable speed remain unverified.
Scripted Start has visibly reached Choose Profile with the software renderer.
A software-aware menu driver can be enabled with H2_DRIVE=1; it waits for
renderer activity and a frame delay, then uses the retained save's expected
menu selections. Its match detection is a heuristic, not visual verification.
The default remains manual controls.

```sh
H2_DRIVE=1 SDL_VIDEODRIVER=dummy bash scripts/run-xita-linux.sh 600 menu-check XV_HOST_SHOT=60
```

Use a fresh run tag each time. Automated software progression has reached a
visibly rendered Ivory Tower match, and scripted right-stick input changed the
camera view. Serious lighting and polygon artifacts remain; firing, desktop
keyboard gameplay, and playable speed are not verified. See
`analysis/xita-software-match-interim.json` and its captures.

An experimental strict O3 unity build of the rasterizer and combiner is available:

```sh
XITA_BUILD_OUT="$PWD/build/xita-linux-unity" XITA_UNITY_RASTER=1 python3 scripts/build-xita-linux.py
```

The unchanged source passes a 512-case differential raster probe and the existing
Xita raster assertions. This candidate is not the default and still requires
whole-game validation. It does not enable fast-math. See
`analysis/xita-raster-unity-probe.json` for the measured scope and limits.

Select a candidate explicitly with `H2_HOST_BIN`. For example:

```sh
H2_HOST_BIN="$PWD/build/xita-linux-unity/harness" H2_DRIVE=1 SDL_VIDEODRIVER=dummy bash scripts/run-xita-linux.sh 600 unity-check XV_HOST_SHOT=60 XV_LINUX_VERTEX_AUDIT=1
```

The optional vertex audit logs nonpositive or mixed-sign clip w, depth outside
the expected range, and nonfinite positions. It observes triangle dispatch
without changing geometry. It is off by default.

`XITA_CLIP=1` builds an experimental homogeneous clipping stage in front of
the software rasterizer. Use a separate `XITA_BUILD_OUT`, such as
`build/xita-linux-clip`. Analytic and randomized sanitizer tests pass, but
game rendering and original Xbox fidelity remain unverified. The implementation
assumes the renderer's 0..1 depth range and uses an explicit 1e-6 positive-w
guard. It is not enabled by default. See `analysis/xita-clip-probe.json`.
