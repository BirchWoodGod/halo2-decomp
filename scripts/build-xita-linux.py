#!/usr/bin/env python3
"""Link the local SDL adapter with preserved Xita reference objects (GPLv3)."""
import hashlib
import json
import importlib.util
import os
from pathlib import Path
import shlex
import subprocess
root = Path(__file__).resolve().parent.parent
stage = Path(os.environ.get('XITA_REFERENCE_ROOT', '/home/birchwoodgod/xita-backups/2026-09-24-halo2-vita3k'))
out = Path(os.environ.get('XITA_BUILD_OUT', str(root / 'build/xita-linux'))).resolve()
out.mkdir(parents=True, exist_ok=True)
spec = importlib.util.spec_from_file_location('xita_build', stage / 'source/tools/h2_host_build.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
units, wraps = module.parse(module.dry_run(stage / 'private/h2v1r', out), False)
for extra in module.EXTRA:
    units[Path(extra).stem + '.o'] = None
objects = [stage / 'private/objs-x86-h2v1r' / name for name in sorted(units)]
for obj in objects:
    if not obj.is_file(): raise SystemExit(f'Missing reference object: {obj}')
# Keep the reference tree untouched; apply only an explicit diagnostic I/O gate.
renderer_source, renderer_flags = units['menu_render.o']
renderer_text = renderer_source.read_text()
old_dump = 'if (drawn >= 20 && drawn % 20 == 0) dump_backbuffer(target, W, H, drawn, c->color_offset);'
new_dump = 'static int dump_every = -1;\n    if (dump_every < 0) dump_every = knob("XV_LINUX_DUMP_EVERY", 0);\n    if (dump_every > 0 && drawn >= (uint64_t)dump_every && drawn % (uint64_t)dump_every == 0)\n        dump_backbuffer(target, W, H, drawn, c->color_offset);'
if renderer_text.count(old_dump) != 1:
    raise SystemExit('Reference renderer changed: review diagnostic patch before building')
patched_renderer = out / 'menu_render.c'
patched_text = renderer_text.replace(old_dump, new_dump)
old_triangle = '{ if (a < n && b < n && c < n) menu_raster_triangle(rs, &g_verts[a], &g_verts[b], &g_verts[c]); }'
new_triangle = '{ if (a < n && b < n && c < n) { h2_linux_vertex_audit(&g_verts[a], &g_verts[b], &g_verts[c]); menu_raster_triangle(rs, &g_verts[a], &g_verts[b], &g_verts[c]); } }'
clip_enabled = os.environ.get('XITA_CLIP') == '1'
if clip_enabled:
    new_triangle = new_triangle.replace('menu_raster_triangle(rs,', 'h2_linux_clip_triangle(rs,')
    declaration = 'void h2_linux_clip_triangle(const menu_raster_state *, const menu_vertex_out *, const menu_vertex_out *, const menu_vertex_out *);\n'
    patched_text = patched_text.replace('static void one_tri(', declaration + 'static void one_tri(', 1)
if patched_text.count(old_triangle) != 1:
    raise SystemExit('Reference triangle dispatch changed: review audit patch')
patched_text = patched_text.replace('static void one_tri(', '#include "vertex_audit.h"\nstatic void one_tri(', 1)
patched_renderer.write_text(patched_text.replace(old_triangle, new_triangle))
renderer_object = out / 'menu_render.o'
subprocess.run(['cc', *renderer_flags, '-g', '-pthread', '-I'+str(renderer_source.parent),
    '-I'+str(root / 'runtime/xita-linux'),
    '-I'+str(stage / 'private/objs-x86-h2v1r/psp2inc'), '-c', str(patched_renderer),
    '-o', str(renderer_object)], cwd=module.GAME, check=True)
objects = [renderer_object if p.name == 'menu_render.o' else p for p in objects]
if clip_enabled:
    clip_object = out / 'clip.o'
    subprocess.run(['cc', *renderer_flags, '-g', '-pthread', '-Wall', '-Wextra', '-Werror',
        '-I'+str(renderer_source.parent), '-c', str(root / 'runtime/xita-linux/clip.c'),
        '-o', str(clip_object)], cwd=module.GAME, check=True)
    objects.append(clip_object)
unity_sources = []
if os.environ.get('XITA_UNITY_RASTER') == '1':
    # Strict O3, no fast-math or architecture-specific instructions. Combining
    # these translation units lets the compiler optimize the fragment call.
    unity_sources = [units[name][0] for name in ('menu_combiner.o', 'menu_raster.o')]
    unity_source = out / 'menu_shader_unity.c'
    unity_source.write_text(''.join('#include ' + json.dumps(str(p)) + '\n' for p in unity_sources))
    unity_object = out / 'menu_shader_unity.o'
    flags = [f for f in units['menu_raster.o'][1] if not f.startswith('-O')]
    subprocess.run(['cc', *flags, '-O3', '-g', '-pthread', '-c', str(unity_source),
        '-o', str(unity_object)], cwd=module.GAME, check=True)
    objects = [p for p in objects if p.name not in ('menu_combiner.o', 'menu_raster.o')]
    objects.append(unity_object)
sdl = shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','sdl2'], text=True))
subprocess.run(['cc','-std=c11','-Wall','-Wextra','-Werror','-g','-pthread',
    '-I'+str(stage / 'private/objs-x86-h2v1r/psp2inc'),
    str(root / 'runtime/xita-linux/display.c'), *map(str,objects),
    '-Wl,--gc-sections',*wraps,'-Wl,--wrap=sceDisplaySetFrameBuf',
    '-Wl,--wrap=sceCtrlPeekBufferPositive',*sdl,'-lm','-o',str(out / 'harness')], check=True)
def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()
manifest = {
    'reference_root': str(stage),
    'reference_revision': subprocess.check_output(['git','-C',str(stage / 'source'),'rev-parse','HEAD'],text=True).strip(),
    'renderer_reference_sha256': digest(renderer_source),
    'renderer_patched_sha256': digest(patched_renderer),
    'unity_raster_sources': {str(p): digest(p) for p in unity_sources},
    'build_script_sha256': digest(Path(__file__).resolve()),
    'adapter_sha256': digest(root / 'runtime/xita-linux/display.c'),
    'vertex_audit_sha256': digest(root / 'runtime/xita-linux/vertex_audit.h'),
    'experimental_clip_sha256': digest(root / 'runtime/xita-linux/clip.c') if clip_enabled else None,
    'binary_sha256': digest(out / 'harness'),
    'objects': {str(p): digest(p) for p in objects},
    'link_wrappers': wraps + ['-Wl,--wrap=sceDisplaySetFrameBuf','-Wl,--wrap=sceCtrlPeekBufferPositive'],
    'linked_recovered_engine': False,
}
(out / 'provenance.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(out / 'harness')
