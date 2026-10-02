#!/usr/bin/env python3
"""Validate this Halo 2 build and prepare reproducible Ghidra mapping metadata."""
import hashlib
import json
from pathlib import Path
import struct
import re
from vendor.xbe_parse import XbeParser, to_json
from vendor.xbox_kernel_exports import KERNEL_EXPORTS

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = '03215919bb7163259257d361f4c7bf802a7ab12aa85e2689436369b5c427935d'

def main():
    source = ROOT / 'default.xbe'
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED:
        raise SystemExit('Unexpected XBE hash; validate a separate build profile before analysis.')
    info = XbeParser(data, str(source)).parse()
    if info.warnings:
        raise SystemExit('\n'.join(info.warnings))
    out = ROOT / 'analysis'
    out.mkdir(exist_ok=True)
    (out / 'xbe.json').write_text(to_json(info) + '\n')
    (out / 'sha256.txt').write_text(digest + '  default.xbe\n')
    # Preserve section flags exactly, even where data sections are marked executable.
    rows = [('XBE_HEADERS', info.base_address, info.size_of_headers, 0, info.size_of_headers, 0)]
    for s in info.sections:
        if not s.raw_in_bounds or s.raw_size > s.virtual_size:
            raise SystemExit('Invalid section: ' + s.name)
        rows.append((f'{s.index:02d}_{s.name}', s.virtual_address, s.virtual_size,
                     s.raw_address, s.raw_size, s.flags))
    (out / 'sections.tsv').write_text(''.join('\t'.join(map(str, r)) + '\n' for r in rows))
    def read_u32(va):
        for s in info.sections:
            offset = va - s.virtual_address
            if 0 <= offset and offset + 4 <= s.raw_size:
                return struct.unpack_from('<I', data, s.raw_address + offset)[0]
        raise ValueError(f'Unmapped thunk: {va:08x}')
    imports = []
    for i in range(4096):
        va = info.kernel_thunk + i * 4
        value = read_u32(va)
        if not value:
            break
        if not value & 0x80000000:
            raise ValueError(f'Unexpected import value: {value:08x}')
        ordinal = value & 0x7fffffff
        imports.append((va, ordinal, KERNEL_EXPORTS.get(ordinal, f'Ordinal_{ordinal}')))
    else:
        raise ValueError('Unterminated import table')
    (out / 'imports.tsv').write_text(''.join('\t'.join(map(str, r)) + '\n' for r in imports))
    (out / 'entry.txt').write_text(str(info.entry_point) + '\n')
    categories = {
        'scripting': r'\bscript(?:s|ing)?\b|(?:^|_)script(?:ed)?(?:_|$)|^hs_',
        'physics': r'havok|physics|collision|rigid|constraint',
        'ai': r'actor|ai_|firing.position|behavior|pathfind|squad|platoon',
        'world': r'scenario|bsp|structure|cluster|portal|visibility',
        'objects': r'object|unit|vehicle|weapon|projectile|player|damage',
        'render_dependency': r'render|rasteriz|shader|texture|d3d',
    }
    anchors = []
    for s in info.sections:
        for match in re.finditer(rb'[ -~]{5,}\x00', data[s.raw_address:s.raw_address+s.raw_size]):
            value = match.group()[:-1].decode('ascii')
            for category, pattern in categories.items():
                if re.search(pattern, value, re.I):
                    anchors.append((s.virtual_address + match.start(), category, value))
    (out / 'anchors.tsv').write_text(''.join('\t'.join(map(str, r)) + '\n' for r in anchors))
    # Reviewed dispatch table: 0x137c20 calls column 0 in increasing order;
    # 0x12b690 calls column 1 in reverse order. Nine pointers per entry.
    table = []
    seeds = {0x2d0a7a: 'XBE entry passes this callback to thread creation',
             0x2d212e: 'XAPI thread creation passes this trampoline to kernel',
             0x61180: 'Reviewed direct CALL at 0005a43c (e8 3f 6d 00 00), session shutdown state 1'}
    for index in range(68):
        for column in range(9):
            slot = 0x440dd8 + index * 36 + column * 4
            target = read_u32(slot)
            table.append(dict(index=index, column=column, slot=f'{slot:08x}', target=f'{target:08x}'))
            if target:
                if not any(s.virtual_address <= target < s.virtual_address+s.raw_size and s.flags & 4 for s in info.sections):
                    raise ValueError(f'Lifecycle table target outside executable data: {target:08x}')
                seeds[target] = f'Lifecycle table entry {index}, column {column}; slot {slot:08x}'
    (out / 'lifecycle-table.json').write_text(json.dumps(table, indent=2)+'\n')
    (out / 'engine-seeds.tsv').write_text(''.join(f'{address:08x}\t{why}\n' for address,why in sorted(seeds.items())))
    print(f'{info.certificate.title_name}: {len(info.sections)} sections, {len(imports)} imports, entry {info.entry_point:#010x}')

if __name__ == '__main__':
    main()
