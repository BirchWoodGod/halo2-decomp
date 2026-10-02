#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Adapted from Xita tools/h2_menu_driver.py; see runtime/xita-linux/COPYING.
"""Drive Xita's software or GXM menu through the retained save's split-screen path.

This is an automation aid, not proof of visual/gameplay correctness. Readiness
uses the first software-renderer profile line or GXM ready diagnostic, then a
frame delay. It assumes the base save highlights SPLIT SCREEN and START GAME.
The terminal LEVEL condition is a map-open/clear-count heuristic; inspect actual
captures before claiming in-match rendering. The driver only writes its run's
pad.txt, never global desktop keyboard input. All intervals are flip-based.
"""
import argparse, atexit, re, signal, sys, time
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('run'); ap.add_argument('--timeout', type=float, default=7200)
    ap.add_argument('--gap', type=int, default=60); ap.add_argument('--hold', type=int, default=10)
    ap.add_argument('--title-wait', type=int, default=60)
    a = ap.parse_args()
    run = Path(a.run)
    pad, status = run / 'pad.txt', run / 'status.txt'
    atexit.register(lambda: pad.write_text(''))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    boot, errlog = run / 'ux0:data/xita-halo2/boot.log', run / 'stderr.log'
    out = (run / 'driver.log').open('a')
    start = time.monotonic()
    pos = {'boot': 0, 'err': 0}
    seen = {'cyclotron': False, 'level': False, 'blocked': None, 'title': False}

    def log(msg):
        line = f'[driver] flip {flip()} t={time.monotonic() - start:.0f}s {msg}'
        print(line, flush=True); out.write(line + '\n'); out.flush()

    def flip():
        try: return int(status.read_text().split()[0])
        except (OSError, ValueError, IndexError): return 0

    def scan():
        for key, path in (('boot', boot), ('err', errlog)):
            try:
                with path.open('rb') as f:
                    f.seek(pos[key]); data = f.read(); pos[key] += len(data)
            except OSError: continue
            for line in data.decode('utf-8', 'replace').splitlines():
                if 'maps\\cyclotron.map' in line or 'maps/cyclotron.map' in line: seen['cyclotron'] = True
                if '[h2/blocked]' in line and not seen['blocked']: seen['blocked'] = line.strip()
                if '[h2/menu-gxm] ready' in line or '[h2/menu-render] profile draws=' in line: seen['title'] = True
                m = re.search(r'\[h2/perf\].* clears=(\d+)', line)
                if m and seen['cyclotron'] and int(m.group(1)) >= 150: seen['level'] = True

    def wait(cond, what):
        while not cond():
            scan()
            if seen['blocked']: log(f'harness stopped: {seen["blocked"]}'); sys.exit(2)
            if seen['level']: return False
            if time.monotonic() - start > a.timeout: log(f'timeout waiting for {what}'); sys.exit(1)
            time.sleep(0.5)
        return True

    last_press = [0]

    def press(button, why):
        last_press[0] = flip()
        log(f'press {button} ({why})')
        pad.write_text(button + '\n')
        t0 = flip(); wait(lambda: flip() - t0 >= a.hold, f'{button} hold')
        pad.write_text('')

    def after(flips, what):
        t0 = flip(); return wait(lambda: flip() - t0 >= flips, what)

    pad.write_text('')
    log('waiting for renderer activity, then title animation')
    if wait(lambda: seen['title'], 'title') and after(a.title_wait, 'title animation'):
        press('start', 'title')
        for why in ('profile', 'main menu', 'lobby profile', 'START GAME'):
            if not after(a.gap, why): break
            press('a', why)
        for attempt in range(3):
            if not wait(lambda: seen['cyclotron'] or flip() - last_press[0] >= 600, 'map load'): break
            if seen['cyclotron']: break
            press('a', f'START GAME again #{attempt + 1} (no map load yet)')
    log('waiting for the level (cyclotron.map + in-match clears)')
    wait(lambda: seen['level'], 'level')
    log('LEVEL: in-match frames; driver done')


if __name__ == '__main__': main()
