#!/usr/bin/env python3
"""Decode coverage audit: how much of a corpus of Zero log files the parser decodes.

Reproducible from a commit: it imports the zero_log_parser next to it, walks every file the way the
real parser does (LogFile/LogData, including the page-aware BMS walker), classifies every entry, and
stores per-file results in SQLite (resumable: a rerun skips files already recorded, results are
committed per file, 6 workers by default).

Usage:
    python tools/coverage_audit.py run    --corpus DIR --db audit.sqlite3 [--workers 6]
    python tools/coverage_audit.py report --db audit.sqlite3 [--dedup]

Entry classes, five mutually exclusive, per entry, in this order:
  corrupted  structured_data has bytes_corrupted, or the type is CORRUPTED
  unknown    the entry's type id has no decoder for that file type
  partial    (a) the entry's declared byte layout (Gen2.payload_layout) has at least one unknown byte,
             or it keeps raw_hex at a length with no declared layout; or
             (b) the decoder declined and fell back to rendering raw bytes ('Raw data: ...' or
             'No additional data'); or
             (c) a text (0xFD) entry with an {undecoded hex: ...} tag and no {corrupted: ...} tag
             (bytes that are not printable and not explained by a page marker: a newline, erased
             0xaa/0xff runs, trailing garbage)
             Undecoded work remains, so it wins over damaged.
  damaged    otherwise fully decoded, but the 128-byte page marker overwrote some of its bytes: a text
             entry with an inline {corrupted: ...} tag, or a binary entry with a non-empty
             corrupted_fields list. Nothing is left to decode. The overlap (partial and damaged) is
             counted as partial and stored in damaged_partial_overlap_entries.
  full       everything else. Decoders without raw_hex and without a layout default to full.
  The earlier classifier called an entry partial whenever structured_data held a raw_hex key; that
  counts transparency copies as undecoded and is kept only as the 'rawhex_partial' counter.

Two extra measures per row:
  payload bytes decoded   entry-weighted share of payload bytes declared field or reserved, over the
                          entries that have a declared layout or that the decoder declined (their raw
                          bytes count as undecoded); text and layout-less entries have no byte count
                          and are left out
  varying bytes decoded   of the payload bytes that vary in the corpus (no single value in at least
                          95% of that type and length's entries), the share declared field

Header details read: MBB files need VIN, model, board revision and firmware revision; BMS files need
the BMS serial number and the pack serial number.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import multiprocessing as mp
import os
import sqlite3
import sys
import traceback

logging.disable(logging.CRITICAL)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

FST_MARKER_IDS = {0x48, 0x49, 0x4F, 0x51, 0x52, 0x53}
BMS_ONLY_IDS = {0x03, 0x04, 0x05, 0x06, 0x08, 0x0b, 0x0d, 0x0e, 0x12, 0x13, 0x15, 0x16, 0x18}
MBB_ONLY_IDS = {0x02, 0x09, 0x1c, 0x1e, 0x1f, 0x20, 0x26, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d,
                0x2f, 0x30, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d}
GROUPS = {'mbb_legacy': 'legacy MBB', 'mbb_fst': 'Gen3 MBB', 'bms_legacy': 'legacy BMS',
          'bms_fst_paged': 'Gen3 BMS', 'bms_131200_sibling': 'Gen3 BMS'}
COLUMNS = (
    'filename', 'file_size', 'content_hash', 'status', 'error', 'bucket', 'log_type', 'dispatch_log_type',
    'route_note', 'log_version', 'vin', 'model', 'board_rev', 'firmware_rev', 'bms_serial', 'pack_serial',
    'header_complete', 'total_entries', 'corrupted_entries', 'unknown_type_entries',
    'partially_decoded_entries', 'fully_decoded_entries', 'rawhex_partial_entries',
    'damaged_entries', 'damaged_partial_overlap_entries',
    'partial_breakdown_json', 'layout_bytes_json', 'hist_json', 'unknown_type_counts_json',
)


def census_verdict(mbb_hits, bms_hits):
    total = mbb_hits + bms_hits
    if total >= 20:
        frac = mbb_hits / total
        return 'MBB' if frac >= 0.95 else 'BMS' if frac <= 0.05 else 'mixed'
    if mbb_hits > 0 and bms_hits == 0:
        return 'MBB(sparse)'
    if bms_hits > 0 and mbb_hits == 0:
        return 'BMS(sparse)'
    return 'none' if mbb_hits == 0 and bms_hits == 0 else 'mixed(sparse)'


def raw_hex_list(data, path=''):
    """[(path, hex string)] for every raw_hex key at any depth."""
    out = []
    if isinstance(data, dict):
        for k, v in data.items():
            p = f"{path}.{k}" if path else k
            if k == 'raw_hex' and isinstance(v, str):
                out.append((p, v))
            else:
                out += raw_hex_list(v, p)
    elif isinstance(data, list):
        for i, v in enumerate(data):
            out += raw_hex_list(v, f"{path}[{i}]")
    return out


def process_one(path):
    import zero_log_parser as zlp
    Gen2 = zlp.Gen2
    res = {c: None for c in COLUMNS}
    res.update(filename=os.path.basename(path), total_entries=0)
    try:
        with open(path, 'rb') as f:
            data = f.read()
        res['file_size'] = len(data)
        res['content_hash'] = hashlib.sha256(data).hexdigest()
        del data
        lf = zlp.LogFile(path)
        ld = zlp.LogData(lf)
        entries = ld._processed_entries or []
        hi = ld.header_info
        res['log_type'] = lf.log_type
        res['log_version'] = {0: 'REV0', 1: 'REV1', 2: 'REV2', 3: 'REV3', -1: 'REV_UNKNOWN'}.get(ld.log_version, str(ld.log_version))
        res['vin'], res['model'] = hi.get('VIN'), hi.get('Model')
        res['board_rev'] = str(hi.get('Board rev.')) if hi.get('Board rev.') is not None else None
        res['firmware_rev'] = str(hi.get('Firmware rev.')) if hi.get('Firmware rev.') is not None else None
        res['bms_serial'], res['pack_serial'] = hi.get('BMS serial number'), hi.get('Pack serial number')

        dispatch = lf.log_type
        note = None
        if lf.log_type == zlp.LogFile.log_type_unknown:
            if lf.has_classic_vin:
                dispatch, note = zlp.LogFile.log_type_mbb, 'has_classic_vin'
            else:
                mh = bh = 0
                for e in entries:
                    mt = e.message_type
                    if not mt or mt == 'CORRUPTED' or not mt.startswith('0x'):
                        continue
                    try:
                        tid = int(mt, 16)
                    except ValueError:
                        continue
                    if tid in BMS_ONLY_IDS:
                        bh += 1
                    elif tid in MBB_ONLY_IDS:
                        mh += 1
                verdict = census_verdict(mh, bh)
                note = f'census={verdict} mbb={mh} bms={bh}'
                dispatch = (zlp.LogFile.log_type_mbb if verdict in ('MBB', 'MBB(sparse)')
                            else zlp.LogFile.log_type_bms if verdict in ('BMS', 'BMS(sparse)') else None)
        res['dispatch_log_type'], res['route_note'] = dispatch, note

        bucket = None
        if dispatch == zlp.LogFile.log_type_mbb:
            has_fst = any(e.message_type and e.message_type.startswith('0x') and int(e.message_type, 16) in FST_MARKER_IDS
                          for e in entries if _hex_ok(e.message_type))
            bucket = 'mbb_fst' if has_fst else 'mbb_legacy'
            res['header_complete'] = int(all(hi.get(k) not in (None, '', 'Unknown')
                                             for k in ('VIN', 'Model', 'Board rev.', 'Firmware rev.')))
        elif dispatch == zlp.LogFile.log_type_bms:
            bucket = ('bms_fst_paged' if res['file_size'] == 131328
                      else 'bms_131200_sibling' if res['file_size'] == 131200 else 'bms_legacy')
            res['header_complete'] = int(hi.get('BMS serial number') not in (None, '', 'Unknown')
                                         and hi.get('Pack serial number') not in (None, '', 'Unknown'))
        res['bucket'] = bucket

        registered = set(Gen2._entry_parsers(dispatch).keys())
        unknown_counts, breakdown, layout_bytes, hist = {}, {}, {}, {}
        corrupted = unknown = partial = full = rawhex_partial = damaged = overlap = 0
        for e in entries:
            mt, sd = e.message_type, e.structured_data
            if (sd and sd.get('bytes_corrupted')) or mt == 'CORRUPTED':
                corrupted += 1
                continue
            tid = int(mt, 16) if _hex_ok(mt) else None
            if tid is None or tid not in registered:
                unknown += 1
                unknown_counts[mt or 'unknown'] = unknown_counts.get(mt or 'unknown', 0) + 1
                continue
            reason, length = None, None
            hexes = raw_hex_list(sd) if isinstance(sd, dict) else []
            if hexes:
                rawhex_partial += 1
            if isinstance(sd, dict) and tid == 0x48 and 'charger_count' in sd:
                length = Gen2.CHARGER_RECORD_OFFSET + Gen2.CHARGER_RECORD_LEN * sd['charger_count']
            elif any(p == 'raw_hex' for p, _ in hexes):
                length = len(next(h for p, h in hexes if p == 'raw_hex')) // 2
            layout = Gen2.payload_layout(tid, length) if length else None
            if layout is not None:
                key = f"{tid:#x}|{length}"
                nbytes = sum(b - a for a, b, k, _ in layout if k != Gen2.LAYOUT_UNKNOWN)
                lb = layout_bytes.setdefault(key, [0, 0, length])
                lb[0] += 1
                lb[1] += nbytes
                if any(k == Gen2.LAYOUT_UNKNOWN for _, _, k, _ in layout):
                    reason = f"layout unknown bytes {tid:#x}|{length}"
                if tid != 0x48 and any(p == 'raw_hex' for p, _ in hexes):
                    h = hist.setdefault(key, [0] + [dict() for _ in range(length)])
                    h[0] += 1
                    raw = bytes.fromhex(next(hx for p, hx in hexes if p == 'raw_hex'))
                    for i, b in enumerate(raw):
                        h[1 + i][str(b)] = h[1 + i].get(str(b), 0) + 1
            elif hexes:
                reason = f"raw_hex without layout {tid:#x}|{length}"
            elif isinstance(sd, dict) or sd is None:
                cond = e.conditions or ''
                if sd is None and (cond.startswith('Raw data: ') or cond == 'No additional data'):
                    n = cond.count('0x') if cond.startswith('Raw data: ') else 0
                    reason = f"decoder declined {tid:#x}|{n}"
                    lb = layout_bytes.setdefault(f"declined|{tid:#x}", [0, 0, 0])
                    lb[0] += 1
                    lb[2] += n
            # Damage by the 128-byte page marker: the bytes were physically overwritten, so
            # nothing is left to decode. Inline {corrupted: ...} tags on text come from the
            # marker (analysis/coverage_rebaseline_damaged.md, section 1). An {undecoded hex: ...}
            # tag with no {corrupted: ...} tag in the same line is NOT marker damage (a newline
            # byte, erased 0xaa/0xff runs, trailing garbage), so the entry stays partial.
            is_damaged = bool(isinstance(sd, dict) and sd.get('corrupted_fields'))
            if tid == 0xfd:
                ev = e.event or ''
                if '{corrupted:' in ev:
                    is_damaged = True
                elif '{undecoded hex:' in ev and reason is None:
                    reason = 'text with undecoded bytes not from a page marker'
            if reason:
                partial += 1
                breakdown[reason] = breakdown.get(reason, 0) + 1
                if is_damaged:
                    overlap += 1
            elif is_damaged:
                damaged += 1
            else:
                full += 1
        res.update(total_entries=len(entries), corrupted_entries=corrupted, unknown_type_entries=unknown,
                   partially_decoded_entries=partial, fully_decoded_entries=full, rawhex_partial_entries=rawhex_partial,
                   damaged_entries=damaged, damaged_partial_overlap_entries=overlap,
                   partial_breakdown_json=json.dumps(breakdown), layout_bytes_json=json.dumps(layout_bytes),
                   hist_json=json.dumps(hist), unknown_type_counts_json=json.dumps(unknown_counts),
                   status='ok' if bucket is not None else 'unclassified')
    except Exception as exc:
        res['status'] = 'garbage'
        res['error'] = f'{type(exc).__name__}: {exc}'
    return res


def _hex_ok(mt):
    if not mt or not mt.startswith('0x'):
        return False
    try:
        int(mt, 16)
        return True
    except ValueError:
        return False


def process_safe(path):
    try:
        return process_one(path)
    except Exception:
        return {'filename': os.path.basename(path), 'status': 'garbage', 'error': 'unwrapped: ' + traceback.format_exc(-1)}


def cmd_run(args):
    conn = sqlite3.connect(args.db)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute(f"CREATE TABLE IF NOT EXISTS files ({', '.join(c + (' TEXT PRIMARY KEY' if c == 'filename' else '') for c in COLUMNS)})")
    done = {r[0] for r in conn.execute('SELECT filename FROM files')}
    names = sorted(f for f in os.listdir(args.corpus) if f.lower().endswith('.bin'))
    pending = [f for f in names if f not in done]
    print(f'{len(names)} files, {len(done)} recorded, {len(pending)} pending', flush=True)
    sql = f"INSERT OR REPLACE INTO files ({', '.join(COLUMNS)}) VALUES ({', '.join('?' * len(COLUMNS))})"
    for start in range(0, len(pending), 300):
        batch = [os.path.join(args.corpus, f) for f in pending[start:start + 300]]
        with mp.Pool(args.workers, maxtasksperchild=50) as pool:
            for r in pool.imap_unordered(process_safe, batch, chunksize=4):
                conn.execute(sql, tuple(r.get(c) for c in COLUMNS))
                conn.commit()
        print(f'{min(start + 300, len(pending))}/{len(pending)}', flush=True)
    print('Run complete.', flush=True)


def _rows(conn, dedup):
    q = "SELECT * FROM files WHERE status='ok'"
    if dedup:
        q += " AND filename IN (SELECT min(filename) FROM files WHERE status='ok' GROUP BY content_hash)"
    conn.row_factory = sqlite3.Row
    return conn.execute(q).fetchall()


def build_report(db, dedup=False):
    conn = sqlite3.connect(db)
    rows = _rows(conn, dedup)
    agg = {}
    for r in rows:
        g = GROUPS[r['bucket']]
        a = agg.setdefault(g, dict(files=0, entries=0, full=0, partial=0, unknown=0, corrupted=0, header=0,
                                   damaged=0, overlap=0, rawhex=0, bd={}, lb={}, hist={}))
        a['files'] += 1
        a['entries'] += r['total_entries']
        a['full'] += r['fully_decoded_entries']
        a['partial'] += r['partially_decoded_entries']
        a['unknown'] += r['unknown_type_entries']
        a['corrupted'] += r['corrupted_entries']
        a['header'] += r['header_complete'] or 0
        a['rawhex'] += r['rawhex_partial_entries'] or 0
        keys = r.keys()
        a['damaged'] += (r['damaged_entries'] or 0) if 'damaged_entries' in keys else 0
        a['overlap'] += (r['damaged_partial_overlap_entries'] or 0) if 'damaged_partial_overlap_entries' in keys else 0
        for k, v in json.loads(r['partial_breakdown_json'] or '{}').items():
            a['bd'][k] = a['bd'].get(k, 0) + v
        for k, v in json.loads(r['layout_bytes_json'] or '{}').items():
            e = a['lb'].setdefault(k, [0, 0, 0])
            e[0] += v[0]; e[1] += v[1]; e[2] += v[2] if k.startswith('declined') else v[2] * v[0]
        for k, v in json.loads(r['hist_json'] or '{}').items():
            h = a['hist'].setdefault(k, [0] + [dict() for _ in v[1:]])
            h[0] += v[0]
            for i, d in enumerate(v[1:]):
                for b, n in d.items():
                    h[1 + i][b] = h[1 + i].get(b, 0) + n
    return agg


def varying_decoded_share(a, layouts):
    """(varying bytes that are fields, all varying bytes) weighted by entries, for one row."""
    num = den = 0
    for key, h in a['hist'].items():
        tid, length = key.split('|')
        layout = layouts(int(tid, 16), int(length))
        if not layout:
            continue
        kinds = {}
        for s, e, k, _ in layout:
            for i in range(s, e):
                kinds[i] = k
        n = h[0]
        for i, d in enumerate(h[1:]):
            if n and max(d.values()) / n < 0.95:
                den += n
                if kinds.get(i) == 'field':
                    num += n
    return num, den


def cmd_report(args):
    import zero_log_parser as zlp
    agg = build_report(args.db, args.dedup)
    print('| row | files | entries | full % | partial % | damaged % | unknown % | corrupted % | header % | payload bytes decoded % | varying bytes decoded % | partial and damaged (counted partial) |')
    print('|---|---|---|---|---|---|---|---|---|---|---|---|')
    for g in ('legacy MBB', 'legacy BMS', 'Gen3 MBB', 'Gen3 BMS'):
        a = agg.get(g)
        if not a:
            continue
        e = a['entries']
        dec = sum(v[1] for k, v in a['lb'].items() if not k.startswith('declined'))
        tot = sum(v[2] for v in a['lb'].values())
        vn, vd = varying_decoded_share(a, zlp.Gen2.payload_layout)
        pb = f'{100*dec/tot:.1f}' if tot and dec else 'n/a'
        vb = f'{100*vn/vd:.1f}' if vd else 'n/a'
        print(f"| {g} | {a['files']} | {e} | {100*a['full']/e:.2f} | {100*a['partial']/e:.2f} | {100*a['damaged']/e:.2f} | "
              f"{100*a['unknown']/e:.2f} | {100*a['corrupted']/e:.2f} | {100*a['header']/a['files']:.2f} | {pb} | {vb} | {a['overlap']} |")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    r = sub.add_parser('run')
    r.add_argument('--corpus', required=True)
    r.add_argument('--db', required=True)
    r.add_argument('--workers', type=int, default=6)
    p = sub.add_parser('report')
    p.add_argument('--db', required=True)
    p.add_argument('--dedup', action='store_true')
    args = ap.parse_args()
    {'run': cmd_run, 'report': cmd_report}[args.cmd](args)


if __name__ == '__main__':
    main()
