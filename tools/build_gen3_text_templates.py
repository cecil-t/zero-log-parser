#!/usr/bin/env python3
"""Build, review and evaluate the Gen3 text template table (gen3_text_templates.json).

The parser restores a Gen3 text line whose bytes were overwritten by the 128-byte page marker only
from this fixed table of messages that were seen intact. The table is built here, offline, from a
directory of log files; the parser never looks at any other file when decoding.

    python tools/build_gen3_text_templates.py extract  --corpus DIR --work WORK [--workers 3]
    python tools/build_gen3_text_templates.py build    --work WORK --out gen3_text_templates.json [--min-files 2]
    python tools/build_gen3_text_templates.py evaluate --work WORK [--seeds 5] [--synthetic 15000]

extract   walks every content-unique file, keeps those on the Gen3 (REV3) path, and stores per file
          (resumable, one JSON per content hash under WORK) the intact Gen3 text lines with their
          counts and the damaged lines as segments. "Intact" means no marker span and no undecoded
          tag; the page marker is not restored while extracting.
build     one template per message seen intact in at least --min-files different files (content
          unique), per board (BMS, MBB). A number or hex value is a slot only where it varies across
          the intact occurrences of that message (length bounds from the observed range); a value that
          never varies is fixed text. Templates are observed messages only: nothing is derived from
          damaged lines. Each template records provenance: id, files seen, intact count, and up to
          three example files by content hash. The output is deterministic.
evaluate  hold-out: build from a random 70% of the files, restore the damaged lines of the other 30%,
          report the restorable share and agreement with the table built from all files; and a
          synthetic test: overwrite four characters of intact held-out lines at random positions,
          restore, count wrong restorations.
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import multiprocessing as mp
import os
import random
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NUMBER = re.compile(r'0x[0-9A-Fa-f]+|-?\d+(?:\.\d+)?')
SLOT = '\x01'


def board_of(lf, head, size, zlp):
    if lf.log_type in (zlp.LogFile.log_type_bms, zlp.LogFile.log_type_mbb):
        return lf.log_type
    if b'BMS' in head[8:24] or b'MS\x00' in head[8:24] or size == 131328:
        return 'BMS'
    if b'MBB' in head[8:24]:
        return 'MBB'
    return None


def extract_one(args):
    path, work = args
    import zero_log_parser as zlp
    Gen2 = zlp.Gen2
    Gen2.GEN3_TEXT_TEMPLATES_FILE = os.devnull + '.none'     # extraction must see the unrestored text
    Gen2._gen3_text_index_cache.clear()
    with open(path, 'rb') as f:
        data = f.read()
    digest = hashlib.sha256(data).hexdigest()
    out = os.path.join(work, digest + '.json')
    if os.path.exists(out):
        return digest, 'cached'
    head, size = data[:32], len(data)
    del data
    seen = []
    def observer(result, segments, board):
        seen.append((result['display'], result['bytes_lost'], segments))
    try:
        lf = zlp.LogFile(path)
        probe = zlp.LogData.__new__(zlp.LogData)
        probe.log_file = lf
        probe.timezone_offset = 0
        version, _ = probe.get_version_and_header(lf)
        if version != zlp.REV3:
            rec = {'skip': 'not REV3'}
        else:
            board = board_of(lf, head, size, zlp)
            Gen2.gen3_text_observer = observer
            zlp.LogData(lf, timezone_offset=0, verbosity_level=0)
            Gen2.gen3_text_observer = None
            intact = collections.Counter()
            damaged = []
            for display, lost, segments in seen:
                if lost:
                    if not any(k == 'u' for k, _ in segments) and '{undecoded' not in display:
                        damaged.append(segments)
                elif '{' not in display:
                    intact[display] += 1
            rec = {'board': board, 'intact': intact, 'damaged': damaged, 'name': os.path.basename(path)}
    except Exception as exc:                                  # unreadable files are simply not used
        rec = {'skip': f'{type(exc).__name__}: {exc}'[:120]}
    Gen2.gen3_text_observer = None
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(rec, f, separators=(',', ':'))
    return digest, 'ok' if 'skip' not in rec else rec['skip']


def cmd_extract(args):
    os.makedirs(args.work, exist_ok=True)
    names = sorted(os.path.join(args.corpus, f) for f in os.listdir(args.corpus) if f.lower().endswith('.bin'))
    seen_hash, todo = set(), []
    for p in names:                                           # content-unique files only
        with open(p, 'rb') as f:
            h = hashlib.sha256(f.read()).hexdigest()
        if h not in seen_hash:
            seen_hash.add(h)
            todo.append((p, args.work))
    print(f'{len(names)} files, {len(todo)} content-unique', flush=True)
    with mp.Pool(args.workers, maxtasksperchild=25) as pool:
        for i, (digest, status) in enumerate(pool.imap_unordered(extract_one, todo, chunksize=2), 1):
            if i % 200 == 0:
                print(f'{i}/{len(todo)}', flush=True)
    print('extract done', flush=True)


def load_work(work, only=None):
    files = {}
    for fn in sorted(os.listdir(work)):
        if not fn.endswith('.json'):
            continue
        digest = fn[:-5]
        if only is not None and digest not in only:
            continue
        with open(os.path.join(work, fn), encoding='utf-8') as f:
            rec = json.load(f)
        if 'skip' in rec or rec.get('board') not in ('BMS', 'MBB'):
            continue
        files[digest] = rec
    return files


def build_templates(files, min_files=2):
    """files: {digest: rec}. Returns {'BMS': [...], 'MBB': [...]} template dicts with ids and provenance."""
    out = {}
    for board in ('BMS', 'MBB'):
        groups = collections.defaultdict(lambda: collections.defaultdict(lambda: [0, set()]))
        for digest, rec in files.items():
            if rec['board'] != board:
                continue
            for text, count in rec['intact'].items():
                g = groups[NUMBER.sub(SLOT, text)][text]
                g[0] += count
                g[1].add(digest)
        templates = {}
        for key, variants in groups.items():
            parts = key.split(SLOT)
            nslot = len(parts) - 1
            values = [[] for _ in range(nslot)]
            for text in variants:
                for i, v in enumerate(NUMBER.findall(text)):
                    values[i].append(v)
            tokens, lit, nslots = [], parts[0], 0
            for i in range(nslot):
                if len(set(values[i])) == 1:                  # never varies: fixed text
                    lit += values[i][0] + parts[i + 1]
                else:
                    if lit:
                        tokens.append(['lit', lit])
                    lens = [len(v) for v in values[i]]
                    kind = 'H' if all(v.startswith('0x') for v in values[i]) else 'N'
                    tokens.append([kind, min(lens), max(lens)])
                    lit = parts[i + 1]
                    nslots += 1
            if lit:
                tokens.append(['lit', lit])
            sig = json.dumps(tokens)
            count = sum(v[0] for v in variants.values())
            digests = set().union(*[v[1] for v in variants.values()])
            t = templates.get(sig)
            if t:
                t['count'] += count
                t['digests'] |= digests
            else:
                templates[sig] = {'t': tokens, 'count': count, 'digests': set(digests)}
        kept = [t for t in templates.values() if len(t['digests']) >= min_files]
        kept.sort(key=lambda t: (-len(t['digests']), -t['count'], json.dumps(t['t'])))
        prefix = 'B' if board == 'BMS' else 'M'
        rows = []
        for i, t in enumerate(kept, 1):
            row = {'id': f'{prefix}{i:04d}', 't': t['t'], 'files': len(t['digests']), 'count': t['count'],
                   'ex': [d[:12] for d in sorted(t['digests'])[:3]]}
            rows.append(row)
        out[board] = rows
    return out


def table_document(templates, files, min_files):
    return {
        'format': 1,
        'description': 'Gen3 text messages seen intact in at least min_files different files; used to restore '
                       'page-marker-damaged text. Built by tools/build_gen3_text_templates.py. Observed messages only.',
        'min_files': min_files,
        'built_from_files': {b: sum(1 for r in files.values() if r['board'] == b) for b in ('BMS', 'MBB')},
        'token_format': 'a token is ["lit", text] (fixed text) or [kind, min, max] (a variable number: N decimal, H 0x hex; '
                        'min and max length in characters). files = different files it was seen intact in, count = intact '
                        'occurrences, ex = the first 12 hex digits of the content hash of up to three of those files.',
        'boards': templates,
    }


def cmd_build(args):
    files = load_work(args.work)
    templates = build_templates(files, args.min_files)
    doc = table_document(templates, files, args.min_files)
    with open(args.out, 'w', encoding='utf-8') as f:
        json.dump(doc, f, separators=(',', ':'), ensure_ascii=False, sort_keys=False)
        f.write('\n')
    size = os.path.getsize(args.out)
    for b in ('BMS', 'MBB'):
        t = templates[b]
        print(f'{b}: {len(t)} templates ({sum(1 for x in t if all(k[0] == "lit" for k in x["t"]))} fixed strings, '
              f'{sum(1 for x in t if any(k[0] != "lit" for k in x["t"]))} parameterized), built from {doc["built_from_files"][b]} files')
    print(f'{args.out}: {size} bytes')


def segments_of(display):
    segs, pos = [], 0
    for m in re.finditer(r'\{corrupted: (\d+) bytes lost\}', display):
        if m.start() > pos:
            segs.append(('t', display[pos:m.start()]))
        segs.append(('gap', int(m.group(1))))
        pos = m.end()
    if pos < len(display):
        segs.append(('t', display[pos:]))
    return segs


def classify(Gen2, index, segments):
    """Same decision the parser makes, against an arbitrary index. Returns (category, restored dict or None)."""
    Gen2._gen3_restore_cache.clear() if len(Gen2._gen3_restore_cache) > 50000 else None
    Gen2._gen3_text_index_cache['EVAL'] = index
    r = Gen2._gen3_restore(tuple(segments), 'EVAL')
    return r


def cmd_evaluate(args):
    import zero_log_parser as zlp
    Gen2 = zlp.Gen2
    Gen2.GEN3_TEXT_TEMPLATES_FILE = os.devnull + '.none'
    Gen2.GEN3_TEXT_TEMPLATE_BOARDS = ('BMS', 'MBB', 'EVAL')
    files = load_work(args.work)
    full_templates = build_templates(files, args.min_files)
    full_index = {b: Gen2.gen3_text_index(t) for b, t in full_templates.items()}
    def restore(index, segments, board):
        Gen2._gen3_restore_cache.clear()
        Gen2._gen3_text_index_cache['EVAL'] = index[board]
        return Gen2._gen3_restore(tuple(segments), 'EVAL')
    bms = sorted(d for d, r in files.items() if r['board'] == 'BMS')
    results = []
    for seed in range(1, args.seeds + 1):
        rng = random.Random(seed)
        order = bms[:]
        rng.shuffle(order)
        cut = int(0.7 * len(order))
        train, test = set(order[:cut]), order[cut:]
        tmpl = build_templates({d: files[d] for d in train}, args.min_files)
        index = {b: Gen2.gen3_text_index(t) for b, t in tmpl.items()}
        lines = collections.Counter()
        for d in test:
            for segs in files[d]['damaged']:
                lines[tuple((k, v) for k, v in segs)] += 1
        total = sum(lines.values())
        restorable = agree = differ = full_restorable = 0
        for segs, n in lines.items():
            r = restore(index, segs, 'BMS')
            f = restore(full_index, segs, 'BMS')
            if f:
                full_restorable += n
            if r:
                restorable += n
                if f and f['text'] == r['text']:
                    agree += n
                elif f:
                    differ += n
        pool = []
        for d in test:
            for text, c in files[d]['intact'].items():
                if len(text) >= 8:
                    pool += [text] * min(c, 3)
        r2 = random.Random(100 + seed)
        ok = wrong = tried = 0
        for text in r2.sample(pool, min(args.synthetic, len(pool))):
            p = r2.randrange(0, len(text) - 3)
            segs = tuple(((('t', text[:p]),) if p else ()) + (('gap', 4),) + ((('t', text[p + 4:]),) if p + 4 < len(text) else ()))
            tried += 1
            r = restore(index, segs, 'BMS')
            if r:
                if r['text'] == text:
                    ok += 1
                else:
                    wrong += 1
        results.append(dict(seed=seed, train_files=len(train), test_files=len(test), templates=len(tmpl['BMS']),
                            heldout_damaged_lines=total, restorable=restorable, restorable_share=restorable / total if total else None,
                            full_table_restorable=full_restorable, agree_with_full_table=agree, differ_from_full_table=differ,
                            synthetic_lines=tried, synthetic_restored=ok + wrong, synthetic_wrong=wrong))
        print(json.dumps(results[-1]), flush=True)
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    e = sub.add_parser('extract'); e.add_argument('--corpus', required=True); e.add_argument('--work', required=True)
    e.add_argument('--workers', type=int, default=3)
    b = sub.add_parser('build'); b.add_argument('--work', required=True); b.add_argument('--out', required=True)
    b.add_argument('--min-files', type=int, default=2)
    v = sub.add_parser('evaluate'); v.add_argument('--work', required=True); v.add_argument('--seeds', type=int, default=5)
    v.add_argument('--synthetic', type=int, default=15000); v.add_argument('--min-files', type=int, default=2)
    args = ap.parse_args()
    {'extract': cmd_extract, 'build': cmd_build, 'evaluate': cmd_evaluate}[args.cmd](args)


if __name__ == '__main__':
    main()
