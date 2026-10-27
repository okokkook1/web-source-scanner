"""Hash a read-only target before/after a scan without exposing source contents."""
import argparse, hashlib, json, pathlib
p=argparse.ArgumentParser()
p.add_argument('root',type=pathlib.Path)
p.add_argument('snapshot',type=pathlib.Path)
p.add_argument('--compare',action='store_true')
a=p.parse_args()
files={}
for f in sorted(a.root.rglob('*')):
    if f.is_file() and not f.is_symlink():
        files[f.relative_to(a.root).as_posix()]=hashlib.sha256(f.read_bytes()).hexdigest()
if a.compare:
    before=json.loads(a.snapshot.read_text(encoding='utf-8'))
    changed=[name for name in before.keys()|files.keys() if before.get(name)!=files.get(name)]
    result={'before':len(before),'after':len(files),'changed_count':len(changed),'changed_paths':changed}
    print(json.dumps(result,ensure_ascii=False))
    a.snapshot.with_name('target-integrity-result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    raise SystemExit(bool(changed))
a.snapshot.write_text(json.dumps(files,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({'snapshotted_files':len(files)}))
