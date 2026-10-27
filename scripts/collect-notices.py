"""Collect licenses and attribution for the resolved Windows Rust dependencies."""
import argparse,json,pathlib,shutil,subprocess
p=argparse.ArgumentParser()
p.add_argument('output',type=pathlib.Path)
a=p.parse_args()
project=pathlib.Path(__file__).resolve().parents[1]
metadata=json.loads(subprocess.check_output(['cargo','metadata','--locked','--offline','--format-version','1','--filter-platform','x86_64-pc-windows-msvc'],cwd=project))
dest=a.output.resolve()
dest.mkdir(parents=True,exist_ok=True)
catalog=[]
for package in metadata['packages']:
    if not package.get('source'):
        continue
    root=pathlib.Path(package['manifest_path']).parent
    files=[f for f in root.iterdir() if f.is_file() and (f.name.upper().startswith(('LICENSE','LICENCE','COPYING','NOTICE','COPYRIGHT')))]
    if package.get('license_file'):
        f=root/package['license_file']
        if f.is_file() and f not in files:
            files.append(f)
    target=dest/f"{package['name']}-{package['version']}"
    target.mkdir(exist_ok=True)
    for f in files:
        shutil.copyfile(f,target/f.name)
    catalog.append({'name':package['name'],'version':package['version'],'license':package.get('license'),'repository':package.get('repository'),'license_files':[f'{target.name}/{f.name}' for f in files]})
(dest/'dependency-catalog.json').write_text(json.dumps(catalog,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({'packages':len(catalog),'license_files':sum(len(p['license_files']) for p in catalog)}))
