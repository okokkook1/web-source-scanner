"""Execute native Semgrep against annotated positive/negative fixtures."""
import argparse, json, os, pathlib, re, subprocess, sys
p = argparse.ArgumentParser()
p.add_argument("engine")
args = p.parse_args()
root = pathlib.Path(__file__).resolve().parents[1]
failures, checks = [], 0
for lang, name in [("csharp", "security.cs"), ("javascript", "client.js")]:
    target = root / "tests" / "fixtures" / "engine" / name
    run = subprocess.run([args.engine, "-json_nodots", "-rules", str(root / "rules" / "website.yml"), "-lang", lang, str(target)], capture_output=True, timeout=45, env={**os.environ, "SEMGREP_SEND_METRICS": "off", "SEMGREP_ENABLE_VERSION_CHECK": "0"})
    data = json.loads(run.stdout)
    if run.returncode or data.get("errors"):
        failures.append(f"{lang}: engine failure/errors: {data.get('errors', [])}")
    hits = {(m["check_id"], m["start"]["line"]) for m in data["results"]}
    for n, line in enumerate(target.read_text(encoding="utf-8").splitlines(), 1):
        match = re.search(r"// (ruleid|ok): ([A-Z0-9-]+)", line)
        if match:
            checks += 1
            expected = match[1] == "ruleid"
            if ((match[2], n+1) in hits) != expected:
                failures.append(f"{name}:{n+1} {match[2]} expected {'hit' if expected else 'safe'}")
print(json.dumps({"checks": checks, "failures": failures, "passed": checks-len(failures)}, ensure_ascii=False))
sys.exit(bool(failures))
