from pathlib import Path
import json
import benign_loader_checks
B=Path(__file__).resolve().parents[1]
records=json.loads((B/'evidence/source_extraction.json').read_text())
refs=json.loads((B/'evidence/references.json').read_text())
assert len(records)==len(refs)==24
assert sorted(r['ref'] for r in records)==list(range(1,25))
assert all(len(r['source_sha256'])==64 for r in records)
original=json.loads((B/'evidence/benign_loader_results.json').read_text())
benign_loader_checks.check()
rerun=json.loads((B/'evidence/benign_loader_results.json').read_text())
assert original['cases']==rerun['cases']
assert rerun['summary']=={'cases':12,'accessible':8,'blocked_at_load':2,'blocked_at_access':2}
print('PASS: 24 source records; twelve recorded probe outcomes reproduced. This is not validation of source interpretations or security effectiveness.')
