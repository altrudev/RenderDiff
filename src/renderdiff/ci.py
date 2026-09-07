"""Local-first CI entrypoint; no hosted runner or network required."""
from __future__ import annotations
import argparse, subprocess, sys
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('paths',nargs='*');p.add_argument('--format',choices=['json','sarif'],default='json');p.add_argument('--output');p.add_argument('--fail-on-material',action='store_true');a=p.parse_args()
    from renderdiff.ingest import acquire_file
    from renderdiff.exports import sarif_report
    import json
    if not a.paths: p.error('at least one evidence path is required')
    reports=[];fail=False
    for name in a.paths:
        path=Path(name)
        if not path.is_file() or path.is_symlink():raise ValueError('regular evidence file required')
        r=acquire_file(path);reports.append({'path':str(path),'report':r})
        fail |= r['summary'].get('material_divergence',False)
    if a.format=='sarif':
        runs=[]
        for item in reports:
            run=sarif_report(item['report'])['runs'][0]
            for result in run['results']:
                for loc in result.get('locations',[]):loc['physicalLocation']['artifactLocation']['uri']=item['path']
            runs.append(run)
        output={'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':runs}
    else:output={'schema':'renderdiff.ci.v1','reports':reports}
    text=json.dumps(output,ensure_ascii=False,sort_keys=True,indent=2)+'\n'
    if a.output:Path(a.output).write_text(text,encoding='utf-8')
    else:sys.stdout.write(text)
    return 2 if fail and a.fail_on_material else 0
if __name__=='__main__':raise SystemExit(main())
