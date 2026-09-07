"""Evidence-bound release qualification; never self-certifies production readiness."""
from __future__ import annotations
import hashlib, importlib.metadata, importlib.util, json, os, random, re, shutil, subprocess, sys, tempfile, time
from datetime import datetime, timezone
from pathlib import Path
from renderdiff import analyze
from renderdiff.assurance import attach, canonical, digest
from renderdiff.bundle import create_bundle, verify_bundle
from renderdiff.receipt import verify
from renderdiff.safe_browser import observe_html

ROOT=Path(__file__).resolve().parents[1]
ART=ROOT/'artifacts'
ART.mkdir(exist_ok=True)

def run(*args, timeout=180, cwd=ROOT):
    return subprocess.run(args,cwd=cwd,capture_output=True,text=True,timeout=timeout,
        env={k:v for k,v in os.environ.items() if k not in {'RENDERDIFF_API_TOKEN','RENDERDIFF_RATE_LIMIT'}} | {'PYTHONPATH':str(ROOT/'src')})

def sha(data):return hashlib.sha256(data).hexdigest()
def gate(name,ok,evidence):return {'dimension':name,'state':'PASS' if ok else 'BLOCK','evidence':evidence}
def read_json(name):return json.loads((ART/name).read_text(encoding='utf-8'))

def main():
    files=run('git','ls-files','--cached','--others','--exclude-standard').stdout.splitlines()
    files=sorted(x for x in files if x.startswith(('src/','tests/','tools/','docs/')) or x in {'README.md','LICENSE','pyproject.toml','action.yml','.pre-commit-hooks.yaml'})
    manifest={x:sha((ROOT/x).read_bytes()) for x in files if (ROOT/x).is_file()}
    manifest_hash=digest(manifest)
    revision=run('git','rev-parse','HEAD').stdout.strip()
    clean=not run('git','status','--porcelain').stdout.strip()
    import tomllib
    declared=tomllib.loads((ROOT/'pyproject.toml').read_text())['project']['version']
    installed=importlib.metadata.version('renderdiff')
    gates=[gate('state',clean and declared==installed and bool(re.fullmatch('[0-9a-f]{40}',revision)),{'revision':revision,'source_manifest_sha256':manifest_hash,'working_tree_clean':clean,'file_count':len(manifest),'declared_version':declared,'installed_version':installed})]
    source=b'pay\xe2\x80\x8bment';report=attach(analyze(source.decode()))
    bundle=create_bundle(report,source)
    gates.append(gate('provenance',verify(report) and verify_bundle(bundle),{'source_sha256':sha(source),'report_sha256':report['receipt']['canonical_json_sha256'],'bundle_sha256':sha(bundle)}))
    modules={x:bool(importlib.util.find_spec(x)) for x in ['fastapi','pypdf','defusedxml','cryptography','tiktoken','playwright','reportlab']}
    gates.append(gate('resource',all(modules.values()) and bool(shutil.which('bwrap')),{'modules':modules,'bubblewrap':bool(shutil.which('bwrap'))}))
    security=run(sys.executable,'-m','unittest','discover','-s','tests','-p','test_release_hardening.py','-v',timeout=90)
    gates.append(gate('authority',security.returncode==0 and 'test_authentication_and_rate_limit' in security.stderr and 'test_semantic_spans_reject_forgery' in security.stderr,{'test_exit_code':security.returncode,'test_output_sha256':sha(security.stderr.encode())}))
    gates.append(gate('physical',security.returncode==0 and 'test_worker_cannot_access_host_or_network' in security.stderr and 'skipped=' not in security.stderr,{'namespace_test':'test_worker_cannot_access_host_or_network','test_output_sha256':sha(security.stderr.encode())}))
    suite=run(sys.executable,'-m','unittest','discover','-s','tests','-q',timeout=120)
    count=re.search(r'Ran (\d+) tests',suite.stderr)
    gates.append(gate('verification',suite.returncode==0 and count is not None and int(count.group(1))>=69,{'exit_code':suite.returncode,'test_count':int(count.group(1)) if count else None,'output_sha256':sha(suite.stderr.encode())}))
    matrix=read_json('release-matrix.json')
    gates.append(gate('python-matrix',matrix['status']=='PASS' and len(matrix['results'])==5 and all(x['state']=='PASS' and 'Ran 69 tests' in x.get('summary','') for x in matrix['results']),{'versions':[x['python'] for x in matrix['results']],'evidence_sha256':sha(canonical(matrix))}))
    audit=read_json('dependency-audit.json')
    vulnerable=[{'name':x['name'],'version':x['version'],'ids':[v['id'] for v in x['vulns']]} for x in audit.get('dependencies',[]) if x.get('vulns')]
    gates.append(gate('dependencies',not vulnerable and len(audit.get('dependencies',[]))>0,{'packages':len(audit.get('dependencies',[])),'vulnerabilities':vulnerable,'evidence_sha256':sha(canonical(audit)),'requirements_sha256':sha((ART/'release-requirements.txt').read_bytes())}))
    lint=run(str(ROOT/'.venv/bin/ruff'),'check','src','tests','tools','--select','E9,F63,F7,F82','--output-format','concise')
    bandit=read_json('bandit.json')
    findings=bandit.get('results',[])
    medium=[x for x in findings if x['issue_severity'] in {'HIGH','MEDIUM'}]
    accepted=all(x['test_id']=='B108' and Path(x['filename']).name in {'sandbox.py','safe_browser.py','playwright_browser.py'} for x in medium)
    gates.append(gate('static-security',lint.returncode==0 and accepted and security.returncode==0,{'syntax_check_exit':lint.returncode,'bandit_high':sum(x['issue_severity']=='HIGH' for x in findings),'bandit_medium':len(medium),'accepted_sandbox_path_heuristics':[{'file':Path(x['filename']).name,'line':x['line_number'],'test':x['test_id']} for x in medium],'evidence_sha256':sha(canonical(bandit)),'full_style_lint':'not-claimed'}))
    cases=['hello','Family: 👨\u200d👩\u200d👧','\U0001F3F4'+''.join(chr(0xE0000+ord(c)) for c in 'gbeng')+chr(0xE007F),'microsоft.com','safe.txt\u202egpj.exe','pay\u200bment','Ａdmin','e\u0301','مرحبا','שלום','日本語','<p>Visible</p><span hidden>Hidden</span>']
    rng=random.Random(0xDDC5);alphabet='abcXYZ019 -_./\n\u200b\u200d\u202e\u2066\u2069\u00e9\u0301\u0430\u03bf'+chr(0xE0020)+chr(0xE007F)
    cases+=[''.join(rng.choice(alphabet) for _ in range(rng.randrange(65))) for _ in range(2000)]
    stable=True;failures=[];start=time.monotonic()
    for i,text in enumerate(cases):
        a=attach(analyze(text));b=attach(analyze(text))
        if not verify(a) or a['receipt']!=b['receipt']:
            stable=False;failures.append(i);break
        if any(e['relation']=='agreement' and e['materiality']!='none' for e in a['views']['radial_assessment']['edges']):
            stable=False;failures.append(i);break
    gates.append(gate('frequency',stable,{'cases':len(cases),'repetitions':2,'failed_indices':failures,'elapsed_seconds':round(time.monotonic()-start,3),'seed':'0xDDC5'}))
    altered=attach(analyze('pay\u200bment'));altered['views']['human_visible']['text']='forged'
    gates.append(gate('lineage',not verify(altered),{'tampered_report_rejected':not verify(altered)}))
    unavailable=observe_html('<p>test</p>')
    gates.append(gate('observer-boundary',unavailable.get('available') is False and unavailable.get('reason')=='sandbox-runner-not-configured',{'unconfigured_browser':unavailable,'model_provider':'not-configured','ocr':'not-configured'}))
    gates.append({'dimension':'production-release','state':'PENDING','evidence':{'independent_security_review':False,'multi_user_identity_and_shared_quotas':False,'production_cgroups_and_egress':False,'ddcal_deployment':False,'model_provider_validation':False,'full_visual_ocr_coverage':False,'owner_release_approval':False}})
    technical=all(g['state']=='PASS' for g in gates if g['dimension']!='production-release')
    result={'schema':'renderdiff.release-qualification.v1','scope':'DDC-aligned public release checks; not private-kernel or independent certification','revision':revision,'source_manifest_sha256':manifest_hash,'engine_version':importlib.metadata.version('renderdiff'),'status':'PASS-CANDIDATE' if technical else 'BLOCKED','gates':gates,'generated_at':datetime.now(timezone.utc).isoformat()}
    result['receipt']={'canonical_json_sha256':digest(result)}
    (ART/'release-source-manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    (ART/'release-qualification.json').write_text(json.dumps(result,sort_keys=True,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps({'status':result['status'],'revision':revision,'gates':[(g['dimension'],g['state']) for g in gates],'receipt':result['receipt']},indent=2))
    return 0 if technical else 2
if __name__=='__main__':raise SystemExit(main())
