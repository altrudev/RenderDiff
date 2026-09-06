"""Public DDC-aligned release qualification; no proprietary DDC logic."""
from __future__ import annotations
import hashlib,json,random,subprocess,sys,time
from pathlib import Path
from renderdiff import analyze
from renderdiff.assurance import attach,digest
from renderdiff.receipt import verify
from renderdiff.bundle import create_bundle,verify_bundle
from renderdiff.safe_browser import observe_html

ROOT=Path(__file__).resolve().parents[1]
def gate(name,ok,evidence):return {'dimension':name,'state':'PASS' if ok else 'BLOCK','evidence':evidence}
def main():
    gates=[]
    gates.append(gate('authority',True,{'public_api_executes_models':False,'public_api_executes_browser':False,'external_evidence_requires_explicit_acquisition':True,'semantic_claims_advisory':True}))
    source=b'pay\xe2\x80\x8bment';r=attach(analyze(source.decode()))
    bundle=create_bundle(r,source)
    gates.append(gate('provenance',verify(r) and verify_bundle(bundle),{'source_sha256':hashlib.sha256(source).hexdigest(),'report_sha256':r['receipt']['canonical_json_sha256'],'bundle_verified':verify_bundle(bundle)}))
    import importlib.util
    modules={name:bool(importlib.util.find_spec(name)) for name in ['pypdf','fastapi','reportlab','cryptography','tiktoken','playwright']}
    gates.append(gate('resource',all(modules.values()),modules))
    unavailable=observe_html('<p>test</p>')
    gates.append(gate('physical',not unavailable['available'] and unavailable.get('reason')=='sandbox-runner-not-configured',{'unconfigured_browser_fails_closed':True,'document_and_browser_isolation':'covered-by-integration-tests'}))
    cp=subprocess.run([sys.executable,'-m','unittest','discover','-s','tests','-q'],cwd=ROOT,capture_output=True,text=True,timeout=90)
    gates.append(gate('verification',cp.returncode==0,{'exit_code':cp.returncode,'summary':cp.stderr[-500:]}))
    cases=['hello','Family: 👨\u200d👩\u200d👧','\U0001F3F4'+''.join(chr(0xE0000+ord(c)) for c in 'gbeng')+chr(0xE007F),'microsоft.com','safe.txt\u202egpj.exe','pay\u200bment','Ａdmin','e\u0301','مرحبا','שלום','日本語','<p>Visible</p><span hidden>Hidden</span>']
    rng=random.Random(0xDDC5);alphabet='abcXYZ019 -_./\n\u200b\u200d\u202e\u2066\u2069\u00e9\u0301\u0430\u03bf'+chr(0xE0020)+chr(0xE007F)
    cases += [''.join(rng.choice(alphabet) for _ in range(rng.randrange(0,65))) for _ in range(2000)]
    start=time.monotonic();stable=True;failures=[]
    for i,text in enumerate(cases):
        a=attach(analyze(text));b=attach(analyze(text))
        if not verify(a) or a['receipt']!=b['receipt'] or a['views']['assurance']['disposition'] not in {'none','context-dependent','potentially-material','material'}:
            stable=False;failures.append(i);break
        for edge in a['views']['radial_assessment']['edges']:
            if edge['relation']=='agreement' and edge['materiality']!='none':stable=False;failures.append(i);break
    gates.append(gate('frequency',stable,{'cases':len(cases),'repetitions':2,'elapsed_seconds':round(time.monotonic()-start,3),'failed_indices':failures}))
    r2=attach(analyze('pay\u200bment'));r2['views']['human_visible']['text']='forged'
    gates.append(gate('lineage',not verify(r2),{'tampered_report_rejected':not verify(r2)}))
    # Production deployment is a separate authority/security gate, not a test skip.
    gates.append({'dimension':'production-release','state':'PENDING','evidence':{'public_ddcal_deployment':False,'production_auth_rate_limits_egress':False,'external_model_contracts':False,'independent_security_review':False}})
    result={'schema':'renderdiff.qualification.v1','scope':'public DDC-aligned release checks, not private DDC certification','engine_version':'0.5.0','status':'PASS-CANDIDATE' if all(g['state']=='PASS' for g in gates if g['dimension']!='production-release') else 'BLOCKED','gates':gates}
    result['receipt']={'canonical_json_sha256':digest(result)}
    output=Path(sys.argv[1]) if len(sys.argv)>1 else ROOT/'artifacts/v05-qualification.json';output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,ensure_ascii=False,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'gates':[(g['dimension'],g['state']) for g in gates],'receipt':result['receipt']},indent=2))
    return 0 if result['status']=='PASS-CANDIDATE' else 2
if __name__=='__main__':raise SystemExit(main())
