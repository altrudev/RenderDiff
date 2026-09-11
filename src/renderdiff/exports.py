"""Escaped human-readable and SARIF outputs, with no network dependencies."""
from __future__ import annotations
import html, json
from .receipt import verify

def html_report(report):
    if not verify(report): raise ValueError('receipt integrity failed')
    esc=lambda x:html.escape(str(x),quote=True)
    findings=''.join('<tr><td>'+esc(f['category'])+'</td><td>'+esc(f['materiality'])+'</td><td><pre>'+esc(f['explanation'])+'</pre></td></tr>' for f in report.get('findings',[]))
    views=report.get('views',{})
    source=views.get('semantic',{}).get('machine_received_text','')
    visible=views.get('human_visible',{}).get('text','')
    return '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'"><title>RenderDiff assurance</title><style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:1rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f2f3f5;padding:1rem}table{width:100%;border-collapse:collapse}td,th{padding:.6rem;border:1px solid #ccc;text-align:left}</style></head><body><h1>RenderDiff assurance</h1><p>Disposition: '+esc(report['summary'].get('assurance_disposition',report['summary'].get('severity','unknown')))+'</p><h2>Human-visible projection</h2><pre>'+esc(visible)+'</pre><h2>Machine received</h2><pre>'+esc(source)+'</pre><h2>Findings</h2><table><thead><tr><th>Category</th><th>Materiality</th><th>Explanation</th></tr></thead><tbody>'+findings+'</tbody></table><h2>Receipt</h2><pre>'+esc(report['receipt']['canonical_json_sha256'])+'</pre><p>Projection is not a certified screenshot. Unavailable observers are not evidence of safety.</p></body></html>'

def sarif_report(report):
    if not verify(report):
        raise ValueError('receipt integrity failed')
    findings=report.get('findings',[])
    rules=sorted({f['category'] for f in findings})
    source=report.get('views',{}).get('semantic',{}).get('machine_received_text')
    results=[]
    for f in findings:
        result={'ruleId':f['category'],'level':'error' if f['severity'] in {'high','critical'} else 'warning' if f['severity']=='medium' else 'note','message':{'text':f['explanation']},'properties':{'finding_id':f['id'],'materiality':f['materiality']}}
        start=f.get('start')
        if type(start) is int and isinstance(source,str) and 0<=start<=len(source):
            prefix=source[:start]
            line=prefix.count('\n')+1
            column=len(prefix.rsplit('\n',1)[-1])+1
            region={'startLine':line,'startColumn':column}
            end=f.get('end')
            if type(end) is int and start<end<=len(source):
                last=source[:end]
                end_line=last.count('\n')+1
                end_column=len(last.rsplit('\n',1)[-1])+1
                region.update({'endLine':end_line,'endColumn':end_column})
            result['locations']=[{'physicalLocation':{'artifactLocation':{'uri':'evidence.txt'},'region':region}}]
        elif type(start) is int:
            result['properties']['source_offset']=start
            result['properties']['location_status']='unavailable-for-decoded-source'
        results.append(result)
    return {'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{'tool':{'driver':{'name':'RenderDiff','version':report.get('engine_version','unknown'),'rules':[{'id':r} for r in rules]}},'results':results}]}
