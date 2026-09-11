"""Public, deterministic evidence policy. No private DDC implementation."""
from __future__ import annotations
import hashlib, json, re
from .divergence import compare_text_views

LEVELS = {'none':0, 'context-dependent':1, 'potentially-material':2, 'material':3}
# Context is explicit. A text fragment never grants its own authority.
SENSITIVE = {'instruction','authority','identity','destination','executable','financial'}

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')

def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()

def assess(report, *, context=None, model_observer=None, semantic_observer=None, semantic_observer_id=None, tokenizer=None, tokenizer_name=None):
    """Add evidence-linked assessments without rewriting legacy findings.

    Context may declare an expected identifier, authorized source, or an exact
    machine-input observer. An unknown context is never inferred from suspicious words.
    """
    context = context or {}
    if not isinstance(context, dict):
        raise TypeError('context must be a dict')
    source = report['views'].get('semantic', {}).get('machine_received_text')
    if source is None:
        return {'schema':'renderdiff.assessment.v1','disposition':'unavailable','reason':'no-decoded-text','edges':[]}
    visible = report['views']['human_visible']['text']
    hidden = report['views']['hidden']
    browser=report['views'].get('browser_render',{})
    findings = report['findings']
    edges=[]
    def add(boundary, materiality, evidence, reason, **extra):
        edges.append({'boundary':boundary,'materiality':materiality,'finding_ids':sorted(set(evidence)), 'reason':reason, **extra})
    for edge in report['views']['radial_assessment']['edges']:
        if edge['relation'] == 'divergence':
            add(edge['boundary'],edge['materiality'],edge['finding_ids'],'representation-divergence',observer_pair=[edge['left'],edge['right']],delta=edge['delta'])
    # A declared expected identity is an exact comparison, not a brand-name guess.
    expected=context.get('expected_identity')
    if expected is not None:
        if not isinstance(expected,str) or len(expected)>4096:
            raise ValueError('expected_identity must be a short string')
        from .uts39 import default_confusables, uts39_skeleton
        actual=visible.strip()
        if actual != expected:
            same=uts39_skeleton(actual,default_confusables()) == uts39_skeleton(expected,default_confusables())
            add('identity','potentially-material' if same else 'context-dependent',[], 'declared-identity-mismatch',expected_sha256=hashlib.sha256(expected.encode()).hexdigest(),confusable_skeleton_equal=same)
    # Hidden content is evidence, not an instruction to the assessor.
    hidden_texts=list(hidden.get('unicode_tag_payloads',[]))
    hidden_texts += [x.get('text','') for x in hidden.get('html_hidden_fragments',[]) if isinstance(x,dict)]
    hidden_texts += [x.get('text','') for x in hidden.get('html_hidden_attributes',[]) if isinstance(x,dict)]
    evidence=[f['id'] for f in findings if f['category'] in {'ascii-smuggling','hidden-html-css'}]
    if hidden_texts and evidence:
        add('hidden-content','potentially-material',evidence,'content-not-present-in-human-view',hidden_sha256=[hashlib.sha256(x.encode()).hexdigest() for x in hidden_texts])
    model={'available':False,'reason':'not-configured'}
    if tokenizer is not None:
        from .modelview import compare_model_views
        model=compare_model_views(source,visible,tokenizer,name=tokenizer_name or 'custom')
        if not model['equal']:
            add('model-tokenization','context-dependent',[], 'exact-token-sequences-differ',token_count_delta=model['token_count_delta'])
    if model_observer is not None:
        observed=model_observer(source)
        if not isinstance(observed,dict):
            raise TypeError('model observer must return an object')
        model=observed
        if observed.get('available') and isinstance(observed.get('text'),str):
            received=observed['text']
            for edge in compare_text_views({'source':source,'model_input':received}):
                if not edge['equal']:
                    add('model-input','potentially-material',[], 'exact-model-input-differs',delta=edge['delta'])
            model={'available':True,'observer':observed.get('observer','custom'), 'text_sha256':hashlib.sha256(received.encode()).hexdigest(), 'char_length':len(received), 'metadata':observed.get('metadata',{})}
        else:
            model={'available':False,'reason':observed.get('reason','observer-unavailable')}
    # Browser metadata is evidence, not an endorsement of page content.
    if browser.get('available') and isinstance(browser.get('nodes'),list):
        concealed=[n for n in browser['nodes'] if isinstance(n,dict) and not n.get('visible',True) and n.get('text','').strip()]
        if concealed:
            add('rendered-hidden-content','potentially-material',[], 'computed-style-hidden-text',node_count=len(concealed),text_sha256=[hashlib.sha256(n['text'].encode()).hexdigest() for n in concealed[:100]])
    # No lexical keyword scanner can prove semantic intent or authorization.
    semantic={'status':'not-evaluated','reason':'no-authorized-semantic-observer','asserted_authority':False}
    if semantic_observer is not None:
        from .semantic import observe_semantics
        semantic=observe_semantics(source,visible,semantic_observer,observer_id=semantic_observer_id,context=context)
        for claim in semantic['claims']:
            if claim['materiality']!='none':
                add(claim['boundary'],claim['materiality'],[], 'trusted-semantic-observer-claim',observer_id=semantic_observer_id,evidence=claim['evidence'],explanation=claim['explanation'])
    if context.get('semantic_observer') is not None:
        raise ValueError('semantic_observer must be supplied as a trusted callable, not serialized evidence')
    coverage={
        'raw_bytes':'available' if 'raw_bytes' in report['views'] else 'unavailable',
        'unicode':'available' if 'unicode' in report['views'] else 'unavailable',
        'human_projection':'heuristic' if visible is not None else 'unavailable',
        'normalization':'available' if 'normalized' in report['views'] else 'unavailable',
        'hidden':'available' if 'hidden' in report['views'] else 'unavailable',
        'browser':'available' if browser.get('available') else 'unavailable',
        'model_tokens':'available' if tokenizer is not None else 'unavailable',
        'model_input':'available' if model_observer is not None and model.get('available') else 'unavailable',
        'semantic':'advisory' if semantic.get('available') else 'unavailable',
        'lineage':'supplied' if report['views'].get('lineage') else 'unavailable',
    }
    strongest=max((e['materiality'] for e in edges),key=lambda x:LEVELS[x],default='none')
    return {'schema':'renderdiff.assessment.v1','disposition':strongest,'material_divergence':LEVELS[strongest]>=2,'edges':edges,'model_input':model,'semantic':semantic,'context_sha256':digest(context),'coverage':coverage,'complete':False,'completeness_reason':'No universal semantic or visual completeness guarantee; inspect observer coverage.'}

def attach(report, **kwargs):
    report=dict(report)
    report['views']=dict(report['views'])
    report['views']['assurance']=assess(report,**kwargs)
    report['summary']=dict(report['summary'])
    report['summary']['assurance_disposition']=report['views']['assurance']['disposition']
    report['receipt']={'canonical_json_sha256':digest({k:v for k,v in report.items() if k!='receipt'})}
    return report
