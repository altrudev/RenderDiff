"""Optional trusted semantic observer. Evidence cannot authorize actions."""
from __future__ import annotations
import hashlib
ALLOWED={'instruction','authority','identity','destination','executable','financial','other'}

def observe_semantics(source, visible, observer, *, observer_id, context=None):
    if not callable(observer) or not observer_id: raise ValueError('trusted named observer required')
    context=context or {}
    result=observer({'machine_text':source,'human_text':visible,'context':context})
    if not isinstance(result,dict) or not isinstance(result.get('claims'),list): raise TypeError('observer must return claims')
    claims=[]
    for claim in result['claims']:
        if not isinstance(claim,dict) or claim.get('boundary') not in ALLOWED or claim.get('materiality') not in {'none','context-dependent','potentially-material','material'}:
            raise ValueError('invalid semantic claim')
        evidence=claim.get('evidence',[])
        if not isinstance(evidence,list) or not evidence or len(evidence)>100: raise ValueError('semantic claims require bounded evidence')
        for item in evidence:
            if not isinstance(item,dict) or item.get('view') not in {'machine','human'} or not isinstance(item.get('start'),int) or not isinstance(item.get('end'),int): raise ValueError('invalid evidence span')
            text=source if item['view']=='machine' else visible
            if not 0<=item['start']<=item['end']<=len(text): raise ValueError('evidence span out of range')
        claims.append({'boundary':claim['boundary'],'materiality':claim['materiality'],'evidence':evidence,'explanation':str(claim.get('explanation',''))[:4096]})
    return {'available':True,'observer_id':observer_id,'claims':claims,'authority':'advisory-only','model_claims_are_not_verified_facts':True}
