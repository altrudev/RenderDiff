"""Explicit, tool-free model probes. Remote transmission is never automatic."""
from __future__ import annotations
import hashlib, json
from urllib.parse import urlsplit

def openai_compatible_observer(*, endpoint, model, token=None, timeout=30, temperature=0):
    """Return a callable for a specifically authorized OpenAI-compatible endpoint.

    No model is fetched, no API key is discovered, and no tool/function calls are sent.
    The caller is responsible for provider consent, retention and data classification.
    """
    parsed=urlsplit(endpoint)
    if parsed.scheme!='https' and not (parsed.scheme=='http' and parsed.hostname in {'localhost','127.0.0.1','::1'}):
        raise ValueError('model endpoint must use HTTPS or loopback HTTP')
    if parsed.username or parsed.password or parsed.fragment:raise ValueError('invalid model endpoint')
    if not isinstance(model,str) or not model:raise ValueError('model ID required')
    def observe(text):
        import httpx
        request={'model':model,'messages':[{'role':'user','content':text}],'temperature':temperature,'stream':False}
        headers={'Content-Type':'application/json'}
        if token:headers['Authorization']='Bearer '+token
        with httpx.Client(timeout=timeout,follow_redirects=False,trust_env=False) as client:
            response=client.post(endpoint,json=request,headers=headers)
            response.raise_for_status();data=response.json()
        content=data['choices'][0]['message']['content']
        if not isinstance(content,str) or len(content)>100000:raise ValueError('invalid model response')
        return {'available':True,'observer':'openai-compatible','text':text,'metadata':{'model_requested':model,'model_returned':data.get('model'),'response_sha256':hashlib.sha256(content.encode()).hexdigest(),'response':content,'usage':data.get('usage'),'request_sha256':hashlib.sha256(json.dumps(request,sort_keys=True,ensure_ascii=False).encode()).hexdigest()}}
    return observe

def compare_model_behaviour(source,visible,observer,*,observer_id):
    """Compare actual model responses; divergent outputs require human review."""
    outcomes={}
    for name,text in [('machine',source),('human_projection',visible)]:
        result=observer(text)
        if not result.get('available'):return {'available':False,'reason':'model-observer-unavailable','observer_id':observer_id}
        meta=result.get('metadata',{});response=meta.get('response')
        if not isinstance(response,str):raise ValueError('model response text required')
        outcomes[name]={'input_sha256':hashlib.sha256(text.encode()).hexdigest(),'response_sha256':hashlib.sha256(response.encode()).hexdigest(),'response':response,'model':meta.get('model_returned'),'usage':meta.get('usage')}
    equal=outcomes['machine']['response']==outcomes['human_projection']['response']
    return {'available':True,'observer_id':observer_id,'responses_equal':equal,'disposition':'context-dependent' if not equal else 'none','interpretation':'Observed response divergence is not proof of semantic materiality, malicious intent, or authorization.','outcomes':outcomes}
