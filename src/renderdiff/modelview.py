"""Exact tokenizer comparisons with explicit model and normalization identity."""
from __future__ import annotations
import hashlib, json
from .divergence import compare_text_views

def compare_model_views(source, visible, tokenizer, *, name, model_id=None, maximum_tokens=100000):
    if not isinstance(name,str) or not name or not isinstance(source,str) or not isinstance(visible,str):
        raise ValueError('named tokenizer and text views required')
    observations={}
    for label,text in [('machine',source),('human_projection',visible)]:
        tokens=tokenizer(text)
        if not isinstance(tokens,list) or len(tokens)>maximum_tokens or any(type(t) not in (int,str) for t in tokens):
            raise ValueError('tokenizer must return bounded integer/string tokens')
        observations[label]={'text_sha256':hashlib.sha256(text.encode()).hexdigest(),'tokens':tokens,'token_count':len(tokens)}
    a=observations['machine']['tokens']; b=observations['human_projection']['tokens']
    return {'available':True,'tokenizer':name,'model_id':model_id,'views':observations,
            'equal':a==b,'token_count_delta':len(a)-len(b),
            'text_comparisons':compare_text_views({'machine':source,'human_projection':visible}),
            'interpretation':'Exact token divergence is evidence, not proof of semantic or behavioral divergence.'}
