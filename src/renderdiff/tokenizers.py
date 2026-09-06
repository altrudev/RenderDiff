from __future__ import annotations
from typing import Callable
import json

def observe_tokenizer(text: str, tokenizer: Callable[[str], list], *, name: str='custom') -> dict:
    tokens=tokenizer(text)
    if not isinstance(tokens,list):
        raise TypeError('tokenizer must return a list')
    try:
        json.dumps(tokens, ensure_ascii=False, sort_keys=True, separators=(',',':'))
    except (TypeError,ValueError) as e:
        raise TypeError('tokenizer tokens must be deterministic JSON data') from e
    return {'available':True,'name':name,'token_count':len(tokens),'tokens':tokens}

def tiktoken_adapter(encoding_name: str='cl100k_base'):
    try:
        import tiktoken
    except ImportError as e:
        raise RuntimeError('tiktoken is not installed') from e
    enc=tiktoken.get_encoding(encoding_name)
    return (lambda text: enc.encode(text)), f'tiktoken:{encoding_name}'

def sentencepiece_adapter(model_file: str):
    try:
        import sentencepiece as spm
    except ImportError as e:
        raise RuntimeError('sentencepiece is not installed') from e
    sp=spm.SentencePieceProcessor(model_file=model_file)
    return (lambda text: list(sp.encode(text, out_type=int))), f'sentencepiece:{model_file}'
