"""Deterministic receipt verification and optional detached Ed25519 signatures."""
from __future__ import annotations
import base64, hashlib, json, hmac
from .assurance import canonical, digest

def verify(report):
    if not isinstance(report,dict) or not isinstance(report.get('receipt'),dict): return False
    try:
        actual=digest({k:v for k,v in report.items() if k!='receipt'})
        expected=report['receipt'].get('canonical_json_sha256')
        return isinstance(expected,str) and hmac.compare_digest(expected,actual)
    except (TypeError,ValueError,OverflowError,RecursionError):
        return False

def seal(report, *, private_key=None, key_id=None):
    if not verify(report): raise ValueError('receipt integrity failed')
    payload={'schema':'renderdiff.seal.v1','report_sha256':digest(report),'key_id':key_id}
    if private_key is not None:
        if not key_id: raise ValueError('key_id required')
        payload['algorithm']='Ed25519'
        payload['signature']=base64.b64encode(private_key.sign(canonical(payload))).decode('ascii')
    return payload

def verify_seal(report, seal_data, public_key=None):
    if not isinstance(seal_data,dict) or not verify(report): return False
    try:
        if seal_data.get('schema')!='renderdiff.seal.v1' or seal_data.get('report_sha256')!=digest(report): return False
    except (TypeError,ValueError): return False
    if 'signature' not in seal_data: return public_key is None and 'algorithm' not in seal_data
    if public_key is None or seal_data.get('algorithm')!='Ed25519' or not seal_data.get('key_id'): return False
    signed={k:v for k,v in seal_data.items() if k!='signature'}
    try:
        public_key.verify(base64.b64decode(seal_data['signature'],validate=True),canonical(signed))
        return True
    except Exception: return False
