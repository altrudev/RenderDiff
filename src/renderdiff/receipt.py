"""Deterministic receipt verification and optional detached Ed25519 signatures."""
from __future__ import annotations
import base64, hashlib, json
from .assurance import canonical, digest

def verify(report):
    if not isinstance(report,dict) or not isinstance(report.get('receipt'),dict): return False
    return report['receipt'].get('canonical_json_sha256')==digest({k:v for k,v in report.items() if k!='receipt'})

def seal(report, *, private_key=None, key_id=None):
    if not verify(report): raise ValueError('receipt integrity failed')
    payload={'schema':'renderdiff.seal.v1','report_sha256':digest(report),'key_id':key_id}
    if private_key is not None:
        if not key_id: raise ValueError('key_id required')
        payload['algorithm']='Ed25519'
        payload['signature']=base64.b64encode(private_key.sign(canonical(payload))).decode('ascii')
    return payload

def verify_seal(report, seal_data, public_key=None):
    if not verify(report) or seal_data.get('report_sha256')!=digest(report): return False
    if 'signature' not in seal_data: return True
    if public_key is None: return False
    signed={k:v for k,v in seal_data.items() if k!='signature'}
    try:
        public_key.verify(base64.b64decode(seal_data['signature'],validate=True),canonical(signed))
        return True
    except (ValueError,TypeError,Exception): return False
