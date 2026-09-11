"""Portable evidence bundle. Original bytes are never reconstructed from extracted text."""
from __future__ import annotations
import hashlib, io, json, zipfile
from .assurance import canonical, digest
from .receipt import verify

def create_bundle(report, source):
    if not verify(report): raise ValueError('report integrity failed')
    if not isinstance(source,bytes): raise TypeError('source must be bytes')
    expected=report.get('views',{}).get('lineage',{}).get('source_sha256') or report.get('input',{}).get('sha256')
    if hashlib.sha256(source).hexdigest()!=expected: raise ValueError('source does not match report')
    manifest={'schema':'renderdiff.bundle.v1','source_sha256':expected,'source_bytes':len(source),'report_sha256':digest(report)}
    buf=io.BytesIO()
    with zipfile.ZipFile(buf,'w',compression=zipfile.ZIP_DEFLATED) as z:
        for name,data in [('manifest.json',canonical(manifest)),('report.json',canonical(report)),('evidence.bin',source)]:
            z.writestr(zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0)),data)
    return buf.getvalue()

def verify_bundle(data):
    if not isinstance(data,bytes) or len(data)>16_000_000: return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            if sorted(z.namelist())!=['evidence.bin','manifest.json','report.json']:return False
            limits={'evidence.bin':4_000_000,'manifest.json':65536,'report.json':8_000_000}
            if any(z.getinfo(n).file_size>limit for n,limit in limits.items()):return False
            manifest=json.loads(z.read('manifest.json')); report=json.loads(z.read('report.json')); source=z.read('evidence.bin')
            return verify(report) and manifest['report_sha256']==digest(report) and manifest['source_sha256']==hashlib.sha256(source).hexdigest() and manifest['source_bytes']==len(source)
    except (ValueError,KeyError,TypeError,zipfile.BadZipFile,UnicodeError,OverflowError,RecursionError,OSError):return False
