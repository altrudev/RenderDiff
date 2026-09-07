"""Bounded, non-executing evidence acquisition and document extraction."""
from __future__ import annotations
import hashlib, io, json, mimetypes, urllib.parse, zipfile
from pathlib import Path
from .engine import analyze_bytes, analyze
from .assurance import attach, digest

MAX_BYTES=4_000_000

def _sha(data): return hashlib.sha256(data).hexdigest()

def acquire_bytes(data, *, filename='evidence.txt', content_type=None, provenance=None, context=None):
    if not isinstance(data,bytes) or len(data)>MAX_BYTES:
        raise ValueError('evidence must be bytes within the configured limit')
    kind=(content_type or mimetypes.guess_type(filename)[0] or 'application/octet-stream').split(';')[0]
    lineage={'source_sha256':_sha(data),'source_bytes':len(data),'filename':Path(filename).name,'content_type':kind,'acquisition':provenance or {}}
    if kind == 'application/pdf' or data.startswith(b'%PDF-'):
        from pypdf import PdfReader
        reader=PdfReader(io.BytesIO(data),strict=True)
        if reader.is_encrypted: raise ValueError('encrypted PDF requires an authorized extraction adapter')
        if len(reader.pages)>100: raise ValueError('page limit exceeded')
        text='\n'.join(page.extract_text() or '' for page in reader.pages)
        lineage['extractor']='pypdf'; lineage['pages']=len(reader.pages); lineage['coverage']='extractable text only; no OCR, images, or visual-layout assurance'
    elif kind in {'application/vnd.openxmlformats-officedocument.wordprocessingml.document','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','application/vnd.openxmlformats-officedocument.presentationml.presentation'} or filename.lower().endswith(('.docx','.xlsx','.pptx')):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            members=z.infolist()
            if len(members)>1000 or sum(x.file_size for x in members)>16_000_000: raise ValueError('document expansion limit exceeded')
            from defusedxml.ElementTree import fromstring
            texts=[]
            for member in members:
                if member.compress_size and member.file_size/member.compress_size>1000: raise ValueError('document compression ratio limit exceeded')
                name=member.filename
                if not (name.startswith(('word/','xl/','ppt/')) and name.endswith('.xml')): continue
                if member.file_size>4_000_000: raise ValueError('XML member limit exceeded')
                if not any(x in name for x in ('document.xml','header','footer','sharedStrings.xml','worksheets/','slides/','notesSlides/','comments')): continue
                root=fromstring(z.read(member))
                texts.extend(x.text for x in root.iter() if x.tag.rsplit('}',1)[-1] in {'t','v'} and x.text)
            text='\n'.join(texts)
        lineage['extractor']='ooxml-xml-text'; lineage['coverage']='selected text-bearing XML; not visual layout'
    elif kind.startswith('text/') or kind in {'application/json','application/xml','application/javascript'}:
        return attach(analyze_bytes(data,content_type=kind,provenance=lineage),context=context)
    else:
        raise ValueError('unsupported format; use an explicit trusted extractor')
    if len(text.encode())>MAX_BYTES: raise ValueError('extracted text limit exceeded')
    lineage['extracted_text_sha256']=_sha(text.encode())
    report=attach(analyze(text,provenance=lineage),context=context)
    report['views']['source_document']={'sha256':_sha(data),'byte_length':len(data),'extractor':lineage['extractor'],'coverage':lineage.get('coverage','text extraction only')}
    report['receipt']={'canonical_json_sha256':digest({k:v for k,v in report.items() if k!='receipt'})}
    return report

def acquire_file(path, **kwargs):
    path=Path(path)
    if path.stat().st_size>MAX_BYTES: raise ValueError('file size limit exceeded')
    return acquire_bytes(path.read_bytes(),filename=path.name,**kwargs)

def acquire_url(url, *, fetcher=None, **kwargs):
    """Explicit network boundary. Public deployments must use a network-isolated fetcher.

    The default rejects all network requests: DNS validation alone cannot prevent
    rebinding, redirects, proxies, or access to internal services.
    """
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme not in {'https','http'} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('invalid public URL')
    if fetcher is None: raise ValueError('URL acquisition requires a configured sandboxed fetcher')
    result=fetcher(url,MAX_BYTES)
    if not isinstance(result,dict) or not isinstance(result.get('data'),bytes): raise TypeError('fetcher must return data bytes and provenance')
    if len(result['data'])>MAX_BYTES: raise ValueError('download limit exceeded')
    return acquire_bytes(result['data'],filename=parsed.path.rsplit('/',1)[-1] or 'index.html',content_type=result.get('content_type'),provenance={'url':url,**result.get('provenance',{})},**kwargs)
