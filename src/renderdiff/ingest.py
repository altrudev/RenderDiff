"""Bounded, non-executing evidence acquisition and document extraction."""
from __future__ import annotations
import hashlib, io, json, mimetypes, os, stat, urllib.parse, zipfile
from pathlib import Path
from .engine import analyze_bytes, analyze
from .assurance import attach, digest
from .limits import check_text_budget, bounded_canonical

MAX_BYTES=4_000_000

def _sha(data): return hashlib.sha256(data).hexdigest()

def acquire_bytes(data, *, filename='evidence.txt', content_type=None, provenance=None, context=None):
    if not isinstance(data,bytes) or len(data)>MAX_BYTES:
        raise ValueError('evidence must be bytes within the configured limit')
    kind=(content_type or mimetypes.guess_type(filename)[0] or 'application/octet-stream').split(';')[0].lower()
    if kind=='application/octet-stream' and not data.startswith((b'%PDF-',b'PK\x03\x04')) and b'\x00' in data[:4096]:
        raise ValueError('unsupported binary evidence format')
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
    check_text_budget(text)
    lineage['extracted_text_sha256']=_sha(text.encode())
    report=attach(analyze(text,provenance=lineage),context=context)
    report['views']['source_document']={'sha256':_sha(data),'byte_length':len(data),'extractor':lineage['extractor'],'coverage':lineage.get('coverage','text extraction only')}
    report['receipt']={'canonical_json_sha256':_sha(bounded_canonical({k:v for k,v in report.items() if k!='receipt'}))}
    return report

def read_evidence_file(path, *, max_bytes=MAX_BYTES):
    """Open a regular file without following symlinks and enforce the byte budget."""
    path=Path(path)
    fd=os.open(path,os.O_RDONLY | getattr(os,'O_NOFOLLOW',0) | getattr(os,'O_CLOEXEC',0))
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size>max_bytes:
            raise ValueError('regular evidence file within the configured limit required')
        with os.fdopen(fd,'rb',closefd=False) as stream:
            data=stream.read(max_bytes+1)
        if len(data)>max_bytes:
            raise ValueError('evidence exceeds input limit')
        return data
    finally:
        os.close(fd)

def acquire_file(path, *, isolated_documents=True, **kwargs):
    path=Path(path)
    data=read_evidence_file(path)
    if isolated_documents and (path.suffix.lower() in {'.pdf','.docx','.xlsx','.pptx'} or data.startswith((b'%PDF-',b'PK\x03\x04'))):
        if kwargs: raise ValueError('document extraction does not support additional observer options')
        from .sandbox import extract_document
        return extract_document(data,filename=path.name)
    return acquire_bytes(data,filename=path.name,**kwargs)

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
    data=result['data']
    name=parsed.path.rsplit('/',1)[-1] or 'index.html'
    if name.lower().endswith(('.pdf','.docx','.xlsx','.pptx')) or data.startswith((b'%PDF-',b'PK\x03\x04')):
        raise ValueError('document URL extraction requires an explicitly isolated acquisition adapter')
    return acquire_bytes(data,filename=name,content_type=result.get('content_type'),provenance={'url':url,**result.get('provenance',{})},**kwargs)
