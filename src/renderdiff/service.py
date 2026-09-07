"""Bounded public API. Deploy behind an authenticated, rate-limited reverse proxy."""
from __future__ import annotations
import json, os, hmac, time, threading, secrets
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, Response
from .api import analyze_request
from .assurance import attach
from .limits import EvidenceLimitError
from .ingest import acquire_bytes, MAX_BYTES
from .sandbox import extract_document
import asyncio
from .exports import html_report, sarif_report

MAX_PUBLIC_CHARS=64_000
MAX_REPORT_BYTES=8_000_000
app=FastAPI(title='RenderDiff',version='0.6.1b1',docs_url=None,redoc_url=None)
_pool=ThreadPoolExecutor(max_workers=2,thread_name_prefix='renderdiff')
_slots=threading.BoundedSemaphore(2)
_rate_lock=threading.Lock()
_rate_windows={}
_MAX_RATE_KEYS=10000

def _authorize(request):
    # Never trust client-supplied forwarding headers as an authentication source.
    configured=os.environ.get('RENDERDIFF_API_TOKEN','')
    if not configured or len(configured)<32:
        raise HTTPException(503,'public assurance authentication is not configured')
    supplied=request.headers.get('authorization','')
    if len(supplied)>4096 or not supplied.startswith('Bearer ') or not hmac.compare_digest(supplied[7:],configured):
        raise HTTPException(401,'authentication required',headers={'WWW-Authenticate':'Bearer'})
    now=time.monotonic()
    try: limit=int(os.environ.get('RENDERDIFF_RATE_LIMIT','30'))
    except ValueError: raise HTTPException(503,'invalid rate-limit configuration')
    limit=max(1,min(limit,600))
    key=hmac.new(configured.encode(),supplied.encode(), 'sha256').hexdigest()
    with _rate_lock:
        if len(_rate_windows)>=_MAX_RATE_KEYS:
            for k in list(_rate_windows):
                if not _rate_windows[k] or _rate_windows[k][-1]<now-60: del _rate_windows[k]
        window=_rate_windows.setdefault(key,deque())
        while window and window[0]<=now-60: window.popleft()
        if len(window)>=limit: raise HTTPException(429,'rate limit exceeded',headers={'Retry-After':'60'})
        window.append(now)


async def _run_bounded(fn, *args, **kwargs):
    """Keep capacity reserved until the real worker finishes, even on cancellation."""
    if not _slots.acquire(blocking=False):
        raise HTTPException(503,'assurance service is busy',headers={'Retry-After':'5'})
    def work():
        try:
            return fn(*args, **kwargs)
        finally:
            _slots.release()
    try:
        future=_pool.submit(work)
    except BaseException:
        _slots.release()
        raise
    try:
        return await asyncio.wait_for(asyncio.shield(asyncio.wrap_future(future)),timeout=30)
    except asyncio.TimeoutError as exc:
        raise HTTPException(504,'assurance operation timed out') from exc

@app.middleware('http')
async def limits(request:Request, call_next):
    if request.method in {'POST','PUT'}:
        try: _authorize(request)
        except HTTPException as exc: return JSONResponse({'detail':exc.detail},status_code=exc.status_code,headers=exc.headers)
        length=request.headers.get('content-length')
        if length and (not length.isdigit() or int(length)>MAX_BYTES+65536):
            return JSONResponse({'detail':'request too large'},status_code=413)
        # Stream through a bounded buffer; never trust Content-Length alone.
        data=bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data)>MAX_BYTES+65536:
                return JSONResponse({'detail':'request too large'},status_code=413)
        request._body=bytes(data)
    response=await call_next(request)
    response.headers['Cache-Control']='no-store'
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['X-Frame-Options']='DENY'
    return response

def response(report,fmt):
    from .receipt import verify
    if not verify(report):
        raise HTTPException(400,'report receipt integrity failed')
    if report.get('schema') != 'renderdiff.assurance.v1':
        raise HTTPException(400,'unsupported report schema')
    raw=json.dumps(report,ensure_ascii=False,allow_nan=False).encode('utf-8')
    if len(raw)>MAX_REPORT_BYTES:
        raise HTTPException(413,'report amplification limit exceeded')
    headers={'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'}
    if fmt=='json':
        return Response(raw,media_type='application/json',headers=headers)
    if fmt=='html':
        body=html_report(report).encode('utf-8')
        headers['Content-Security-Policy']="default-src 'none'; style-src 'unsafe-inline'"
        media='text/html; charset=utf-8'
    elif fmt=='sarif':
        body=json.dumps(sarif_report(report),ensure_ascii=False,allow_nan=False).encode('utf-8')
        media='application/sarif+json'
    elif fmt=='pdf':
        from .pdf_report import pdf_report
        body=pdf_report(report)
        media='application/pdf'
        headers['Content-Disposition']='attachment; filename=renderdiff-report.pdf'
    else:
        raise HTTPException(400,'unsupported report format')
    if len(body)>MAX_REPORT_BYTES:
        raise HTTPException(413,'report export limit exceeded')
    return Response(body,media_type=media,headers=headers)

@app.get('/health')
def health(): return {'status':'ok','version':'0.6.1b1'}

@app.post('/v1/analyze')
async def analyze_endpoint(request:Request):
    try:
        payload=await request.json()
        if not isinstance(payload,dict): raise ValueError('JSON object required')
        if payload.get('browser'): raise ValueError('active browser observation is not enabled on the public endpoint')
        context=payload.pop('context',None)
        if context is not None and len(json.dumps(context,ensure_ascii=False,allow_nan=False).encode())>65536: raise HTTPException(413,'context limit exceeded')
        if not isinstance(payload.get('text'),str): raise ValueError('text must be a string')
        if len(payload['text'])>MAX_PUBLIC_CHARS: raise HTTPException(413,'public text limit exceeded')
        return await _run_bounded(lambda: response(attach(analyze_request(payload),context=context),payload.get('format','json')))
    except HTTPException: raise
    except EvidenceLimitError as exc: raise HTTPException(413,str(exc)) from exc
    except (ValueError,TypeError,UnicodeError) as exc: raise HTTPException(400,'invalid assurance input') from exc

@app.post('/v1/upload')
async def upload_endpoint(file:UploadFile=File(...),format:str='json'):
    try:
        data=await file.read(MAX_BYTES+1)
        if len(data)>MAX_BYTES: raise HTTPException(413,'file too large')
        def process_upload():
            if (file.filename or '').lower().endswith(('.pdf','.docx','.xlsx','.pptx')) or data.startswith((b'%PDF-',b'PK\x03\x04')):
                report=extract_document(data,filename=file.filename or 'evidence.bin')
            else:
                report=acquire_bytes(data,filename=file.filename or 'evidence.bin',content_type=file.content_type)
            return response(report,format)
        return await _run_bounded(process_upload)
    except HTTPException: raise
    except RuntimeError as exc: raise HTTPException(503,'required isolated observer unavailable') from exc
    except EvidenceLimitError as exc: raise HTTPException(413,str(exc)) from exc
    except (ValueError,TypeError,UnicodeError) as exc: raise HTTPException(400,'invalid assurance input') from exc
    finally: await file.close()

@app.get('/',response_class=HTMLResponse)
def home():
    from pathlib import Path
    return HTMLResponse(Path(__file__).with_name('web').joinpath('index.html').read_text(encoding='utf-8'),headers={'Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'",'X-Content-Type-Options':'nosniff','Cache-Control':'no-store'})

@app.post('/v1/export/{format}')
async def export_endpoint(format:str,request:Request):
    from .receipt import verify
    try:
        report=await request.json()
    except (ValueError,UnicodeError) as exc:
        raise HTTPException(400,'invalid report JSON') from exc
    if not isinstance(report,dict): raise HTTPException(400,'report must be an object')
    if not verify(report): raise HTTPException(400,'report receipt integrity failed')
    if format not in {'html','sarif','pdf'}: raise HTTPException(400,'unsupported format')
    return await _run_bounded(response,report,format)
