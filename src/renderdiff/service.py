"""Bounded public API. Deploy behind an authenticated, rate-limited reverse proxy."""
from __future__ import annotations
import json, os
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, Response
from .api import analyze_request
from .assurance import attach
from .ingest import acquire_bytes, MAX_BYTES
from .sandbox import extract_document
import asyncio
from .exports import html_report, sarif_report

MAX_PUBLIC_CHARS=64_000
MAX_REPORT_BYTES=8_000_000
app=FastAPI(title='RenderDiff',version='0.5.0b1',docs_url=None,redoc_url=None)
_pool=ThreadPoolExecutor(max_workers=2)

@app.middleware('http')
async def limits(request:Request, call_next):
    if request.method in {'POST','PUT'}:
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
    return await call_next(request)

def response(report,fmt):
    if len(json.dumps(report,ensure_ascii=False,allow_nan=False).encode())>MAX_REPORT_BYTES: raise HTTPException(413,'report amplification limit exceeded')
    if fmt=='json': return JSONResponse(report)
    if fmt=='html': return HTMLResponse(html_report(report),headers={'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'",'X-Content-Type-Options':'nosniff'})
    if fmt=='sarif': return JSONResponse(sarif_report(report))
    if fmt=='pdf':
        from .pdf_report import pdf_report
        return Response(pdf_report(report),media_type='application/pdf',headers={'Content-Disposition':'attachment; filename=renderdiff-report.pdf','X-Content-Type-Options':'nosniff'})
    raise HTTPException(400,'unsupported report format')

@app.get('/health')
def health(): return {'status':'ok','version':'0.5.0b1'}

@app.post('/v1/analyze')
async def analyze_endpoint(request:Request):
    try:
        payload=await request.json()
        if not isinstance(payload,dict): raise ValueError('JSON object required')
        if payload.get('browser'): raise ValueError('active browser observation is not enabled on the public endpoint')
        context=payload.pop('context',None)
        if len(payload.get('text',''))>MAX_PUBLIC_CHARS: raise HTTPException(413,'public text limit exceeded')
        report=await asyncio.to_thread(lambda: attach(analyze_request(payload),context=context))
        return response(report,payload.get('format','json'))
    except HTTPException: raise
    except (ValueError,TypeError,UnicodeError) as exc: raise HTTPException(400,str(exc)) from exc

@app.post('/v1/upload')
async def upload_endpoint(file:UploadFile=File(...),format:str='json'):
    try:
        data=await file.read(MAX_BYTES+1)
        if len(data)>MAX_BYTES: raise HTTPException(413,'file too large')
        if (file.filename or '').lower().endswith(('.pdf','.docx','.xlsx','.pptx')) or data.startswith((b'%PDF-',b'PK\x03\x04')):
            report=await asyncio.to_thread(extract_document,data,filename=file.filename or 'evidence.bin')
        else:
            report=await asyncio.to_thread(acquire_bytes,data,filename=file.filename or 'evidence.bin',content_type=file.content_type)
        return response(report,format)
    except HTTPException: raise
    except RuntimeError as exc: raise HTTPException(503,str(exc)) from exc
    except (ValueError,TypeError,UnicodeError) as exc: raise HTTPException(400,str(exc)) from exc
    finally: await file.close()

@app.get('/',response_class=HTMLResponse)
def home():
    from pathlib import Path
    return HTMLResponse(Path(__file__).with_name('web').joinpath('index.html').read_text(encoding='utf-8'),headers={'Content-Security-Policy':"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'",'X-Content-Type-Options':'nosniff'})

@app.post('/v1/export/{format}')
async def export_endpoint(format:str,request:Request):
    from .receipt import verify
    report=await request.json()
    if not verify(report): raise HTTPException(400,'report receipt integrity failed')
    if format not in {'html','sarif','pdf'}: raise HTTPException(400,'unsupported format')
    return response(report,format)
