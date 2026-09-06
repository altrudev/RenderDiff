"""Bounded public-URL acquisition with pinned DNS and no proxy use.

Network policy is defense in depth, not an OS sandbox. Public service operators must
also enforce egress isolation. No cookies, credentials, scripts or redirects to private
addresses are accepted.
"""
from __future__ import annotations
import hashlib, http.client, ipaddress, socket, ssl, urllib.parse

MAX_REDIRECTS=3

def _target(url):
    parsed=urllib.parse.urlsplit(url)
    if parsed.scheme not in {'https','http'} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError('only public HTTP(S) URLs without credentials are permitted')
    host=parsed.hostname
    if '%' in host:raise ValueError('IP zone identifiers are not permitted')
    try:host=host.encode('idna').decode('ascii')
    except UnicodeError as exc:raise ValueError('invalid hostname') from exc
    port=parsed.port or (443 if parsed.scheme=='https' else 80)
    if port not in {80,443}:raise ValueError('only standard HTTP(S) ports are permitted')
    addresses=socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)
    if not addresses:raise ValueError('DNS returned no addresses')
    ips=sorted({entry[4][0] for entry in addresses})
    if any(not ipaddress.ip_address(ip).is_global for ip in ips):raise ValueError('URL resolves to a non-public address')
    return parsed,host,port,ips[0]

def pinned_public_fetch(url,max_bytes=4_000_000,*,timeout=8):
    if not isinstance(url,str) or len(url)>4096:raise ValueError('invalid URL')
    if not 0<max_bytes<=4_000_000:raise ValueError('invalid download limit')
    history=[];current=url
    for _ in range(MAX_REDIRECTS+1):
        parsed,host,port,ip=_target(current)
        if parsed.scheme=='https':
            connection=http.client.HTTPSConnection(host,port,timeout=timeout,context=ssl.create_default_context())
            context=connection._context
            def connect():
                sock=socket.create_connection((ip,port),timeout=timeout)
                connection.sock=context.wrap_socket(sock,server_hostname=host)
            connection.connect=connect
        else:
            connection=http.client.HTTPConnection(host,port,timeout=timeout)
            connection.connect=lambda: setattr(connection,'sock',socket.create_connection((ip,port),timeout=timeout))
        path=urllib.parse.urlunsplit(('', '',parsed.path or '/',parsed.query,''))
        try:
            connection.request('GET',path,headers={'Host':host,'Accept-Encoding':'identity','User-Agent':'RenderDiff/0.5','Connection':'close'})
            response=connection.getresponse()
            if response.status in {301,302,303,307,308}:
                location=response.getheader('Location')
                if not location:raise ValueError('redirect missing Location')
                history.append({'url':current,'status':response.status,'resolved_ip':ip})
                current=urllib.parse.urljoin(current,location)
                continue
            if response.status!=200:raise ValueError('HTTP acquisition failed with status '+str(response.status))
            if response.getheader('Content-Encoding','identity').lower()!='identity':raise ValueError('compressed HTTP responses are not supported')
            length=response.getheader('Content-Length')
            if length and int(length)>max_bytes:raise ValueError('download exceeds limit')
            data=response.read(max_bytes+1)
            if len(data)>max_bytes:raise ValueError('download exceeds limit')
            return {'data':data,'content_type':response.getheader('Content-Type','application/octet-stream'),'provenance':{'final_url':current,'resolved_ip':ip,'redirects':history,'status':response.status,'sha256':hashlib.sha256(data).hexdigest(),'acquisition':'pinned-public-http'}}
        finally:connection.close()
    raise ValueError('redirect limit exceeded')
