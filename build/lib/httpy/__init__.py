#  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
#  APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
#  HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
#  OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
#  THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#  PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
#  IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
#  ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

import socket
import os
import re
import ssl
import io
import warnings
import gzip
import zlib
try:
    import chardet
except ImportError:
    chardet=None
import json
import sys
import random
import string
import mimetypes
import pathlib
import math
import base64
import email.utils
import datetime
import time
import ctypes

HTTPY_DIR=pathlib.Path.home()/'.cache/httpy'
os.makedirs(HTTPY_DIR/'sites',exist_ok=True)
version='1.0.3'
urlpattern=re.compile('^(?P<scheme>[a-z]+)://(?P<host>[^/:]*)(:(?P<port>(\d+)?))?/?(?P<path>.*)$')
statuspattern=re.compile(br'(?P<version>.*)\s*(?P<status>\d{3})\s*(?P<reason>[^\r\n]*)')
context=ssl.create_default_context()
schemes={'http':80,'https':443}
class HTTPyError(Exception):
    '''A metaclass for all HTTPy Exceptions.'''
class ServerError(HTTPyError):
    '''Raised if server is not found'''
class TooManyRedirectsError(HTTPyError):
    '''Raised if server has responded with too many redirects (over redirection limit)'''
def _mk2l(l):
    if len(l)==1:
        l.append(True)
    return l
class Status:
    '''
    Creates HTTP status from string.

    :param statstring: string to parse
    '''
    def __init__(self,statstring):
        _,self.status,self.reason=statuspattern.search(statstring).groups()
        self.status=int(self.status)
        self.reason=self.reason.decode()
class CaseInsensitiveDict(dict):
    def __init__(self,data):
        self.original={force_string(k).lower():v for k,v in dict(data).items()}
        super().__init__(self.original)
    def __contains__(self,item):
        return force_string(item).lower() in self.original
    def __getitem__(self,item):
        return self.original[force_string(item).lower()]
    def __setitem__(self,item,val):
        self.original[force_string(item).lower()]=val
        super().__init__(self.original)#remake??
    def get(self,key,default=None):
        if key in self:
            return self[key]
        return default
    def __iter__(self):
        return iter(self.original)
    def keys(self):
        return self.original.keys()
    def values(self):
        return self.original.values()
    def items(self):
        return self.original.items()
def _binappendstr(s):
    return bytes([len(s)])+force_bytes(s)
def _binappendint(b):
    b=int(b)
    ba=int(b).to_bytes(math.ceil(b.bit_length()/8),'little')
    return bytes([len(ba)])+ba
class ETag:
    '''Class for HTTP ETags'''
    def __init__(self,s):
        self.weak=False
        if s.startswith('W/')or s.startswith('w/'):
            self.weak=True
        self.etag=s.replace('"','')
    def __eq__(self,e):
        return self.etag==e.etag
    def __str__(self):
        if self.weak:
            return f'W/"{self.etag}"'
        return f'"{self.etag}"'

    def add_header(self,headers):
        '''Appends this ETag in If-None-Match header.'''
        if 'If-None-Match' in headers:
            headers['If-None-Match']+=', '+str(self)
        else:
            headers['If-None-Match']=str(self)
class CacheControl():
    '''Class for parsing Cache-Control HTTP Headers'''
    def __init__(self,directives):
        d= [_mk2l(x.split('=')) for x in directives.split(',')]

        self.directives=CaseInsensitiveDict(d)
        if 'max-age' in self.directives:
            self.max_age=int(self.directives['max-age'])
            self.cache=True
        elif 'no-cache' in self.directives:
            self.cache=False
            self.max_age=0
        else:
            self.max_age=0
            self.cache=True
class CacheFile():
    '''HTTPy cache file parser'''
    def __init__(self,f):
        self.src=f
        file=gzip.GzipFile(f,'rb')
        tml=ord(file.read(1))
        self.time_cached=int.from_bytes(file.read(tml),'little')
        srl=ord(file.read(1))
        sl=file.read(srl)
        self.status=Status(sl)
        self.url=os.path.split(f)[-1].replace('\x01','://').replace('\x02','/')
        self.content=file.read()
        file.close()
        self.headers,self.body=self.content.split(b'\x00')
        self.headers=Headers(self.headers.split(b'\r'))
        self.age=0
        self.etag=None
        self.last_modified=None
        if 'ETag' in self.headers:
            self.etag=ETag(self.headers['ETag'])
        if 'last-modified' in self.headers:
            self.last_modified=self.headers['Last-Modified']
        if 'Age' in self.headers:
            self.age=int(self.headers['Age'])
        self.time_generated=self.time_cached-self.age
        if 'Cache-Control' in self.headers:
            self.cache_control=CacheControl(self.headers['Cache-Control'])
        else:
            self.cache_control=CacheControl('no-cache')
    @property
    def expired(self):
        return time.time()-self.time_generated>self.cache_control.max_age
    def __repr__(self):
        return f'<CacheFile {self.url!r}>'
    def add_header(self,headers):
        '''
        Adds If-None-Match and If-Modified-Since headers to request.

        :param  headers: Headers to add into
        '''
        if self.etag:
            self.etag.add_header(headers)
        if self.last_modified:
            headers['if-modified-since']=self.last_modified


class Cache():
    '''
    Cache Class
    '''
    def __init__(self,d=HTTPY_DIR/'sites'):
        self.dir=d
        self.files=[CacheFile(os.path.join(d,i)) for i in os.listdir(d)]
    def updateCache(self):
        '''Updates self.files according to /sites directory content and removes expired ones'''
        for file in self.files:
            if file.expired:
                os.remove(os.path.join(self.dir,file.url.replace('://','\x01').replace('/','\x02')))
        self.files=[CacheFile(os.path.join(self.dir,i)) for i in os.listdir(self.dir)]
    def __getitem__(self,u):
        for f in self.files:
            if reslash(f.url)==reslash(u):
                return f
        return None
    def __contains__(self,u):
        return self[u] is not None

class Cookie:
    '''
    Class for HTTP Cookies
    '''
    def __init__(self,name,value,attributes,host):
        self.name,self.value=name,value
        self.attributes=CaseInsensitiveDict(attributes)
        self.secure='Secure' in self.attributes
        self.expires=self.attributes.get('Expires',None)
        if self.expires is not None:
            if isinstance(self.expires,str):
                self.expires=email.utils.parsedate_to_datetime(self.expires)
            else:
                self.expires=datetime.datetime.fromtimestamp(self.expires)
        self.path=self.attributes.get('Path','/')
        self.host=self.attributes.get('domain',host)
        self._host=host
        self.samesite=self.attributes.get('samesite','lax').lower()
    @property
    def expired(self):
        '''Checks if Cookie expired'''
        if self.expires is None:
            return False
        return time.time()>=self.expires.timestamp()
    def to_binary(self):
        '''Converts Cookie to binary representation'''
        data=_binappendstr(self.name+'='+self.value)
        if self.host==self._host:
            data+=b'\x00'
        else:
            data+=_binappendstr(self.host)
        data+=_binappendstr(self.path)
        

        if self.secure:
            data+=b'\x01'
        if self.expires:
            b=self.expires.timestamp()
            data+=_binappendint(b)
        else:
            data+=b'\x00'
        return data
    @classmethod
    def from_header(self,header,host):
        '''Parses Cookie header'''
        n=header.split(';')
        f=n[0].split('=',1)
        if '' in n:
            n.remove('')
        attrs=(_mk2l([a.strip() for a in i.split('=')]) for i in n[1:])
        return Cookie(*f,attrs,host)
    def as_header(self):
        '''Returns Set-Cookie Header'''
        return self.name+'='+self.value
    @classmethod
    def from_binary(self,binary,host):
        '''Makes Cookie from binary representation'''
        buffer=io.BytesIO(binary)
        kvpl=ord(buffer.read(1))
        k,v=buffer.read(kvpl).split(b'=',1)
        hostl=ord(buffer.read(1))
        data={}
        if hostl>0:
            data['Host']=buffer.read(hostl).decode()
        pl=buffer.read(1)
        p=buffer.read(ord(pl))
        data['Path']=p
        n=buffer.read(1)
        if n==b'\x01':
            data['Secure']=True
            n=buffer.read(1)
        if n==b'\x00':
            expires=None
        else:
            b64tstamp=buffer.read(ord(n))
            expires=int.from_bytes(b64tstamp,'little')
            data['Expires']=expires
        return Cookie(k.decode(),v.decode(),data,host)       



class CookieDomain:
    'Class for domain storing cookies'
    def __init__(self,content,jar):
        self.content=content
        bio=io.BytesIO(content)
        nl=ord(bio.read(1))
        self.jar=jar
        self.name=bio.read(nl).decode()
        self.cookies=[]
        for co in bio.read().split(b'\xfe'):
            if co:
                self.cookies.append( Cookie.from_binary(co,self.name))

    def as_binary(self):
        '''Returns binary representation for domain'''
        self.check_expired()
        return _binappendstr(self.name)+b'\xfe'.join([cook.to_binary() for cook in self.cookies])
    def __delitem__(self,key):
        for ix,i in enumerate(self.cookies):
            if i.name==key:
                del self.cookies[ix]
        

    def delete_cookie(self,key):
        ''' Deletes cookie from domain '''
        del self[key]
        self.jar.update()
    def add_cookie(self,header):
        '''Adds cookie from header to domain'''
        ck=Cookie.from_header(header,self.name)
        self.delete_cookie(ck.name)
        self.cookies.append(ck)
        self.check_expired()
        self.jar.update()
    def check_expired(self):
        '''Checks for expired cookies and deletes them'''
        new_cookies=[]
        for c in self.cookies:
            if not c.expired:
                new_cookies.append(c)
            else:
                del c
        self.cookies=new_cookies
    def __getitem__(self,name):
        for cookie in self.cookies:
            if cookie.name==name:
                return cookie
    def __repr__(self):
        return f'<CookieDomain {self.name!r}>'
class CookieJar:
    '''Class for cookie jar'''
    def __init__(self,jarfile=HTTPY_DIR/'CookieJar'):
        try:
            self.jarfile=open(jarfile,'rb')
            self.domains=[]
            for dom in self.jarfile.read().split(b'\xff'):
                if dom:
                    self.domains.append(CookieDomain(dom,self))
        except FileNotFoundError:
            self.jarfile=open(jarfile,'wb')
            self.jarfile.close()
            self.jarfile=open(jarfile,'rb')

            self.domains=[]
        self.jarfile.close()
    def __contains__(self,host):
        for dom in self.domains:
            if host.endswith(dom.name):
                return True
        return False
    def __getitem__(self,item):
        doms=[]
        for dom in self.domains:
            if item.endswith(dom.name):
                doms.append(dom)
        return doms
    def add_domain(self,name):
        '''Adds domain to jar'''
        self.domains.append(CookieDomain(_binappendstr(name),self))
    def update(self):
        '''Updates jar file with domains'''
        with open(self.jarfile.name,'wb') as f:
            f.write(b'\xff'.join(dom.as_binary() for dom in self.domains))
            f.close()

    def get_cookies(self,host,scheme,path):
        '''Gets cookies for request'''
        if host not in self:
            return []
        data=[]
        for domain in self[host]:
            print(domain)
            for cookie in domain.cookies:
                print(cookie)
                if not(cookie.secure and scheme=='http'):
                    if reslash(path).startswith(reslash(cookie.path)):
                        data.append(cookie)
                        print('ok')
                       
        return data

        
class File(io.IOBase):
    '''Class for file used to upload files'''
    def __init__(self,buffer,filename,content_type=None):
        if content_type is None:
            content_type=force_string(mimetypes.guess_type(os.path.split(filename)[1])[0])
        content_type=force_string(content_type)

        self.size=len(buffer)
        self.buffer=io.BytesIO(buffer)

        self.name=force_string(os.path.split(filename)[1])
        self.mode='rb'
        self.content_type=content_type
    def read(self,size=-1):
        return self.buffer.read(size)
    def save(self,destination):
        if os.path.exists(destination):
            if os.path.isdir(destination):
                destination=os.path.join(destination,self.name)
                
        return open(destination,'wb').write(self.buffer.getvalue())
    def seek(self,pos):
        self.buffer.seek(pos)
    def tell(self):
        return self.buffer.tell()
    def write(self,anything):
        raise(io.UnsupportedOperation('not writable'))
    def value(self):
        return self.buffer.getvalue()
    @classmethod
    def open(self,file):
        reader=open(file,'rb')
        return File(reader.read(),file)
class Headers():
    '''Class for Headers'''
    def __init__(self,h):
        self.headers=([a.split(b': ',1)[0].lower().decode(),a.split(b': ',1)[1].decode().strip()] for a in h)
        self.headers=mkdict(self.headers)
    def __getitem__(self,item):
        if isinstance(item,bytes):
            item=item.decode()
        return self.headers[item.lower()]
    def __contains__(self,item):
        if isinstance(item,bytes):
            item=item.decode()
        item=item.lower()
        return item in self.headers
    def get(self,key,default=None):
        if isinstance(key,bytes):
            key=key.decode()
        key=key.lower()
        if key in self:
            return self[key]
        return default
    def __iter__(self):
        return iter(self.headers)
    def __setitem__(self,item,value):
        raise NotImplementedError

class Response:
    '''
    Class for HTTP Response.

    :param status: status returned by server
    :type status: Status
    :ivar status: status returned by server
    :param headers: headers attached to the document
    :type headers: Headers
    :ivar headers: headers attached to the document
    :param content: Document content
    :type content: bytes
    :ivar content: Document content
    :param history: response history
    :type history: list
    :ivar history: response history
    :param fromcache: Indicates if response was loaded from cache
    :type fromcache: bool
    :ivar fromcache: Indicates if response was loaded from cache
    :ivar charset: Document charset
    '''
    def __init__(self,status,headers,content,history,url,fromcache):
        self.status=status.status
        self.reason=status.reason
        self.headers=headers
        self.content=content
        self.url=reslash(url)
        self.fromcache=fromcache
        if not self.fromcache:
            cacheWrite(self)

        self.charset=determine_charset(headers)
        if self.charset is None and chardet is not None:
            self.charset=chardet.detect(content)['encoding']
        self.history=history
        self.history.append(self)
    @classmethod
    def cacheload(self,cf):
        '''Loads Response from cache'''
        return Response(cf.status,cf.headers,cf.content,[],cf.url,True) 
    def __repr__(self):
        return f'<Response [{self.status} {self.reason}] ({self.url})>'
def cacheWrite(response):
    '''
    Writes response to cache

    :param response: response to save
    :type response: Response'''
    data=b''
    data+=_binappendint(round(time.time()))
    data+=_binappendstr(f'{response.status} {response.reason}')
    data+='\r'.join([mkHeader(i)for i in response.headers.headers.items()]).encode()
    data+=b'\x00'
    data+=response.content

    open(HTTPY_DIR/'sites'/response.url.replace('://','\x01').replace('/','\x02'),'wb').write(gzip.compress(data))
def mkdict(kvp):
    '''Makes dict from key/value pairs'''
    d={}
    for k,v in kvp:
        k=k.lower()
        if k in d:
            if isinstance(d[k],list):
                d[k].append(v)
            else:
                d[k]=[d[k]]+[v]
        else:
            d[k]=v
    return d
def urlencode(data):
    '''As urllib.parse.urlencode'''
    return b'&'.join(b'='.join(force_bytes(i) for i in x) for x in data.items())
def _gzip_decompress(data):
    return gzip.GzipFile(fileobj=io.BytesIO(data)).read()
def _zlib_decompress(data):
    return zlib.decompress(data,-zlib.MAX_WBITS)
def _generate_boundary():
    return b'--'+''.join(random.choices(string.ascii_letters+string.digits,k=10)).encode()+b'\r\n'
def force_string(anything):
    '''Converts string or bytes to string'''
    if isinstance(anything,str):
        return anything
    elif isinstance(anything,bytes):
        return anything.decode()
    else:
        return str(anything)
def force_bytes(anything):
    '''Converts bytes or string to bytes'''
    if isinstance(anything,bytes):
        return anything
    elif isinstance(anything,str):
        return anything.encode()
    elif isinstance(anything,int):
        return force_bytes(str(anything))
    else:
        return bytes(anything)

def get_content_type(data):
    '''Used to automatically get request content type'''
    if isinstance(data,bytes):
        return 'application/octet-stream'
    elif isinstance(data,str):
        return 'text/plain'
    elif isinstance(data,dict):
        for x in data.values():
            if isinstance(x,File):
                return 'multipart/form-data'
        return 'application/x-www-form-urlencoded'
    raise TypeError("could not get content type(can encode only bytes,str and dict). Please specify raw data and set content_type argument")
def multipart(form,boundary=_generate_boundary()):
    '''Builds multipart/form-data from form'''
    built=b''
    for i in form.items():
        built+=boundary
        disp=b'Content-Disposition: form-data; name="'+force_bytes(i[0])+b'"'
        val=i[1]
        if isinstance(val,File):
            disp+=b'; filename="'+force_bytes(val.name)+b'"'
            val=val.read()
        disp+=b'\r\n\r\n'
        val=force_bytes(val)
        disp+=val
        disp+=b'\r\n'
        built+=disp
    built+=boundary.strip()+b'--\r\n'
    return built,'multipart/form-data; boundary='+boundary[2:].strip().decode()




def _encode_form_data(data,content_type=None):
    if content_type==None:
        content_type=get_content_type(data)
    if content_type in ('text/plain','application/octet-stream'):
        return force_bytes(data),content_type
    elif content_type == 'application/x-www-form-urlencoded':
        return urlencode(data),content_type
    elif content_type == 'multipart/form-data':
        return multipart(data)
    elif content_type == 'application/json':
        return json.dumps(data).encode(),content_type
    return force_bytes(data)
def encode_form_data(data,content_type=None):
    '''Encodes form data according to content type'''
    encoded,content_type=_encode_form_data(data,content_type)
    return force_bytes(encoded),{'Content-Type':content_type,'Content-Length':len(encoded)}

def determine_charset(headers):
    '''Gets charset from headers'''
    if 'Content-Type' in headers:
        charset=headers['Content-Type'].split(';')[-1].strip()
        if not charset.startswith('charset'):
            return None
        return charset.split('=')[-1].strip()
    return None
def chain_functions(funs):
    '''Chains functions . Called by get_encoding_chain()'''
    def chained(r):
        for fun in funs:
            r=fun(r)
        return r
    return chained
def get_encoding_chain(encoding):
    '''Gets decoding chain from Content-Encoding'''
    encds=encoding.split(',')
    return chain_functions(
            encodings[enc.strip()] for enc in encds
            )

def decode_content(content,encoding):
    '''Decodes content with get_encoding_chain()'''
    try:
        return get_encoding_chain(encoding)(content)
    except:
        return content
def makehost(host,port):
    '''Creates hostname from host and port'''

    if int(port) in [443,80]:
        return host
    return host+':'+str(port)
def reslash(url):
    '''Adds trailing slash to the end of URL'''
    url=force_string(url)
    if url.endswith('/'):
        return url
    return url+'/'
def deslash(url):
    '''Removes trailing slash from the end of URL'''
    url=force_string(url)
    if url.endswith('/'):
        return url[:-1]
    return url
def mkHeader(i):
    '''Makes header from key/value pair'''
    if isinstance(i[1],list):
        d=''
        for x in i[1]:
            d+=i[0]+': '+x+'\r\n'
        return d.strip()
    return ': '.join([str(h) for h in i])
def _debugprint(debug,*args,**kwargs):
    if debug:
        print(*args,**kwargs)
def _raw_request(host,port,path,scheme,url='',method='GET',data=b'',content_type=None,timeout=32,headers={},auth={},history=[],debug=False):
    cf=cache[deslash(url)]
    socket.setdefaulttimeout(timeout)
    if cf and not cf.expired:
        return Response.cacheload(cf)
    defhdr={'Accept-Encoding':'gzip, deflate, identity','Host':makehost(host,port),'User-Agent':'httpy/'+version,'Connection':'keep-alive'}
    if data:
        data,cth=encode_form_data(data,content_type)
        defhdr.update(cth)
    if auth:
        c=next(iter(auth.items()))
        defhdr['Authorization']=b'Basic '+base64.b64encode(':'.join(c).encode())
    cookies=jar.get_cookies(makehost(host,port),scheme,path)
    if cookies:
        defhdr['Cookie']=[]
        for c in cookies:
            defhdr['Cookie'].append(c.name+'='+c.value)
            
    defhdr.update(headers)
    try:
        sock=socket.create_connection((host,port))
    except socket.gaierror:
        #Get errno using ctypes, check for  -2
        errno=ctypes.c_int.in_dll(ctypes.pythonapi,"errno").value
        if errno==2:
            raise ServerError(
            f"could not find server {host!r}"
            )
    
    try:
        if scheme=='https':
            sock=context.wrap_socket(sock,server_hostname=host)
        
        defhdr.update(headers)
        if cf:
            cf.add_header(defhdr)
        headers='\r\n'.join([mkHeader(i)for i in defhdr.items()])
        request_data=f"{method} {path} HTTP/1.1"+'\r\n'
        request_data+=headers
        _debugprint(debug,"\nsend:\n"+request_data)
        request_data+='\r\n\r\n'
        request_data=request_data.encode() 
        sock.send(request_data)
        sock.send(data)
        file=sock.makefile('b')
        statusline=file.readline()
        status=Status(statusline)
        _debugprint(debug,"\nresponse: ")
        _debugprint(debug,statusline.decode())
        if status.status==304:
            return Response.cacheload(cf)
        headers=[]
        while True:
            line=file.readline()
            if line==b'\r\n':
                break
            _debugprint(debug,line.decode(),end='')
            headers.append(line)
        headers=Headers(headers)
        if 'set-cookie' in headers:
            cookie=headers['set-cookie']
            h=makehost(host,port)
            if h not in jar:
                jar.add_domain(h)
            domain=jar[h][0]
            if isinstance(cookie,list):
                for c in cookie:
                    domain.add_cookie(c)
            else:
                domain.add_cookie(cookie)
        body=b''
        chunked=headers.get('transfer-encoding','').strip()=='chunked'
        if not chunked:
            cl=int(headers.get('content-length',-1))
            if cl==-1:
                warnings.warn('no content-length nor transfer-encoding, setting socket timeout')
                sock.settimeout(0.5)
                while True:
                    try:
                        b=file.read(1)# recv 1 byte
                        if not b:
                            break
                    except socket.timeout: #end of response??
                        break
                    body+=b
            else:
                body=file.read(cl)#recv <content-length> bytes
        else: #chunked read
            while True:
                chunksize=int(file.readline().strip(),base=16)#get chunk size
                if chunksize==0: #final byte
                    break
                chunk=file.read(chunksize)
                file.read(2)#discard CLRF
                body+=chunk
    finally:
        sock.close()
    content_encoding=headers.get('content-encoding','identity')
    body=decode_content(body,content_encoding)
    return Response(status,headers,body,history,url,False)
        

def request(url,method='GET',headers={},body=b'',auth={},redirlimit=20,content_type=None,timeout=30,history=None,debug=False):
    '''
    Performs request.

    :param url: url to request
    :type url: ``str``
    :param method: method to use, defaults to ``"GET"``
    :type method: ``str``
    :param headers: headers to add to the request, defaults to ``{}``
    :type headers: ``dict``
    :param body: request body, can be ``bytes`` , ``str`` or  ``dict``, defaults to ``b''``
    :param auth: credentials to use (``{"username":"password"}``), defaults to ``{}``
    :type auth: ``dict``
    :param redirlimit: redirect limit . If number of redirects has reached ``redirlimit``, ``TooManyRedirectsError`` will be raised. Defaults to ``20``.
    :type redirlimit: ``int``
    :param content_type: Content type of request body, defaults to ``None``
    :param timeout: Request timeout, defaults to ``30``
    :type timeout: ``int``
    :param history: Request history, defaults to ``None``
    :param debug: Use debug mode, defaults to ``False``
    :type debug: ``bool``
    '''
    if history is None:
        history=[]
    if isinstance(url,bytes):
        url=url.decode()
    dt=urlpattern.search(url)
    if dt is None:
        raise ValueError('Invalid URL')
    gp=dt.groupdict()
    if 'path' not in gp:
        gp['path']='/'
    scheme=gp['scheme']
    path=gp['path']
    host=gp['host']

    if scheme not in schemes:
        raise ValueError('Invalid scheme')
    if 'port' in gp:
        port=gp['port']
    else:
        port=schemes[scheme]
    if port is None:
        port=schemes[scheme]
    resp=_raw_request(host,port,'/'+path,scheme,url=url,history=history,auth=auth,data=body,method=method,headers=headers,timeout=timeout,content_type=content_type,debug=debug)
    if 300<=resp.status<400:
        if len(history)==redirlimit:
            raise TooManyRedirectsError('too many redirects')
        if 'Location' in resp.headers:
            return request(resp.headers['Location'],auth=auth,redirlimit=redirlimit,timeout=timeout,body=body,headers=headers,content_type=content_type,history=resp.history,debug=debug)
    return resp
encodings={'identity':lambda x:x,'deflate':_zlib_decompress,'gzip':_gzip_decompress}
jar=CookieJar()
cache=Cache()
__version__=version
__author__='Adam Jenca'

