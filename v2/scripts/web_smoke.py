#!/usr/bin/env python3
"""Production static Web UI against real isolated backend/PG; private browser inputs."""
import http.client,http.server,json,os,ssl,subprocess,threading,urllib.parse
from machine_smoke import main as machine_harness,freeport
from dev import ROOT
POLICY="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
def browser_scenario(**s):
 context=ssl.create_default_context(cafile=s['ca_file']);port=urllib.parse.urlsplit(s['origin']).port
 class Handler(http.server.SimpleHTTPRequestHandler):
  def __init__(self,*args,**kwargs):super().__init__(*args,directory=str(ROOT/'web/dist'),**kwargs)
  def log_message(self,*args):pass
  def end_headers(self):self.send_header('Content-Security-Policy',POLICY);self.send_header('Cache-Control','no-store');super().end_headers()
  def dispatch(self):
   if self.path.startswith('/api/') or self.path.startswith('/health/'):
    length=int(self.headers.get('Content-Length','0'))
    if length>1048576:self.send_error(413);return
    body=self.rfile.read(length);headers={k:v for k,v in self.headers.items() if k.lower() not in ('host','connection','content-length')};connection=http.client.HTTPSConnection('127.0.0.1',s['center_port'],context=context,timeout=20)
    try:
     connection.request(self.command,self.path,body=body,headers=headers);response=connection.getresponse();raw=response.read();self.send_response(response.status)
     for key,value in response.getheaders():
      if key.lower() not in ('connection','content-length','transfer-encoding'):self.send_header(key,value)
     self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    finally:connection.close()
   elif self.path=='/contracts/openapi.json':
    raw=(ROOT/'.dist/contracts/openapi.json').read_bytes();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
   elif self.command=='GET':super().do_GET()
   else:self.send_error(405)
  do_GET=dispatch
  do_POST=dispatch
  do_DELETE=dispatch
 server=http.server.ThreadingHTTPServer(('127.0.0.1',port),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();path=s['directory']/'browser-input.json';fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
 with os.fdopen(fd,'w') as f:json.dump({k:s[k] for k in ('origin','username','password','asset')},f)
 try:
  env=dict(os.environ);env.setdefault('PLAYWRIGHT_BROWSERS_PATH','/workspace/.cache/surveyscan-browsers');subprocess.run(['node','scripts/smoke.mjs',str(path)],cwd=ROOT/'web',env=env,check=True,timeout=80)
 finally:server.shutdown();server.server_close();thread.join(timeout=5)
if __name__=='__main__':machine_harness(web_scenario=browser_scenario,browser_origin=f'http://127.0.0.1:{freeport()}')
