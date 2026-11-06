"""Offline test endpoints on the runner; no external TLS website dependency."""
import http.server, ssl, threading, json, argparse, time
from pathlib import Path

def start(fixtures,log):
    nonce=json.loads((fixtures/'fixture.json').read_text())['nonce']
    lock=threading.Lock()
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body=json.dumps({'server':'ASL fixture','nonce':nonce,'port':self.server.server_port}).encode()
            self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
            with lock:
                with open(log,'a') as f:f.write(json.dumps({'time':time.time(),'port':self.server.server_port,'path':self.path})+'\n')
        def log_message(self,*args): pass
    servers=[]
    try:
        for port,label in [(8080,None),(8443,'trusted'),(8444,'foreign'),(8445,'wrongname')]:
            server=http.server.ThreadingHTTPServer(('0.0.0.0',port),Handler)
            if label:
                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(fixtures/f'{label}.pem',fixtures/f'{label}.key');server.socket=ctx.wrap_socket(server.socket,server_side=True)
            threading.Thread(target=server.serve_forever,daemon=True).start();servers.append(server)
        return servers
    except Exception:
        for s in servers:s.shutdown();s.server_close()
        raise
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--fixtures',type=Path,default=Path('.lab-secrets'));p.add_argument('--log',default='server.jsonl');a=p.parse_args()
    servers=start(a.fixtures,a.log)
    try:
        while True:time.sleep(1)
    except KeyboardInterrupt:
        for s in servers:s.shutdown();s.server_close()
