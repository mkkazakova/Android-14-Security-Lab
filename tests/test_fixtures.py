import sys,tempfile,unittest,ssl,socket,threading,http.server
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import prepare
class FixtureTests(unittest.TestCase):
 def test_ca_and_names_are_independent(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);prepare.fixtures(p);ca=x509.load_pem_x509_certificate((p/'ca.pem').read_bytes())
   for label in ('trusted','wrongname'):
    cert=x509.load_pem_x509_certificate((p/(label+'.pem')).read_bytes());ca.public_key().verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),hashes.SHA256())
   cert=x509.load_pem_x509_certificate((p/'foreign.pem').read_bytes())
   with self.assertRaises(Exception):ca.public_key().verify(cert.signature,cert.tbs_certificate_bytes,padding.PKCS1v15(),hashes.SHA256())
 def test_real_tls_positive_and_negative_controls(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td);prepare.fixtures(p)
   for label,success in [('trusted',True),('foreign',False),('wrongname',False)]:
    class Handler(http.server.BaseHTTPRequestHandler):
     def do_GET(self):self.send_response(200);self.end_headers();self.wfile.write(b'ok')
     def log_message(self,*args):pass
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(p/(label+'.pem'),p/(label+'.key'));server.socket=ctx.wrap_socket(server.socket,server_side=True)
    t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
    client=ssl.create_default_context(cafile=str(p/'ca.pem'))
    try:
     def connect():
      with socket.create_connection(server.server_address,timeout=3) as sock:
       with client.wrap_socket(sock,server_hostname='10.0.2.2') as tls:
        self.assertIsNotNone(tls.cipher());tls.sendall(b'GET / HTTP/1.0\r\nHost: 10.0.2.2\r\n\r\n');body=b''
        while True:
         block=tls.recv(4096)
         if not block:break
         body+=block
        self.assertIn(b'200 OK',body)
     if success:connect()
     else:
      with self.assertRaises(ssl.SSLCertVerificationError):connect()
    finally:server.shutdown();server.server_close();t.join()
if __name__=='__main__':unittest.main()
