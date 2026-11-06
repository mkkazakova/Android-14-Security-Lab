"""Generate disposable fixtures; never commit .lab-secrets. Python 3.10+."""
from pathlib import Path
from datetime import datetime, timedelta, timezone
import ipaddress, json, subprocess, uuid
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
ROOT=Path(__file__).resolve().parents[1]
SECRETS=ROOT/'.lab-secrets'

def fixtures(dest):
    dest.mkdir(parents=True,exist_ok=True)
    now=datetime.now(timezone.utc)
    def key(): return rsa.generate_private_key(public_exponent=65537,key_size=2048)
    def name(s): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,s)])
    def cert(subject,issuer,pub,signer,ca=False,san=None):
        b=(x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer)).public_key(pub)
           .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=7))
           .add_extension(x509.BasicConstraints(ca=ca,path_length=0 if ca else None),critical=True))
        if san:b=b.add_extension(x509.SubjectAlternativeName(san),critical=False)
        return b.sign(signer,hashes.SHA256())
    cak=key();ca=cert('ASL ephemeral CA','ASL ephemeral CA',cak.public_key(),cak,True)
    otherk=key();other=cert('ASL foreign CA','ASL foreign CA',otherk.public_key(),otherk,True)
    (dest/'ca.pem').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for label,issuer,signer,san in [('trusted','ASL ephemeral CA',cak,[x509.IPAddress(ipaddress.ip_address('10.0.2.2'))]),('foreign','ASL foreign CA',otherk,[x509.IPAddress(ipaddress.ip_address('10.0.2.2'))]),('wrongname','ASL ephemeral CA',cak,[x509.DNSName('wrong.invalid')])]:
        k=key();c=cert(label,issuer,k.public_key(),signer,san=san)
        (dest/f'{label}.pem').write_bytes(c.public_bytes(serialization.Encoding.PEM)+(ca if label!='foreign' else other).public_bytes(serialization.Encoding.PEM))
        (dest/f'{label}.key').write_bytes(k.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (dest/'fixture.json').write_text(json.dumps({'nonce':str(uuid.uuid4()),'generated_utc':now.isoformat()}))

def main():
    if (SECRETS/'fixture.json').exists(): raise SystemExit('Fixtures already exist. Remove .lab-secrets to start a NEW run; do not regenerate between APK builds.')
    fixtures(SECRETS)
    raw=SECRETS/'generated-res/raw';raw.mkdir(parents=True)
    (raw/'lab_ca.pem').write_bytes((SECRETS/'ca.pem').read_bytes())
    for signer in ('a','b'):
        subprocess.run(['keytool','-genkeypair','-noprompt','-keystore',str(SECRETS/f'{signer}.p12'),'-storetype','PKCS12','-alias','lab','-storepass','laboratory-only','-keypass','laboratory-only','-keyalg','RSA','-keysize','2048','-validity','7','-dname',f'CN=Disposable laboratory signer {signer}'],check=True,capture_output=True)
    print('Generated disposable CA, TLS fixtures and two independent APK signers.')
if __name__=='__main__': main()
