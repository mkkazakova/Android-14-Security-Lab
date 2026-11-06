"""Validate experiment inputs using Android SDK tools, before launching an AVD."""
import argparse,hashlib,json,os,re,subprocess
from pathlib import Path
EXPECTED={'security-lab.apk':('ru.securitylab.lab',1),'lab-helper.apk':('ru.securitylab.helper',1),'sample-v1-a.apk':('ru.securitylab.sample',1),'sample-v2-a.apk':('ru.securitylab.sample',2),'sample-v2-b.apk':('ru.securitylab.sample',2)}
def inspect(folder,sdk):
 tool=sdk/'build-tools/35.0.0/aapt';records={}
 for name,(package,version) in EXPECTED.items():
  file=folder/name;text=subprocess.check_output([str(tool),'dump','badging',str(file)],text=True)
  actual=re.search(r"package: name='([^']+)' versionCode='(\d+)'",text)
  if not actual or actual.group(1)!=package or int(actual.group(2))!=version:raise RuntimeError('Unexpected APK identity: '+name)
  if "sdkVersion:'34'" not in text or "targetSdkVersion:'34'" not in text:raise RuntimeError('Unexpected SDK policy: '+name)
  # apksigner output differs across Android Build Tools releases:
  # e.g. 'Signer #1 certificate SHA-256 digest: ...' (35.x)
  # and 'V2 Signer: certificate SHA-256 digest: ...' (37.x).
  cert=(folder/(name+'.cert.txt')).read_text()
  m=re.search(r'(?im)^(?:Signer(?:\s+#\d+|\s+\([^)]*\))|V\d+(?:\.\d+)?\s+Signer:?)\s+certificate SHA-256 digest:\s*([0-9a-f]{64})\s*$',cert)
  if not m:raise RuntimeError('Missing verified signing certificate: '+name+'; apksigner output: '+repr(cert[:800]))
  records[name]={'package':package,'version':version,'certificate_sha256':m.group(1),'apk_sha256':hashlib.sha256(file.read_bytes()).hexdigest()}
 if records['sample-v1-a.apk']['certificate_sha256']!=records['sample-v2-a.apk']['certificate_sha256']:raise RuntimeError('Positive update signer changed')
 if records['sample-v1-a.apk']['certificate_sha256']==records['sample-v2-b.apk']['certificate_sha256']:raise RuntimeError('Negative update signer is not independent')
 (folder/'manifest-and-signatures.json').write_text(json.dumps(records,indent=2))
 print('Five APK identities, API 34 policies and update signing controls verified.')
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--apk',type=Path,default=Path('results/apk'));p.add_argument('--sdk',type=Path,default=os.getenv('ANDROID_HOME',os.getenv('ANDROID_SDK_ROOT','')));a=p.parse_args();inspect(a.apk,a.sdk)
