"""Best-effort diagnostics even after Gradle/emulator runner failure. No private fixtures."""
import argparse, os, subprocess, json, hashlib
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
meta={k:os.getenv(k) for k in ('GITHUB_SHA','GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','RUNNER_OS','RUNNER_ARCH')}
for name,args in [('adb-devices',['adb','devices','-l']),('sdk-packages',['sdkmanager','--list_installed']),('java',['java','-version']),('last-logcat',['adb','logcat','-d','-v','threadtime'])]:
 try:
  r=subprocess.run(args,capture_output=True,timeout=15);(a.out/(name+'.txt')).write_bytes(r.stdout+r.stderr)
 except Exception as e:(a.out/(name+'.txt')).write_text(str(e))
meta['apk_sha256']={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (a.out/'apk').glob('*.apk')}
(a.out/'provenance.json').write_text(json.dumps(meta,indent=2))
