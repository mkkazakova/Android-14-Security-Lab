"""Host-side protocol. An infrastructure failure is ERROR, never protection PASS."""
from __future__ import annotations
import argparse, base64, hashlib, json, os, re, secrets, shutil, subprocess, time, traceback, uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from PIL import Image
import server
ROOT=Path(__file__).resolve().parents[1]
LAB='ru.securitylab.lab';HELPER='ru.securitylab.helper';SAMPLE='ru.securitylab.sample'
IDS=['direct_boot','keystore','apk_signature','tapjacking','tls','media_projection']
GROUPS={'credentials':IDS[:2],'standard':IDS[2:]}
class Inconclusive(Exception):pass
class Infrastructure(Exception):pass

def require(condition,message):
    if not condition:raise AssertionError(message)

def pixels(path,kind):
    image=Image.open(path).convert('RGB');p=list(image.getdata())
    if kind=='magenta':n=sum(r>190 and b>190 and g<90 for r,g,b in p)
    elif kind=='cyan':n=sum(g>190 and b>190 and r<100 for r,g,b in p)
    else:raise ValueError(kind)
    return n/len(p)

class Runner:
 def __init__(self,group,out):
    self.group=group;self.out=out;out.mkdir(parents=True,exist_ok=False)
    self.run_id=os.getenv('GITHUB_RUN_ID','local')+'-'+os.getenv('GITHUB_RUN_ATTEMPT','1')+'-'+str(uuid.uuid4())
    self.commit=os.getenv('GITHUB_SHA','unversioned-local');self.results=[];self.case=None;self.pin=None;self.server_error=None
    self.metadata={'run_id':self.run_id,'commit':self.commit,'github_run_id':os.getenv('GITHUB_RUN_ID'),'github_run_attempt':os.getenv('GITHUB_RUN_ATTEMPT'),'group':group,'started_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())}
    self.current=out;self.commands=out/'commands.jsonl'
 def cmd(self,args,timeout=30,check=True,private=False,binary=False):
    try:r=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    except (subprocess.TimeoutExpired,OSError) as e:raise Infrastructure(f'Command could not complete: {args[:2]}: {type(e).__name__}') from e
    if not private:
      with self.commands.open('a') as f:f.write(json.dumps({'time':time.time(),'args':args,'code':r.returncode,'stdout':r.stdout.decode(errors='replace')[:20000] if not binary else f'{len(r.stdout)} bytes','stderr':r.stderr.decode(errors='replace')[:8000]},ensure_ascii=False)+'\n')
    if check and r.returncode:raise Infrastructure(f'Command failed ({r.returncode}): {args[:3]}: {r.stderr.decode(errors="replace")[:300]}')
    return r if binary else r.stdout.decode(errors='replace')+r.stderr.decode(errors='replace')
 def adb(self,*args,**kw):return self.cmd(['adb',*map(str,args)],**kw)
 def save(self,name,value):
    path=self.current/name;path.write_text(value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,indent=2));return str(path.relative_to(self.out))
 def screenshot(self,name):
    result=self.adb('exec-out','screencap','-p',binary=True);path=self.current/(name+'.png');path.write_bytes(result.stdout)
    with Image.open(path) as im:im.verify()
    self.case['images'].append({'path':str(path.relative_to(self.out)),'caption':name,'sha256':hashlib.sha256(result.stdout).hexdigest(),'source':'adb screencap','run_id':self.run_id})
    return path
 def log(self):return self.adb('logcat','-d','-v','raw','-s','ASL:I','*:S')
 def event(self,token,op,timeout=20):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
      chunks={};count=None
      try:lines=self.log().splitlines()
      except Infrastructure:
        time.sleep(.5);continue
      for line in lines:
        prefix=f'ASL_CHUNK:{token}:{op}:'
        if prefix not in line:continue
        try:
          index,total,chunk=line.split(prefix,1)[1].split(':',2)
          chunks[int(index)]=chunk;count=int(total)
          if all(n in chunks for n in range(count)):break
        except (ValueError,IndexError):continue
      if count is not None and all(n in chunks for n in range(count)):
        try:r=json.loads(base64.b64decode(''.join(chunks[n] for n in range(count))))
        except (ValueError,json.JSONDecodeError):raise Infrastructure('Corrupt event in Logcat')
        if r.get('token')==token and r.get('operation')==op:
          self.case['events'].append(r)
          if r['data'].get('operation_error'):raise Infrastructure(f'{op}: {r["data"]}')
          return r['data']
      time.sleep(.5)
    raise Infrastructure(f'No fresh event for {op} within {timeout}s')
 def launch(self,pkg,op,**extras):
    token=uuid.uuid4().hex
    if pkg==HELPER and op in ('snapshot','reuse','capture_stop'):
      args=['shell','am','broadcast','-n',pkg+'/.CommandReceiver','--es','op',op,'--es','token',token]
    else:args=['shell','am','start','-W','-n',pkg+'/.MainActivity','--es','op',op,'--es','token',token]
    for k,v in extras.items():args+=['--ez' if isinstance(v,bool) else '--es',k,str(v).lower() if isinstance(v,bool) else str(v)]
    response=self.adb(*args)
    if 'Error:' in response or 'Exception' in response:raise Infrastructure(response)
    return token
 def call(self,pkg,op,**extras):return self.event(self.launch(pkg,op,**extras),op)
 def dump(self):
    self.adb('shell','uiautomator','dump','/sdcard/asl-window.xml',timeout=20)
    xml=self.adb('shell','cat','/sdcard/asl-window.xml')
    try:return ET.fromstring(xml)
    except ET.ParseError as e:raise Infrastructure('UI hierarchy unavailable') from e
 def center(self,node):
    numbers=list(map(int,re.findall(r'\d+',node.get('bounds',''))))
    if len(numbers)!=4:raise Infrastructure('Missing UI bounds')
    return ((numbers[0]+numbers[2])//2,(numbers[1]+numbers[3])//2)
 def find(self,predicate,timeout=15):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
      try:
       for n in self.dump().iter('node'):
        if predicate(n):return n
      except Infrastructure:pass
      time.sleep(.4)
    raise Infrastructure('Required system UI element not found')
 def tap(self,xy):self.adb('shell','input','tap',*xy);time.sleep(.5)
 def unlock(self,confirmation=False):
    # Enter credentials ONLY in observed Android keyguard/settings UI, never lab UI.
    if not self.pin:raise Infrastructure('No laboratory PIN configured')
    if not confirmation:
      self.adb('shell','input','keyevent','KEYCODE_WAKEUP');self.adb('shell','input','swipe','360','1200','360','250','400');time.sleep(1)
    n=self.find(lambda n:n.get('package') in ('com.android.systemui','com.android.settings') and ('pinEntry' in n.get('resource-id','') or 'password_entry' in n.get('resource-id','') or n.get('class')=='android.widget.EditText'))
    self.tap(self.center(n))
    self.adb('shell','input','text',self.pin,private=True)
    self.adb('shell','input','keyevent','KEYCODE_ENTER',private=True)
    # Some credential screens use a separate Next/Done button.
    time.sleep(1)
    if confirmation:
      try:
       for node in self.dump().iter('node'):
        if node.get('package')=='com.android.settings' and (node.get('resource-id','').endswith('/next_button') or node.get('text','').lower() in ('done','next','готово','далее')):
         self.tap(self.center(node));break
      except Infrastructure:pass
 def install(self,name):
    s=self.adb('install','-r',str(ROOT/'results/apk'/name),timeout=90)
    if 'Success' not in s:raise Infrastructure('Install did not report success: '+s)
 def setup(self):
    self.adb('wait-for-device',timeout=120)
    # Emulator version is diagnostic metadata, not a test prerequisite.
    emulator_executable=shutil.which('emulator')
    if not emulator_executable:
       for sdk_root in (os.getenv('ANDROID_SDK_ROOT'),os.getenv('ANDROID_HOME')):
         if sdk_root and (Path(sdk_root)/'emulator'/'emulator').is_file():
           emulator_executable=str(Path(sdk_root)/'emulator'/'emulator')
           break
    if emulator_executable:
       try: emulator_version=self.cmd([emulator_executable,'-version'],check=False)[:1000]
       except Infrastructure: emulator_version='unavailable (optional diagnostic)'
    else:
       emulator_version='unavailable (optional diagnostic)'
    self.metadata.update({'sdk':self.adb('shell','getprop','ro.build.version.sdk').strip(),'fingerprint':self.adb('shell','getprop','ro.build.fingerprint').strip(),'crypto_type':self.adb('shell','getprop','ro.crypto.type').strip(),'crypto_state':self.adb('shell','getprop','ro.crypto.state').strip(),'selinux':self.adb('shell','getenforce').strip(),'emulator_version':emulator_version})
    if self.metadata['sdk']!='34':raise Infrastructure('Only API 34 protocol is approved')
    if self.metadata['selinux']!='Enforcing':raise Infrastructure('SELinux is not Enforcing')
    self.adb('shell','wm','size','720x1280');self.adb('shell','wm','density','240')
    for key in ('window_animation_scale','transition_animation_scale','animator_duration_scale'):self.adb('shell','settings','put','global',key,'0')
    self.adb('shell','settings','put','system','screen_off_timeout','1800000')
    self.adb('shell','svc','power','stayon','true')
    self.adb('shell','input','keyevent','KEYCODE_WAKEUP');self.adb('shell','wm','dismiss-keyguard',check=False)
    self.install('security-lab.apk');self.install('lab-helper.apk')
    self.adb('logcat','-G','16M',check=False)
    if self.group=='credentials':
      self.pin=''.join(secrets.choice('0123456789') for _ in range(6))
      result=self.adb('shell','locksettings','set-pin',self.pin,private=True)
      if 'success' not in result.lower():raise Infrastructure('Unable to set laboratory PIN')
    installed={pkg:self.adb('shell','dumpsys','package',pkg) for pkg in (LAB,HELPER)}
    self.save('installed-packages.json',installed)
    for pkg,description in installed.items():
      if 'targetSdk=34' not in description:raise Infrastructure('Unexpected targetSdk for '+pkg)
    self.save('environment.json',self.metadata)
 def direct_boot(self):
    if self.metadata['crypto_type']!='file' or self.metadata['crypto_state']!='encrypted':raise Inconclusive('AVD does not report real file-based encryption; emulated FBE is not substituted')
    before=self.call(LAB,'boot_prepare');require(before['unlocked'] and before['de']['matches'] and before['ce']['matches'],'Both prepared files must be readable')
    self.screenshot('01-записи-перед-перезагрузкой')
    token=self.case['events'][-1]['token']
    self.adb('reboot');self.adb('wait-for-device',timeout=180)
    locked=self.event(token,'boot_receiver',timeout=150)
    require(locked['stage']=='locked_boot' and not locked['unlocked'],'Probe must execute before first unlock')
    require(locked['de'].get('matches') and not locked['ce'].get('read') and bool(locked['ce'].get('exception')),'DE readable and actual CE exception required')
    require(locked['boot_count']>before['boot_count'],'A real reboot is required')
    self.screenshot('02-первичная-блокировка-Android')
    self.unlock();time.sleep(2)
    after=self.call(LAB,'boot_probe',stage='first_unlock');require(after['unlocked'] and after['de']['matches'] and after['ce']['matches'],'Original bytes must become readable after PIN')
    self.screenshot('03-данные-после-PIN')
    self.adb('shell','input','keyevent','KEYCODE_SLEEP');time.sleep(1)
    state=self.adb('shell','dumpsys','user');self.save('user-after-screen-lock.txt',state)
    require('RUNNING_UNLOCKED' in state,'Screen lock must not return primary user to pre-first-unlock state')
    self.unlock();self.call(LAB,'boot_history')
    self.case['conclusion']='DE доступно до первого PIN; исходная запись CE доступна после разблокировки. Повторная блокировка экрана не возвращает пользователя в Direct Boot.'
 def keystore(self):
    # Recover independently if Direct Boot failed while keyguard stayed locked.
    keyguard=self.adb('shell','dumpsys','window','policy')
    if 'showing=true' in keyguard or 'mShowingLockscreen=true' in keyguard:
      self.unlock()
    create=self.call(LAB,'key_create')
    require(create.get('authentication_required') and create.get('validity_seconds')==30,'Key must require timed device credential authentication')
    self.save('key-properties.json',create)
    t=self.launch(LAB,'key_auth');time.sleep(1);self.screenshot('01-системный-запрос-PIN');self.unlock(confirmation=True)
    seed=self.event(t,'key_auth');require(seed.get('authenticated') and seed.get('decrypted') and seed.get('matches'),'Authenticated encryption and decryption must work')
    self.screenshot('02-открытая-запись')
    time.sleep(35)
    denied=self.call(LAB,'key_try');require(not denied.get('decrypted') and denied.get('exception')=='android.security.keystore.UserNotAuthenticatedException','Timeout must cause UserNotAuthenticatedException')
    self.screenshot('03-истёкшее-разрешение-ключа')
    t=self.launch(LAB,'key_auth');time.sleep(1);self.unlock(confirmation=True);again=self.event(t,'key_auth')
    require(again.get('authenticated') and again.get('matches') and again.get('ciphertext')==seed.get('ciphertext') and again.get('plaintext')==seed.get('plaintext'),'Same ciphertext must decrypt after a new system PIN')
    self.screenshot('04-повторное-расшифрование')
    self.case['conclusion']='Реальная операция AES/GCM блокируется после истечения окна аутентификации и разрешается после нового PIN. Уровень реализации ключа записан отдельно; физическая TEE/StrongBox не доказана.'
 def apk_signature(self):
    self.adb('uninstall',SAMPLE,check=False);self.install('sample-v1-a.apk')
    original=self.call(SAMPLE,'sample_state');require(original['version']==1,'Version 1 required');self.screenshot('01-исходное-приложение')
    bad=self.adb('install','-r',str(ROOT/'results/apk/sample-v2-b.apk'),check=False,timeout=90);self.save('incompatible-update.txt',bad)
    if 'INSTALL_FAILED_UPDATE_INCOMPATIBLE' not in bad and 'Success' not in bad:raise Infrastructure('APK update failed for unrelated reason: '+bad)
    require('INSTALL_FAILED_UPDATE_INCOMPATIBLE' in bad,'Expected Package Manager incompatible-signature rejection')
    state=self.call(SAMPLE,'sample_state');require(state['version']==1 and state['note_sha256']==original['note_sha256'],'Rejected update must preserve version and data')
    self.screenshot('02-приложение-после-отказа')
    self.install('sample-v2-a.apk');updated=self.call(SAMPLE,'sample_state')
    require(updated['version']==2 and updated['note_sha256']==original['note_sha256'],'Correct signer must update and preserve data');self.screenshot('03-корректное-обновление')
    self.case['conclusion']='Package Manager отклонил обновление с независимым сертификатом и сохранил данные при корректном обновлении. Проверка не устанавливает доверие к разработчику и не исследует ротацию ключей.'
 def tapjacking(self):
    self.adb('shell','appops','set',HELPER,'SYSTEM_ALERT_WINDOW','allow')
    self.call(HELPER,'overlay_stop');self.call(LAB,'tap');self.call(LAB,'hide_overlay',enabled=False)
    node=self.find(lambda n:n.get('content-desc')=='tap-target');xy=self.center(node)
    self.tap(xy);before=self.call(LAB,'tap_state');require(before['clicks']==1 and before['saved_count']==1,'Baseline tap must save one record');self.screenshot('01-обычное-касание')
    policy=self.adb('shell','settings','get','global','block_untrusted_touches').strip()
    if policy not in ('null','2'):raise Infrastructure('Untrusted touch blocking is disabled or nondefault')
    shown=self.call(HELPER,'overlay');require(shown.get('shown') and shown['alpha']>.8,'Untrusted overlay must exceed Android threshold')
    time.sleep(1);overlay=self.screenshot('02-чужое-непрозрачное-окно');require(pixels(overlay,'cyan')>.25,'Actual helper window must be visible')
    self.tap(xy);time.sleep(.5);after=self.call(LAB,'tap_state');require(after['clicks']==before['clicks'] and after['saved_count']==before['saved_count'] and after['touches']==before['touches'],'Blocked touch must not reach target Activity')
    log=self.adb('logcat','-d','-v','threadtime');self.save('input-dispatcher.txt',log)
    rejection=any(('Untrusted touch' in line or 'untrusted touch' in line) and HELPER in line for line in log.splitlines())
    self.call(LAB,'hide_overlay',enabled=True);time.sleep(1);hidden=self.screenshot('03-Android-скрыл-наложение');require(pixels(hidden,'cyan')<.01,'Overlay must disappear via Window API')
    self.tap(xy);restored=self.call(LAB,'tap_state');require(restored['clicks']==2 and restored['saved_count']==2,'Same target must receive touch after hiding overlay')
    self.call(LAB,'hide_overlay',enabled=False);time.sleep(1);visible=self.screenshot('04-наложение-снова-видно');require(pixels(visible,'cyan')>.25,'Helper overlay must still exist, not have been stopped')
    self.call(HELPER,'overlay_stop')
    if not rejection:raise Inconclusive('Behavior controls passed, but InputDispatcher did not expose expected occlusion rejection. Do not attribute missing tap solely to Android protection.')
    self.case['conclusion']='Android отфильтровал касание через непрозрачное недоверенное окно; setHideOverlayWindows скрыл живое окно другого UID. Это не доказательство защиты от всех видов tapjacking.'
 def tls(self):
    if self.server_error:raise Infrastructure(self.server_error)
    self.adb('reverse','tcp:8080','tcp:8080')
    nonce=json.loads((ROOT/'.lab-secrets/fixture.json').read_text())['nonce']
    def query(port,host='10.0.2.2',https=True):
      return self.call(LAB,'tls',url=f'{"https" if https else "http"}://{host}:{port}/{self.run_id}')
    good=query(8443);require(good.get('received') and good.get('code')==200 and json.loads(good['body'])['nonce']==nonce,'Trusted TLS must return current fixture nonce');self.screenshot('01-доверенное-TLS-соединение')
    foreign=query(8444);require(not foreign.get('received') and foreign.get('exception')=='javax.net.ssl.SSLHandshakeException' and ('CertPathValidatorException' in foreign.get('causes','') or 'Trust anchor' in foreign.get('message','')),'Foreign CA must fail chain validation');self.screenshot('02-недоверенный-CA')
    wrong=query(8445);require(not wrong.get('received') and wrong.get('exception')=='javax.net.ssl.SSLPeerUnverifiedException','Trusted CA with wrong hostname must fail hostname verification');self.screenshot('03-ошибка-имени-сервера')
    plain=query(8080,https=False);require(not plain.get('received') and 'Cleartext' in plain.get('message','') and 'not permitted' in plain.get('message',''),'HTTP must be rejected by NSC');self.screenshot('04-HTTP-запрещён')
    control=query(8080,host='localhost',https=False);require(control.get('received') and json.loads(control['body'])['nonce']==nonce,'Same HTTP server must be reachable through explicitly permitted localhost control');self.screenshot('05-контроль-доступности-HTTP')
    self.case['conclusion']='Стандартный сетевой стек проверил цепочку доверия, имя сервера и политику cleartext. Лабораторный CA доверен только в конфигурации приложения; обходов TrustManager/HostnameVerifier нет.'
 def projection_image(self,name):
    t=self.launch(HELPER,'snapshot');data=self.event(t,'snapshot',timeout=25)
    require(re.fullmatch(r'capture-[0-9a-f-]+\.png',data.get('file','')) is not None,'Unexpected capture filename')
    payload=self.adb('exec-out','run-as',HELPER,'cat','files/'+data['file'],binary=True).stdout
    require(hashlib.sha256(payload).hexdigest()==data['sha256'],'Captured frame digest mismatch')
    path=self.current/(name+'.png');path.write_bytes(payload)
    with Image.open(path) as im:im.verify()
    self.case['images'].append({'path':str(path.relative_to(self.out)),'caption':name,'sha256':data['sha256'],'source':'MediaProjection / ImageReader','run_id':self.run_id})
    return path
 def media_projection(self):
    self.call(LAB,'capture',secure=False)
    t=self.launch(HELPER,'capture_start');time.sleep(1)
    node=self.find(lambda n:n.get('package')=='com.android.systemui' and n.get('resource-id')=='android:id/button1')
    self.screenshot('01-системное-согласие-на-захват');self.save('consent-ui.xml',ET.tostring(self.dump(),encoding='unicode'));self.tap(self.center(node))
    started=self.event(t,'capture_start');require(started.get('consented') and started.get('display_created'),'Projection must have a valid first virtual display')
    self.call(LAB,'capture',secure=False);ordinary=self.projection_image('02-захваченный-обычный-экран');require(pixels(ordinary,'magenta')>.04,'Visible marker must appear in ordinary captured frame')
    self.call(LAB,'capture',secure=True);time.sleep(1);secure=self.projection_image('03-захваченный-защищённый-экран');require(pixels(secure,'magenta')<.001,'Secure marker must be excluded from captured frame')
    self.call(LAB,'capture',secure=False);restored=self.projection_image('04-захват-после-снятия-защиты');require(pixels(restored,'magenta')>.04,'Capture must remain alive and marker must return')
    reused=self.call(HELPER,'reuse');require(not reused.get('accepted') and reused.get('exception')=='java.lang.SecurityException','Second createVirtualDisplay on same projection must throw SecurityException')
    self.call(HELPER,'capture_stop')
    self.case['conclusion']='Захват начат после системного согласия. FLAG_SECURE исключил содержимое окна из действующего захвата, снятие флага восстановило его. Повторный createVirtualDisplay с тем же MediaProjection отклонён на targetSdk 34.'
 def diagnostics(self):
    for filename,args in [('logcat.txt',['logcat','-d','-v','threadtime']),('windows.txt',['shell','dumpsys','window']),('activities.txt',['shell','dumpsys','activity','activities']),('users.txt',['shell','dumpsys','user']),('projection.txt',['shell','dumpsys','media_projection'])]:
      try:self.save(filename,self.adb(*args,timeout=15,check=False))
      except Exception as e:self.save(filename,str(e))
    try:self.screenshot('диагностика-финальный-экран')
    except Exception as e:self.case['diagnostic_error']=str(e)
 def checkpoint(self):
    target=self.out/'results.json';tmp=self.out/'results.tmp'
    tmp.write_text(json.dumps({'metadata':self.metadata,'experiments':self.results},ensure_ascii=False,indent=2));tmp.replace(target)
 def execute(self):
    self.checkpoint()
    setup_error=None
    try:self.setup()
    except Exception:setup_error=traceback.format_exc();self.save('setup-error.txt',setup_error)
    for case_id in GROUPS[self.group]:
      self.current=self.out/case_id;self.current.mkdir();self.case={'id':case_id,'status':'ERROR','run_id':self.run_id,'commit':self.commit,'images':[],'events':[],'started':time.time()}
      try:
        if setup_error:raise Infrastructure('Environment preparation failed; see setup-error.txt')
        getattr(self,case_id)();self.case['status']='PASS'
      except Inconclusive as e:self.case.update(status='INCONCLUSIVE',reason=str(e))
      except AssertionError as e:self.case.update(status='FAIL',reason=str(e),traceback=traceback.format_exc())
      except Exception as e:self.case.update(status='ERROR',reason=str(e),traceback=traceback.format_exc())
      finally:
        self.diagnostics()
        # Cleanup is independent from the scientific assertion and never creates a PASS.
        for pkg,op in [(HELPER,'overlay_stop'),(HELPER,'capture_stop')]:
          try:self.launch(pkg,op)
          except Exception:pass
        self.case['finished']=time.time();self.save('result.json',self.case);self.results.append(self.case);self.checkpoint()
        print(case_id,self.case['status'],self.case.get('reason',''),flush=True)
    self.current=self.out;self.save('results.json',{'metadata':self.metadata,'experiments':self.results})
    return all(x['status']=='PASS' for x in self.results)

def main():
 p=argparse.ArgumentParser();p.add_argument('--group',choices=GROUPS,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 servers=[]
 try:
    # Server failure is recorded by run setup instead of silently dropping the entire run.
    runner=Runner(a.group,a.out)
    if a.group=='standard':
      try:servers=server.start(ROOT/'.lab-secrets',ROOT/'results/server.jsonl')
      except Exception as e:runner.server_error='TLS fixture server failed: '+str(e)
    ok=runner.execute()
 finally:
    for s in servers:s.shutdown();s.server_close()
 raise SystemExit(0 if ok else 1)
if __name__=='__main__':main()
