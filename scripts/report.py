"""Aggregate only current-run evidence. Missing/corrupt artifacts can never yield PASS."""
import argparse, base64, hashlib, html, json, os, shutil
from pathlib import Path
import xml.etree.ElementTree as ET
from protocol import CASES
STATES={'PASS','FAIL','ERROR','INCONCLUSIVE','NOT_RUN'}
def esc(x):return html.escape(str(x))
def collect(root,commit=None):
 records={};metadata=[];errors=[]
 for path in sorted(root.rglob('results.json')):
  try:
   payload=json.loads(path.read_text());meta=payload['metadata'];metadata.append(meta)
   for r in payload['experiments']:
    if r['id'] not in CASES:continue
    r=dict(r);r['evidence_root']=str(path.parent.relative_to(root));issues=[]
    if r['id'] in records:issues.append('Повторяющийся результат опыта: неоднозначный источник')
    if r.get('status') not in STATES:issues.append('Неизвестный статус')
    if r.get('run_id')!=meta.get('run_id') or r.get('commit')!=meta.get('commit'):issues.append('Результат не соответствует метаданным запуска')
    if commit and r.get('commit')!=commit:issues.append('Коммит не соответствует текущему workflow')
    for field,var in [('github_run_id','GITHUB_RUN_ID'),('github_run_attempt','GITHUB_RUN_ATTEMPT')]:
     if os.getenv(var) and meta.get(field)!=os.getenv(var):issues.append('Материалы другого запуска GitHub: '+field)
    if not r.get('events') and r.get('status')=='PASS':issues.append('PASS без событий API')
    if not r.get('images') and r.get('status')=='PASS':issues.append('PASS без изображений')
    valid=[]
    for im in r.get('images',[]):
     candidate=(path.parent/im['path']).resolve()
     if not candidate.is_relative_to(path.parent.resolve()):issues.append('Недопустимый путь изображения');continue
     if im.get('run_id')!=r.get('run_id') or not candidate.is_file():issues.append('Нет изображения текущего запуска');continue
     if hashlib.sha256(candidate.read_bytes()).hexdigest()!=im.get('sha256'):issues.append('Хеш изображения не совпадает');continue
     if candidate.read_bytes()[:8]!=b'\x89PNG\r\n\x1a\n':issues.append('Файл не является PNG');continue
     valid.append(dict(im,path=str(candidate.relative_to(root.resolve()))))
    r['images']=valid
    if issues:r['status']='ERROR';r['reason']='; '.join(issues)
    records[r['id']]=r
  except Exception as e:errors.append(f'{path.relative_to(root)}: {e}')
 for key in CASES:
  if key not in records:records[key]={'id':key,'status':'NOT_RUN','reason':'Результат не получен: проверьте журнал сборки, запуск AVD и диагностический архив.','images':[],'events':[]}
 return {'metadata':metadata,'experiments':[records[k] for k in CASES],'aggregation_errors':errors}

def render(data,root,out):
 out.mkdir(parents=True,exist_ok=True)
 # Keep all raw evidence and logs accessible without a web server.
 target=out/'evidence'
 if target.exists():shutil.rmtree(target)
 shutil.copytree(root,target)
 (out/'results.json').write_text(json.dumps(data,ensure_ascii=False,indent=2))
 suite=ET.Element('testsuite',name='Android Security Lab API 34',tests='6',failures=str(sum(r['status']=='FAIL' for r in data['experiments'])),errors=str(sum(r['status']=='ERROR' for r in data['experiments'])),skipped=str(sum(r['status'] in ('INCONCLUSIVE','NOT_RUN') for r in data['experiments'])))
 parts=['<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Android Security Lab — отчёт</title>',
 '<style>body{font:16px/1.55 system-ui,sans-serif;max-width:1100px;margin:36px auto;padding:0 20px;color:#18273a;background:#f3f6fa}section{background:white;padding:26px;margin:24px 0;border-radius:12px}h1,h2{line-height:1.2}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f6fa;padding:14px}figure{display:inline-block;vertical-align:top;margin:10px;max-width:310px}img{width:100%;border:1px solid #aaa}figcaption{font-size:13px}.PASS{color:#006a48}.FAIL,.ERROR{color:#a51923}.INCONCLUSIVE,.NOT_RUN{color:#855900}table{border-collapse:collapse;width:100%}td,th{padding:9px;border-bottom:1px solid #ddd;text-align:left}a{color:#086782}</style>',
 '<h1>Исследование механизмов безопасности Android</h1><p>Фактические результаты одного workflow. Ожидаемое поведение ниже — методика, а не свидетельство успешного выполнения.</p>',
 '<p>PASS — все предусмотренные контроли выполнены; FAIL — наблюдение противоречит критерию; ERROR — ошибка выполнения/доказательств; INCONCLUSIVE — данных недостаточно; NOT_RUN — результата запуска нет.</p>',
 '<h2>Среда и происхождение</h2><pre>'+esc(json.dumps(data['metadata'],ensure_ascii=False,indent=2))+'</pre><table><tr><th>Опыт</th><th>Статус</th></tr>']
 for r in data['experiments']:parts.append(f'<tr><td><a href="#{r["id"]}">{esc(CASES[r["id"]]["title"])}</a></td><td class="{r["status"]}">{r["status"]}</td></tr>')
 parts.append('</table>')
 if data['aggregation_errors']:parts.append('<pre>'+esc(data['aggregation_errors'])+'</pre>')
 for r in data['experiments']:
  case=CASES[r['id']];node=ET.SubElement(suite,'testcase',name=r['id'],classname='android.security.lab',time=str(max(0,r.get('finished',0)-r.get('started',0))))
  status=r['status']
  if status!='PASS':ET.SubElement(node,{'FAIL':'failure','ERROR':'error'}.get(status,'skipped'),message=r.get('reason',status)).text=r.get('traceback','')
  ET.SubElement(node,'system-out').text=json.dumps(r,ensure_ascii=False)
  parts.append(f'<section id="{r["id"]}"><h2>{esc(case["title"])}</h2><p class="{status}"><b>{status}</b></p>')
  for label,key in [('Цель','goal'),('Условия и предусмотренные действия','method'),('Ожидаемая реакция','expected')]:parts.append(f'<p><b>{label}.</b> {esc(case[key])}</p>')
  parts.append('<p><b>Фактический результат.</b> '+esc(r.get('conclusion') if status=='PASS' else r.get('reason','Нет подтверждённого вывода'))+'</p>')
  for im in r['images']:
   png=(root/im['path']).read_bytes()
   parts.append('<figure><img alt="'+esc(im['caption'])+'" src="data:image/png;base64,'+base64.b64encode(png).decode()+'"><figcaption>'+esc(im['caption'])+'<br>'+esc(im.get('source',''))+'</figcaption></figure>')
  if not r['images']:parts.append('<p>Снимки текущего запуска отсутствуют. Изображения-заглушки не используются.</p>')
  folder=r.get('evidence_root')
  if folder is not None:
   files=sorted((root/folder/r['id']).glob('*'))
   parts.append('<p><b>Технические доказательства:</b> '+ ' · '.join(f'<a href="evidence/{esc(str(f.relative_to(root)))}">{esc(f.name)}</a>' for f in files if f.suffix!='.png')+'</p>')
  parts.append('<details><summary>Полученные события API и исключения</summary><pre>'+esc(json.dumps(r.get('events',[]),ensure_ascii=False,indent=2))+'</pre></details>')
  parts.append('<p><b>Ограничения вывода.</b> '+esc(case['limits'])+'</p></section>')
 parts.append('<p><a href="results.json">JSON</a> · <a href="junit.xml">JUnit</a> · Исходные материалы: папка evidence.</p></html>')
 (out/'report.html').write_text('\n'.join(parts),encoding='utf-8');ET.ElementTree(suite).write(out/'junit.xml',encoding='utf-8',xml_declaration=True)
 summary='\n'.join(f'| {CASES[r["id"]]["title"]} | {r["status"]} |' for r in data['experiments'])
 (out/'summary.md').write_text('| Опыт | Статус |\n|---|---|\n'+summary+'\n\nПолный отчёт: артефакт securitylab-report → report.html.\n')

def main():
 p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--commit',default=os.getenv('GITHUB_SHA'));a=p.parse_args()
 a.input.mkdir(parents=True,exist_ok=True)
 data=collect(a.input.resolve(),a.commit);render(data,a.input.resolve(),a.output.resolve())
 print('Report generated; '+', '.join(r['id']+':'+r['status'] for r in data['experiments']))
if __name__=='__main__':main()
