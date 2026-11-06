import sys,tempfile,unittest,json,hashlib,os,xml.etree.ElementTree as ET
from unittest.mock import patch
from pathlib import Path
from PIL import Image
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import report
class ReportingTests(unittest.TestCase):
 def fixture(self,root):
  folder=root/'standard';folder.mkdir();(folder/'tls').mkdir();png=folder/'tls/image.png';Image.new('RGB',(3,3),'red').save(png)
  record={'id':'tls','status':'PASS','run_id':'run1','commit':'abc','events':[{'data':{'received':True}}],'images':[{'path':'tls/image.png','run_id':'run1','caption':'test','sha256':hashlib.sha256(png.read_bytes()).hexdigest()}]}
  data={'metadata':{'run_id':'run1','commit':'abc','github_run_id':os.getenv('GITHUB_RUN_ID'),'github_run_attempt':os.getenv('GITHUB_RUN_ATTEMPT')},'experiments':[record]};(folder/'results.json').write_text(json.dumps(data));return folder,data
 def test_missing_results_never_pass(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td)/'raw';root.mkdir();r=report.collect(root,'abc');self.assertEqual(len(r['experiments']),6);self.assertTrue(all(x['status']=='NOT_RUN' for x in r['experiments']))
   report.render(r,root,Path(td)/'report');self.assertEqual(len(ET.parse(Path(td)/'report/junit.xml').findall('.//skipped')),6)
 def test_current_image_is_included(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);self.fixture(root);r=report.collect(root,'abc');self.assertEqual(r['experiments'][4]['status'],'PASS')
 def test_stale_commit_is_error(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);self.fixture(root);self.assertEqual(report.collect(root,'other')['experiments'][4]['status'],'ERROR')
 def test_modified_image_is_error(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);folder,data=self.fixture(root);(folder/'tls/image.png').write_bytes(b'corrupt');self.assertEqual(report.collect(root,'abc')['experiments'][4]['status'],'ERROR')
 def test_old_run_image_is_error(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);folder,data=self.fixture(root);data['experiments'][0]['images'][0]['run_id']='old';(folder/'results.json').write_text(json.dumps(data));self.assertEqual(report.collect(root,'abc')['experiments'][4]['status'],'ERROR')
 def test_previous_workflow_run_is_error(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);self.fixture(root)
   with patch.dict(os.environ,{'GITHUB_RUN_ID':'another-workflow-run'}):self.assertEqual(report.collect(root,'abc')['experiments'][4]['status'],'ERROR')
 def test_no_events_cannot_pass(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td);folder,data=self.fixture(root);data['experiments'][0]['events']=[];(folder/'results.json').write_text(json.dumps(data));self.assertEqual(report.collect(root,'abc')['experiments'][4]['status'],'ERROR')
 def test_escape_runtime_text(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td)/'raw';root.mkdir();r=report.collect(root);r['experiments'][0]['reason']='<script>bad</script>';report.render(r,root,Path(td)/'report');html=(Path(td)/'report/report.html').read_text();self.assertNotIn('<script>bad',html);self.assertIn('&lt;script&gt;',html)
if __name__=='__main__':unittest.main()
