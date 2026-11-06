import sys,unittest,tempfile,json,contextlib,io
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import run
class RunnerTests(unittest.TestCase):
 def test_independent_experiment_runs_after_infrastructure_error(self):
  with tempfile.TemporaryDirectory() as td:
   class Fixture(run.Runner):
    def setup(self):pass
    def diagnostics(self):pass
    def launch(self,*args,**kw):pass
    def direct_boot(self):raise run.Infrastructure('Test infrastructure unavailable')
    def keystore(self):self.case['conclusion']='unit-test only'
   r=Fixture('credentials',Path(td)/'results')
   with contextlib.redirect_stdout(io.StringIO()):self.assertFalse(r.execute())
   result=json.loads((r.out/'results.json').read_text())
   self.assertEqual([x['status'] for x in result['experiments']],['ERROR','PASS'])
 def test_assertion_and_inconclusive_are_distinct(self):
  with tempfile.TemporaryDirectory() as td:
   class Fixture(run.Runner):
    def setup(self):pass
    def diagnostics(self):pass
    def launch(self,*args,**kw):pass
    def direct_boot(self):raise AssertionError('unit mismatch')
    def keystore(self):raise run.Inconclusive('unit evidence missing')
   r=Fixture('credentials',Path(td)/'results')
   with contextlib.redirect_stdout(io.StringIO()):self.assertFalse(r.execute())
   self.assertEqual([x['status'] for x in r.results],['FAIL','INCONCLUSIVE'])
 def test_existing_run_directory_is_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   with self.assertRaises(FileExistsError):run.Runner('standard',Path(td))
if __name__=='__main__':unittest.main()
