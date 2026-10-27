import unittest,pathlib,sys
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from supplygate import components,evaluate
class Tests(unittest.TestCase):
 def test_policy_blocks(self):
  root=pathlib.Path(__file__).resolve().parents[1]
  self.assertFalse(evaluate(components(root/'examples/sbom.json'),policy={'blocked_licenses':['GPL-3.0-only']})['passed'])
 def test_diff(self):
  r=evaluate({'x':{}},{'y':{}});self.assertEqual(r['added'],['x']);self.assertEqual(r['removed'],['y'])
