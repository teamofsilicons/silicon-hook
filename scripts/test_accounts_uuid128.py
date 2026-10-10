"""Pure regression checks for the shared Accounts mapping contract and JSON boundary."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('consumer',Path(__file__).with_name('accounts_uuid128.py'))
consumer=importlib.util.module_from_spec(spec)
spec.loader.exec_module(consumer)
NEW='a750a68a-1bc2-4b3f-888e-0349c9d7289a'
class MappingTests(unittest.TestCase):
 def parse(self,content):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'map.csv';p.write_text(content);return consumer.read_mapping(p)
 def test_unknown_tombstone_kinds_require_explicit_manifest_opt_in(self):
  self.assertFalse(consumer.kind_matches(None,"carbon"))
  self.assertTrue(consumer.kind_matches(None,"carbon",True))
  self.assertFalse(consumer.kind_matches("silicon","carbon",True))
  self.assertTrue(consumer.kind_matches("carbon","carbon"))
 def test_every_legacy_account_requires_mapping_and_error_is_count_only(self):
  with self.assertRaisesRegex(ValueError, r"^mapping omits 2 legacy account\(s\)$"):
   consumer.require_mapping_coverage([("secretOld","active"),("deletedOld","deleted"),(NEW,"active")], {})
  consumer.require_mapping_coverage([("a8K","active"),(NEW,"deleted")], {"a8K":NEW})
 def test_only_valid_explicit_unlinked_iam_placeholders_are_exempt(self):
  private="iam:"+NEW+":"+NEW
  consumer.require_mapping_coverage([(private,"unlinked")], {}, True)
  for identity,status,allow in [(private,"active",True),(private,"unlinked",False),("iam:not-a-uuid:"+NEW,"unlinked",True)]:
   with self.subTest(identity=identity,status=status,allow=allow),self.assertRaises(ValueError):
    consumer.require_mapping_coverage([(identity,status)],{},allow)
 def test_exact_mapping_contract(self):
  mapping,kinds,digest=self.parse(f'old_uuid,new_uuid,kind\na8K,{NEW},carbon\n')
  self.assertEqual(mapping,{'a8K':NEW});self.assertEqual(kinds,{'a8K':'carbon'});self.assertEqual(len(digest),64)
 def test_refuses_merges_duplicates_noncanonical_and_bad_kinds(self):
  for text in [f'old_uuid,new_uuid,kind\na8K,{NEW},carbon\nb8K,{NEW},silicon\n',f'old_uuid,new_uuid,kind\na8K,{NEW},carbon\na8K,b750a68a-1bc2-4b3f-888e-0349c9d7289b,carbon\n',f'old_uuid,new_uuid,kind\na8K,{NEW.upper()},carbon\n',f'old_uuid,new_uuid,kind\na8K,{NEW},robot\n',f'new_uuid,old_uuid,kind\n{NEW},a8K,carbon\n']:
   with self.subTest(text=text),self.assertRaises(ValueError):self.parse(text)
 def test_only_identity_fields_change_in_approved_json(self):
  before={'actor':{'type':'carbon','id':'c:ada','uuid':'a8K'},'title':'a8K','description':'a8K','object_id':'a8K','membership_id':'commit:a8K','participants':[{'type':'silicon','id':'a8K'}],'resource':{'id':'a8K'}}
  after=consumer.rewrite_identity_json(before,{'a8K':NEW})
  self.assertEqual(after['actor'],{'type':'carbon','id':'c:ada','uuid':NEW})
  self.assertEqual(after['title'],'a8K');self.assertEqual(after['description'],'a8K');self.assertEqual(after['object_id'],'a8K');self.assertEqual(after['resource'],{'id':'a8K'})
  self.assertEqual(after['membership_id'],'commit:'+NEW);self.assertEqual(after['participants'][0]['id'],NEW)
  self.assertEqual(consumer.rewrite_identity_json(after,{'a8K':NEW}),after)
if __name__=='__main__':unittest.main()
