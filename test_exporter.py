import json
import tempfile
import unittest
from pathlib import Path

import wiz_two_menu_export as wz

class Checks(unittest.TestCase):
    def test_csv_formula_escape(self):
        self.assertEqual(wz.safe_cell('=2+2'), "'=2+2")
        self.assertEqual(wz.safe_cell('@SUM(A1:A2)'), "'@SUM(A1:A2)")
    def test_group_does_not_silently_export_all(self):
        with tempfile.TemporaryDirectory() as d:
            fn = Path(d) / 'groups.json'
            fn.write_text(json.dumps({'container_registry': []}))
            with self.assertRaisesRegex(RuntimeError, 'No verified'):
                wz.select_group(None, 'container_registry', fn)
    def test_project_filter(self):
        q, v, label, field = wz.prepare_plan('vulnerability','project',['p-id'],{})
        self.assertEqual(v['filterBy'], {'projectId':['p-id']})
        self.assertIn('vulnerabilityFindings',q)
        self.assertEqual(field,'projectId')
    def test_registry_filter_uses_related_assets(self):
        q, v, label, field = wz.prepare_plan('vulnerability','container_registry',['image-id'],{})
        self.assertEqual(v['filterBy'], {'assetId':['image-id']})
        self.assertEqual(field,'assetId')
    def test_unmapped_category_fails(self):
        with self.assertRaisesRegex(RuntimeError, 'tenant-verified'):
            wz.prepare_plan('secrets','project',['p'],{})
    def test_pagination(self):
        class MockClient:
            def __init__(self): self.calls = 0
            def graphql(self, query, variables):
                self.calls += 1
                if self.calls == 1:
                    return {'findings':{'nodes':[{'id':'a'}], 'pageInfo': {'hasNextPage': True, 'endCursor':'next'}}}
                return {'findings':{'nodes':[{'id':'b'}], 'pageInfo': {'hasNextPage': False,'endCursor':None}}}
        findings, partial = wz.fetch_connection(MockClient(),'',{},'findings',10,10)
        self.assertEqual(len(findings),2)
        self.assertFalse(partial)

if __name__ == '__main__': unittest.main()
