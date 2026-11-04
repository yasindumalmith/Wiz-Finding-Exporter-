import csv
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import wiz_two_menu_export as wz

REPO_ID = '21a82117-ac86-5807-a0d0-98fef22ce910'
REPO_NAME = 'wiz-code-demo/public-demo'


def connection(alias, nodes, has_next=False, cursor=None):
    return {alias: {'nodes': nodes, 'pageInfo': {
        'hasNextPage': has_next, 'endCursor': cursor}}}


def repository_group(repo_id=REPO_ID, name=REPO_NAME, count=2):
    return {'id': '{"repository":"group-identifier"}',
            'repository': {'id': repo_id, 'name': name, 'platform': 'GitHub'},
            'analytics': {'findingCount': count, 'highSeverityCount': count}}


def sast_finding(finding_id, name, line):
    return {'id': finding_id, 'name': name, 'severity': 'HIGH', 'status': 'OPEN',
            'description': 'First line, "quoted"\nSecond line',
            'repository': {'id': REPO_ID, 'name': REPO_NAME, 'platform': 'GitHub'},
            'repositoryBranch': {'id': 'branch-id', 'name': 'main'},
            'filePath': 'sast-demo/app.py', 'startLine': line, 'endLine': line,
            'snippet': None, 'codeLibraryLanguage': 'Python',
            'remediationInstructions': None, 'createdAt': '2026-01-01T00:00:00Z',
            'updatedAt': '2026-01-02T00:00:00Z',
            'firstDetectedAtSource': '2026-01-01T00:00:00Z',
            'sourceUrl': 'https://example.invalid/finding'}


class SequenceClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def graphql(self, query, variables):
        self.calls.append((query, variables))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


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

    def test_group_parsing_uses_repository_id_and_count(self):
        client = SequenceClient([connection('repositories', [repository_group()])])
        repos = wz.get_sast_repositories(client, 10)
        self.assertEqual(repos, [{'id': REPO_ID, 'name': REPO_NAME,
                                  'platform': 'GitHub', 'finding_count': 2}])
        self.assertIn('sastFindingsGroupedByValues', client.calls[0][0])
        self.assertIn('groupBy: { fields: [REPOSITORY] }', client.calls[0][0])
        self.assertNotEqual(repos[0]['id'], repository_group()['id'])

    def test_repository_menu_displays_names_counts_and_selects_id(self):
        client = SequenceClient([connection('repositories', [repository_group()])])
        stdout = StringIO()
        with patch('builtins.input', return_value='1'), redirect_stdout(stdout):
            name, ids = wz.select_sast_repository(client, 10)
        self.assertEqual((name, ids), (REPO_NAME, [REPO_ID]))
        self.assertIn(f'{REPO_NAME} — 2 findings (GitHub)', stdout.getvalue())

    def test_repository_grouping_fetches_all_pages(self):
        client = SequenceClient([
            connection('repositories', [repository_group(name='z-repo')], True, 'group-cursor'),
            connection('repositories', [repository_group('second-id', 'a-repo', 1)]),
        ])
        repos = wz.get_sast_repositories(client, 1)
        self.assertEqual([r['name'] for r in repos], ['a-repo', 'z-repo'])
        self.assertEqual([call[1]['after'] for call in client.calls], [None, 'group-cursor'])

    def test_missing_repository_ids_are_skipped_and_empty_list_refused(self):
        client = SequenceClient([connection('repositories', [repository_group(repo_id=None)])])
        stdout = StringIO()
        with redirect_stdout(stdout):
            with self.assertRaisesRegex(RuntimeError, 'No SAST repository groups'):
                wz.select_sast_repository(client, 10)
        self.assertIn('Skipped 1 repository groups', stdout.getvalue())
        with self.assertRaisesRegex(RuntimeError, 'No SAST repository groups'):
            wz.select_sast_repository(SequenceClient([connection('repositories', [])]), 10)

    def test_sast_filter_is_nested_and_query_has_verified_fields(self):
        query, variables, label, path = wz.prepare_plan('sast', 'code_repository', [REPO_ID], {})
        self.assertEqual(variables, {'filterBy': {'resource': {
            'repositoryId': {'equals': [REPO_ID]}}}})
        self.assertEqual(path, ('resource', 'repositoryId', 'equals'))
        self.assertEqual(label, 'SAST')
        self.assertIn('$filterBy: SASTFindingFilters', query)
        self.assertIn('repositoryBranch { id name }', query)
        self.assertIn('firstDetectedAtSource', query)

    def test_full_cli_workflow_passes_selected_repository_id_and_all_pages(self):
        client = SequenceClient([
            connection('repositories', [repository_group()]),
            connection('findings', [sast_finding('xss', 'Cross-site Scripting (XSS)', 51)], True, 'next'),
            connection('findings', [sast_finding('command', 'Command Injection', 40)]),
        ])
        with tempfile.TemporaryDirectory() as directory:
            with patch('sys.argv', ['wiz_two_menu_export.py', '--page-size', '1',
                                    '--out-dir', directory]), \
                 patch('builtins.input', side_effect=['2', '2', '1']), \
                 patch.object(wz, 'WizClient', return_value=client), \
                 redirect_stdout(StringIO()):
                wz.main()
            output = Path(directory) / 'sast_wiz-code-demo_public-demo.csv'
            with output.open(encoding='utf-8-sig', newline='') as file:
                rows = list(csv.DictReader(file))
            self.assertEqual({row['name'] for row in rows},
                             {'Cross-site Scripting (XSS)', 'Command Injection'})
            self.assertEqual([call[1]['after'] for call in client.calls], [None, None, 'next'])
            self.assertEqual(client.calls[1][1]['filterBy']['resource']['repositoryId']['equals'], [REPO_ID])

    def test_sast_csv_deduplicates_and_handles_nulls_and_special_text(self):
        client = SequenceClient([
            connection('findings', [sast_finding('xss', 'Cross-site Scripting (XSS)', 51)], True, 'next'),
            connection('findings', [sast_finding('xss', 'Cross-site Scripting (XSS)', 51),
                                    sast_finding('command', 'Command Injection', 40)]),
        ])
        with tempfile.TemporaryDirectory() as directory:
            output = wz.export(client, 'sast', 'code_repository', REPO_NAME, [REPO_ID],
                               1, 0, {}, Path(directory))
            self.assertEqual(output.name, 'sast_wiz-code-demo_public-demo.csv')
            self.assertTrue(output.read_bytes().startswith(b'\xef\xbb\xbf'))
            with output.open(encoding='utf-8-sig', newline='') as file:
                reader = csv.DictReader(file)
                fields = reader.fieldnames
                rows = list(reader)
            self.assertEqual(len(rows), 2)
            self.assertEqual(fields, ['finding_category', 'group_type', 'group_name', 'id']
                             + wz.SAST_REPOSITORY_COLUMNS)
            self.assertEqual(rows[0]['description'], 'First line, "quoted"\nSecond line')
            self.assertEqual(rows[0]['snippet'], '')
            self.assertEqual(rows[0]['remediationInstructions'], '')
            self.assertEqual(rows[0]['repositoryBranch.name'], 'main')
            self.assertEqual(rows[1]['startLine'], '40')

    def test_empty_sast_findings_produce_complete_header_only_csv(self):
        client = SequenceClient([connection('findings', [])])
        with tempfile.TemporaryDirectory() as directory:
            output = wz.export(client, 'sast', 'code_repository', REPO_NAME, [REPO_ID],
                               10, 0, {}, Path(directory))
            with output.open(encoding='utf-8-sig', newline='') as file:
                reader = csv.DictReader(file)
                self.assertEqual(reader.fieldnames, ['finding_category', 'group_type',
                                                      'group_name', 'id'] + wz.SAST_REPOSITORY_COLUMNS)
                self.assertEqual(list(reader), [])

    def test_sample_and_partial_filenames_are_unique(self):
        finding_page = connection('findings', [sast_finding('xss', 'XSS', 51)], True, 'next')
        client = SequenceClient([finding_page, finding_page])
        with tempfile.TemporaryDirectory() as directory:
            first = wz.export(client, 'sast', 'code_repository', REPO_NAME, [REPO_ID],
                              1, 1, {}, Path(directory))
            second = wz.export(client, 'sast', 'code_repository', REPO_NAME, [REPO_ID],
                               1, 1, {}, Path(directory))
            self.assertEqual(first.name, 'sast_wiz-code-demo_public-demo_sample_partial.csv')
            self.assertEqual(second.name, 'sast_wiz-code-demo_public-demo_sample_partial_2.csv')
            self.assertTrue(first.exists())

    def test_repeated_cursor_and_malformed_page_info_are_rejected(self):
        repeated = SequenceClient([
            connection('repositories', [repository_group()], True, 'same'),
            connection('repositories', [repository_group()], True, 'same'),
        ])
        with self.assertRaisesRegex(RuntimeError, 'repeated pagination cursor'):
            wz.get_sast_repositories(repeated, 1)
        malformed = SequenceClient([{'findings': {'nodes': [], 'pageInfo': None}}])
        with self.assertRaisesRegex(RuntimeError, 'Missing/malformed'):
            wz.fetch_connection(malformed, '', {}, 'findings', 10, 0)
        missing_cursor = SequenceClient([connection('findings', [], True)])
        with self.assertRaisesRegex(RuntimeError, 'Missing/repeated pagination cursor'):
            wz.fetch_connection(missing_cursor, '', {}, 'findings', 10, 0)

    def test_graphql_failure_does_not_create_csv(self):
        client = SequenceClient([RuntimeError('GraphQL query rejected')])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'GraphQL query rejected'):
                wz.export(client, 'sast', 'code_repository', REPO_NAME, [REPO_ID],
                          10, 0, {}, Path(directory))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_repository_group_graphql_failure_is_propagated(self):
        client = SequenceClient([RuntimeError('GraphQL query rejected')])
        with self.assertRaisesRegex(RuntimeError, 'GraphQL query rejected'):
            wz.select_sast_repository(client, 10)

    def test_mismatched_finding_repository_refuses_csv(self):
        finding = sast_finding('xss', 'XSS', 51)
        finding['repository']['id'] = 'other-repository'
        client = SequenceClient([connection('findings', [finding])])
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'does not match'):
                wz.export(client, 'sast', 'code_repository', REPO_NAME, [REPO_ID],
                          10, 0, {}, Path(directory))
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_existing_vulnerability_and_ungrouped_sast_plans_remain(self):
        vuln_query, vuln_vars, _, _ = wz.prepare_plan('vulnerability', 'all', [], {})
        sast_query, sast_vars, _, _ = wz.prepare_plan('sast', 'all', [], {})
        self.assertIn('vulnerabilityFindings', vuln_query)
        self.assertEqual(vuln_vars, {'filterBy': {}})
        self.assertIn('sastFindings', sast_query)
        self.assertNotIn('$filterBy', sast_query)
        self.assertEqual(sast_vars, {})

    def test_existing_vulnerability_and_ungrouped_sast_exports_remain(self):
        with tempfile.TemporaryDirectory() as directory:
            client = SequenceClient([connection('findings', [{'id': 'v-1', 'name': 'Vulnerability'}])])
            vuln_output = wz.export(client, 'vulnerability', 'project', 'My Project',
                                    ['p-id'], 10, 1, {}, Path(directory))
            self.assertEqual(client.calls[0][1]['filterBy'], {'projectId': ['p-id']})
            with vuln_output.open(encoding='utf-8-sig', newline='') as file:
                self.assertEqual(list(csv.DictReader(file))[0]['name'], 'Vulnerability')
            client = SequenceClient([connection('findings', [{'id': 's-1'}])])
            sast_output = wz.export(client, 'sast', 'all', 'all_accessible', [],
                                    10, 1, {}, Path(directory))
            self.assertNotIn('filterBy', client.calls[0][1])
            with sast_output.open(encoding='utf-8-sig', newline='') as file:
                reader = csv.DictReader(file)
                self.assertEqual(reader.fieldnames,
                                 ['finding_category', 'group_type', 'group_name', 'id'])
                self.assertEqual(list(reader)[0]['id'], 's-1')

    def test_existing_profile_filter_mapping_remains(self):
        profile = {'secrets': {'query': 'queries/vulnerability_filtered.graphql',
                               'group_filter_fields': {'project': 'projectId'}}}
        query, variables, label, key = wz.prepare_plan('secrets', 'project', ['p-id'], profile)
        self.assertIn('vulnerabilityFindings', query)
        self.assertEqual(variables, {'filterBy': {'projectId': ['p-id']}})
        self.assertEqual((label, key), ('secrets', 'projectId'))

if __name__ == '__main__': unittest.main()
