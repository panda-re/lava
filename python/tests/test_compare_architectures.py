"""Offline comparison invariants, independent of database insertion order."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from pyroclastic.utils.compare_architectures import (
    TABLES, compare, load_site_map, main, normalize, read_snapshot)


def fixture(arch='arm', shift=0):
    """Build a minimal internally linked snapshot, optionally renumbering all IDs."""
    def loc():
        """Return a source range shared by the test lvalue and attack point."""
        return dict(loc_filename='toy.c', loc_begin_line=1, loc_begin_column=1,
                    loc_end_line=1, loc_end_column=5)
    return dict(tables=dict(
        filetaint=[dict(id=1+shift, filename='/old/inputs/seed', sha256='hash',
                       command='toy {input_file}', architecture=arch, complete=True)],
        sourcelval=[dict(id=2+shift, ast_name='value', **loc())],
        attackpoint=[dict(id=3+shift, type=0, **loc())],
        labelset=[dict(id=4+shift, ptr=900+shift, inputfile=1+shift, labels=[0, 1])],
        dua=[dict(id=5+shift, inputfile=1+shift, lval=2+shift, trace_index=1,
                  fake_dua=False, length=4, byte_tcn=[0]*4, all_labels=[0, 1],
                  max_tcn=0, max_cardinality=2)],
        dua_viable_bytes=[dict(object_id=5+shift, index=i, value=4+shift) for i in range(4)],
        atp_execution=[dict(id=6+shift, inputfile=1+shift, atp=3+shift, trace_index=1)]))


class ArchitectureComparisonTests(unittest.TestCase):
    def test_renumbered_ids_and_pointer_values_do_not_change_comparison(self):
        """Identical semantics survive different target names, IDs, and row order."""
        left = normalize(fixture(), 'arm', 'toy {input_file}')
        snapshot = fixture('aarch64', 100)
        for rows in snapshot['tables'].values():
            rows.reverse()
        right = normalize(snapshot, 'aarch64', 'toy {input_file}')
        for population in compare(left, right)['populations'].values():
            self.assertEqual(population['changed'], [])
            self.assertEqual(population['left_only'], [])
            self.assertEqual(population['right_only'], [])

    def test_mixed_database_matches_separate_slices(self):
        """Merging noncolliding rows does not change either architecture slice."""
        a, b = fixture(), fixture('aarch64', 100)
        mixed = dict(tables={table: a['tables'][table]+b['tables'][table] for table in TABLES})
        for arch, original in [('arm', a), ('aarch64', b)]:
            self.assertEqual(normalize(mixed, arch, 'toy {input_file}'),
                             normalize(original, arch, 'toy {input_file}'))

    def test_payload_width_change_is_visible(self):
        """Observed width is compared separately from source and DUA identity."""
        a, b = fixture(), fixture('aarch64')
        b['tables']['dua'][0]['length'] = 8
        b['tables']['dua'][0]['byte_tcn'] += [0]*4
        result = compare(normalize(a, 'arm', 'toy {input_file}'),
                         normalize(b, 'aarch64', 'toy {input_file}'))
        self.assertEqual(len(result['populations']['duas']['changed']), 1)
        self.assertEqual(result['populations']['source_lvals']['changed'], [])

    def test_ambiguous_input_is_reported_and_excluded(self):
        """Equal basenames and hashes must not silently collapse different inputs."""
        snapshot = fixture()
        other = dict(snapshot['tables']['filetaint'][0], id=99, filename='/other/seed')
        snapshot['tables']['filetaint'].append(other)
        result = normalize(snapshot, 'arm', 'toy {input_file}')
        self.assertEqual(result['issues'][0]['kind'], 'ambiguous_input')
        self.assertEqual(result['duas'], {})

    def test_duplicate_dua_identity_is_not_overwritten(self):
        """Repeated source-trace keys remain explicitly ambiguous."""
        snapshot = fixture()
        snapshot['tables']['dua'].append(dict(snapshot['tables']['dua'][0], id=99))
        result = normalize(snapshot, 'arm', 'toy {input_file}')
        compared = compare(result, result)['populations']['duas']
        self.assertEqual(len(compared['ambiguous']), 1)
        self.assertEqual(compared['changed'], [])

    def test_cross_input_label_reference_is_flagged(self):
        """A label-set ID cannot hide incorrect FileTaint ownership."""
        snapshot = fixture()
        snapshot['tables']['labelset'][0]['inputfile'] = 999
        result = normalize(snapshot, 'arm', 'toy {input_file}')
        self.assertEqual({issue['kind'] for issue in result['issues']}, {'invalid_labelset_owner'})

    def test_explicit_site_mapping_handles_shifted_locations(self):
        """Source alignment happens only through a supplied correspondence."""
        a, b = fixture(), fixture('aarch64')
        for table in ['sourcelval', 'attackpoint']:
            b['tables'][table][0]['loc_begin_line'] = 20
            b['tables'][table][0]['loc_end_line'] = 20
        with tempfile.TemporaryDirectory() as directory:
            mapping = Path(directory)/'sites.json'
            mapping.write_text(json.dumps([
                dict(architecture='arm', location=['toy.c', 1, 1, 1, 5], site='expression'),
                dict(architecture='aarch64', location=['toy.c', 20, 1, 20, 5], site='expression')]))
            sites = load_site_map(mapping)
        result = compare(normalize(a, 'arm', 'toy {input_file}', sites),
                         normalize(b, 'aarch64', 'toy {input_file}', sites))
        self.assertEqual(result['populations']['duas']['shared'], 1)
        self.assertEqual(result['populations']['duas']['changed'], [])

    def test_cli_offline_report_and_explicit_legacy_provenance(self):
        """Offline mode writes complete reports and honors known legacy provenance."""
        with tempfile.TemporaryDirectory() as directory:
            args = []
            for arch in ['arm', 'aarch64']:
                snapshot = fixture(arch)
                del snapshot['tables']['filetaint'][0]['architecture']
                snapshot['manifest'] = dict(architecture=arch)
                path = Path(directory)/f'{arch}.json'
                path.write_text(json.dumps(snapshot))
                args += ['--snapshot', str(path)]
            output = Path(directory)/'report'
            main(args + ['-o', str(output)])
            report = json.loads((output/'comparison.json').read_text())
            self.assertEqual(len(report['comparisons']), 1)
            self.assertTrue((output/'report.md').is_file())
            unknown = fixture()
            del unknown['tables']['filetaint'][0]['architecture']
            path.write_text(json.dumps(unknown))
            with self.assertRaisesRegex(ValueError, 'architecture is unknown'):
                read_snapshot(path)


if __name__ == '__main__':
    unittest.main()
