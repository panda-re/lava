"""ARM compact base-register locations must retain their signed operands."""
import unittest

from pyroclastic.taint.dwarfdump import reprocess_ops


class ARMLocationTests(unittest.TestCase):
    def test_compact_offsets(self):
        cases = {
            'DW_OP_breg13+148': ['DW_OP_breg13', 148],
            'DW_OP_breg31+60': ['DW_OP_breg31', 60],
            'DW_OP_breg29-8': ['DW_OP_breg29', -8],
            'DW_OP_breg0+0': ['DW_OP_breg0', 0],
            'DW_OP_breg12+0x20': ['DW_OP_breg12', 32],
            'DW_OP_breg30-0x10': ['DW_OP_breg30', -16],
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(reprocess_ops([source], arm_locations=True), expected)

    def test_separate_operands_unchanged(self):
        source = ['DW_OP_breg31', '-24', 'DW_OP_plus_uconst', '0x10']
        expected = ['DW_OP_breg31', -24, 'DW_OP_plus_uconst', 16]
        self.assertEqual(reprocess_ops(source, arm_locations=True), expected)
        self.assertEqual(reprocess_ops(source), expected)

    def test_other_architectures_keep_existing_parsing(self):
        self.assertEqual(reprocess_ops(['DW_OP_breg31+60']), ['DW_OP_breg31+60'])

    def test_register_and_frame_operations_unchanged(self):
        self.assertEqual(reprocess_ops(['DW_OP_reg29'], arm_locations=True), ['DW_OP_reg29'])
        self.assertEqual(reprocess_ops(['DW_OP_fbreg', '-32'], arm_locations=True),
                         ['DW_OP_fbreg', -32])


if __name__ == '__main__':
    unittest.main()
