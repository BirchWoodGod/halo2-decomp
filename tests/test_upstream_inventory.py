"""Inventory comparison must keep external claims separate from local coverage."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "comparison", Path(__file__).resolve().parents[1] / "scripts/compare-upstream-inventory.py")
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class InventoryComparisonTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.inventory = root / "functions.csv"
        self.catalog = root / "abi.json"
        self.catalog.write_text(json.dumps(dict(
            xbe_sha256=comparison.EXPECTED_XBE,
            functions=[dict(address="1000", name="local_a"),
                       dict(address="2000", name="local_b"),
                       dict(address="9000", name="local_missing")])) )
        self.inventory.write_text(
            "va,size,owner,source,status,calls,name,object\n"
            "1000,10,game,src/a.cpp,matched,,atlas_name,atlas_object\n"
            "2000,20,game,,todo,,,\n"
            "3000,30,game,src/c.cpp,matched,1000 4000,,\n"
            "4000,40,xdk:libcmt,src/d.cpp,matched,,,\n")

    def run_comparison(self):
        return comparison.compare(self.inventory, [self.catalog], "a" * 40)

    def test_partition_and_dependencies(self):
        result = self.run_comparison()
        self.assertEqual(result["local_routines"], 3)
        self.assertEqual(result["upstream_reported_matches"], 3)
        self.assertEqual([r["address"] for r in result["shared_reported_matches"]], ["00001000"])
        self.assertEqual([r["address"] for r in result["local_without_upstream_match"]], ["00002000"])
        self.assertEqual(result["local_missing_from_upstream"], ["00009000"])
        self.assertEqual(len(result["upstream_game_candidates"]), 1)
        self.assertEqual(result["upstream_game_candidates"][0]["callees_outside_local_catalog"], ["00004000"])
        self.assertNotIn("atlas_name", json.dumps(result))
        self.assertNotIn("atlas_object", json.dumps(result))

    def test_wrong_xbe_rejected(self):
        self.catalog.write_text('{"xbe_sha256":"wrong","functions":[]}')
        with self.assertRaisesRegex(ValueError, "different XBE"):
            self.run_comparison()

    def test_duplicate_upstream_rejected(self):
        with self.inventory.open("a") as output:
            output.write("1000,10,game,,todo,,,\n")
        with self.assertRaisesRegex(ValueError, "duplicate upstream"):
            self.run_comparison()

    def test_duplicate_local_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate local"):
            comparison.compare(self.inventory, [self.catalog, self.catalog], "a" * 40)


if __name__ == "__main__":
    unittest.main()
