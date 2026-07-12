from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from obfuscator import (
    _rewrite_fabric_value,
    _rewrite_manifest,
    _rewrite_yaml,
    inspect_jar,
    normalize_class_reference,
    parse_mapping,
)


class ObfuscatorTests(unittest.TestCase):
    def test_normalize_class_reference(self):
        self.assertEqual(normalize_class_reference("com.example.Main::init"), "com.example.Main")
        self.assertEqual(normalize_class_reference("com/example/Main.class"), "com.example.Main")
        self.assertIsNone(normalize_class_reference("not-a-class"))

    def test_inspects_paper_plugin(self):
        with tempfile.TemporaryDirectory() as directory:
            jar_path = Path(directory) / "plugin.jar"
            with zipfile.ZipFile(jar_path, "w") as jar:
                jar.writestr("plugin.yml", "name: Demo\nmain: com.example.DemoPlugin\nversion: 1.0\n")
                jar.writestr("com/example/DemoPlugin.class", b"not-real-bytecode")
                jar.writestr("META-INF/OLD.SF", b"signature")
            inspection = inspect_jar(jar_path)
            self.assertIn("Bukkit / Spigot", inspection.frameworks)
            self.assertEqual(inspection.entry_classes, ["com.example.DemoPlugin"])
            self.assertIn("META-INF/OLD.SF", inspection.signed_entries_removed)

    def test_inspects_fabric_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            jar_path = Path(directory) / "mod.jar"
            payload = {
                "schemaVersion": 1,
                "id": "demo",
                "entrypoints": {
                    "main": ["com.example.Main", {"adapter": "default", "value": "com.example.Other::start"}]
                },
            }
            with zipfile.ZipFile(jar_path, "w") as jar:
                jar.writestr("fabric.mod.json", json.dumps(payload))
                jar.writestr("com/example/Main.class", b"x")
                jar.writestr("com/example/Other.class", b"x")
            inspection = inspect_jar(jar_path)
            self.assertEqual(set(inspection.entry_classes), {"com.example.Main", "com.example.Other"})

    def test_rewrites_metadata(self):
        mapping = {"com.example.Main": "o.a"}
        yaml_text = "name: Demo\nmain: com.example.Main # entry\n"
        self.assertIn("main: o.a # entry", _rewrite_yaml(yaml_text, mapping))
        manifest = b"Manifest-Version: 1.0\r\nMain-Class: com.example.Main\r\n\r\n"
        self.assertIn(b"Main-Class: o.a", _rewrite_manifest(manifest, mapping))
        fabric = ["com.example.Main", {"value": "com.example.Main::init"}]
        self.assertEqual(_rewrite_fabric_value(fabric, mapping), ["o.a", {"value": "o.a::init"}])

    def test_parse_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mapping.txt"
            path.write_text("com.example.Main -> o.a:\n    int field -> a\n", encoding="utf-8")
            self.assertEqual(parse_mapping(path), {"com.example.Main": "o.a"})


if __name__ == "__main__":
    unittest.main()
