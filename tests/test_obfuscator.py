from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from obfuscator import (
    _rewrite_fabric_value,
    _rewrite_manifest,
    _rewrite_service_resource,
    _rewrite_yaml,
    generate_skid_config,
    generate_yguard_build,
    inspect_jar,
    normalize_class_reference,
    normalize_engine,
    parse_mapping,
    parse_yguard_mapping,
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

    def test_engine_aliases(self):
        self.assertEqual(normalize_engine("skidfuscator"), "skid")
        self.assertEqual(normalize_engine("y-guard"), "yguard")
        with self.assertRaises(Exception):
            normalize_engine("unknown")

    def test_skid_safe_config_exempts_entry_class(self):
        with tempfile.TemporaryDirectory() as directory:
            inspection = inspect_jar(self._plugin_jar(Path(directory) / "plugin.jar"))
            config = generate_skid_config(Path(directory), inspection, "safe").read_text(encoding="utf-8")
            self.assertIn(r"class{^com/example/DemoPlugin$}", config)
            self.assertIn("flowException", config)
            self.assertIn("enabled=false", config)

    def test_yguard_mapping_is_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "yguard.xml"
            path.write_text(
                '<yguard><map>'
                '<package name="com" map="A"/>'
                '<package name="com.example" map="B"/>'
                '<class name="com.example.Main" map="C"/>'
                '<class name="com.example.Main$Inner" map="D"/>'
                '</map></yguard>',
                encoding="utf-8",
            )
            self.assertEqual(
                parse_yguard_mapping(path),
                {"com.example.Main": "A.B.C", "com.example.Main$Inner": "A.B.C$D"},
            )

    def test_service_loader_metadata_rewrite(self):
        name, data = _rewrite_service_resource(
            "META-INF/services/com.example.Service",
            b"com.example.Provider\n# keep\n",
            {"com.example.Service": "o.A", "com.example.Provider": "o.B"},
        )
        self.assertEqual(name, "META-INF/services/o.A")
        self.assertIn(b"o.B", data)
        self.assertIn(b"# keep", data)

    def test_yguard_build_contains_dependencies_and_keep_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            jar_path = self._plugin_jar(root / "plugin.jar")
            dependency = root / "dependency.jar"
            with zipfile.ZipFile(dependency, "w") as jar:
                jar.writestr("Dependency.class", b"x")
            fake_lib = root / "yguard-lib"
            fake_lib.mkdir()
            (fake_lib / "yguard-5.0.0.jar").write_bytes(b"jar")
            import os
            old = os.environ.get("YGUARD_LIB_DIR")
            os.environ["YGUARD_LIB_DIR"] = str(fake_lib)
            try:
                inspection = inspect_jar(jar_path)
                build = generate_yguard_build(jar_path, root / "out.jar", root, inspection, "strong", [dependency])
            finally:
                if old is None:
                    os.environ.pop("YGUARD_LIB_DIR", None)
                else:
                    os.environ["YGUARD_LIB_DIR"] = old
            text = build.read_text(encoding="utf-8")
            self.assertIn("com.example.DemoPlugin", text)
            self.assertIn(str(dependency.resolve()), text)
            self.assertIn('naming-scheme" value="mix', text)

    @staticmethod
    def _plugin_jar(path: Path) -> Path:
        with zipfile.ZipFile(path, "w") as jar:
            jar.writestr("plugin.yml", "name: Demo\nmain: com.example.DemoPlugin\nversion: 1.0\n")
            jar.writestr("com/example/DemoPlugin.class", b"x")
        return path


if __name__ == "__main__":
    unittest.main()
