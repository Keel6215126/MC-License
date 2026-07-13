from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
import shutil
from pathlib import Path
from unittest.mock import patch

from obfuscator import (
    ObfuscationResult,
    _run_skid_hybrid_obfuscation,
    _rewrite_fabric_value,
    _rewrite_manifest,
    _rewrite_service_resource,
    _rewrite_yaml,
    _java_environment,
    _skid_failure_reasons,
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


    def test_skid_stable_config_disables_v3_strings(self):
        with tempfile.TemporaryDirectory() as directory:
            inspection = inspect_jar(self._plugin_jar(Path(directory) / "plugin.jar"))
            config = generate_skid_config(Path(directory), inspection, "strong").read_text(encoding="utf-8")
            self.assertIn("stringEncryption {\n    enabled=false", config)
            self.assertIn("strength=GOOD", config)

    def test_skid_compatibility_profile_disables_risky_flow(self):
        with tempfile.TemporaryDirectory() as directory:
            inspection = inspect_jar(self._plugin_jar(Path(directory) / "plugin.jar"))
            config = generate_skid_config(Path(directory), inspection, "strong", profile="compatibility").read_text(encoding="utf-8")
            self.assertIn("flowException {\n    enabled=false", config)
            self.assertIn("flowRange {\n    enabled=false", config)
            self.assertIn(r"class{^com/example/DemoPlugin$}", config)

    def test_java_environment_replaces_existing_heap(self):
        import os
        previous = os.environ.get("JAVA_TOOL_OPTIONS")
        os.environ["JAVA_TOOL_OPTIONS"] = "-Ddemo=true -Xmx256m"
        try:
            value = _java_environment(1536)["JAVA_TOOL_OPTIONS"]
        finally:
            if previous is None:
                os.environ.pop("JAVA_TOOL_OPTIONS", None)
            else:
                os.environ["JAVA_TOOL_OPTIONS"] = previous
        self.assertIn("-Xmx1536m", value)
        self.assertNotIn("-Xmx256m", value)
        self.assertIn("-XX:+ExitOnOutOfMemoryError", value)

    def test_skid_failure_classification(self):
        reasons = _skid_failure_reasons("BoissinotDestructor StringTransformerV2 OutOfMemoryError")
        self.assertIn("mapleir_ssa_failure", reasons)
        self.assertIn("v3_string_transformer_failure", reasons)
        self.assertIn("java_heap_exhausted", reasons)

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


    def test_skid_hybrid_runs_yguard_before_skid_and_returns_real_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_jar = self._plugin_jar(root / "plugin.jar")

            def stage_files(stage_dir: Path, prefix: str) -> dict[str, Path]:
                stage_dir.mkdir(parents=True, exist_ok=True)
                files = {
                    "mapping": stage_dir / "mapping.txt",
                    "seeds": stage_dir / "seeds.txt",
                    "usage": stage_dir / "usage.txt",
                    "dump": stage_dir / f"{prefix}-map.xml",
                    "config": stage_dir / f"{prefix}-config.conf",
                    "log": stage_dir / f"{prefix}.log",
                    "report": stage_dir / "report.json",
                }
                for key, path in files.items():
                    if key == "report":
                        path.write_text('{"ok": true}\n', encoding="utf-8")
                    elif key == "dump":
                        path.write_text("<map/>\n", encoding="utf-8")
                    else:
                        path.write_text("", encoding="utf-8")
                return files

            def fake_yguard(input_jar, work_dir, output_name, mode, library_jars=(), timeout_seconds=240):
                files = stage_files(work_dir, "yguard")
                output = work_dir / output_name
                with zipfile.ZipFile(output, "w") as jar:
                    jar.writestr("plugin.yml", "name: Demo\nmain: o.A\nversion: 1.0\n")
                    jar.writestr("o/A.class", b"renamed")
                files["mapping"].write_text("com.example.DemoPlugin -> o.A:\n", encoding="utf-8")
                return ObfuscationResult(
                    engine="yguard", output_jar=output, mapping_file=files["mapping"],
                    seeds_file=files["seeds"], usage_file=files["usage"], dump_file=files["dump"],
                    config_file=files["config"], log_file=files["log"], report_file=files["report"],
                    inspection=inspect_jar(input_jar), mapped_entry_classes={"com.example.DemoPlugin": "o.A"},
                    renamed_class_count=1, elapsed_seconds=0.25,
                )

            def fake_skid(input_jar, work_dir, output_name, mode, library_jars=(), timeout_seconds=240):
                files = stage_files(work_dir, "skid")
                output = work_dir / output_name
                shutil.copy2(input_jar, output)
                inspection = inspect_jar(input_jar)
                files["mapping"].write_text("o.A -> o.A:\n", encoding="utf-8")
                return ObfuscationResult(
                    engine="skid", output_jar=output, mapping_file=files["mapping"],
                    seeds_file=files["seeds"], usage_file=files["usage"], dump_file=files["dump"],
                    config_file=files["config"], log_file=files["log"], report_file=files["report"],
                    inspection=inspection, mapped_entry_classes={"o.A": "o.A"},
                    renamed_class_count=0, elapsed_seconds=0.5,
                )

            with patch("obfuscator._run_yguard_obfuscation", side_effect=fake_yguard) as yguard_mock, \
                 patch("obfuscator._run_skid_transform_only", side_effect=fake_skid) as skid_mock:
                result = _run_skid_hybrid_obfuscation(
                    input_jar=input_jar, work_dir=root / "job", output_name="final.jar",
                    mode="strong", timeout_seconds=30,
                )

            self.assertEqual(yguard_mock.call_count, 1)
            self.assertEqual(skid_mock.call_count, 1)
            self.assertEqual(result.renamed_class_count, 1)
            self.assertEqual(parse_mapping(result.mapping_file), {"com.example.DemoPlugin": "o.A"})
            self.assertEqual(result.mapped_entry_classes, {"com.example.DemoPlugin": "o.A"})
            with zipfile.ZipFile(result.output_jar, "r") as jar:
                self.assertIn("o/A.class", jar.namelist())
                self.assertIn("main: o.A", jar.read("plugin.yml").decode("utf-8"))
            report = json.loads(result.report_file.read_text(encoding="utf-8"))
            self.assertEqual(report["pipeline"][0], "yGuard structural renaming")


    def test_skid_hybrid_rejects_zero_rename_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            input_jar = self._plugin_jar(root / "plugin.jar")
            stage = root / "fake-stage"
            stage.mkdir()
            output = stage / "unchanged.jar"
            shutil.copy2(input_jar, output)
            mapping = stage / "mapping.txt"
            mapping.write_text("com.example.DemoPlugin -> com.example.DemoPlugin:\n", encoding="utf-8")
            placeholders = []
            for name in ("seeds.txt", "usage.txt", "dump.xml", "config.xml", "log.txt", "report.json"):
                path = stage / name
                path.write_text("{}" if name == "report.json" else "", encoding="utf-8")
                placeholders.append(path)
            fake_result = ObfuscationResult(
                engine="yguard", output_jar=output, mapping_file=mapping,
                seeds_file=placeholders[0], usage_file=placeholders[1], dump_file=placeholders[2],
                config_file=placeholders[3], log_file=placeholders[4], report_file=placeholders[5],
                inspection=inspect_jar(input_jar),
                mapped_entry_classes={"com.example.DemoPlugin": "com.example.DemoPlugin"},
                renamed_class_count=0, elapsed_seconds=0.1,
            )
            with patch("obfuscator._run_yguard_obfuscation", return_value=fake_result), \
                 patch("obfuscator._run_skid_transform_only") as skid_mock:
                with self.assertRaisesRegex(Exception, "renamed zero classes"):
                    _run_skid_hybrid_obfuscation(
                        input_jar=input_jar, work_dir=root / "job", output_name="final.jar", mode="strong"
                    )
            skid_mock.assert_not_called()

    @staticmethod
    def _plugin_jar(path: Path) -> Path:
        with zipfile.ZipFile(path, "w") as jar:
            jar.writestr("plugin.yml", "name: Demo\nmain: com.example.DemoPlugin\nversion: 1.0\n")
            jar.writestr("com/example/DemoPlugin.class", b"x")
        return path


if __name__ == "__main__":
    unittest.main()
