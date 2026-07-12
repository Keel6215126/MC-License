from pathlib import Path
import tempfile
import unittest
import zipfile

from license_injector import LicenseInjectionError, PLUGIN_ID_RE, validate_licensed_jar


class LicenseInjectorTests(unittest.TestCase):
    def test_plugin_id_format(self):
        self.assertIsNotNone(PLUGIN_ID_RE.fullmatch("3gd7u9r4"))
        self.assertIsNone(PLUGIN_ID_RE.fullmatch("short"))
        self.assertIsNone(PLUGIN_ID_RE.fullmatch("bad-id!!"))

    def test_validation_requires_json_and_mclicense(self):
        with tempfile.TemporaryDirectory() as directory:
            jar = Path(directory) / "test.jar"
            with zipfile.ZipFile(jar, "w") as out:
                out.writestr("META-INF/mclicense-implementer.properties", "x=y")
                out.writestr("org/mclicense/library/MCLicense.class", b"x")
            with self.assertRaises(LicenseInjectionError):
                validate_licensed_jar(jar)

    def test_validation_accepts_required_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            jar = Path(directory) / "test.jar"
            with zipfile.ZipFile(jar, "w") as out:
                out.writestr("META-INF/mclicense-implementer.properties", "x=y")
                out.writestr("org/mclicense/library/MCLicense.class", b"x")
                out.writestr("org/json/JSONObject.class", b"x")
            validate_licensed_jar(jar)


if __name__ == "__main__":
    unittest.main()
