import io
import unittest
import zipfile
from unittest.mock import patch

import app as webapp


class AppTests(unittest.TestCase):
    def setUp(self):
        webapp.app.config.update(TESTING=True)
        self.client = webapp.app.test_client()

    def test_pages_load(self):
        for path in ["/", "/license", "/obfuscate", "/protect", "/license-check"]:
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200, path)

    def test_protect_rejects_bad_plugin_id(self):
        response = self.client.post("/api/jobs", data={"workflow": "protect", "plugin_id": "bad"})
        self.assertEqual(response.status_code, 400)

    def test_valid_upload_is_blocked_without_required_webhook(self):
        jar = io.BytesIO()
        with zipfile.ZipFile(jar, "w") as archive:
            archive.writestr("Example.class", b"class")
        jar.seek(0)
        response = self.client.post(
            "/api/jobs",
            data={"workflow": "obfuscate", "mode": "strong", "jar": (jar, "Example.jar")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 503)

    def test_main_and_dependency_uploads_are_forwarded(self):
        main_jar = io.BytesIO()
        with zipfile.ZipFile(main_jar, "w") as archive:
            archive.writestr("Example.class", b"class")
        main_jar.seek(0)

        dependency_jar = io.BytesIO()
        with zipfile.ZipFile(dependency_jar, "w") as archive:
            archive.writestr("Dependency.class", b"class")
        dependency_jar.seek(0)

        with patch("app.require_webhook"), patch("app.forward_upload") as forward, patch.object(webapp.executor, "submit"):
            response = self.client.post(
                "/api/jobs",
                data={
                    "workflow": "obfuscate",
                    "mode": "strong",
                    "jar": (main_jar, "Example.jar"),
                    "libraries": (dependency_jar, "Dependency.jar"),
                },
                content_type="multipart/form-data",
            )
        self.assertEqual(response.status_code, 202)
        self.assertEqual(forward.call_count, 2)
        kinds = [call.args[3] for call in forward.call_args_list]
        self.assertEqual(kinds, ["main JAR", "dependency"])


if __name__ == "__main__":
    unittest.main()
