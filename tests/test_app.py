import unittest

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


if __name__ == "__main__":
    unittest.main()
