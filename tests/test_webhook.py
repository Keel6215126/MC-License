import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from discord_webhook import DiscordWebhookConfig, WebhookDeliveryError, send_uploaded_file


class DiscordWebhookTests(unittest.TestCase):
    def test_upload_uses_attachment_and_disables_mentions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plugin.jar"
            path.write_bytes(b"PK\x03\x04test")
            response = Mock(status_code=204, text="")
            with patch("discord_webhook.requests.post", return_value=response) as post:
                send_uploaded_file(
                    DiscordWebhookConfig(
                        url="https://discord.com/api/webhooks/123/token",
                        max_file_bytes=1024,
                    ),
                    path,
                    "Example.jar",
                    "protect",
                    "main JAR",
                    "upload-123",
                )
            self.assertEqual(post.call_count, 1)
            kwargs = post.call_args.kwargs
            self.assertIn("files[0]", kwargs["files"])
            payload = json.loads(kwargs["data"]["payload_json"])
            self.assertEqual(payload["allowed_mentions"], {"parse": []})
            self.assertEqual(payload["embeds"][0]["fields"][0]["value"], "Example.jar")

    def test_oversized_file_is_rejected_before_request(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.jar"
            path.write_bytes(b"x" * 20)
            with patch("discord_webhook.requests.post") as post:
                with self.assertRaises(WebhookDeliveryError):
                    send_uploaded_file(
                        DiscordWebhookConfig(
                            url="https://discord.com/api/webhooks/123/token",
                            max_file_bytes=10,
                        ),
                        path,
                        "large.jar",
                        "obfuscate",
                        "main JAR",
                        "upload-456",
                    )
            post.assert_not_called()

    def test_non_discord_url_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plugin.jar"
            path.write_bytes(b"test")
            with self.assertRaises(WebhookDeliveryError):
                send_uploaded_file(
                    DiscordWebhookConfig(url="https://example.com/webhook"),
                    path,
                    "plugin.jar",
                    "license",
                    "main JAR",
                    "upload-789",
                )


if __name__ == "__main__":
    unittest.main()
