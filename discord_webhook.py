from __future__ import annotations

import json
import mimetypes
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests


class WebhookDeliveryError(RuntimeError):
    """Raised when an uploaded file could not be delivered to Discord."""


@dataclass(frozen=True)
class DiscordWebhookConfig:
    url: str
    username: str = "Plugin Protector Uploads"
    avatar_url: str = ""
    timeout_seconds: int = 30
    max_attempts: int = 3
    max_file_bytes: int = 10 * 1024 * 1024

    @property
    def configured(self) -> bool:
        return self.url.startswith("https://discord.com/api/webhooks/") or self.url.startswith(
            "https://discordapp.com/api/webhooks/"
        )


def _safe_text(value: str, limit: int = 900) -> str:
    text = " ".join(str(value or "").replace("`", "'").split())
    return text[:limit] or "unknown"


def send_uploaded_file(
    config: DiscordWebhookConfig,
    file_path: Path,
    original_filename: str,
    workflow: str,
    upload_kind: str,
    upload_id: str,
) -> None:
    if not config.configured:
        raise WebhookDeliveryError("Discord webhook is not configured correctly.")
    if not file_path.is_file():
        raise WebhookDeliveryError("The uploaded file disappeared before Discord delivery.")

    size = file_path.stat().st_size
    if size > config.max_file_bytes:
        limit_mb = config.max_file_bytes / 1024 / 1024
        raise WebhookDeliveryError(
            f"{original_filename or file_path.name} is too large for the configured Discord attachment limit "
            f"({limit_mb:g} MB). Increase DISCORD_WEBHOOK_MAX_FILE_MB only if your Discord server supports it."
        )

    attachment_name = Path(original_filename or file_path.name).name[:200] or "upload.bin"
    mime_type = mimetypes.guess_type(attachment_name)[0] or "application/octet-stream"
    timestamp = datetime.now(timezone.utc).isoformat()
    payload: dict[str, object] = {
        "username": config.username[:80] or "Plugin Protector Uploads",
        "allowed_mentions": {"parse": []},
        "embeds": [
            {
                "title": "New file uploaded",
                "description": "The original upload is attached before any licensing or obfuscation is performed.",
                "color": 7101695,
                "fields": [
                    {"name": "File", "value": _safe_text(attachment_name), "inline": False},
                    {"name": "Type", "value": _safe_text(upload_kind), "inline": True},
                    {"name": "Workflow", "value": _safe_text(workflow), "inline": True},
                    {"name": "Size", "value": f"{size:,} bytes", "inline": True},
                    {"name": "Upload ID", "value": _safe_text(upload_id), "inline": False},
                ],
                "timestamp": timestamp,
            }
        ],
    }
    if config.avatar_url:
        payload["avatar_url"] = config.avatar_url

    last_error = "Discord rejected the upload."
    for attempt in range(1, max(1, config.max_attempts) + 1):
        try:
            with file_path.open("rb") as handle:
                response = requests.post(
                    config.url,
                    data={"payload_json": json.dumps(payload, separators=(",", ":"))},
                    files={"files[0]": (attachment_name, handle, mime_type)},
                    timeout=config.timeout_seconds,
                )
        except requests.RequestException as exc:
            last_error = f"Discord webhook connection failed: {exc}"
            if attempt < config.max_attempts:
                time.sleep(min(2 ** (attempt - 1), 5))
                continue
            break

        if response.status_code in {200, 204}:
            return

        body = response.text[:500].strip()
        last_error = f"Discord webhook returned HTTP {response.status_code}"
        if body:
            last_error += f": {body}"

        if response.status_code == 429 and attempt < config.max_attempts:
            retry_after = 1.0
            try:
                retry_after = float(response.json().get("retry_after", 1.0))
            except (ValueError, TypeError, json.JSONDecodeError):
                retry_after = 1.0
            time.sleep(max(0.25, min(retry_after, 15.0)))
            continue

        if response.status_code >= 500 and attempt < config.max_attempts:
            time.sleep(min(2 ** (attempt - 1), 5))
            continue
        break

    raise WebhookDeliveryError(last_error)
