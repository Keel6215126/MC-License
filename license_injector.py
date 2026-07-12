from __future__ import annotations

import json
import os
import re
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path


class LicenseInjectionError(RuntimeError):
    pass


@dataclass
class LicenseInjectionResult:
    output_jar: Path
    original_main: str
    wrapper_main: str
    descriptor: str
    library_classes: int
    signatures_removed: int


PLUGIN_ID_RE = re.compile(r"^[A-Za-z0-9]{8}$")
MARKER_PATH = "META-INF/mclicense-implementer.properties"


def run_license_injection(
    input_jar: Path,
    output_jar: Path,
    plugin_id: str,
    dependency_dir: Path,
    timeout_seconds: int = 45,
) -> LicenseInjectionResult:
    plugin_id = (plugin_id or "").strip()
    if not PLUGIN_ID_RE.fullmatch(plugin_id):
        raise LicenseInjectionError("The MC License plugin ID must be exactly 8 letters and numbers.")
    if not input_jar.is_file():
        raise LicenseInjectionError("The uploaded JAR does not exist.")
    if not dependency_dir.is_dir():
        raise LicenseInjectionError("The MC License runtime dependencies are missing from this deployment.")

    classpath = Path(os.environ.get("MCL_PATCHER_CLASSPATH", Path(__file__).resolve().parent / "java-build"))
    command = [
        os.environ.get("JAVA_CMD", "java"),
        "-cp",
        str(classpath),
        "dev.railguard.patcher.JarPatcher",
        str(input_jar),
        str(output_jar),
        plugin_id,
        str(dependency_dir),
        os.urandom(16).hex(),
    ]

    try:
        completed = subprocess.run(
            command,
            cwd=Path(__file__).resolve().parent,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise LicenseInjectionError("MC License implementation timed out.") from exc

    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "MC License implementation failed.").strip()
        raise LicenseInjectionError(message[-4000:])

    try:
        payload = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise LicenseInjectionError("The MC License processor returned an unreadable result.") from exc

    validate_licensed_jar(output_jar)
    return LicenseInjectionResult(
        output_jar=output_jar,
        original_main=str(payload.get("original_main", "")),
        wrapper_main=str(payload.get("wrapper_main", "")),
        descriptor=str(payload.get("descriptor", "")),
        library_classes=int(payload.get("library_classes", 0)),
        signatures_removed=int(payload.get("signatures_removed", 0)),
    )


def validate_licensed_jar(output_jar: Path) -> None:
    if not output_jar.is_file() or output_jar.stat().st_size == 0:
        raise LicenseInjectionError("The MC License processor did not produce an output JAR.")
    try:
        with zipfile.ZipFile(output_jar, "r") as jar:
            bad = jar.testzip()
            if bad:
                raise LicenseInjectionError(f"The licensed JAR is corrupt near {bad}.")
            names = set(jar.namelist())
            required = {
                MARKER_PATH,
                "org/mclicense/library/MCLicense.class",
                "org/json/JSONObject.class",
            }
            missing = sorted(required - names)
            if missing:
                raise LicenseInjectionError("The licensed JAR is missing runtime classes: " + ", ".join(missing))
    except zipfile.BadZipFile as exc:
        raise LicenseInjectionError("The MC License processor produced an invalid JAR.") from exc


def validate_protected_jar(output_jar: Path, mapping_file: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if mapping_file.is_file():
        for line in mapping_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith((" ", "\t")) or " -> " not in line or not line.endswith(":"):
                continue
            old, new = line[:-1].split(" -> ", 1)
            mapping[old.strip()] = new.strip()

    required_classes = {
        "org.mclicense.library.MCLicense": mapping.get("org.mclicense.library.MCLicense", "org.mclicense.library.MCLicense"),
        "org.json.JSONObject": mapping.get("org.json.JSONObject", "org.json.JSONObject"),
    }
    try:
        with zipfile.ZipFile(output_jar, "r") as jar:
            names = set(jar.namelist())
            if MARKER_PATH not in names:
                raise LicenseInjectionError("The protected JAR lost its MC License implementation marker.")
            missing = [original for original, mapped in required_classes.items() if mapped.replace(".", "/") + ".class" not in names]
            if missing:
                raise LicenseInjectionError("The protected JAR lost required licensing classes: " + ", ".join(missing))
    except zipfile.BadZipFile as exc:
        raise LicenseInjectionError("The protected output is not a valid JAR.") from exc
    return required_classes
