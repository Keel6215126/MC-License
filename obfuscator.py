from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
import zipfile
import xml.etree.ElementTree as ET
from xml.sax.saxutils import quoteattr
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


SIGNATURE_RE = re.compile(r"^META-INF/(?:[^/]+\.(?:SF|RSA|DSA|EC)|SIG-[^/]+)$", re.IGNORECASE)
CLASS_NAME_RE = re.compile(r"^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*$")


class ObfuscationError(RuntimeError):
    pass


@dataclass
class JarInspection:
    frameworks: list[str] = field(default_factory=list)
    entry_classes: list[str] = field(default_factory=list)
    entry_methods: dict[str, list[str]] = field(default_factory=dict)
    metadata_resources: list[str] = field(default_factory=list)
    class_count: int = 0
    resource_count: int = 0
    signed_entries_removed: list[str] = field(default_factory=list)

    def add_framework(self, name: str) -> None:
        if name not in self.frameworks:
            self.frameworks.append(name)

    def add_entry(self, class_name: str | None, method_name: str | None = None) -> None:
        if not class_name:
            return
        normalized = normalize_class_reference(class_name)
        if normalized and normalized not in self.entry_classes:
            self.entry_classes.append(normalized)
        if normalized and method_name:
            clean_method = method_name.strip()
            if re.match(r"^[A-Za-z_$][\w$]*$", clean_method):
                methods = self.entry_methods.setdefault(normalized, [])
                if clean_method not in methods:
                    methods.append(clean_method)

    def add_metadata(self, resource: str) -> None:
        if resource not in self.metadata_resources:
            self.metadata_resources.append(resource)


@dataclass
class ObfuscationResult:
    engine: str
    output_jar: Path
    mapping_file: Path
    seeds_file: Path
    usage_file: Path
    dump_file: Path
    config_file: Path
    log_file: Path
    report_file: Path
    inspection: JarInspection
    mapped_entry_classes: dict[str, str]
    renamed_class_count: int
    elapsed_seconds: float


def normalize_class_reference(value: str) -> str | None:
    value = value.strip().strip('"\'')
    if not value:
        return None
    if "::" in value:
        value = value.split("::", 1)[0]
    value = value.replace("/", ".")
    if value.endswith(".class"):
        value = value[:-6]
    return value if CLASS_NAME_RE.match(value) else None


def _decode(data: bytes) -> str:
    return data.decode("utf-8-sig", errors="replace")


def _parse_manifest(text: str) -> dict[str, str]:
    attrs: dict[str, str] = {}
    current: str | None = None
    for raw_line in text.replace("\r\n", "\n").split("\n"):
        if raw_line.startswith(" ") and current:
            attrs[current] += raw_line[1:]
            continue
        if ":" not in raw_line:
            current = None
            continue
        key, value = raw_line.split(":", 1)
        current = key.strip()
        attrs[current] = value.strip()
    return attrs


def _yaml_top_level_classes(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    pattern = re.compile(
        r"^(?P<indent>\s*)(?P<key>main|bootstrapper|loader)\s*:\s*(?P<quote>[\"']?)(?P<value>[^\s#\"']+)(?P=quote)(?:\s*(?:#.*)?)$",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        if match.group("indent"):
            continue
        value = normalize_class_reference(match.group("value"))
        if value:
            found[match.group("key")] = value
    return found


def _collect_fabric_entries(value: Any, output: set[tuple[str, str | None]]) -> None:
    if isinstance(value, str):
        method_name: str | None = None
        class_value = value
        if "::" in value:
            class_value, method_name = value.split("::", 1)
        normalized = normalize_class_reference(class_value)
        if normalized:
            output.add((normalized, method_name))
    elif isinstance(value, list):
        for item in value:
            _collect_fabric_entries(item, output)
    elif isinstance(value, dict):
        if isinstance(value.get("value"), str):
            _collect_fabric_entries(value["value"], output)
        else:
            for item in value.values():
                _collect_fabric_entries(item, output)


def inspect_jar(
    jar_path: Path,
    max_entries: int = 100_000,
    max_uncompressed_bytes: int = 1024 * 1024 * 1024,
    max_single_entry_bytes: int = 512 * 1024 * 1024,
) -> JarInspection:
    inspection = JarInspection()
    try:
        with zipfile.ZipFile(jar_path, "r") as jar:
            infos = jar.infolist()
            if len(infos) > max_entries:
                raise ObfuscationError(f"JAR has too many entries ({len(infos):,}; limit {max_entries:,}).")
            total_uncompressed = sum(info.file_size for info in infos)
            if total_uncompressed > max_uncompressed_bytes:
                raise ObfuscationError("The JAR expands beyond the allowed uncompressed-size limit.")
            oversized = next((info for info in infos if info.file_size > max_single_entry_bytes), None)
            if oversized:
                raise ObfuscationError(f"JAR entry is too large: {oversized.filename}")
            suspicious = next(
                (
                    info
                    for info in infos
                    if info.file_size > 50 * 1024 * 1024
                    and info.compress_size > 0
                    and info.file_size / info.compress_size > 1000
                ),
                None,
            )
            if suspicious:
                raise ObfuscationError(f"JAR has a suspicious compression ratio: {suspicious.filename}")
            bad = jar.testzip()
            if bad:
                raise ObfuscationError(f"JAR is corrupt near entry: {bad}")

            names = set(jar.namelist())
            inspection.class_count = sum(name.endswith(".class") for name in names)
            inspection.resource_count = len(names) - inspection.class_count
            if inspection.class_count == 0:
                raise ObfuscationError("The uploaded file contains no .class files.")

            for name in names:
                if SIGNATURE_RE.match(name):
                    inspection.signed_entries_removed.append(name)

            yaml_candidates = {
                "plugin.yml": "Bukkit / Spigot",
                "paper-plugin.yml": "Paper",
                "bungee.yml": "BungeeCord",
            }
            for resource, framework in yaml_candidates.items():
                if resource in names:
                    inspection.add_framework(framework)
                    inspection.add_metadata(resource)
                    for class_name in _yaml_top_level_classes(_decode(jar.read(resource))).values():
                        inspection.add_entry(class_name)

            velocity_candidates = ["velocity-plugin.json", "META-INF/velocity-plugin.json"]
            for resource in velocity_candidates:
                if resource in names:
                    inspection.add_framework("Velocity")
                    inspection.add_metadata(resource)
                    try:
                        payload = json.loads(_decode(jar.read(resource)))
                        inspection.add_entry(payload.get("main"))
                    except json.JSONDecodeError as exc:
                        raise ObfuscationError(f"Invalid {resource}: {exc}") from exc

            if "fabric.mod.json" in names:
                inspection.add_framework("Fabric")
                inspection.add_metadata("fabric.mod.json")
                try:
                    payload = json.loads(_decode(jar.read("fabric.mod.json")))
                    entries: set[tuple[str, str | None]] = set()
                    _collect_fabric_entries(payload.get("entrypoints", {}), entries)
                    for class_name, method_name in sorted(entries, key=lambda item: (item[0], item[1] or "")):
                        inspection.add_entry(class_name, method_name)
                except json.JSONDecodeError as exc:
                    raise ObfuscationError(f"Invalid fabric.mod.json: {exc}") from exc

            if "META-INF/mods.toml" in names:
                inspection.add_framework("Forge")
                inspection.add_metadata("META-INF/mods.toml")
            if "META-INF/neoforge.mods.toml" in names:
                inspection.add_framework("NeoForge")
                inspection.add_metadata("META-INF/neoforge.mods.toml")

            manifest_name = "META-INF/MANIFEST.MF"
            if manifest_name in names:
                attrs = _parse_manifest(_decode(jar.read(manifest_name)))
                main_class = attrs.get("Main-Class")
                start_class = attrs.get("Start-Class")
                if start_class:
                    inspection.add_framework("Spring Boot")
                    inspection.add_entry(start_class)
                    inspection.add_metadata(manifest_name)
                elif main_class:
                    inspection.add_framework("Executable JAR")
                    inspection.add_entry(main_class)
                    inspection.add_metadata(manifest_name)

            service_resources = sorted(
                name for name in names if name.startswith("META-INF/services/") and not name.endswith("/")
            )
            if service_resources:
                inspection.add_framework("Java ServiceLoader")
                for resource in service_resources:
                    inspection.add_metadata(resource)

    except zipfile.BadZipFile as exc:
        raise ObfuscationError("The uploaded file is not a valid JAR/ZIP archive.") from exc

    if not inspection.frameworks:
        inspection.frameworks.append("Generic Java JAR")
    return inspection


def _pg_path(path: Path) -> str:
    return "'" + str(path.resolve()).replace("'", "\\'") + "'"


def discover_jmods() -> list[Path]:
    java_home = os.environ.get("JAVA_HOME")
    candidates: list[Path] = []
    if java_home:
        candidates.append(Path(java_home) / "jmods")
    java_bin = shutil.which("java")
    if java_bin:
        resolved = Path(java_bin).resolve()
        candidates.extend([resolved.parent.parent / "jmods", resolved.parent.parent.parent / "jmods"])
    candidates.extend([Path("/opt/java/openjdk/jmods"), Path("/usr/lib/jvm/default-java/jmods")])
    for directory in candidates:
        if directory.is_dir():
            return sorted(directory.glob("*.jmod"))
    return []


def generate_proguard_config(
    input_jar: Path,
    output_jar: Path,
    work_dir: Path,
    inspection: JarInspection,
    mode: str,
    library_jars: Iterable[Path] = (),
) -> Path:
    if mode not in {"safe", "strong"}:
        raise ObfuscationError("Mode must be 'safe' or 'strong'.")

    mapping_file = work_dir / "mapping.txt"
    seeds_file = work_dir / "seeds.txt"
    usage_file = work_dir / "usage.txt"
    dump_file = work_dir / "dump.txt"
    config_file = work_dir / "generated-config.pro"

    lines = [
        f"-injars {_pg_path(input_jar)}",
        f"-outjars {_pg_path(output_jar)}",
        "",
        "# Universal compatibility defaults: rename only; do not delete or optimize code.",
        "-dontshrink",
        "-dontoptimize",
        "-ignorewarnings",
        "-dontwarn **",
        "-dontnote",
        "-keepdirectories",
        "-adaptclassstrings",
        "-adaptresourcefilenames META-INF/services/**",
        "-adaptresourcefilecontents META-INF/services/**,META-INF/spring/**,META-INF/spring.factories,META-INF/MANIFEST.MF,plugin.yml,paper-plugin.yml,bungee.yml,velocity-plugin.json,META-INF/velocity-plugin.json,fabric.mod.json",
        "-keepattributes Exceptions,InnerClasses,Signature,Deprecated,SourceFile,LineNumberTable,*Annotation*,EnclosingMethod,MethodParameters,Record,PermittedSubclasses,NestHost,NestMembers",
        "-renamesourcefileattribute Source",
        "",
        "# Keep names that runtimes commonly invoke by reflection or fixed convention.",
        "-keepclassmembernames class * {",
        "    public static void main(java.lang.String[]);",
        "    public void onLoad();",
        "    public void onEnable();",
        "    public void onDisable();",
        "    public void onInitialize();",
        "    public void onInitializeClient();",
        "    public void onInitializeServer();",
        "    public void bootstrap(...);",
        "    public *** createPlugin(...);",
        "    public void classloader(...);",
        "    public boolean onCommand(org.bukkit.command.CommandSender, org.bukkit.command.Command, java.lang.String, java.lang.String[]);",
        "    public java.util.List onTabComplete(org.bukkit.command.CommandSender, org.bukkit.command.Command, java.lang.String, java.lang.String[]);",
        "}",
        "-keepclasseswithmembernames,includedescriptorclasses class * {",
        "    native <methods>;",
        "}",
        "-keepclassmembernames enum * {",
        "    public static final ** *;",
        "    public static **[] values();",
        "    public static ** valueOf(java.lang.String);",
        "}",
        "-keepclassmembers class * implements java.io.Serializable {",
        "    private static final long serialVersionUID;",
        "    private void writeObject(java.io.ObjectOutputStream);",
        "    private void readObject(java.io.ObjectInputStream);",
        "    java.lang.Object writeReplace();",
        "    java.lang.Object readResolve();",
        "}",
    ]

    if mode == "safe":
        lines.extend([
            "",
            "# Safe mode keeps detected launch classes and their members unchanged.",
        ])
        for class_name in inspection.entry_classes:
            lines.append(f"-keep class {class_name} {{ *; }}")
    else:
        lines.extend([
            "",
            "# Strong mode repackages renamed classes and reuses short member names.",
            "-repackageclasses 'o'",
            "-allowaccessmodification",
            "-useuniqueclassmembernames",
            "",
            "# Entry class names may change; metadata is rewritten after ProGuard finishes.",
        ])
        for class_name in inspection.entry_classes:
            lines.extend([
                f"-keepclassmembernames class {class_name} {{",
                "    public <init>(...);",
                "    public void onLoad();",
                "    public void onEnable();",
                "    public void onDisable();",
                "    public void onInitialize();",
                "    public void onInitializeClient();",
                "    public void onInitializeServer();",
                "    public static void main(java.lang.String[]);",
            ])
            for method_name in inspection.entry_methods.get(class_name, []):
                lines.append(f"    *** {method_name}(...);")
            lines.append("}")

    jmods = discover_jmods()
    lines.append("")
    lines.append("# Java runtime libraries")
    if jmods:
        for jmod in jmods:
            lines.append(f"-libraryjars {_pg_path(jmod)}(!**.jar;!module-info.class)")
    else:
        lines.append("# No JMOD directory was found. Missing references will be ignored.")

    valid_libraries = [path for path in library_jars if path.is_file()]
    if valid_libraries:
        lines.append("")
        lines.append("# User-supplied dependency libraries")
        for library in valid_libraries:
            lines.append(f"-libraryjars {_pg_path(library)}")

    lines.extend([
        "",
        f"-printmapping {_pg_path(mapping_file)}",
        f"-printseeds {_pg_path(seeds_file)}",
        f"-printusage {_pg_path(usage_file)}",
        f"-dump {_pg_path(dump_file)}",
        "",
    ])

    config_file.write_text("\n".join(lines), encoding="utf-8")
    return config_file


def parse_mapping(mapping_file: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    if not mapping_file.is_file():
        return mapping
    class_line = re.compile(r"^(?P<old>[^\s].*?)\s+->\s+(?P<new>[^:]+):$")
    for line in mapping_file.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith(" ") or line.startswith("\t"):
            continue
        match = class_line.match(line)
        if match:
            mapping[match.group("old").strip()] = match.group("new").strip()
    return mapping


def _replace_class_ref(value: str, mapping: dict[str, str]) -> str:
    if "::" in value:
        class_name, suffix = value.split("::", 1)
        return f"{mapping.get(class_name, class_name)}::{suffix}"
    return mapping.get(value, value)


def _rewrite_yaml(text: str, mapping: dict[str, str]) -> str:
    pattern = re.compile(
        r"^(?P<indent>\s*)(?P<key>main|bootstrapper|loader)(?P<sep>\s*:\s*)(?P<quote>[\"']?)(?P<value>[^\s#\"']+)(?P=quote)(?P<tail>\s*(?:#.*)?)$",
        re.MULTILINE,
    )

    def replace(match: re.Match[str]) -> str:
        if match.group("indent"):
            return match.group(0)
        old = match.group("value")
        new = mapping.get(old, old)
        return (
            match.group("indent")
            + match.group("key")
            + match.group("sep")
            + match.group("quote")
            + new
            + match.group("quote")
            + match.group("tail")
        )

    return pattern.sub(replace, text)


def _rewrite_fabric_value(value: Any, mapping: dict[str, str]) -> Any:
    if isinstance(value, str):
        return _replace_class_ref(value, mapping)
    if isinstance(value, list):
        return [_rewrite_fabric_value(item, mapping) for item in value]
    if isinstance(value, dict):
        return {key: _rewrite_fabric_value(item, mapping) for key, item in value.items()}
    return value


def _rewrite_json_resource(name: str, data: bytes, mapping: dict[str, str]) -> bytes:
    payload = json.loads(_decode(data))
    if name in {"velocity-plugin.json", "META-INF/velocity-plugin.json"}:
        if isinstance(payload.get("main"), str):
            payload["main"] = mapping.get(payload["main"], payload["main"])
    elif name == "fabric.mod.json":
        if "entrypoints" in payload:
            payload["entrypoints"] = _rewrite_fabric_value(payload["entrypoints"], mapping)
    return (json.dumps(payload, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _rewrite_manifest(data: bytes, mapping: dict[str, str]) -> bytes:
    text = _decode(data).replace("\r\n", "\n")
    lines = text.split("\n")
    output: list[str] = []
    for line in lines:
        if line.startswith("Main-Class:") or line.startswith("Start-Class:"):
            key, value = line.split(":", 1)
            class_name = value.strip()
            line = f"{key}: {mapping.get(class_name, class_name)}"
        output.append(line)
    return "\r\n".join(output).encode("utf-8")


def _rewrite_service_resource(name: str, data: bytes, mapping: dict[str, str]) -> tuple[str, bytes]:
    prefix = "META-INF/services/"
    service_name = name[len(prefix):].replace("/", ".")
    mapped_service = mapping.get(service_name, service_name)
    output_lines: list[str] = []
    for raw_line in _decode(data).replace("\r\n", "\n").split("\n"):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            output_lines.append(raw_line)
            continue
        class_name, separator, comment = raw_line.partition("#")
        provider = class_name.strip()
        replaced = mapping.get(provider, provider)
        rebuilt = replaced
        if separator:
            rebuilt += " #" + comment
        output_lines.append(rebuilt)
    return prefix + mapped_service, ("\n".join(output_lines)).encode("utf-8")


def rewrite_output_metadata(output_jar: Path, mapping: dict[str, str], inspection: JarInspection) -> None:
    temporary = output_jar.with_suffix(".rewritten.jar")
    metadata = set(inspection.metadata_resources)
    with zipfile.ZipFile(output_jar, "r") as source, zipfile.ZipFile(
        temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as target:
        for info in source.infolist():
            name = info.filename
            if SIGNATURE_RE.match(name):
                continue
            data = source.read(name)
            output_name = name
            if name in metadata:
                if name in {"plugin.yml", "paper-plugin.yml", "bungee.yml"}:
                    data = _rewrite_yaml(_decode(data), mapping).encode("utf-8")
                elif name in {"velocity-plugin.json", "META-INF/velocity-plugin.json", "fabric.mod.json"}:
                    data = _rewrite_json_resource(name, data, mapping)
                elif name == "META-INF/MANIFEST.MF":
                    data = _rewrite_manifest(data, mapping)
                elif name.startswith("META-INF/services/"):
                    output_name, data = _rewrite_service_resource(name, data, mapping)
            new_info = zipfile.ZipInfo(filename=output_name, date_time=info.date_time)
            new_info.compress_type = zipfile.ZIP_DEFLATED
            new_info.external_attr = info.external_attr
            new_info.comment = info.comment
            new_info.extra = info.extra
            target.writestr(new_info, data)
    temporary.replace(output_jar)


def validate_output(output_jar: Path, inspection: JarInspection, mapping: dict[str, str]) -> dict[str, Any]:
    if not output_jar.is_file() or output_jar.stat().st_size == 0:
        raise ObfuscationError("The selected obfuscator did not produce an output JAR.")
    try:
        with zipfile.ZipFile(output_jar, "r") as jar:
            bad = jar.testzip()
            if bad:
                raise ObfuscationError(f"Output JAR is corrupt near entry: {bad}")
            names = set(jar.namelist())
            output_class_count = sum(name.endswith(".class") for name in names)
            if output_class_count == 0:
                raise ObfuscationError("Output JAR contains no classes.")
            missing_entries: list[str] = []
            mapped_entries: dict[str, str] = {}
            for original in inspection.entry_classes:
                mapped = mapping.get(original, original)
                mapped_entries[original] = mapped
                class_path = mapped.replace(".", "/") + ".class"
                if class_path not in names:
                    missing_entries.append(mapped)
            if missing_entries:
                raise ObfuscationError(
                    "Output JAR is missing required entry classes: " + ", ".join(missing_entries)
                )
            signatures = sorted(name for name in names if SIGNATURE_RE.match(name))
            if signatures:
                raise ObfuscationError("Invalid signature files remained in the output JAR.")
            return {
                "output_class_count": output_class_count,
                "output_resource_count": len(names) - output_class_count,
                "mapped_entry_classes": mapped_entries,
            }
    except zipfile.BadZipFile as exc:
        raise ObfuscationError("The selected obfuscator produced an invalid JAR archive.") from exc


def _resolve_proguard_command() -> list[str]:
    configured = os.environ.get("PROGUARD_CMD", "").strip()
    if configured:
        path = Path(configured)
        suffix = path.suffix.lower()
        if suffix == ".jar":
            return [shutil.which("java") or "java", "-jar", str(path)]
        if os.name == "nt" and suffix in {".bat", ".cmd"}:
            return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/s", "/c", configured]
        return [configured]

    candidates = [
        Path("/opt/proguard/bin/proguard.sh"),
        Path("/opt/proguard/bin/proguard"),
        Path("tools/proguard/bin/proguard.sh"),
        Path("tools/proguard/bin/proguard.bat"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return [str(candidate.resolve())]
    raise ObfuscationError("ProGuard was not found. Set the PROGUARD_CMD environment variable.")


def _run_proguard_obfuscation(
    input_jar: Path,
    work_dir: Path,
    output_name: str,
    mode: str,
    library_jars: Iterable[Path] = (),
    timeout_seconds: int = 240,
) -> ObfuscationResult:
    work_dir.mkdir(parents=True, exist_ok=True)
    output_jar = work_dir / output_name
    inspection = inspect_jar(input_jar)
    config_file = generate_proguard_config(
        input_jar=input_jar,
        output_jar=output_jar,
        work_dir=work_dir,
        inspection=inspection,
        mode=mode,
        library_jars=library_jars,
    )
    log_file = work_dir / "proguard.log"

    command = _resolve_proguard_command() + [f"@{config_file}"]
    env = _java_environment()

    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=work_dir,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        log_file.write_text(output + "\nERROR: ProGuard timed out.\n", encoding="utf-8")
        raise ObfuscationError(f"ProGuard exceeded the {timeout_seconds}-second time limit.") from exc
    elapsed = time.monotonic() - started
    log_file.write_text(completed.stdout or "", encoding="utf-8")
    if completed.returncode != 0:
        tail = "\n".join((completed.stdout or "").splitlines()[-24:])
        raise ObfuscationError(f"ProGuard failed with exit code {completed.returncode}.\n{tail}")

    mapping_file = work_dir / "mapping.txt"
    mapping = parse_mapping(mapping_file)
    rewrite_output_metadata(output_jar, mapping, inspection)
    validation = validate_output(output_jar, inspection, mapping)
    renamed_class_count = sum(1 for old, new in mapping.items() if old != new)

    report = {
        "engine": "proguard",
        "engine_name": "ProGuard",
        "mode": mode,
        "frameworks": inspection.frameworks,
        "entry_classes_before": inspection.entry_classes,
        "entry_classes_after": validation["mapped_entry_classes"],
        "input_class_count": inspection.class_count,
        "output_class_count": validation["output_class_count"],
        "renamed_class_count": renamed_class_count,
        "removed_signature_entries": inspection.signed_entries_removed,
        "elapsed_seconds": round(elapsed, 3),
        "proguard_exit_code": completed.returncode,
        "warnings_ignored": True,
        "shrinking_enabled": False,
        "optimization_enabled": False,
    }
    report_file = work_dir / "report.json"
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    return ObfuscationResult(
        engine="proguard",
        output_jar=output_jar,
        mapping_file=mapping_file,
        seeds_file=work_dir / "seeds.txt",
        usage_file=work_dir / "usage.txt",
        dump_file=work_dir / "dump.txt",
        config_file=config_file,
        log_file=log_file,
        report_file=report_file,
        inspection=inspection,
        mapped_entry_classes=validation["mapped_entry_classes"],
        renamed_class_count=renamed_class_count,
        elapsed_seconds=elapsed,
    )



def normalize_engine(engine: str) -> str:
    normalized = (engine or "proguard").strip().lower()
    aliases = {
        "pg": "proguard",
        "pro-guard": "proguard",
        "skidfuscator": "skid",
        "skidfuscator-community": "skid",
        "y-guard": "yguard",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in {"proguard", "skid", "yguard"}:
        raise ObfuscationError("Engine must be 'proguard', 'skid', or 'yguard'.")
    return normalized


def engine_display_name(engine: str) -> str:
    return {
        "proguard": "ProGuard",
        "skid": "Skidfuscator Community",
        "yguard": "yGuard",
    }[normalize_engine(engine)]


def _environment_int(name: str, default: int, minimum: int = 128) -> int:
    raw = os.environ.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        value = default
    return max(minimum, value)


def _java_environment(max_heap_mb: int | None = None) -> dict[str, str]:
    """Return a deterministic JVM environment with one explicit heap limit.

    JAVA_TOOL_OPTIONS may already contain an -Xmx value supplied by Railway or a
    local shell. Remove it before applying the per-engine value so Skidfuscator
    cannot accidentally remain capped at the generic 512 MB default.
    """
    env = os.environ.copy()
    if max_heap_mb is None:
        max_heap_mb = _environment_int("JAVA_MAX_HEAP_MB", 512)
    java_options = env.get("JAVA_TOOL_OPTIONS", "")
    java_options = re.sub(r"(?:^|\s)-Xmx\S+", " ", java_options).strip()
    options = [java_options] if java_options else []
    options.extend([
        f"-Xmx{max_heap_mb}m",
        "-XX:+ExitOnOutOfMemoryError",
    ])
    env["JAVA_TOOL_OPTIONS"] = " ".join(options)
    return env


def _run_command(
    command: list[str],
    work_dir: Path,
    log_file: Path,
    timeout_seconds: int,
    tool_name: str,
    *,
    environment: dict[str, str] | None = None,
    check: bool = True,
    append_log: bool = False,
) -> tuple[subprocess.CompletedProcess[str], float]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command,
            cwd=work_dir,
            env=environment or _java_environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        mode = "a" if append_log else "w"
        with log_file.open(mode, encoding="utf-8") as handle:
            handle.write(output + f"\nERROR: {tool_name} timed out.\n")
        raise ObfuscationError(f"{tool_name} exceeded the {timeout_seconds}-second time limit.") from exc
    elapsed = time.monotonic() - started
    mode = "a" if append_log else "w"
    with log_file.open(mode, encoding="utf-8") as handle:
        handle.write(completed.stdout or "")
    if check and completed.returncode != 0:
        tail = "\n".join((completed.stdout or "").splitlines()[-32:])
        raise ObfuscationError(f"{tool_name} failed with exit code {completed.returncode}.\n{tail}")
    return completed, elapsed


def _skid_heap_mb() -> int:
    return _environment_int("SKID_MAX_HEAP_MB", 1536, minimum=512)


def _skid_failure_reasons(output: str) -> list[str]:
    reasons: list[str] = []
    if "OutOfMemoryError" in output or "Java heap space" in output:
        reasons.append("java_heap_exhausted")
    if "BoissinotDestructor" in output or "leaveSSA" in output:
        reasons.append("mapleir_ssa_failure")
    if "StringTransformerV2" in output or "AbstractEncryptionGeneratorV3" in output:
        reasons.append("v3_string_transformer_failure")
    if not reasons:
        reasons.append("unknown_engine_failure")
    return reasons


def _resolve_skid_command() -> list[str]:
    configured = os.environ.get("SKIDFUSCATOR_CMD", "").strip()
    if configured:
        path = Path(configured)
        if path.suffix.lower() == ".jar":
            return [shutil.which("java") or "java", "-jar", str(path)]
        return [configured]
    candidates = [
        Path("/opt/skidfuscator/skidfuscator.jar"),
        Path("tools/skidfuscator/skidfuscator.jar"),
        Path("skidfuscator.jar"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return [shutil.which("java") or "java", "-jar", str(candidate.resolve())]
    raise ObfuscationError("Skidfuscator was not found. Set SKIDFUSCATOR_CMD to its JAR or launcher.")


def _resolve_ant_command() -> str:
    configured = os.environ.get("ANT_CMD", "").strip()
    if configured:
        return configured
    ant = shutil.which("ant")
    if ant:
        return ant
    raise ObfuscationError("Apache Ant was not found. Set ANT_CMD to the Ant executable.")


def _resolve_yguard_lib_dir() -> Path:
    configured = os.environ.get("YGUARD_LIB_DIR", "").strip()
    candidates = [Path(configured)] if configured else []
    candidates.extend([Path("/opt/yguard/lib"), Path("tools/yguard/lib")])
    for candidate in candidates:
        if candidate.is_dir() and any(candidate.glob("*.jar")):
            return candidate.resolve()
    jar_value = os.environ.get("YGUARD_JAR", "").strip()
    if jar_value:
        jar_path = Path(jar_value)
        if jar_path.is_file():
            return jar_path.resolve().parent
    raise ObfuscationError("yGuard libraries were not found. Set YGUARD_LIB_DIR to a directory containing yGuard and its dependencies.")


def get_engine_status() -> dict[str, bool]:
    status: dict[str, bool] = {}
    try:
        _resolve_proguard_command()
        status["proguard"] = True
    except ObfuscationError:
        status["proguard"] = False
    try:
        _resolve_skid_command()
        status["skid"] = True
    except ObfuscationError:
        status["skid"] = False
    try:
        _resolve_ant_command()
        _resolve_yguard_lib_dir()
        status["yguard"] = True
    except ObfuscationError:
        status["yguard"] = False
    return status


def _hocon_quote(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def generate_skid_config(
    work_dir: Path,
    inspection: JarInspection,
    mode: str,
    profile: str = "stable",
) -> Path:
    if mode not in {"safe", "strong"}:
        raise ObfuscationError("Mode must be 'safe' or 'strong'.")
    if profile not in {"stable", "compatibility", "experimental"}:
        raise ObfuscationError("Unknown Skidfuscator profile.")

    suffix = "" if profile == "stable" else f"-{profile}"
    config_file = work_dir / f"skidfuscator-config{suffix}.conf"
    exemptions: list[str] = []
    if mode == "safe" or profile == "compatibility":
        for class_name in inspection.entry_classes:
            internal = re.escape(class_name.replace(".", "/"))
            exemptions.append(f"class{{^{internal}$}}")

    # Skidfuscator's V3 string generator currently routes generated byte-array
    # methods through MapleIR's SSA destructor. Some normal Java 21 plugin methods
    # trigger an unbounded/invalid graph there. Keep it off by default; it can be
    # explicitly re-enabled for testing with SKID_EXPERIMENTAL_STRING_ENCRYPTION.
    experimental_strings = (
        profile == "experimental"
        or os.environ.get("SKID_EXPERIMENTAL_STRING_ENCRYPTION", "").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    compatibility = profile == "compatibility"
    exception_enabled = mode == "strong" and not compatibility
    range_enabled = mode == "strong" and not compatibility

    lines = ["exempt=["]
    for index, pattern in enumerate(exemptions):
        comma = "," if index < len(exemptions) - 1 else ""
        lines.append(f"    {_hocon_quote(pattern)}{comma}")
    lines.extend([
        "]",
        "flowCondition {",
        "    enabled=true",
        "}",
        "flowException {",
        f"    enabled={'true' if exception_enabled else 'false'}",
        f"    strength={'GOOD' if exception_enabled else 'WEAK'}",
        "}",
        "flowRange {",
        f"    enabled={'true' if range_enabled else 'false'}",
        "}",
        "native {",
        "    enabled=false",
        "}",
        "numberEncryption {",
        "    enabled=true",
        "}",
        "stringEncryption {",
        f"    enabled={'true' if experimental_strings else 'false'}",
        "    type=STANDARD",
        "}",
        "",
    ])
    config_file.write_text("\n".join(lines), encoding="utf-8")
    return config_file


def _prepare_library_directory(work_dir: Path, library_jars: Iterable[Path]) -> Path | None:
    valid = [Path(path) for path in library_jars if Path(path).is_file()]
    if not valid:
        return None
    destination = work_dir / "engine-libraries"
    destination.mkdir(parents=True, exist_ok=True)
    for index, library in enumerate(valid, start=1):
        target = destination / f"{index:03d}-{library.name}"
        shutil.copy2(library, target)
    return destination


def _write_identity_mapping(path: Path, classes: Iterable[str]) -> None:
    lines = [f"{class_name} -> {class_name}:" for class_name in sorted(set(classes))]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _run_skid_obfuscation(
    input_jar: Path,
    work_dir: Path,
    output_name: str,
    mode: str,
    library_jars: Iterable[Path] = (),
    timeout_seconds: int = 240,
) -> ObfuscationResult:
    work_dir.mkdir(parents=True, exist_ok=True)
    output_jar = work_dir / output_name
    inspection = inspect_jar(input_jar)
    log_file = work_dir / "skidfuscator.log"
    library_dir = _prepare_library_directory(work_dir, library_jars)
    heap_mb = _skid_heap_mb()
    auto_retry = os.environ.get("SKID_AUTO_COMPATIBILITY_RETRY", "true").strip().lower() not in {
        "0", "false", "no", "off"
    }

    primary_profile = (
        "experimental"
        if os.environ.get("SKID_EXPERIMENTAL_STRING_ENCRYPTION", "").strip().lower()
        in {"1", "true", "yes", "on"}
        else "stable"
    )
    profiles = [primary_profile]
    if auto_retry and primary_profile != "compatibility":
        profiles.append("compatibility")

    attempts: list[dict[str, Any]] = []
    completed: subprocess.CompletedProcess[str] | None = None
    config_file: Path | None = None
    elapsed = 0.0

    for attempt_number, profile in enumerate(profiles, start=1):
        config_file = generate_skid_config(work_dir, inspection, mode, profile=profile)
        if output_jar.exists():
            output_jar.unlink()
        command = _resolve_skid_command() + [
            "obfuscate",
            str(input_jar.resolve()),
            "-o",
            str(output_jar.resolve()),
            "-cfg",
            str(config_file.resolve()),
            "-ph",
            "-notrack",
        ]
        if library_dir:
            command.extend(["-li", str(library_dir.resolve())])

        with log_file.open("a" if attempt_number > 1 else "w", encoding="utf-8") as handle:
            handle.write(
                f"\n===== Skidfuscator attempt {attempt_number}: profile={profile}, "
                f"heap={heap_mb}m =====\n"
            )
        try:
            current, current_elapsed = _run_command(
                command,
                work_dir,
                log_file,
                timeout_seconds,
                "Skidfuscator",
                environment=_java_environment(heap_mb),
                check=False,
                append_log=True,
            )
            output_text = current.stdout or ""
            return_code = current.returncode
        except ObfuscationError as exc:
            current = None
            current_elapsed = 0.0
            output_text = str(exc)
            return_code = -1

        elapsed += current_elapsed
        reasons = _skid_failure_reasons(output_text)
        success = return_code == 0 and output_jar.is_file() and output_jar.stat().st_size > 0
        attempts.append({
            "attempt": attempt_number,
            "profile": profile,
            "heap_mb": heap_mb,
            "exit_code": return_code,
            "success": success,
            "failure_reasons": [] if success else reasons,
        })
        if success:
            completed = current
            break

        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(
                "\nCompatibility retry will disable V3 string encryption, "
                "exception flow, and range flow.\n"
                if attempt_number < len(profiles)
                else "\nNo Skidfuscator attempts remain.\n"
            )

    if completed is None or config_file is None:
        log_text = log_file.read_text(encoding="utf-8", errors="replace") if log_file.exists() else ""
        tail = "\n".join(log_text.splitlines()[-36:])
        all_reasons = sorted({reason for attempt in attempts for reason in attempt["failure_reasons"]})
        advice = (
            f" Skidfuscator was given a {heap_mb} MB heap. Increase the Railway service memory "
            "and SKID_MAX_HEAP_MB if java_heap_exhausted remains in the reasons."
            if "java_heap_exhausted" in all_reasons else ""
        )
        raise ObfuscationError(
            "Skidfuscator failed after its stable and compatibility attempts "
            f"({', '.join(all_reasons) or 'unknown failure'}).{advice}\n{tail}"
        )

    mapping_file = work_dir / "mapping.txt"
    _write_identity_mapping(mapping_file, inspection.entry_classes)
    mapping = parse_mapping(mapping_file)
    rewrite_output_metadata(output_jar, mapping, inspection)
    validation = validate_output(output_jar, inspection, mapping)
    report = {
        "engine": "skid",
        "engine_name": engine_display_name("skid"),
        "mode": mode,
        "frameworks": inspection.frameworks,
        "entry_classes_before": inspection.entry_classes,
        "entry_classes_after": validation["mapped_entry_classes"],
        "input_class_count": inspection.class_count,
        "output_class_count": validation["output_class_count"],
        "renamed_class_count": 0,
        "removed_signature_entries": inspection.signed_entries_removed,
        "elapsed_seconds": round(elapsed, 3),
        "exit_code": completed.returncode,
        "skid_heap_mb": heap_mb,
        "attempts": attempts,
        "compatibility_retry_used": len(attempts) > 1,
        "v3_string_encryption_enabled": any(attempt["profile"] == "experimental" for attempt in attempts),
        "community_edition_note": "Community Skidfuscator applies flow and constant transformations; structural renaming is not included.",
    }
    report_file = work_dir / "report.json"
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return ObfuscationResult(
        engine="skid",
        output_jar=output_jar,
        mapping_file=mapping_file,
        seeds_file=work_dir / "seeds.txt",
        usage_file=work_dir / "usage.txt",
        dump_file=work_dir / "dump.txt",
        config_file=config_file,
        log_file=log_file,
        report_file=report_file,
        inspection=inspection,
        mapped_entry_classes=validation["mapped_entry_classes"],
        renamed_class_count=0,
        elapsed_seconds=elapsed,
    )


def generate_yguard_build(
    input_jar: Path,
    output_jar: Path,
    work_dir: Path,
    inspection: JarInspection,
    mode: str,
    library_jars: Iterable[Path] = (),
) -> Path:
    if mode not in {"safe", "strong"}:
        raise ObfuscationError("Mode must be 'safe' or 'strong'.")
    build_file = work_dir / "yguard-build.xml"
    log_file = work_dir / "yguard-map.xml"
    lib_dir = _resolve_yguard_lib_dir()
    libraries = [Path(path).resolve() for path in library_jars if Path(path).is_file()]

    lines = [
        '<project name="plugin-protector-yguard" default="obfuscate">',
        '  <path id="yguard.classpath">',
        f'    <fileset dir={quoteattr(str(lib_dir))}><include name="*.jar"/><exclude name="ant*.jar"/></fileset>',
        '  </path>',
        '  <taskdef name="yguard" classname="com.yworks.yguard.YGuardTask" classpathref="yguard.classpath"/>',
        '  <target name="obfuscate">',
        '    <yguard>',
        f'      <inoutpair in={quoteattr(str(input_jar.resolve()))} out={quoteattr(str(output_jar.resolve()))}/>',
    ]
    if libraries:
        lines.append('      <externalclasses>')
        for library in libraries:
            lines.append(f'        <pathelement location={quoteattr(str(library))}/>')
        lines.append('      </externalclasses>')
    lines.extend([
        '      <attribute name="Exceptions,InnerClasses,Signature,Deprecated,RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations,RuntimeVisibleParameterAnnotations,RuntimeInvisibleParameterAnnotations,AnnotationDefault,EnclosingMethod,MethodParameters,Record,PermittedSubclasses,NestHost,NestMembers"/>',
        f'      <rename logfile={quoteattr(str(log_file.resolve()))} conservemanifest="true" replaceClassNameStrings="true" scramble={quoteattr("true" if mode == "strong" else "false")}>',
        f'        <property name="naming-scheme" value={quoteattr("mix" if mode == "strong" else "small")}/>',
        '        <property name="language-conformity" value="compatible"/>',
        '        <property name="overload-enabled" value="true"/>',
        '        <property name="digests" value="none"/>',
        '        <keep sourcefile="remove" linenumbertable="remove" localvariabletable="remove" localvariabletypetable="remove">',
        '          <class classes="none" methods="protected" fields="none"/>',
    ])
    for class_name in inspection.entry_classes:
        if mode == "safe":
            lines.append(f'          <class name={quoteattr(class_name)} classes="private" methods="private" fields="private"/>')
        else:
            lines.append(f'          <class name={quoteattr(class_name)} classes="none" methods="private" fields="none"/>')
    lines.extend([
        '        </keep>',
        '      </rename>',
        '    </yguard>',
        '  </target>',
        '</project>',
        '',
    ])
    build_file.write_text("\n".join(lines), encoding="utf-8")
    return build_file


def parse_yguard_mapping(yguard_log: Path) -> dict[str, str]:
    if not yguard_log.is_file():
        return {}
    try:
        root = ET.parse(yguard_log).getroot()
    except ET.ParseError as exc:
        raise ObfuscationError(f"yGuard produced an unreadable mapping log: {exc}") from exc
    package_segments: dict[str, str] = {}
    class_nodes: list[tuple[str, str]] = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        name = element.attrib.get("name", "")
        mapped = element.attrib.get("map", "")
        if not name or not mapped:
            continue
        if tag == "package":
            package_segments[name] = mapped.replace("/", ".")
        elif tag == "class":
            class_nodes.append((name, mapped))

    def mapped_package(package_name: str) -> str:
        if not package_name:
            return ""
        result: list[str] = []
        parts = package_name.split(".")
        for index, part in enumerate(parts, start=1):
            full = ".".join(parts[:index])
            result.append(package_segments.get(full, part))
        return ".".join(filter(None, result))

    mapping: dict[str, str] = {}
    for original, mapped_short in sorted(class_nodes, key=lambda item: (item[0].count("$"), item[0])):
        package_name, _, class_part = original.rpartition(".")
        if "$" in class_part:
            outer_original = original.rsplit("$", 1)[0]
            outer_mapped = mapping.get(outer_original)
            if outer_mapped:
                mapped_name = outer_mapped + "$" + mapped_short
            else:
                mapped_name = (mapped_package(package_name) + "." if package_name else "") + mapped_short
        else:
            mapped_name = (mapped_package(package_name) + "." if package_name else "") + mapped_short
        mapping[original] = mapped_name
    return mapping


def _write_proguard_style_mapping(path: Path, mapping: dict[str, str]) -> None:
    lines = [f"{old} -> {new}:" for old, new in sorted(mapping.items())]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _run_yguard_obfuscation(
    input_jar: Path,
    work_dir: Path,
    output_name: str,
    mode: str,
    library_jars: Iterable[Path] = (),
    timeout_seconds: int = 240,
) -> ObfuscationResult:
    work_dir.mkdir(parents=True, exist_ok=True)
    output_jar = work_dir / output_name
    inspection = inspect_jar(input_jar)
    config_file = generate_yguard_build(input_jar, output_jar, work_dir, inspection, mode, library_jars)
    log_file = work_dir / "yguard.log"
    command = [_resolve_ant_command(), "-f", str(config_file.resolve()), "obfuscate"]
    completed, elapsed = _run_command(command, work_dir, log_file, timeout_seconds, "yGuard")
    yguard_mapping_file = work_dir / "yguard-map.xml"
    mapping = parse_yguard_mapping(yguard_mapping_file)
    mapping_file = work_dir / "mapping.txt"
    _write_proguard_style_mapping(mapping_file, mapping)
    rewrite_output_metadata(output_jar, mapping, inspection)
    validation = validate_output(output_jar, inspection, mapping)
    renamed_class_count = sum(1 for old, new in mapping.items() if old != new)
    report = {
        "engine": "yguard",
        "engine_name": engine_display_name("yguard"),
        "mode": mode,
        "frameworks": inspection.frameworks,
        "entry_classes_before": inspection.entry_classes,
        "entry_classes_after": validation["mapped_entry_classes"],
        "input_class_count": inspection.class_count,
        "output_class_count": validation["output_class_count"],
        "renamed_class_count": renamed_class_count,
        "removed_signature_entries": inspection.signed_entries_removed,
        "elapsed_seconds": round(elapsed, 3),
        "exit_code": completed.returncode,
        "native_mapping_log": yguard_mapping_file.name,
    }
    report_file = work_dir / "report.json"
    report_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return ObfuscationResult(
        engine="yguard",
        output_jar=output_jar,
        mapping_file=mapping_file,
        seeds_file=work_dir / "seeds.txt",
        usage_file=work_dir / "usage.txt",
        dump_file=yguard_mapping_file,
        config_file=config_file,
        log_file=log_file,
        report_file=report_file,
        inspection=inspection,
        mapped_entry_classes=validation["mapped_entry_classes"],
        renamed_class_count=renamed_class_count,
        elapsed_seconds=elapsed,
    )


def run_obfuscation(
    input_jar: Path,
    work_dir: Path,
    output_name: str,
    mode: str,
    library_jars: Iterable[Path] = (),
    timeout_seconds: int = 240,
    engine: str = "proguard",
) -> ObfuscationResult:
    selected = normalize_engine(engine)
    if selected == "proguard":
        return _run_proguard_obfuscation(input_jar, work_dir, output_name, mode, library_jars, timeout_seconds)
    if selected == "skid":
        return _run_skid_obfuscation(input_jar, work_dir, output_name, mode, library_jars, timeout_seconds)
    return _run_yguard_obfuscation(input_jar, work_dir, output_name, mode, library_jars, timeout_seconds)

def build_bundle(result: ObfuscationResult, bundle_path: Path) -> Path:
    files = [
        result.output_jar,
        result.mapping_file,
        result.seeds_file,
        result.usage_file,
        result.dump_file,
        result.config_file,
        result.log_file,
        result.report_file,
    ]
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in files:
            if path.is_file():
                bundle.write(path, arcname=path.name)
    return bundle_path


def safe_extract_library_zip(
    archive_path: Path,
    destination: Path,
    max_files: int = 100,
    max_uncompressed_bytes: int = 500 * 1024 * 1024,
) -> list[Path]:
    destination.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    total_size = 0
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            candidates = [info for info in archive.infolist() if not info.is_dir() and info.filename.lower().endswith(".jar")]
            if len(candidates) > max_files:
                raise ObfuscationError(f"Library ZIP contains more than {max_files} JAR files.")
            for index, info in enumerate(candidates, start=1):
                total_size += info.file_size
                if total_size > max_uncompressed_bytes:
                    raise ObfuscationError("Library ZIP exceeds the allowed uncompressed size.")
                clean_name = Path(info.filename).name
                if not clean_name:
                    continue
                target = destination / f"{index:03d}-{clean_name}"
                with archive.open(info, "r") as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                try:
                    with zipfile.ZipFile(target, "r") as nested:
                        if not any(name.endswith(".class") for name in nested.namelist()):
                            target.unlink(missing_ok=True)
                            continue
                except zipfile.BadZipFile:
                    target.unlink(missing_ok=True)
                    continue
                extracted.append(target)
    except zipfile.BadZipFile as exc:
        raise ObfuscationError("A supplied library ZIP is invalid.") from exc
    return extracted
