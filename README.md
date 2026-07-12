# Minecraft Plugin Protector 3.0.0

A single Railway-hostable website combining:

- The fixed MC License 1.5.1 plugin implementer
- The Universal ProGuard 7.9.1 web obfuscator
- A one-click **Protect** pipeline that runs both in the correct order

## Pages

- `/protect` — adds MC License, then strongly obfuscates the completed plugin
- `/license` — adds only MC License
- `/obfuscate` — runs only ProGuard
- `/license-check` — MC License integration documentation

## Fixed licensing behavior

The website never offers licensing modes. Every licensed output performs this check before the original plugin starts:

```java
if (!MCLicense.validateKey(this, "yourPluginId")) {
    Bukkit.getPluginManager().disablePlugin(this);
    return;
}
```

A missing, invalid, expired, rejected, or failed validation always disables the plugin. The only runtime file created by MC License is the empty `mclicense.txt` file where the user places their key.

The injector shades both the MC License library and its required `org.json` runtime classes. This fixes the `NoClassDefFoundError: org/json/JSONObject` failure seen when only the MC License package was copied.

## Combined Protect pipeline

1. Validates the upload and the 8-character plugin ID.
2. Injects the official MC License 1.5.1 library.
3. Injects `org.json`, including `JSONObject.class`.
4. Generates a mandatory wrapper entry point.
5. Runs ProGuard in fixed **strong** mode.
6. Rewrites supported plugin metadata after class renaming.
7. Confirms the final JAR still contains the license marker and mapped licensing runtime classes.
8. Returns the final JAR and a diagnostic bundle with mapping/config/log files.

## Standalone obfuscator

The standalone page keeps the original safe and strong modes and detects Bukkit, Paper, BungeeCord, Velocity, Fabric, Forge, NeoForge, executable JARs, Spring metadata, services, and generic Java JARs.

## Railway deployment

1. Upload every file in this folder to a GitHub repository.
2. Connect the repository to Railway.
3. Railway automatically uses the root `Dockerfile`.
4. Generate a public domain.

No database or persistent volume is required. Railway injects `PORT` automatically.

Recommended variables:

```text
APP_PASSWORD=optional-long-password
MAX_UPLOAD_MB=100
JOB_TTL_MINUTES=60
OBFUSCATION_TIMEOUT_SECONDS=240
LICENSE_TIMEOUT_SECONDS=45
MAX_PARALLEL_JOBS=1
MAX_QUEUED_JOBS=20
JAVA_MAX_HEAP_MB=512
```

## Local testing

Requirements: Python 3.11+, Java/JDK 17+, ProGuard 7.9.1, and MC License dependencies in a directory referenced by `MCL_DEPENDENCY_DIR`.

```bash
python3 -m pip install -r requirements.txt
./scripts/build-java.sh
python3 -m unittest discover -s tests -v
./scripts/test-license.sh
python3 app.py
```

## Security and limitations

- Uploaded code is parsed and repackaged but never executed by the website.
- Jobs use random directories and random download tokens.
- Temporary jobs are deleted after the configured TTL.
- Set `APP_PASSWORD` before exposing a paid Railway deployment publicly.
- Obfuscation makes decompiled code harder to understand; it cannot make JVM bytecode impossible to reverse engineer.
