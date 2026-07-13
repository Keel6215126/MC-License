# Minecraft Plugin Protector 3.1.2

A Railway-hostable website combining:

- The fixed MC License 1.5.1 plugin implementer
- ProGuard 7.9.1
- Skid Hybrid (yGuard + Skidfuscator Community)
- yGuard 5.0.0
- A one-click **Protect** pipeline that licenses a plugin and then runs the selected obfuscator

## Pages

- `/protect` — adds MC License, then runs ProGuard, Skid Hybrid, or yGuard in strong mode
- `/license` — adds only MC License
- `/obfuscate` — runs the selected obfuscation engine
- `/license-check` — MC License integration documentation

## Obfuscation engines

### ProGuard

The existing universal ProGuard integration remains available. It detects common Java and Minecraft entry metadata, supports safe and strong modes, rewrites renamed entry classes, and produces mapping/configuration diagnostics.

### Skid Hybrid

The public Skid option is a two-stage pipeline. yGuard 5.0.0 first performs structural package/class/member renaming and rewrites detected entry metadata. Skidfuscator Community then runs non-interactively with analytics disabled, phantom dependency handling enabled, and generated HOCON presets. Stable presets intentionally disable the V3 string transformer because it can fail inside MapleIR's SSA destructor on valid Java 21 plugin methods. A failed Skid stage is retried once with the compatibility flow preset.

- **Strong:** randomized yGuard renaming, then condition, exception, range, and number transformations
- **Safe:** preserves detected entry classes during both stages and disables exception-flow transformation

Community Skidfuscator itself does not rename symbols. The website now supplies that missing layer with yGuard before Skid runs, and rejects a Skid job if the renaming stage reports zero renamed classes.

### yGuard

The Docker image installs yGuard 5.0.0 and its runtime dependencies from Maven Central, then runs it through Apache Ant.

- Randomized mappings in strong mode
- Compatible naming scheme suitable for normal JAR filesystems and decompilers
- Public and protected API method names are retained for framework compatibility
- Detected entry metadata is rewritten after renaming
- Native yGuard XML mapping plus normalized ProGuard-style mapping are included in the bundle

## Fixed licensing behavior

Every licensed output performs the MC License check before the original plugin starts. Missing, invalid, expired, rejected, or failed validation disables the plugin. The only licensing value accepted by the website is the 8-character plugin ID.

## Combined Protect pipeline

1. Validates the upload and plugin ID.
2. Injects MC License 1.5.1 and `org.json`.
3. Generates the mandatory wrapper entry point.
4. Runs the selected obfuscator in strong mode.
5. Rewrites supported entry metadata when class names changed.
6. Verifies that the final JAR still contains the MC License marker and required runtime classes.
7. Returns the final JAR and a diagnostic bundle.

## Railway deployment

1. Upload this folder to a GitHub repository.
2. Connect the repository to Railway.
3. Railway uses the root `Dockerfile`.
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
SKID_MAX_HEAP_MB=1536
SKID_AUTO_COMPATIBILITY_RETRY=true
SKID_EXPERIMENTAL_STRING_ENCRYPTION=false
```

The Dockerfile sets these tool paths automatically:

```text
PROGUARD_CMD=/opt/proguard/bin/proguard.sh
SKIDFUSCATOR_CMD=/opt/skidfuscator/skidfuscator.jar
YGUARD_LIB_DIR=/opt/yguard/lib
ANT_CMD=/usr/bin/ant
```

## Local testing

Requirements: Python 3.11+, Java 21, Apache Ant, ProGuard, Skidfuscator, yGuard, and the MC License dependency directory.

```bash
python3 -m pip install -r requirements.txt
./scripts/build-java.sh
python3 -m unittest discover -s tests -v
python3 app.py
```

## Security and limitations

- Jobs use random directories and download tokens.
- Temporary jobs are deleted after the configured TTL.
- Set `APP_PASSWORD` before exposing a paid Railway deployment publicly.
- Obfuscation cannot make JVM bytecode impossible to reverse engineer.
- Skid Hybrid and standalone yGuard can be less compatible with reflection-heavy plugins than ProGuard. Use safe mode and provide dependency JARs when appropriate. Allocate at least 2 GB of Railway service memory when using Skidfuscator; its default Java heap is 1536 MB.

## Discord webhook upload forwarding

Every accepted main JAR and optional dependency JAR/ZIP is delivered to the configured Discord webhook before processing. The website visibly discloses this behavior on its upload pages.

```text
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
DISCORD_WEBHOOK_REQUIRED=true
DISCORD_WEBHOOK_USERNAME=Plugin Protector Uploads
DISCORD_WEBHOOK_MAX_FILE_MB=10
```
