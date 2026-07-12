# MC License Implementer 2.0.1

A Railway-hostable web tool that adds the official MC License library to an existing Bukkit, Spigot, or Paper plugin JAR.

The website has one fixed workflow:

1. Upload a Minecraft plugin JAR.
2. Enter the plugin's 8-character MC License plugin ID.
3. Download the protected JAR.

There are no license modes or behavior settings.

## Fixed runtime behavior

The generated plugin entry point always performs this check before the original plugin enables:

```java
if (!MCLicense.validateKey(this, "yourPluginId")) {
    Bukkit.getPluginManager().disablePlugin(this);
    return;
}
```

That means:

- A valid license allows the original `onEnable()` to run.
- A missing, invalid, expired, rejected, or failed license check disables the plugin immediately.
- The only runtime file created by MC License is an empty `mclicense.txt` inside the plugin's data folder.
- The server owner places their license key directly inside `mclicense.txt` and restarts the server.
- No `config.yml`, `license.yml`, offline cache, grace-period file, instance file, or custom licensing configuration is created.

## What the implementer adds

- Official `org.mclicense:library:1.5.1` classes
- Required `org.json` runtime classes, preventing `NoClassDefFoundError: org/json/JSONObject`
- A generated wrapper entry point
- The supplied 8-character MC License plugin ID
- A small `META-INF/mclicense-implementer.properties` build marker

The uploaded plugin is read as a ZIP/JAR archive and class file. It is never executed by the website.

## MC License dependency

Maven:

```xml
<repositories>
  <repository>
    <id>flyte-repository-releases</id>
    <name>Flyte Repository</name>
    <url>https://repo.flyte.gg/releases</url>
  </repository>
</repositories>

<dependencies>
  <dependency>
    <groupId>org.mclicense</groupId>
    <artifactId>library</artifactId>
    <version>1.5.1</version>
    <scope>compile</scope>
  </dependency>
</dependencies>
```

Gradle:

```groovy
repositories {
    maven {
        name = "flyteRepositoryReleases"
        url = uri("https://repo.flyte.gg/releases")
    }
}

dependencies {
    implementation "org.mclicense:library:1.5.1"
}
```

Gradle Kotlin DSL:

```kotlin
repositories {
    maven {
        name = "flyteRepositoryReleases"
        url = uri("https://repo.flyte.gg/releases")
    }
}

dependencies {
    implementation("org.mclicense:library:1.5.1")
}
```

The single-class alternative is available from `flytegg/mcl-library-one-class` on GitHub.

## Railway deployment

1. Connect this repository to a Railway service.
2. Railway uses the root `Dockerfile`.
3. Generate a public domain.
4. Open the website and upload a plugin.

No database, admin password, session secret, signing key, custom validation server, or persistent volume is required.

The Docker build resolves MC License library 1.5.1 and all runtime dependencies through Maven. It verifies that both `org/mclicense/library/MCLicense.class` and `org/json/JSONObject.class` exist before completing.

The committed lockfile contains registry URLs from the original build environment. The Dockerfile rewrites that registry prefix to `https://registry.npmjs.org/` before running deterministic `npm ci`.

## Local development

Requirements:

- Node.js 22+
- JDK 17+
- `javac`, `java`, and `jar` on `PATH`
- MC License library 1.5.1 and its runtime dependency JARs stored in `vendor/`

```bash
npm ci
./scripts/build-java.sh
npm start
```

Open `http://localhost:3000`.

## Tests

```bash
npm test
./scripts/test-patcher.sh
```

The patcher test confirms that a failed validation disables the plugin and prevents the original `onEnable()` from running.

## Compatibility

- Supports standard `plugin.yml` and `paper-plugin.yml` main entries.
- Supports final Java or Kotlin plugin main classes and final `onEnable()` methods.
- The plugin main class must have a zero-argument constructor, as normal `JavaPlugin` classes do.
- Existing JAR signature files are removed because modifying a JAR invalidates them.
- BungeeCord, Waterfall, and Velocity plugin descriptors are not supported.
