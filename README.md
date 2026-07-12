# RailGuard — Railway Minecraft Plugin License Implementer

RailGuard is a self-hosted web dashboard that takes a standard Bukkit, Spigot, or Paper plugin JAR and returns a licensed build.

You drag in a JAR, choose a product, choose whether the customer enters a key in `license.yml` or receives a key embedded in the JAR, and download the modified plugin.

## Included

- Drag-and-drop JAR implementer
- Product and license-key dashboard
- Activation limits
- License expiration and revocation
- Activation reset
- Ed25519-signed validation responses
- Signed offline lease cache with configurable grace period
- Persistent instance IDs
- Clock rollback check for cached leases
- Runtime `license.yml` generation
- Railway-ready Dockerfile and health check
- No execution of uploaded plugin code
- No Maven, Gradle, ASM, or external Java library required

## How the JAR patching works

1. RailGuard reads `plugin.yml` or `paper-plugin.yml` and locates the `main` class.
2. It removes `final` from that class and its `onEnable()` method when necessary.
3. It creates a tiny generated subclass in the same package.
4. The descriptor's `main` value is changed to the generated subclass.
5. The generated class validates the license before calling the original `onEnable()`.
6. A JDK-only verifier and a RailGuard marker are added to the JAR.

The uploaded plugin is parsed as an archive and class file. It is never loaded or executed by the web service.

## Railway deployment

### 1. Put the project in GitHub

Upload this entire folder to a private GitHub repository.

### 2. Create the Railway service

Create a Railway project and deploy the GitHub repository. Railway automatically detects the root `Dockerfile`; `railway.toml` sets `/health` as the deployment health check.

### 3. Set variables

Set at least:

```text
ADMIN_PASSWORD=use-a-long-random-password
SESSION_SECRET=use-at-least-32-random-characters
```

Optional custom-domain setting:

```text
PUBLIC_BASE_URL=https://licenses.yourdomain.com
```

When `PUBLIC_BASE_URL` is omitted, the app uses Railway's `RAILWAY_PUBLIC_DOMAIN` when available.

### 4. Add a persistent Railway Volume

Attach one volume to the service and mount it at:

```text
/data
```

The volume stores:

- `database.json`
- Ed25519 private and public signing keys
- Session secret when one was not supplied

Do not deploy multiple replicas against this JSON store. This build is intentionally designed for one Railway service instance with one persistent volume.

### 5. Generate a public domain

Open Railway Networking and generate a public domain. Visit it, sign in using `ADMIN_PASSWORD`, create a product, issue a key, and patch a plugin.

## Local development

Requirements:

- Node.js 22+
- JDK 17+
- `jar` and `javac` on `PATH`

```bash
cp .env.example .env
npm install
./scripts/build-java.sh
ADMIN_PASSWORD=change-this SESSION_SECRET=replace-with-a-long-random-value npm start
```

Open `http://localhost:3000`.

## Customer installation

### Config-key mode

1. Put the downloaded licensed JAR in the server's `plugins` folder.
2. Start the server once.
3. RailGuard creates `plugins/<PluginName>/license.yml`.
4. Replace `CHANGE-ME` with the issued key.
5. Restart the server.

Example:

```yaml
license-key: RG-ABCDE-FGHIJ-KLMNP-QRSTU
```

### Embedded-key mode

The selected key is stored in the patched JAR. The customer only installs the JAR. Use this for a build issued to one specific customer.

## Validation behavior

At plugin enable, the injected runtime sends:

- Product ID
- License key
- Persistent random instance ID
- Plugin version
- Server version
- Random nonce
- Requested offline grace period

RailGuard replies with an Ed25519-signed payload. The plugin contains only the public key, so it can verify responses but cannot create valid responses itself.

A successful response is cached. When the license server is unreachable, the plugin can use that signed cache until `offline_until`. Revocation therefore becomes fully effective after the configured offline window.

## Compatibility and limits

- Java 17 or newer is required by the injected runtime.
- Standard Bukkit, Spigot, and Paper plugin descriptors are supported.
- The main plugin class must have a zero-argument constructor, as normal JavaPlugin classes do.
- Existing JAR signature files are removed because any JAR modification invalidates them.
- BungeeCord, Waterfall, and Velocity descriptors are not supported in this release.
- Paper bootstrap or loader code may execute before `onEnable`; RailGuard protects the normal enable phase.
- Licensing inside distributable JVM bytecode is a deterrent, not mathematically unbreakable DRM. A determined attacker can alter client-side checks. Keep sensitive server-side functionality behind APIs when possible.

## Security notes

- Use HTTPS in production. The production patch form rejects non-HTTPS license URLs.
- Keep `/data/ed25519-private.pem` private and backed up.
- Use a long random admin password.
- Keep the dashboard private when practical.
- Do not expose a deployment without a persistent `/data` volume; regenerated signing keys would make old patched JARs reject new responses.

## Commands

```bash
npm test
./scripts/build-java.sh
./scripts/test-patcher.sh
npm start
```
