'use strict';

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function code(value) {
  return `<pre><code>${esc(value.trim())}</code></pre>`;
}

function layout(title, body, options = {}) {
  const notice = options.notice
    ? `<div class="notice ${esc(options.notice.type || '')}">${esc(options.notice.text)}</div>`
    : '';

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="description" content="Add the official MC License check to a Minecraft plugin JAR.">
  <title>${esc(title)} · MC License Implementer</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">MC License Implementer</a>
    <nav>
      <a href="/">Implementer</a>
      <a href="/license-check">License Check</a>
    </nav>
  </header>
  <main class="shell">${notice}${body}</main>
  <script src="/app.js" defer></script>
</body>
</html>`;
}

function implementerPage({ notice }) {
  return layout('Implementer', `
    <section class="hero">
      <div>
        <div class="eyebrow">Official MC License integration</div>
        <h1>Drop in your plugin. Add its plugin ID. Done.</h1>
        <p>MC License 1.5.1 is inserted directly into the uploaded JAR. There are no modes, grace periods, custom servers, embedded customer keys, or optional behavior.</p>
      </div>
      <div class="status-chip">MC License library 1.5.1</div>
    </section>

    <section class="panel implement-panel">
      <form method="post" action="/implement" enctype="multipart/form-data" class="stack" id="implement-form">
        <label class="dropzone" id="dropzone">
          <input type="file" name="plugin" id="plugin-file" accept=".jar,application/java-archive" required>
          <strong>Drag and drop your Minecraft plugin JAR</strong>
          <span id="file-label">or click to choose one — maximum 50 MB</span>
        </label>

        <label class="plugin-id-field">
          MC License plugin ID
          <input type="text" name="plugin_id" maxlength="8" minlength="8" pattern="[A-Za-z0-9]{8}" placeholder="3gd7u9r4" autocomplete="off" spellcheck="false" required>
          <span class="field-help">Copy the 8-character ID from the plugin URL on your MC License dashboard.</span>
        </label>

        <button type="submit">Implement MC License and download JAR</button>
      </form>
    </section>

    <section class="grid three behavior-grid">
      <article class="panel">
        <div class="step-number">1</div>
        <h2>Mandatory validation</h2>
        <p>The license is checked before the original plugin enables. The original <code>onEnable</code> only runs after a valid result.</p>
      </article>
      <article class="panel">
        <div class="step-number">2</div>
        <h2>Invalid means disabled</h2>
        <p>If the key is missing, rejected, expired, or the check fails, Bukkit immediately disables the plugin. This cannot be changed in the website.</p>
      </article>
      <article class="panel">
        <div class="step-number">3</div>
        <h2>Only mclicense.txt</h2>
        <p>The library creates one empty file: <code>plugins/YourPlugin/mclicense.txt</code>. The server owner places the license key inside it and restarts.</p>
      </article>
    </section>

    <section class="panel fixed-behavior">
      <h2>Exactly what is added</h2>
      <ul>
        <li>The official <code>org.mclicense:library:1.5.1</code> classes are shaded into the JAR.</li>
        <li>A generated entry-point wrapper calls <code>MCLicense.validateKey(this, "yourPluginId")</code>.</li>
        <li>A rejected check calls <code>Bukkit.getPluginManager().disablePlugin(this)</code> and returns immediately.</li>
        <li>No <code>config.yml</code>, <code>license.yml</code>, cache file, offline lease, or custom setting is created.</li>
      </ul>
    </section>
  `, { notice });
}

function licenseCheckPage() {
  const maven = `<repositories>
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
</dependencies>`;

  const gradle = `repositories {
    maven {
        name = "flyteRepositoryReleases"
        url = uri("https://repo.flyte.gg/releases")
    }
}

dependencies {
    implementation "org.mclicense:library:1.5.1"
}`;

  const gradleKts = `repositories {
    maven {
        name = "flyteRepositoryReleases"
        url = uri("https://repo.flyte.gg/releases")
    }
}

dependencies {
    implementation("org.mclicense:library:1.5.1")
}`;

  const javaCheck = `if (!MCLicense.validateKey(this, "yourPluginId")) {
    Bukkit.getPluginManager().disablePlugin(this);
    return;
}`;

  const kotlinCheck = `if (!MCLicense.validateKey(this, "yourPluginId")) {
    Bukkit.getPluginManager().disablePlugin(this)
    return
}`;

  return layout('License Check', `
    <article class="docs">
      <div class="eyebrow">Integration guide</div>
      <h1>License Check</h1>
      <p>This page shows how to integrate MC License into your plugin.</p>

      <h2 id="adding-library">Adding the library</h2>
      <p>We offer two ways to add MC License to your plugin:</p>

      <h3>Option 1 — Dependency (recommended)</h3>
      <p>Add the following repository and dependency to your build file:</p>

      <div class="tabs" data-tabs>
        <div class="tab-list" role="tablist">
          <button type="button" class="tab active" data-tab="maven">Maven (pom.xml)</button>
          <button type="button" class="tab" data-tab="gradle">Gradle (build.gradle)</button>
          <button type="button" class="tab" data-tab="gradle-kts">Gradle Kotlin DSL (build.gradle.kts)</button>
        </div>
        <div class="tab-panel active" data-panel="maven">${code(maven)}</div>
        <div class="tab-panel" data-panel="gradle">${code(gradle)}</div>
        <div class="tab-panel" data-panel="gradle-kts">${code(gradleKts)}</div>
      </div>

      <h3>Option 2 — Single class (copy/paste)</h3>
      <p>If you are having trouble shading the library into your plugin, or prefer not to manage external dependencies, copy a single class directly into your project instead. Open the <a class="text-link" href="https://github.com/flytegg/mcl-library-one-class" target="_blank" rel="noreferrer">mcl-library-one-class repository</a> and copy either <code>MCLicense.java</code> or <code>MCLicense.kt</code> into your project.</p>
      <p>No shading is needed. All required dependencies are already on the Paper server classpath at runtime. With the single-class approach, you must manually check the repository for updates instead of bumping a dependency version.</p>

      <h2 id="checking-license">Checking a license</h2>
      <p>Each license check requires the <code>pluginId</code> and the license key. The <code>pluginId</code> uniquely identifies your plugin. The user places their license key in the <code>mclicense.txt</code> file inside your plugin folder; the library creates that empty file automatically.</p>
      <p>Find the plugin ID by opening the plugin on your MC License dashboard and copying the random string from the URL. It looks like <code>3gd7u9r4</code> and is exactly 8 characters.</p>
      <p>Add the following check at the beginning of your <code>onEnable</code>:</p>

      <div class="tabs" data-tabs>
        <div class="tab-list" role="tablist">
          <button type="button" class="tab active" data-tab="java">Java</button>
          <button type="button" class="tab" data-tab="kotlin">Kotlin</button>
        </div>
        <div class="tab-panel active" data-panel="java">${code(javaCheck)}</div>
        <div class="tab-panel" data-panel="kotlin">${code(kotlinCheck)}</div>
      </div>

      <p><code>validateKey</code> returns a Boolean. If the key is invalid, the plugin is disabled and returns immediately. If the key is valid, the plugin continues loading. The library handles successful and rejected console logging.</p>

      <div class="callout">
        <strong>The online implementer always uses this exact behavior.</strong>
        <span>There are no optional modes. It always blocks startup after a failed validation and only creates the empty <code>mclicense.txt</code> file.</span>
      </div>

      <h2>Not building a Minecraft plugin?</h2>
      <p>MC License is not limited to Minecraft plugins. Other software can use the MC License HTTP API directly.</p>
    </article>
  `);
}

module.exports = { esc, layout, implementerPage, licenseCheckPage };
