'use strict';

function esc(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function layout(title, body, options = {}) {
  const notice = options.notice ? `<div class="notice ${esc(options.notice.type || '')}">${esc(options.notice.text)}</div>` : '';
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${esc(title)} · RailGuard</title>
  <link rel="stylesheet" href="/app.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">RailGuard</a>
    ${options.authenticated ? `<nav><a href="/">Implementer</a><a href="/admin">Licenses</a><form method="post" action="/admin/logout" class="inline"><input type="hidden" name="_csrf" value="${esc(options.csrf)}"><button class="link-button">Log out</button></form></nav>` : ''}
  </header>
  <main class="shell">${notice}${body}</main>
  <script src="/app.js" defer></script>
</body>
</html>`;
}

function loginPage(csrf, error = '') {
  return layout('Admin login', `
    <section class="auth-card">
      <div class="eyebrow">Private dashboard</div>
      <h1>License control center</h1>
      <p>Sign in with the Railway <code>ADMIN_PASSWORD</code> value.</p>
      ${error ? `<div class="notice error">${esc(error)}</div>` : ''}
      <form method="post" action="/admin/login" class="stack">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        <label>Password<input type="password" name="password" required autofocus autocomplete="current-password"></label>
        <button type="submit">Sign in</button>
      </form>
    </section>
  `);
}

function implementerPage({ csrf, products, publicBaseUrl, publicKeyB64, notice }) {
  const active = products.filter((p) => p.active);
  const options = active.length
    ? active.map((p) => `<option value="${esc(p.id)}">${esc(p.name)} (${esc(p.slug)})</option>`).join('')
    : '<option value="">Create an active product first</option>';
  return layout('Plugin implementer', `
    <section class="hero">
      <div><div class="eyebrow">Minecraft plugin licensing</div><h1>Drop a plugin in. Download it licensed.</h1>
      <p>The uploaded JAR is never executed. RailGuard changes its plugin entry point, injects a signed validation gate, and returns a new JAR.</p></div>
      <div class="status-chip">Ed25519 signed responses</div>
    </section>

    <section class="panel">
      <form method="post" action="/patch" enctype="multipart/form-data" class="stack" id="patch-form">
        <input type="hidden" name="_csrf" value="${esc(csrf)}">
        <label class="dropzone" id="dropzone">
          <input type="file" name="plugin" id="plugin-file" accept=".jar,application/java-archive" required>
          <strong>Drag and drop a plugin JAR</strong>
          <span id="file-label">or click to choose one — maximum 50 MB</span>
        </label>
        <div class="grid two">
          <label>License product<select name="product_id" required ${active.length ? '' : 'disabled'}>${options}</select></label>
          <label>Public license-server URL<input type="url" name="api_url" value="${esc(publicBaseUrl)}" required></label>
          <label>License-key mode<select name="key_mode" id="key-mode"><option value="config">Customer enters key in license.yml</option><option value="embedded">Embed one specific key</option></select></label>
          <label id="embedded-wrap" hidden>License key to embed<input type="text" name="embedded_key" placeholder="RG-XXXXX-XXXXX-XXXXX-XXXXX"></label>
          <label>Requested offline grace (hours)<input type="number" name="grace_hours" min="0" max="720" value="24" required></label>
          <label>Connection timeout (milliseconds)<input type="number" name="timeout_ms" min="1000" max="15000" value="4000" required></label>
        </div>
        <button type="submit" ${active.length ? '' : 'disabled'}>Implement license and download JAR</button>
      </form>
    </section>

    <section class="grid two info-grid">
      <article class="panel"><h2>What gets added</h2><p>A generated wrapper main class, a JDK-only verifier, a runtime <code>license.yml</code>, signed cached leases, activation limits, expiration checks, and revocation support.</p></article>
      <article class="panel"><h2>Signing public key</h2><p class="mono break">${esc(publicKeyB64)}</p><p class="muted">This key is embedded in patched JARs. Keep the private key files in your Railway volume.</p></article>
    </section>
  `, { authenticated: true, csrf, notice });
}

function adminPage({ csrf, products, licenses, activations, baseUrl, notice }) {
  const productRows = products.length ? products.map((p) => {
    const licenseCount = licenses.filter((l) => l.productId === p.id).length;
    return `<tr><td><strong>${esc(p.name)}</strong><div class="muted">${esc(p.slug)}</div></td><td>${licenseCount}</td><td>${p.maxActivations}</td><td>${p.maxOfflineHours}h</td><td><span class="pill ${p.active ? 'good' : 'bad'}">${p.active ? 'Active' : 'Disabled'}</span></td><td><form method="post" action="/admin/products/${esc(p.id)}/toggle"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="small secondary">${p.active ? 'Disable' : 'Enable'}</button></form></td></tr>`;
  }).join('') : '<tr><td colspan="6" class="muted">No products yet.</td></tr>';

  const licenseRows = licenses.length ? licenses.slice().reverse().map((l) => {
    const product = products.find((p) => p.id === l.productId);
    const count = activations.filter((a) => a.licenseId === l.id).length;
    return `<tr><td><button class="copy-key mono" data-copy="${esc(l.key)}" title="Copy key">${esc(l.key)}</button><div class="muted">${esc(l.customer || 'Unassigned')}</div></td><td>${esc(product?.name || 'Deleted product')}</td><td>${count}/${l.maxActivations ?? product?.maxActivations ?? 1}</td><td>${l.expiresAt ? esc(new Date(l.expiresAt).toLocaleDateString()) : 'Never'}</td><td><span class="pill ${l.active ? 'good' : 'bad'}">${l.active ? 'Active' : 'Revoked'}</span></td><td class="actions"><form method="post" action="/admin/licenses/${esc(l.id)}/toggle"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="small secondary">${l.active ? 'Revoke' : 'Restore'}</button></form><form method="post" action="/admin/licenses/${esc(l.id)}/reset"><input type="hidden" name="_csrf" value="${esc(csrf)}"><button class="small secondary">Reset activations</button></form></td></tr>`;
  }).join('') : '<tr><td colspan="6" class="muted">No licenses yet.</td></tr>';

  const productOptions = products.filter((p) => p.active).map((p) => `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
  return layout('License dashboard', `
    <section class="hero compact"><div><div class="eyebrow">Administration</div><h1>Products and license keys</h1><p>Validation endpoint: <code>${esc(baseUrl)}/api/v1/validate</code></p></div><div class="metrics"><span><strong>${products.length}</strong> products</span><span><strong>${licenses.length}</strong> licenses</span><span><strong>${activations.length}</strong> activations</span></div></section>

    <section class="grid two">
      <article class="panel"><h2>Create product</h2><form method="post" action="/admin/products" class="stack"><input type="hidden" name="_csrf" value="${esc(csrf)}"><label>Name<input name="name" maxlength="80" required placeholder="Quasar SMP"></label><label>Slug<input name="slug" maxlength="60" required pattern="[a-z0-9-]+" placeholder="quasar-smp"></label><div class="grid two"><label>Default max activations<input type="number" name="max_activations" min="1" max="1000" value="1" required></label><label>Maximum offline hours<input type="number" name="max_offline_hours" min="0" max="720" value="24" required></label></div><button>Create product</button></form></article>
      <article class="panel"><h2>Issue license</h2><form method="post" action="/admin/licenses" class="stack"><input type="hidden" name="_csrf" value="${esc(csrf)}"><label>Product<select name="product_id" required>${productOptions || '<option value="">Create a product first</option>'}</select></label><label>Customer / note<input name="customer" maxlength="120" placeholder="Customer name or order ID"></label><div class="grid two"><label>Activation override<input type="number" name="max_activations" min="1" max="1000" placeholder="Use product default"></label><label>Expiration<input type="date" name="expires_at"></label></div><button ${productOptions ? '' : 'disabled'}>Generate license key</button></form></article>
    </section>

    <section class="panel"><div class="section-head"><h2>Products</h2></div><div class="table-wrap"><table><thead><tr><th>Product</th><th>Licenses</th><th>Activations</th><th>Offline</th><th>Status</th><th></th></tr></thead><tbody>${productRows}</tbody></table></div></section>
    <section class="panel"><div class="section-head"><h2>License keys</h2><span class="muted">Click a key to copy it</span></div><div class="table-wrap"><table><thead><tr><th>Key / customer</th><th>Product</th><th>Uses</th><th>Expires</th><th>Status</th><th>Actions</th></tr></thead><tbody>${licenseRows}</tbody></table></div></section>
  `, { authenticated: true, csrf, notice });
}

module.exports = { esc, layout, loginPage, implementerPage, adminPage };
