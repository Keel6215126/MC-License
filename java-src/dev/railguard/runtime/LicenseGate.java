package dev.railguard.runtime;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Runtime verifier inserted into patched plugins. Uses only the JDK and reflection. */
public final class LicenseGate {
    private static final Pattern JSON_STRING = Pattern.compile("\\\"%s\\\"\\s*:\\s*\\\"((?:\\\\.|[^\\\"])*)\\\"");
    private static final Pattern JSON_BOOL = Pattern.compile("\\\"%s\\\"\\s*:\\s*(true|false)");
    private static final Pattern JSON_LONG = Pattern.compile("\\\"%s\\\"\\s*:\\s*(-?\\d+)");

    private LicenseGate() {}

    public static boolean verify(
            Object plugin,
            String apiUrl,
            String productId,
            String publicKeyB64,
            String embeddedKey,
            int requestedGraceHours,
            int timeoutMs) {
        try {
            Path dataFolder = resolveDataFolder(plugin);
            Files.createDirectories(dataFolder);
            String licenseKey = embeddedKey == null || embeddedKey.isBlank()
                    ? readOrCreateLicenseConfig(dataFolder)
                    : embeddedKey.trim();

            if (licenseKey == null || licenseKey.isBlank() || "CHANGE-ME".equalsIgnoreCase(licenseKey)) {
                log(plugin, "severe", "No license key is configured. Set license-key in " + dataFolder.resolve("license.yml"));
                disable(plugin);
                return false;
            }

            String instanceId = readOrCreateInstanceId(dataFolder);
            String nonce = UUID.randomUUID().toString();
            String pluginVersion = reflectString(plugin, "getDescription", "getVersion", "unknown");
            String serverVersion = reflectString(plugin, "getServer", "getVersion", "unknown");
            int grace = Math.max(0, Math.min(requestedGraceHours, 24 * 30));
            int timeout = Math.max(1000, Math.min(timeoutMs, 15000));

            try {
                String requestJson = "{" +
                        "\"product_id\":\"" + escape(productId) + "\"," +
                        "\"license_key\":\"" + escape(licenseKey) + "\"," +
                        "\"instance_id\":\"" + escape(instanceId) + "\"," +
                        "\"plugin_version\":\"" + escape(pluginVersion) + "\"," +
                        "\"server_version\":\"" + escape(serverVersion) + "\"," +
                        "\"nonce\":\"" + escape(nonce) + "\"," +
                        "\"grace_hours\":" + grace +
                        "}";

                HttpClient client = HttpClient.newBuilder()
                        .connectTimeout(Duration.ofMillis(timeout))
                        .followRedirects(HttpClient.Redirect.NORMAL)
                        .build();
                HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(normalizeApiUrl(apiUrl) + "/api/v1/validate"))
                        .timeout(Duration.ofMillis(timeout))
                        .header("Content-Type", "application/json")
                        .header("User-Agent", "RailGuard-Minecraft/1.0")
                        .POST(HttpRequest.BodyPublishers.ofString(requestJson, StandardCharsets.UTF_8))
                        .build();
                HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    throw new IOException("License server returned HTTP " + response.statusCode());
                }

                Envelope envelope = parseAndVerifyEnvelope(response.body(), publicKeyB64);
                Decision decision = parseDecision(envelope.payloadJson);
                if (!nonce.equals(decision.nonce)) {
                    throw new SecurityException("License response nonce mismatch");
                }
                if (!productId.equals(decision.productId) || !instanceId.equals(decision.instanceId)
                        || !sha256Hex(licenseKey.trim().toUpperCase(Locale.ROOT)).equals(decision.keyHash)) {
                    throw new SecurityException("License response identity mismatch");
                }
                if (!decision.valid) {
                    log(plugin, "severe", "License rejected [" + decision.code + "]: " + decision.message);
                    disable(plugin);
                    return false;
                }

                atomicWrite(dataFolder.resolve(".license-cache"), response.body());
                updateClockState(dataFolder, System.currentTimeMillis());
                log(plugin, "info", "License accepted for product " + productId + ".");
                return true;
            } catch (Exception onlineFailure) {
                CachedResult cached = tryCached(dataFolder, publicKeyB64, productId, instanceId, licenseKey);
                if (cached.valid) {
                    log(plugin, "warning", "License server is unavailable; using signed offline lease until " + cached.offlineUntil + ".");
                    return true;
                }
                log(plugin, "severe", "License validation failed: " + safeMessage(onlineFailure));
                disable(plugin);
                return false;
            }
        } catch (Exception fatal) {
            log(plugin, "severe", "License system could not initialize: " + safeMessage(fatal));
            disable(plugin);
            return false;
        }
    }

    private static CachedResult tryCached(Path dataFolder, String publicKeyB64, String productId, String instanceId, String licenseKey) {
        try {
            Path cache = dataFolder.resolve(".license-cache");
            if (!Files.isRegularFile(cache)) return CachedResult.invalid();
            long now = System.currentTimeMillis();
            long lastSeen = readLastSeen(dataFolder);
            if (lastSeen > 0 && now + 5 * 60_000L < lastSeen) return CachedResult.invalid();

            String body = Files.readString(cache, StandardCharsets.UTF_8);
            Envelope envelope = parseAndVerifyEnvelope(body, publicKeyB64);
            Decision d = parseDecision(envelope.payloadJson);
            if (!d.valid || !productId.equals(d.productId) || !instanceId.equals(d.instanceId)
                    || !sha256Hex(licenseKey.trim().toUpperCase(Locale.ROOT)).equals(d.keyHash) || now > d.offlineUntil) {
                return CachedResult.invalid();
            }
            updateClockState(dataFolder, now);
            return new CachedResult(true, d.offlineUntil);
        } catch (Exception ignored) {
            return CachedResult.invalid();
        }
    }

    private static Envelope parseAndVerifyEnvelope(String body, String publicKeyB64) throws Exception {
        String payloadB64 = jsonString(body, "payload");
        String signatureB64 = jsonString(body, "signature");
        byte[] payload = Base64.getDecoder().decode(payloadB64);
        byte[] signatureBytes = Base64.getDecoder().decode(signatureB64);
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyB64);
        PublicKey publicKey = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(keyBytes));
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(publicKey);
        verifier.update(payload);
        if (!verifier.verify(signatureBytes)) throw new SecurityException("Invalid license signature");
        return new Envelope(new String(payload, StandardCharsets.UTF_8));
    }

    private static Decision parseDecision(String payloadJson) {
        return new Decision(
                jsonBool(payloadJson, "valid"),
                jsonString(payloadJson, "code"),
                jsonString(payloadJson, "message"),
                jsonString(payloadJson, "product_id"),
                jsonString(payloadJson, "instance_id"),
                jsonString(payloadJson, "nonce"),
                jsonString(payloadJson, "key_hash"),
                jsonLong(payloadJson, "offline_until"));
    }

    private static String readOrCreateLicenseConfig(Path dataFolder) throws IOException {
        Path config = dataFolder.resolve("license.yml");
        if (!Files.exists(config)) {
            atomicWrite(config, "# License key issued by the plugin author\nlicense-key: CHANGE-ME\n");
            return "CHANGE-ME";
        }
        for (String line : Files.readAllLines(config, StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (trimmed.toLowerCase(Locale.ROOT).startsWith("license-key:")) {
                String value = trimmed.substring(trimmed.indexOf(':') + 1).trim();
                if ((value.startsWith("\"") && value.endsWith("\"")) || (value.startsWith("'") && value.endsWith("'"))) {
                    value = value.substring(1, value.length() - 1);
                }
                return value.trim();
            }
        }
        return "CHANGE-ME";
    }

    private static String readOrCreateInstanceId(Path dataFolder) throws IOException {
        Path file = dataFolder.resolve(".license-instance");
        if (Files.exists(file)) {
            String value = Files.readString(file, StandardCharsets.UTF_8).trim();
            if (!value.isBlank()) return value;
        }
        String value = UUID.randomUUID().toString();
        atomicWrite(file, value + "\n");
        return value;
    }

    private static Path resolveDataFolder(Object plugin) throws Exception {
        Object value = plugin.getClass().getMethod("getDataFolder").invoke(plugin);
        if (value instanceof java.io.File file) return file.toPath();
        throw new IllegalStateException("Plugin data folder is unavailable");
    }

    private static String reflectString(Object root, String firstMethod, String secondMethod, String fallback) {
        try {
            Object first = root.getClass().getMethod(firstMethod).invoke(root);
            if (first == null) return fallback;
            Object second = first.getClass().getMethod(secondMethod).invoke(first);
            return second == null ? fallback : String.valueOf(second);
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private static void disable(Object plugin) {
        try {
            Object server = plugin.getClass().getMethod("getServer").invoke(plugin);
            Object manager = server.getClass().getMethod("getPluginManager").invoke(server);
            for (Method method : manager.getClass().getMethods()) {
                if (method.getName().equals("disablePlugin") && method.getParameterCount() == 1
                        && method.getParameterTypes()[0].isAssignableFrom(plugin.getClass())) {
                    method.invoke(manager, plugin);
                    return;
                }
            }
        } catch (Exception ignored) {
            // Returning false from the generated onEnable wrapper still prevents plugin initialization.
        }
    }

    private static void log(Object plugin, String level, String message) {
        try {
            Object logger = plugin.getClass().getMethod("getLogger").invoke(plugin);
            Method method = logger.getClass().getMethod(level, String.class);
            method.invoke(logger, "[RailGuard] " + message);
        } catch (Exception ignored) {
            System.err.println("[RailGuard] " + message);
        }
    }

    private static void atomicWrite(Path path, String content) throws IOException {
        Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
        Files.writeString(tmp, content, StandardCharsets.UTF_8);
        try {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (IOException unsupported) {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void updateClockState(Path dataFolder, long now) {
        try {
            long previous = readLastSeen(dataFolder);
            atomicWrite(dataFolder.resolve(".license-clock"), Long.toString(Math.max(previous, now)));
        } catch (Exception ignored) {}
    }

    private static long readLastSeen(Path dataFolder) {
        try {
            return Long.parseLong(Files.readString(dataFolder.resolve(".license-clock"), StandardCharsets.UTF_8).trim());
        } catch (Exception ignored) {
            return 0L;
        }
    }

    private static String normalizeApiUrl(String value) {
        String v = value == null ? "" : value.trim();
        while (v.endsWith("/")) v = v.substring(0, v.length() - 1);
        if (!(v.startsWith("https://") || v.startsWith("http://"))) {
            throw new IllegalArgumentException("Invalid license API URL");
        }
        return v;
    }

    private static String jsonString(String json, String key) {
        Matcher m = Pattern.compile(String.format(JSON_STRING.pattern(), Pattern.quote(key))).matcher(json);
        if (!m.find()) throw new IllegalArgumentException("Missing JSON field: " + key);
        return unescape(m.group(1));
    }

    private static boolean jsonBool(String json, String key) {
        Matcher m = Pattern.compile(String.format(JSON_BOOL.pattern(), Pattern.quote(key))).matcher(json);
        if (!m.find()) throw new IllegalArgumentException("Missing JSON field: " + key);
        return Boolean.parseBoolean(m.group(1));
    }

    private static long jsonLong(String json, String key) {
        Matcher m = Pattern.compile(String.format(JSON_LONG.pattern(), Pattern.quote(key))).matcher(json);
        if (!m.find()) throw new IllegalArgumentException("Missing JSON field: " + key);
        return Long.parseLong(m.group(1));
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r");
    }

    private static String unescape(String value) {
        StringBuilder out = new StringBuilder();
        boolean escaped = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!escaped) {
                if (c == '\\') escaped = true; else out.append(c);
            } else {
                switch (c) {
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case '"' -> out.append('"');
                    case '\\' -> out.append('\\');
                    default -> out.append(c);
                }
                escaped = false;
            }
        }
        if (escaped) out.append('\\');
        return out.toString();
    }

    private static String sha256Hex(String value) throws Exception {
        byte[] hash = java.security.MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder(hash.length * 2);
        for (byte b : hash) out.append(String.format("%02x", b));
        return out.toString();
    }

    private static String safeMessage(Exception e) {
        String message = e.getMessage();
        return (message == null || message.isBlank()) ? e.getClass().getSimpleName() : message;
    }

    private record Envelope(String payloadJson) {}
    private record Decision(boolean valid, String code, String message, String productId, String instanceId,
                            String nonce, String keyHash, long offlineUntil) {}
    private record CachedResult(boolean valid, long offlineUntil) {
        static CachedResult invalid() { return new CachedResult(false, 0L); }
    }
}
