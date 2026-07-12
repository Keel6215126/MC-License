package dev.railguard.patcher;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.jar.Attributes;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Repackages a Bukkit/Paper plugin without executing it. The patcher updates the main class so a generated
 * subclass performs a signed online license check before delegating to the original onEnable method.
 */
public final class JarPatcher {
    private static final long MAX_UNCOMPRESSED_BYTES = 300L * 1024 * 1024;
    private static final int MAX_ENTRIES = 25_000;
    private static final String RUNTIME_PATH = "dev/railguard/runtime/LicenseGate.class";
    private static final String[] RUNTIME_CLASSES = {
            "dev/railguard/runtime/LicenseGate.class",
            "dev/railguard/runtime/LicenseGate$Envelope.class",
            "dev/railguard/runtime/LicenseGate$Decision.class",
            "dev/railguard/runtime/LicenseGate$CachedResult.class"
    };
    private static final int ACC_PRIVATE = 0x0002;
    private static final int ACC_PROTECTED = 0x0004;
    private static final int ACC_FINAL = 0x0010;

    private JarPatcher() {}

    public static void main(String[] args) throws Exception {
        if (args.length != 9) {
            System.err.println("Usage: JarPatcher <input> <output> <productId> <apiUrl> <publicKeyB64> <embeddedKeyB64> <graceHours> <timeoutMs> <marker>");
            System.exit(2);
        }
        Path input = Path.of(args[0]);
        Path output = Path.of(args[1]);
        String productId = args[2];
        String apiUrl = args[3];
        String publicKeyB64 = args[4];
        String embeddedKey = new String(Base64.getDecoder().decode(args[5]), StandardCharsets.UTF_8);
        int graceHours = Integer.parseInt(args[6]);
        int timeoutMs = Integer.parseInt(args[7]);
        String marker = args[8];

        PatchResult result = patch(input, output, productId, apiUrl, publicKeyB64, embeddedKey, graceHours, timeoutMs, marker);
        System.out.println("{\"ok\":true,\"original_main\":\"" + json(result.originalMain) +
                "\",\"wrapper_main\":\"" + json(result.wrapperMain) +
                "\",\"descriptor\":\"" + json(result.descriptor) +
                "\",\"signatures_removed\":" + result.signaturesRemoved + "}");
    }

    public static PatchResult patch(Path input, Path output, String productId, String apiUrl, String publicKeyB64,
                                    String embeddedKey, int graceHours, int timeoutMs, String marker) throws Exception {
        if (!Files.isRegularFile(input)) throw new IOException("Input JAR does not exist");
        Map<String, byte[]> entries = new LinkedHashMap<>();
        int signaturesRemoved = 0;
        long total = 0;

        try (JarFile jar = new JarFile(input.toFile(), false)) {
            var enumeration = jar.entries();
            int count = 0;
            while (enumeration.hasMoreElements()) {
                JarEntry entry = enumeration.nextElement();
                count++;
                if (count > MAX_ENTRIES) throw new IOException("JAR contains too many entries");
                String name = normalizeEntryName(entry.getName());
                if (entry.isDirectory()) continue;
                if (isSignatureFile(name)) {
                    signaturesRemoved++;
                    continue;
                }
                try (InputStream in = jar.getInputStream(entry)) {
                    byte[] bytes = readLimited(in, MAX_UNCOMPRESSED_BYTES - total);
                    total += bytes.length;
                    if (total > MAX_UNCOMPRESSED_BYTES) throw new IOException("JAR is too large after decompression");
                    entries.put(name, bytes);
                }
            }
        }

        if (entries.containsKey("META-INF/railguard.properties")) {
            throw new IOException("This plugin already contains a RailGuard marker");
        }

        String descriptor = entries.containsKey("plugin.yml") ? "plugin.yml"
                : entries.containsKey("paper-plugin.yml") ? "paper-plugin.yml" : null;
        if (descriptor == null) throw new IOException("No plugin.yml or paper-plugin.yml was found");

        String descriptorText = new String(entries.get(descriptor), StandardCharsets.UTF_8);
        String originalMain = parseMainClass(descriptorText);
        if (originalMain == null || originalMain.isBlank()) throw new IOException("The plugin descriptor has no main class");
        String originalInternal = originalMain.replace('.', '/');
        String originalPath = originalInternal + ".class";
        byte[] originalBytes = entries.get(originalPath);
        if (originalBytes == null) throw new IOException("Main class not found in JAR: " + originalPath);

        ParsedClass parsed = parseClass(originalBytes);
        if (!originalInternal.equals(parsed.thisClassName)) {
            throw new IOException("Descriptor main class does not match class bytecode");
        }
        if (!parsed.hasNoArgConstructor) {
            throw new IOException("The plugin main class has no zero-argument constructor, so it cannot be wrapped safely");
        }

        String suffix = shortHash(originalBytes, productId, apiUrl, marker);
        String wrapperInternal = originalInternal + "$RailGuard_" + suffix;
        String wrapperMain = wrapperInternal.replace('/', '.');

        entries.put(originalPath, parsed.modifiedBytes);
        entries.put(wrapperInternal + ".class", generateWrapper(wrapperInternal, originalInternal,
                apiUrl, productId, publicKeyB64, embeddedKey, graceHours, timeoutMs));
        for (String runtimeClass : RUNTIME_CLASSES) entries.put(runtimeClass, loadRuntimeClass(runtimeClass));
        entries.put(descriptor, replaceMainClass(descriptorText, wrapperMain).getBytes(StandardCharsets.UTF_8));
        sanitizeManifest(entries);

        Properties markerProps = new Properties();
        markerProps.setProperty("version", "1.0.1");
        markerProps.setProperty("product_id", productId);
        markerProps.setProperty("original_main", originalMain);
        markerProps.setProperty("wrapper_main", wrapperMain);
        markerProps.setProperty("marker", marker);
        ByteArrayOutputStream markerBytes = new ByteArrayOutputStream();
        markerProps.store(markerBytes, "RailGuard license injection metadata");
        entries.put("META-INF/railguard.properties", markerBytes.toByteArray());

        Files.createDirectories(output.toAbsolutePath().getParent());
        Path temp = output.resolveSibling(output.getFileName() + ".tmp");
        try (JarOutputStream out = new JarOutputStream(Files.newOutputStream(temp))) {
            for (Map.Entry<String, byte[]> item : entries.entrySet()) {
                JarEntry entry = new JarEntry(item.getKey());
                entry.setTime(0L);
                out.putNextEntry(entry);
                out.write(item.getValue());
                out.closeEntry();
            }
        }
        Files.move(temp, output, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        return new PatchResult(originalMain, wrapperMain, descriptor, signaturesRemoved);
    }

    private static ParsedClass parseClass(byte[] input) throws IOException {
        byte[] bytes = input.clone();
        Cursor c = new Cursor(bytes);
        if (c.u4() != 0xCAFEBABEL) throw new IOException("Main class has an invalid class-file header");
        c.skip(4); // minor + major
        int cpCount = c.u2();
        String[] utf8 = new String[cpCount];
        int[] classNameIndexes = new int[cpCount];
        for (int i = 1; i < cpCount; i++) {
            int tag = c.u1();
            switch (tag) {
                case 1 -> {
                    int len = c.u2();
                    utf8[i] = new String(bytes, c.position, len, StandardCharsets.UTF_8);
                    c.skip(len);
                }
                case 3, 4 -> c.skip(4);
                case 5, 6 -> { c.skip(8); i++; }
                case 7 -> classNameIndexes[i] = c.u2();
                case 8, 16, 19, 20 -> c.skip(2);
                case 9, 10, 11, 12, 17, 18 -> c.skip(4);
                case 15 -> c.skip(3);
                default -> throw new IOException("Unsupported constant-pool tag: " + tag);
            }
        }

        int classAccessPos = c.position;
        int classAccess = c.u2();
        putU2(bytes, classAccessPos, classAccess & ~ACC_FINAL);
        int thisClassIndex = c.u2();
        c.u2(); // super
        String thisClassName = utf8[classNameIndexes[thisClassIndex]];

        int interfaceCount = c.u2();
        c.skip(interfaceCount * 2);
        skipMembers(c); // fields

        int methodCount = c.u2();
        boolean hasNoArgConstructor = false;
        for (int i = 0; i < methodCount; i++) {
            int accessPos = c.position;
            int access = c.u2();
            int nameIndex = c.u2();
            int descIndex = c.u2();
            String name = utf8[nameIndex];
            String descriptor = utf8[descIndex];
            if ("<init>".equals(name) && "()V".equals(descriptor)) {
                hasNoArgConstructor = true;
                int changed = access & ~ACC_FINAL;
                if ((changed & ACC_PRIVATE) != 0) changed = (changed & ~ACC_PRIVATE) | ACC_PROTECTED;
                putU2(bytes, accessPos, changed);
            } else if ("onEnable".equals(name) && "()V".equals(descriptor)) {
                putU2(bytes, accessPos, access & ~ACC_FINAL);
            }
            int attributes = c.u2();
            skipAttributes(c, attributes);
        }
        return new ParsedClass(thisClassName, hasNoArgConstructor, bytes);
    }

    private static void skipMembers(Cursor c) throws IOException {
        int count = c.u2();
        for (int i = 0; i < count; i++) {
            c.skip(6);
            int attributes = c.u2();
            skipAttributes(c, attributes);
        }
    }

    private static void skipAttributes(Cursor c, int count) throws IOException {
        for (int i = 0; i < count; i++) {
            c.skip(2);
            long length = c.u4();
            if (length > Integer.MAX_VALUE) throw new IOException("Class attribute is too large");
            c.skip((int) length);
        }
    }

    private static byte[] generateWrapper(String wrapperInternal, String originalInternal, String apiUrl,
                                          String productId, String publicKey, String embeddedKey,
                                          int graceHours, int timeoutMs) throws IOException {
        ConstantPool cp = new ConstantPool();
        int thisClass = cp.classInfo(wrapperInternal);
        int superClass = cp.classInfo(originalInternal);
        int codeUtf8 = cp.utf8("Code");
        int initName = cp.utf8("<init>");
        int voidDesc = cp.utf8("()V");
        int superInit = cp.methodRef(originalInternal, "<init>", "()V");
        int onEnableName = cp.utf8("onEnable");
        int superOnEnable = cp.methodRef(originalInternal, "onEnable", "()V");
        int apiString = cp.string(apiUrl);
        int productString = cp.string(productId);
        int keyString = cp.string(publicKey);
        int embeddedString = cp.string(embeddedKey == null ? "" : embeddedKey);
        int verify = cp.methodRef("dev/railguard/runtime/LicenseGate", "verify",
                "(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;II)Z");

        ByteArrayOutputStream classBytes = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(classBytes);
        out.writeInt(0xCAFEBABE);
        out.writeShort(0);
        out.writeShort(49); // Java 5 format deliberately avoids StackMapTable requirements.
        cp.write(out);
        out.writeShort(0x0021); // public + super
        out.writeShort(thisClass);
        out.writeShort(superClass);
        out.writeShort(0); // interfaces
        out.writeShort(0); // fields
        out.writeShort(2); // methods

        byte[] ctorCode = new byte[] {
                0x2a,
                (byte) 0xb7, hi(superInit), lo(superInit),
                (byte) 0xb1
        };
        writeMethod(out, 0x0001, initName, voidDesc, codeUtf8, 1, 1, ctorCode);

        ByteArrayOutputStream methodBuffer = new ByteArrayOutputStream();
        DataOutputStream code = new DataOutputStream(methodBuffer);
        code.writeByte(0x2a); // aload_0
        writeLdcW(code, apiString);
        writeLdcW(code, productString);
        writeLdcW(code, keyString);
        writeLdcW(code, embeddedString);
        writePushInt(code, graceHours);
        writePushInt(code, timeoutMs);
        code.writeByte(0xb8); code.writeShort(verify); // invokestatic
        code.writeByte(0x9a); code.writeShort(4); // ifne +4 -> aload_0 after return
        code.writeByte(0xb1); // return
        code.writeByte(0x2a); // aload_0
        code.writeByte(0xb7); code.writeShort(superOnEnable); // invokespecial
        code.writeByte(0xb1);
        writeMethod(out, 0x0001, onEnableName, voidDesc, codeUtf8, 7, 1, methodBuffer.toByteArray());

        out.writeShort(0); // class attributes
        out.flush();
        return classBytes.toByteArray();
    }

    private static void writeMethod(DataOutputStream out, int access, int nameIndex, int descriptorIndex,
                                    int codeNameIndex, int maxStack, int maxLocals, byte[] code) throws IOException {
        out.writeShort(access);
        out.writeShort(nameIndex);
        out.writeShort(descriptorIndex);
        out.writeShort(1); // attributes
        out.writeShort(codeNameIndex);
        out.writeInt(12 + code.length);
        out.writeShort(maxStack);
        out.writeShort(maxLocals);
        out.writeInt(code.length);
        out.write(code);
        out.writeShort(0); // exception table
        out.writeShort(0); // code attributes
    }

    private static void writeLdcW(DataOutputStream out, int index) throws IOException {
        out.writeByte(0x13);
        out.writeShort(index);
    }

    private static void writePushInt(DataOutputStream out, int value) throws IOException {
        if (value >= -1 && value <= 5) {
            out.writeByte(value == -1 ? 0x02 : 0x03 + value);
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            out.writeByte(0x10); out.writeByte(value);
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            out.writeByte(0x11); out.writeShort(value);
        } else {
            throw new IOException("Integer constant is out of supported range");
        }
    }

    private static byte hi(int value) { return (byte) ((value >>> 8) & 0xff); }
    private static byte lo(int value) { return (byte) (value & 0xff); }

    private static String parseMainClass(String yaml) {
        Pattern pattern = Pattern.compile("(?m)^([ \\t]*)main[ \\t]*:[ \\t]*[\"']?([^#\"'\\r\\n]+?)[\"']?[ \\t]*(?:#.*)?$");
        Matcher matcher = pattern.matcher(yaml);
        return matcher.find() ? matcher.group(2).trim() : null;
    }

    private static String replaceMainClass(String yaml, String wrapperMain) throws IOException {
        Pattern pattern = Pattern.compile("(?m)^([ \\t]*)main([ \\t]*):([ \\t]*)(?:[\"']?)([^#\"'\\r\\n]+?)(?:[\"']?)([ \\t]*)(#.*)?$");
        Matcher matcher = pattern.matcher(yaml);
        if (!matcher.find()) throw new IOException("Could not update main class in descriptor");
        String comment = matcher.group(6) == null ? "" : matcher.group(6);
        String replacement = matcher.group(1) + "main" + matcher.group(2) + ":" + matcher.group(3) + wrapperMain + matcher.group(5) + comment;
        return matcher.replaceFirst(Matcher.quoteReplacement(replacement));
    }

    private static void sanitizeManifest(Map<String, byte[]> entries) {
        byte[] bytes = entries.get("META-INF/MANIFEST.MF");
        if (bytes == null) return;
        try {
            Manifest manifest = new Manifest(new ByteArrayInputStream(bytes));
            stripDigestAttributes(manifest.getMainAttributes());
            for (Attributes attributes : manifest.getEntries().values()) stripDigestAttributes(attributes);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            manifest.write(out);
            entries.put("META-INF/MANIFEST.MF", out.toByteArray());
        } catch (Exception ignored) {
            entries.remove("META-INF/MANIFEST.MF");
        }
    }

    private static void stripDigestAttributes(Attributes attrs) {
        List<Object> remove = new ArrayList<>();
        for (Object keyObj : attrs.keySet()) {
            String key = String.valueOf(keyObj).toLowerCase(Locale.ROOT);
            if (key.endsWith("-digest") || key.contains("digest-") || key.equals("magic")) remove.add(keyObj);
        }
        for (Object key : remove) attrs.remove(key);
    }

    private static byte[] loadRuntimeClass(String resourcePath) throws IOException {
        try (InputStream in = JarPatcher.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (in == null) throw new IOException("Embedded runtime class is missing");
            return in.readAllBytes();
        }
    }

    private static boolean isSignatureFile(String name) {
        String upper = name.toUpperCase(Locale.ROOT);
        if (!upper.startsWith("META-INF/")) return false;
        return upper.endsWith(".SF") || upper.endsWith(".RSA") || upper.endsWith(".DSA") || upper.endsWith(".EC")
                || upper.startsWith("META-INF/SIG-");
    }

    private static String normalizeEntryName(String name) throws IOException {
        String normalized = name.replace('\\', '/');
        if (normalized.startsWith("/") || normalized.contains("../") || normalized.equals("..")) {
            throw new IOException("Unsafe JAR entry: " + name);
        }
        return normalized;
    }

    private static byte[] readLimited(InputStream in, long remaining) throws IOException {
        if (remaining < 0) throw new IOException("JAR is too large");
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[8192];
        long count = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            count += read;
            if (count > remaining) throw new IOException("JAR is too large after decompression");
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    private static String shortHash(byte[] bytes, String... values) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(bytes);
        for (String value : values) digest.update(value.getBytes(StandardCharsets.UTF_8));
        byte[] hash = digest.digest();
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < 6; i++) out.append(String.format("%02x", hash[i]));
        return out.toString();
    }

    private static String json(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static void putU2(byte[] bytes, int pos, int value) {
        bytes[pos] = (byte) ((value >>> 8) & 0xff);
        bytes[pos + 1] = (byte) (value & 0xff);
    }

    public record PatchResult(String originalMain, String wrapperMain, String descriptor, int signaturesRemoved) {}
    private record ParsedClass(String thisClassName, boolean hasNoArgConstructor, byte[] modifiedBytes) {}

    private static final class Cursor {
        private final byte[] bytes;
        private int position;
        private Cursor(byte[] bytes) { this.bytes = bytes; }
        int u1() throws IOException { require(1); return bytes[position++] & 0xff; }
        int u2() throws IOException { require(2); int v = ((bytes[position] & 0xff) << 8) | (bytes[position + 1] & 0xff); position += 2; return v; }
        long u4() throws IOException { require(4); long v = ((long)(bytes[position] & 0xff) << 24) | ((long)(bytes[position + 1] & 0xff) << 16) | ((long)(bytes[position + 2] & 0xff) << 8) | (bytes[position + 3] & 0xffL); position += 4; return v; }
        void skip(int amount) throws IOException { require(amount); position += amount; }
        private void require(int amount) throws IOException { if (amount < 0 || position + amount > bytes.length) throw new IOException("Truncated class file"); }
    }

    private static final class ConstantPool {
        private final List<Entry> entries = new ArrayList<>();
        private final Map<String, Integer> dedupe = new LinkedHashMap<>();
        int utf8(String value) { return add("U:" + value, new Utf8Entry(value)); }
        int classInfo(String internalName) { int name = utf8(internalName); return add("C:" + internalName, new PairEntry(7, name, 0)); }
        int string(String value) { int utf = utf8(value); return add("S:" + value, new PairEntry(8, utf, 0)); }
        int nameAndType(String name, String desc) { int n = utf8(name), d = utf8(desc); return add("N:" + name + ":" + desc, new PairEntry(12, n, d)); }
        int methodRef(String owner, String name, String desc) { int c = classInfo(owner), nt = nameAndType(name, desc); return add("M:" + owner + ":" + name + desc, new PairEntry(10, c, nt)); }
        private int add(String key, Entry entry) { Integer old = dedupe.get(key); if (old != null) return old; entries.add(entry); int index = entries.size(); dedupe.put(key, index); return index; }
        void write(DataOutputStream out) throws IOException { out.writeShort(entries.size() + 1); for (Entry entry : entries) entry.write(out); }
    }

    private interface Entry { void write(DataOutputStream out) throws IOException; }
    private record Utf8Entry(String value) implements Entry {
        public void write(DataOutputStream out) throws IOException {
            byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > 65535) throw new IOException("Embedded string exceeds class-file UTF-8 limit");
            out.writeByte(1); out.writeShort(bytes.length); out.write(bytes);
        }
    }
    private record PairEntry(int tag, int first, int second) implements Entry {
        public void write(DataOutputStream out) throws IOException {
            out.writeByte(tag); out.writeShort(first); if (tag != 7 && tag != 8) out.writeShort(second);
        }
    }
}
