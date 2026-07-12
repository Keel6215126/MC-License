#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
[ -f "$ROOT/java-build/dev/railguard/patcher/JarPatcher.class" ] || "$ROOT/scripts/build-java.sh" >/dev/null
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/src/org/bukkit/plugin/java" "$TMP/src/org/bukkit/plugin" "$TMP/src/org/bukkit" "$TMP/src/org/mclicense/library" "$TMP/src/org/json" "$TMP/src/example" "$TMP/classes" "$TMP/plugin" "$TMP/deps"
cat > "$TMP/src/org/bukkit/plugin/Plugin.java" <<'JAVA'
package org.bukkit.plugin; public interface Plugin {}
JAVA
cat > "$TMP/src/org/bukkit/plugin/PluginManager.java" <<'JAVA'
package org.bukkit.plugin; public interface PluginManager { void disablePlugin(Plugin plugin); }
JAVA
cat > "$TMP/src/org/bukkit/Bukkit.java" <<'JAVA'
package org.bukkit; public final class Bukkit { public static org.bukkit.plugin.PluginManager getPluginManager(){ return p -> System.out.println("DISABLED"); } }
JAVA
cat > "$TMP/src/org/bukkit/plugin/java/JavaPlugin.java" <<'JAVA'
package org.bukkit.plugin.java; public class JavaPlugin implements org.bukkit.plugin.Plugin { public JavaPlugin(){} public void onEnable(){} }
JAVA
cat > "$TMP/src/org/mclicense/library/MCLicense.java" <<'JAVA'
package org.mclicense.library; public final class MCLicense { public static boolean validateKey(org.bukkit.plugin.java.JavaPlugin p,String id){ System.out.println("VALIDATE:"+id); return false; } }
JAVA
cat > "$TMP/src/org/json/JSONObject.java" <<'JAVA'
package org.json; public class JSONObject {}
JAVA
cat > "$TMP/src/example/Demo.java" <<'JAVA'
package example; public final class Demo extends org.bukkit.plugin.java.JavaPlugin { public final void onEnable(){ System.out.println("ORIGINAL"); } }
JAVA
javac --release 17 -d "$TMP/classes" $(find "$TMP/src" -name '*.java')
cp -R "$TMP/classes/example" "$TMP/plugin/"; printf 'name: Demo\nversion: 1.0\nmain: example.Demo\n' > "$TMP/plugin/plugin.yml"
jar --create --file "$TMP/input.jar" -C "$TMP/plugin" .
jar --create --file "$TMP/deps/mcl.jar" -C "$TMP/classes" org/mclicense
jar --create --file "$TMP/deps/json.jar" -C "$TMP/classes" org/json
java -cp "$ROOT/java-build" dev.railguard.patcher.JarPatcher "$TMP/input.jar" "$TMP/output.jar" 3gd7u9r4 "$TMP/deps" marker >/dev/null
jar tf "$TMP/output.jar" | grep -q '^org/json/JSONObject.class$'
WRAPPER=$(unzip -p "$TMP/output.jar" plugin.yml | sed -n 's/^main:[[:space:]]*//p')
cat > "$TMP/Runner.java" <<'JAVA'
public final class Runner { public static void main(String[] a)throws Exception{Object p=Class.forName(a[0]).getDeclaredConstructor().newInstance();p.getClass().getMethod("onEnable").invoke(p);} }
JAVA
javac --release 17 -cp "$TMP/output.jar:$TMP/classes" -d "$TMP/classes" "$TMP/Runner.java"
RESULT=$(java -cp "$TMP/output.jar:$TMP/classes" Runner "$WRAPPER")
printf '%s\n' "$RESULT" | grep -q 'VALIDATE:3gd7u9r4'
printf '%s\n' "$RESULT" | grep -q 'DISABLED'
! printf '%s\n' "$RESULT" | grep -q 'ORIGINAL'
echo "License injection test passed."
