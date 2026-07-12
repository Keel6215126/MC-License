#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ ! -f "$ROOT/java-build/dev/railguard/patcher/JarPatcher.class" ]; then
  "$ROOT/scripts/build-java.sh" >/dev/null
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p \
  "$TMP/src/org/bukkit/plugin/java" \
  "$TMP/src/org/bukkit/plugin" \
  "$TMP/src/org/bukkit" \
  "$TMP/src/org/mclicense/library" \
  "$TMP/src/example" \
  "$TMP/src/org/json" \
  "$TMP/classes" \
  "$TMP/plugin" \
  "$TMP/vendor"

cat > "$TMP/src/org/bukkit/plugin/Plugin.java" <<'JAVA'
package org.bukkit.plugin;
public interface Plugin {}
JAVA

cat > "$TMP/src/org/bukkit/plugin/PluginManager.java" <<'JAVA'
package org.bukkit.plugin;
public interface PluginManager { void disablePlugin(Plugin plugin); }
JAVA

cat > "$TMP/src/org/bukkit/Bukkit.java" <<'JAVA'
package org.bukkit;
import org.bukkit.plugin.PluginManager;
public final class Bukkit {
  public static PluginManager getPluginManager() {
    return plugin -> System.out.println("DISABLED");
  }
}
JAVA

cat > "$TMP/src/org/bukkit/plugin/java/JavaPlugin.java" <<'JAVA'
package org.bukkit.plugin.java;
public class JavaPlugin implements org.bukkit.plugin.Plugin {
  public JavaPlugin() {}
  public void onEnable() {}
}
JAVA

cat > "$TMP/src/org/mclicense/library/MCLicense.java" <<'JAVA'
package org.mclicense.library;
public final class MCLicense {
  public static boolean validateKey(org.bukkit.plugin.java.JavaPlugin plugin, String pluginId) {
    System.out.println("VALIDATE:" + pluginId);
    return false;
  }
}
JAVA


cat > "$TMP/src/org/json/JSONObject.java" <<'JAVA'
package org.json;
public class JSONObject { public JSONObject() {} }
JAVA

cat > "$TMP/src/example/Demo.java" <<'JAVA'
package example;
public final class Demo extends org.bukkit.plugin.java.JavaPlugin {
  public Demo() {}
  public final void onEnable() { System.out.println("ORIGINAL"); }
}
JAVA

javac --release 17 -d "$TMP/classes" $(find "$TMP/src" -name '*.java')
cp -R "$TMP/classes/example" "$TMP/plugin/"
printf 'name: Demo\nversion: 1.0\nmain: example.Demo\n' > "$TMP/plugin/plugin.yml"
jar --create --file "$TMP/input.jar" -C "$TMP/plugin" .
jar --create --file "$TMP/vendor/mc-license-library.jar" -C "$TMP/classes" org/mclicense
jar --create --file "$TMP/vendor/json.jar" -C "$TMP/classes" org/json

java -cp "$ROOT/java-build" dev.railguard.patcher.JarPatcher \
  "$TMP/input.jar" "$TMP/output.jar" 3gd7u9r4 "$TMP/vendor" test-marker >/dev/null

unzip -p "$TMP/output.jar" plugin.yml | grep -q 'main: example.Demo\$MCLicense_'
jar tf "$TMP/output.jar" | grep -q 'org/mclicense/library/MCLicense.class'
jar tf "$TMP/output.jar" | grep -q 'org/json/JSONObject.class'
jar tf "$TMP/output.jar" | grep -q 'META-INF/mclicense-implementer.properties'

WRAPPER=$(unzip -p "$TMP/output.jar" plugin.yml | sed -n 's/^main:[[:space:]]*//p')
cat > "$TMP/Runner.java" <<'JAVA'
public final class Runner {
  public static void main(String[] args) throws Exception {
    Object plugin = Class.forName(args[0]).getDeclaredConstructor().newInstance();
    plugin.getClass().getMethod("onEnable").invoke(plugin);
  }
}
JAVA
javac --release 17 -cp "$TMP/output.jar:$TMP/classes" -d "$TMP/classes" "$TMP/Runner.java"
RESULT=$(java -cp "$TMP/output.jar:$TMP/classes" Runner "$WRAPPER")
printf '%s\n' "$RESULT" | grep -q 'VALIDATE:3gd7u9r4'
printf '%s\n' "$RESULT" | grep -q 'DISABLED'
if printf '%s\n' "$RESULT" | grep -q 'ORIGINAL'; then
  echo 'Original onEnable ran after a failed license check.' >&2
  exit 1
fi

echo "MC License patcher integration test passed."
