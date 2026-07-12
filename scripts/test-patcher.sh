#!/usr/bin/env sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
if [ ! -f "$ROOT/java-build/dev/railguard/patcher/JarPatcher.class" ]; then
  "$ROOT/scripts/build-java.sh" >/dev/null
fi
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/src/org/bukkit/plugin/java" "$TMP/src/example" "$TMP/classes"
cat > "$TMP/src/org/bukkit/plugin/java/JavaPlugin.java" <<'JAVA'
package org.bukkit.plugin.java;
public class JavaPlugin { public JavaPlugin() {} public void onEnable() {} }
JAVA
cat > "$TMP/src/example/Demo.java" <<'JAVA'
package example;
public final class Demo extends org.bukkit.plugin.java.JavaPlugin {
  public Demo() {}
  public final void onEnable() {}
}
JAVA
javac --release 17 -d "$TMP/classes" $(find "$TMP/src" -name '*.java')
printf 'name: Demo\nversion: 1.0\nmain: example.Demo\n' > "$TMP/classes/plugin.yml"
jar --create --file "$TMP/input.jar" -C "$TMP/classes" .
java -cp "$ROOT/java-build" dev.railguard.patcher.JarPatcher \
  "$TMP/input.jar" "$TMP/output.jar" product-test http://localhost:3000 AAAA '' 24 4000 test-marker >/dev/null
unzip -p "$TMP/output.jar" plugin.yml | grep -q 'main: example.Demo\$RailGuard_'
jar tf "$TMP/output.jar" | grep -q 'dev/railguard/runtime/LicenseGate.class'
jar tf "$TMP/output.jar" | grep -q 'META-INF/railguard.properties'
echo "Patcher integration test passed."
