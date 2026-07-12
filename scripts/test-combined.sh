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
package org.bukkit; public final class Bukkit { public static org.bukkit.plugin.PluginManager getPluginManager(){ return p -> {}; } }
JAVA
cat > "$TMP/src/org/bukkit/plugin/java/JavaPlugin.java" <<'JAVA'
package org.bukkit.plugin.java; public class JavaPlugin implements org.bukkit.plugin.Plugin { public JavaPlugin(){} public void onEnable(){} }
JAVA
cat > "$TMP/src/org/mclicense/library/MCLicense.java" <<'JAVA'
package org.mclicense.library; public final class MCLicense { public static boolean validateKey(org.bukkit.plugin.java.JavaPlugin p,String id){ return false; } }
JAVA
cat > "$TMP/src/org/json/JSONObject.java" <<'JAVA'
package org.json; public class JSONObject {}
JAVA
cat > "$TMP/src/example/Demo.java" <<'JAVA'
package example; public final class Demo extends org.bukkit.plugin.java.JavaPlugin { public final void onEnable(){} }
JAVA
javac --release 17 -d "$TMP/classes" $(find "$TMP/src" -name '*.java')
cp -R "$TMP/classes/example" "$TMP/plugin/"; printf 'name: Demo\nversion: 1.0\nmain: example.Demo\n' > "$TMP/plugin/plugin.yml"
jar --create --file "$TMP/input.jar" -C "$TMP/plugin" .
jar --create --file "$TMP/deps/mcl.jar" -C "$TMP/classes" org/mclicense
jar --create --file "$TMP/deps/json.jar" -C "$TMP/classes" org/json
java -cp "$ROOT/java-build" dev.railguard.patcher.JarPatcher "$TMP/input.jar" "$TMP/licensed.jar" 3gd7u9r4 "$TMP/deps" marker >/dev/null
cat > "$TMP/fake-proguard.py" <<'PY'
#!/usr/bin/env python3
import re, shutil, sys
from pathlib import Path
config=Path(sys.argv[1][1:]).read_text()
def path_for(flag):
 m=re.search(r'^'+re.escape(flag)+r"\s+'([^']+)'",config,re.M); return Path(m.group(1))
inj=path_for('-injars'); out=path_for('-outjars'); shutil.copyfile(inj,out)
for flag in ['-printmapping','-printseeds','-printusage','-dump']:
 p=path_for(flag); p.write_text('')
PY
chmod +x "$TMP/fake-proguard.py"
PROGUARD_CMD="$TMP/fake-proguard.py" MCL_PATCHER_CLASSPATH="$ROOT/java-build" MCL_DEPENDENCY_DIR="$TMP/deps" PYTHONPATH="$ROOT" python3 - "$TMP/licensed.jar" "$TMP/work" <<'PY'
import sys
from pathlib import Path
from obfuscator import run_obfuscation
from license_injector import validate_protected_jar
source=Path(sys.argv[1]); work=Path(sys.argv[2])
result=run_obfuscation(source,work,'Demo-Protected.jar','strong',timeout_seconds=30)
validate_protected_jar(result.output_jar,result.mapping_file)
print('Combined pipeline test passed.')
PY
