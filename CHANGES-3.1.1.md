# Minecraft Plugin Protector 3.1.1

## Skidfuscator stability fix

- Disabled Skidfuscator V3 string encryption in the default safe and strong presets.
- Reduced strong exception flow from `AGGRESSIVE` to `GOOD`.
- Added a separate `SKID_MAX_HEAP_MB` setting with a 1536 MB default.
- JVM subprocesses now replace stale `-Xmx` values and use `-XX:+ExitOnOutOfMemoryError`.
- Added an automatic compatibility retry that disables exception and range flow.
- Added explicit failure classification for MapleIR SSA, V3 string-transformer, and heap failures.
- Added attempt details to `report.json` and retained all attempt output in `skidfuscator.log`.

V3 string encryption can be re-enabled for testing with `SKID_EXPERIMENTAL_STRING_ENCRYPTION=true`, but it is not recommended for public Railway deployments.
