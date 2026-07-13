# Minecraft Plugin Protector 3.1.2

## Skid Hybrid correction

- Fixed the misleading Skidfuscator mode that left package, class, method, and field names readable.
- The public **Skid** choice is now a two-stage pipeline:
  1. yGuard 5.0.0 performs structural package/class/member renaming.
  2. Skidfuscator Community applies its stable flow and number transformations to the renamed JAR.
- The pipeline aborts rather than returning an apparently unchanged JAR when yGuard reports zero renamed classes.
- The final mapping file is the real yGuard mapping and is used to validate/rewrite Bukkit, Paper, Velocity, Fabric, manifest, and ServiceLoader metadata.
- Build bundles now contain both native engine configurations, the yGuard XML map, a combined stage log, and a merged report.
- Skid health checks now require both Skidfuscator and yGuard because both are part of that engine choice.
- Updated the website copy so it no longer claims Community Skidfuscator performs structural renaming by itself.
