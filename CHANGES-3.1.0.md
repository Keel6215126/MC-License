# Minecraft Plugin Protector 3.1.0

## Added

- Selectable ProGuard 7.9.1, Skidfuscator Community, and yGuard 5.0.0 engines.
- Engine selection on both the standalone Obfuscate page and combined MC License + Obfuscation page.
- Skidfuscator safe and strong community presets with dependency-library support.
- yGuard safe and strong presets, external dependency classpaths, randomized mappings, and normalized mapping exports.
- Java ServiceLoader metadata rewriting after class renaming.
- Health endpoint reporting for all installed obfuscation engines.
- Railway Docker installation for ProGuard, Skidfuscator, yGuard, Maven dependency resolution, and Ant.

## Compatibility

- Existing ProGuard behavior and MC License workflows remain available.
- Uploaded dependency JARs continue to be accepted and are passed to the selected engine.
- Existing Discord webhook forwarding behavior remains unchanged.

## Validation

- 22 Python tests pass.
- Python bytecode compilation and JavaScript syntax validation pass.
