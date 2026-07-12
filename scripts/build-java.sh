#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
rm -rf java-build
mkdir -p java-build
javac --release 17 -d java-build $(find java-src -name '*.java')
echo "Built MC License JAR patcher into java-build/"
