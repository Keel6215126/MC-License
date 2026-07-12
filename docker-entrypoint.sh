#!/bin/sh
set -eu
mkdir -p "${DATA_DIR:-/data}" "${TMP_DIR:-/app/tmp}"
chown -R node:node "${DATA_DIR:-/data}" "${TMP_DIR:-/app/tmp}"
exec gosu node "$@"
