#!/usr/bin/env sh

set -e

muck_dir=$(dirname $0)
DYLD_INSERT_LIBRARIES=$muck_dir/muck/libmuck.so MUCK_DEPS_DBG=1 "$@"
