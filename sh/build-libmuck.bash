#!/usr/bin/env bash

# This script builds the libmuck library.

set -e

fail() { echo "Error: $1" >&2; exit 1; }

out_file="$1"
shift

[[ -z "$out_file" ]] && fail "No output file specified."

cc="${CC:-cc}"
[[ -z "$cc" ]] && fail "No compiler specified."

_uname=$(uname -s)
case $_uname in
  Darwin)
    os=macos
    flags='-dynamiclib'
    ;;
  Linux)
    os=linux
    flags='-shared'
    ;;
  *) fail "Unsupported OS: $_uname" ;;
esac

echo "Compiler: $cc; OS: $os; flags: '$flags'"
echo "output: $out_file; args: $@"

set -x

$cc \
-std=c17 \
-Werror \
-Weverything \
-Wno-declaration-after-statement \
-Wno-gnu-empty-initializer \
-Wno-gnu-zero-variadic-macro-arguments \
-Wno-poison-system-directories \
-Wno-unused-function \
-o "$out_file" \
$flags \
$@
