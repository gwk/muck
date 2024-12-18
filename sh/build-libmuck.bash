#!/usr/bin/env bash

# This script builds the libmuck library.

set -e

fail() { echo "Error: $1" >&2; exit 1; }

while getopts "ho:" arg; do
  echo "arg: $arg; OPTIND: $OPTIND; OPTARG: $OPTARG"
  case "$arg" in
    h) echo "Usage: $0 [-o out_file] [source_files...]" >&2 && exit 0;;
    o) out_file="$OPTARG";;
    *) fail "Invalid argument: $arg";;
  esac
done

shift $((OPTIND-1)) # Remove processed options.
inputs=("$@")

[[ -z "$out_file" ]] && fail "No output file specified."

cc="${CC:-cc}" # Default to "cc" if CC is not set.
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
echo "output: $out_file; inputs: $inputs"

set -x

$cc \
-std=c2x \
-Werror \
-Weverything \
-Wno-pre-c2x-compat \
-Wno-declaration-after-statement \
-Wno-gnu-zero-variadic-macro-arguments \
-Wno-poison-system-directories \
-Wno-unused-function \
-fPIC \
$flags \
-o "$out_file" \
$inputs

chmod -x "$out_file"
