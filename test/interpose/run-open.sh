#!/usr/bin/env bash

# On macOS, executables in /usr/bin have System Integrity Protection set,
# which means that DYLD_* env variables get stripped by dyld.
# This means that muck interposition fails silently.
# Particularly vexing is that launching using `/usr/bin/env INTERPRETER` also strips the vars.
# Therefore, we must specify the interpreter paths used to launch child processes.
# In this test, we use `which` to choose the executable like `env` would, and then provide it directly.
# If it has SIP, then `open.py` will notice the missing variable and fail.

lldb='/Applications/Xcode.app/Contents/Developer/usr/bin/lldb' # Do not use /usr/bin/lldb.
python3="$(which python3)"

set -x

DYLD_INSERT_LIBRARIES=$PWD/muck/_libmuck.cpython-37m-darwin.so \
MUCK_DEPS_DBG= \
$python3 test/interpose/open.py pithy/pithy/ansi.py
