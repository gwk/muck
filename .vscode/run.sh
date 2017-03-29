#!/bin/sh
# Dedicated to the public domain under CC0: https://creativecommons.org/publicdomain/zero/1.0/.

# Hack around vscode's lame task runner. Simply runs the argument vector.

set -e
"$@"
echo "done: $@"
