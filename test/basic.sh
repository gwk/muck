#!/bin/bash


set -e

function label { printf "\n$@\n" 1>&2; }

label "initial."
muck -no-times test/basic/basic.html

label "rebuild: no-op."
muck -no-times test/basic/basic.html

label "rebuild: no-op."
muck -no-times test/basic/basic.html

label "clean b.txt."
muck clean test/basic/b.txt

label "rebuild: b.txt, basic.html."
muck -no-times test/basic/basic.html
