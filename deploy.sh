#!/bin/bash

SRC="src/*"
DST="$HOME/.binaryninja/plugins/annotate"

mkdir -p $DST
cp -r $SRC $DST
