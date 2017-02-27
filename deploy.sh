#!/bin/bash

SRC="src/*"
DST="$HOME/.binaryninja/plugins/annotate"

if [ "$(uname)" == 'Linux' ]; then
  mkdir -p $DST
  cp -r $SRC $DST
fi
