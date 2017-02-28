#!/usr/bin/env python

# Little helper function to extract function prototypes
# from https://github.com/zachriggle/functions.git by Zach Riggle

import sys
from functions import functions


def main():

  for f in functions.values():
    name = "{ret} {p}{name}".format(ret=f.type, p=('*' if f.derefcnt else ''), name=f.name)

    args = []
    for arg in f.args:
      args.append("{ret} {p}{name}".format(ret=arg.type, p=('*' if arg.derefcnt else ''), name=arg.name))

    print "{}({});".format(name,", ".join(args))

if __name__ == "__main__":
  sys.exit(main())
