#!/usr/bin/env python

import json
import re
import sys

def main():
  if len(sys.argv) < 2:
    print("No filename provided")
    return -1

  fn_pattern = re.compile('(\w+)$')
  functions = {}

  with open(sys.argv[1], 'r') as fh:
    for line in fh.readlines():
      if line.strip() == "" or line.startswith('//'):
        continue

      name, args = line.split('(')
      f_name = fn_pattern.search(name).group(0)
      functions[f_name] = []

      for i, arg in enumerate(args.split(',')):
        functions[f_name].append(arg.strip().rstrip(');'))


    print json.dumps(functions, indent=2)

if __name__ == "__main__":
  sys.exit(main())
