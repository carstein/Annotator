#!/usr/bin/env python

import glob
import json
import os
import re
import sys

def parse(function_array):
  fn_pattern = re.compile('(\w+)$')
  functions = {}

  for line in function_array:
    if line.strip() == "" or line.startswith('//'):
      continue

    name, args = line.split('(',1)
    f_name = fn_pattern.search(name).group(0)

    if functions.has_key(f_name):
      print "Name conflict for function: %s"%f_name
      print functions[f_name]
      print line
      continue

    functions[f_name] = []

    for i, arg in enumerate(args.split(',')):
      functions[f_name].append(arg.strip().rstrip(');'))

  return json.dumps(functions, indent=2)

def parse_file(file_name):
  with open(file_name, "r") as fh:
    return fh.readlines()

def parse_dir(dir_name):
    dir_list = []

    for file_name in glob.glob(dir_name + '/*.prot'):
      with open(file_name, "r") as fh:
        dir_list.extend(fh.readlines())

    return dir_list

def main():
  function_list = []

  if len(sys.argv) < 2:
    print("No filename provided")
    return -1

  # Fetch content of all files in question
  for name in sys.argv[1:]:
    if os.path.isfile(name):
      function_list.extend(parse_file(name))

    if os.path.isdir(name):
      function_list.extend(parse_dir(name))

  # Parse it
  print parse(function_list)

if __name__ == "__main__":
  sys.exit(main())
