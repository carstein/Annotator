# Author: carstein <michal.melewski@gmail.com>
# Annotate function with prototype

import os
import sys
import json
from binaryninja import *

from stacks import linux_x86

stack_changing_llil = ['LLIL_STORE', 'LLIL_PUSH']
data_path = '/annotate/data/functions.json'

# Simple database loader - assume all is in one file for now
def load_database():
  fh = open(sys.path[0]+data_path, 'r')
  return json.load(fh)

# Function to be executed when we invoke plugin
def run_plugin(bv, function):
  # load database
  db = load_database()

  # logic of stack selection
  if bv.platform.name == 'linux-x86':
    stack = linux_x86.Stack()
  else:
    log_error('[x] Virtual stack not found for {platform}'.format(platform=bv.platform.name))
    return -1

  log_info('[*] Annotating function <{name}>'.format(name=function.symbol.name))

  for block in function.low_level_il:
    for i in block:
      if i.operation.name in stack_changing_llil:
        stack.update(i)
      if i.operation.name == 'LLIL_CALL':
        callee = bv.get_function_at(i.dest.value) # Fetching function in question

        if (callee.symbol.type.name == 'ImportedFunctionSymbol' and
            db.has_key(callee.name)):
          s_args = iter(stack)

          for f_arg in db[callee.name]:
            try:
              stack_i = s_args.next()
              function.set_comment(stack_i.address, f_arg)
            except StopIteration:
              log_error('[x] Virtual Stack Empty. Unable to find function arguments for <{}>'.format(callee.name))
