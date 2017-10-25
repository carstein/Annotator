# Author: carstein <michal.melewski@gmail.com>
# Annotate function with prototype

import sys
import json
from binaryninja import *
import os
from stacks import linux_x86, linux_x64


# Simple database loader - assume all is in one file for now
def load_database(data_path):
    annotator_folder = os.path.dirname(os.path.abspath(__file__)).split(user_plugin_path)[1].split("/")[1]
    fh = open(user_plugin_path + '/' + annotator_folder
              + '/data/' + data_path, 'r')
    return json.load(fh)

# Function to be executed when we invoke plugin
def run_plugin(bv, function):
  # logic of stack selection
  if bv.platform.name == 'linux-x86':
    stack = linux_x86.Stack()
  elif bv.platform.name == 'linux-x86_64':
    stack = linux_x64.Stack()
  else:
    log_error('[x] Virtual stack not found for {platform}'.format(platform=bv.platform.name))
    return -1

  log_info('[*] Annotating function <{name}>'.format(name=function.symbol.name))

  functions_db = stack.get_function_path()
  stack_changing_llil =  stack.get_relevant_llil()
  log_info(stack_changing_llil)

  db = load_database(functions_db)

  for block in function.low_level_il:
    for instruction in block:
      log_info(instruction.operation)
      if instruction.operation in stack_changing_llil:
        stack.update(instruction)
      if (instruction.operation == LowLevelILOperation.LLIL_CALL and
          instruction.dest.operation == LowLevelILOperation.LLIL_CONST_PTR):
        callee = bv.get_function_at(instruction.dest.constant) # Fetching function in question

        if (callee.symbol.type.name == 'ImportedFunctionSymbol' and db.has_key(callee.name)):
          stack_args = iter(stack)

          for function_args in db[callee.name]:
            try:
              stack_instruction = stack_args.next()
              function.set_comment(stack_instruction.address, function_args)
            except StopIteration:
              log_error('[x] Virtual Stack Empty. Unable to find function arguments for <{}>'.format(callee.name))
