# Virtual Call stack implementation for Linux x86

# Virtual stack is represented as a dictionary
# It does not store values but last instruction that modified given element
# We are assuming addressing in form of ESP + X
# ex:
# {
#  0: <il: push>
#  4: <il: store>
#  8: <il: store>
# }
import linux_x86
from binaryninja import log_info

WORD_SIZE = 8

mapping = {
  'rdi':'rdi', 'edi': 'rdi', 'di':'rdi', 'dil':'rdi',
  'rsi':'rsi', 'esi': 'rsi', 'si':'rsi', 'sil':'rsi',
  'rdx':'rdx', 'edx': 'rdx', 'dx':'rdx', 'dl':'rdx',
  'rcx':'rcx', 'ecx': 'rcx', 'cx':'rcx', 'cl':'rcx',
  'r8':'r8',   'r8d': 'r8',  'r8w':'r8', 'r8b':'r8',
  'r9':'r9',   'r9d': 'r9',  'r9w':'r9', 'r9b':'r9'
}

class Stack(linux_x86.Stack):
  def __init__(self):
    self.stack = {}

    self.registers = {
      'rdi': None,
      'rsi': None,
      'rdx': None,
      'rcx': None,
      'r8':  None,
      'r9':  None
    }

    self.stack_changing_llil = ['LLIL_STORE', 'LLIL_PUSH', 'LLIL_POP', 'LLIL_SET_REG']
    self.functions_path = 'all_functions_no_fp.json'

  def clear(self):
    self.stack = {}

    for reg in self.registers.keys():
      self.registers[reg] = None

  def update(self, instr):
    if instr.operation.name == 'LLIL_PUSH':
      self.__process_push(instr)

    if instr.operation.name == 'LLIL_STORE':
      self.__process_store(instr)

    if instr.operation.name == 'LLIL_POP':
      self.__process_pop()

    if instr.operation.name == 'LLIL_SET_REG':
      self.__process_set_reg(instr)

  def __process_set_reg(self, set_i):
    if set_i.dest in mapping.keys():
      self.registers[mapping[set_i.dest]] = set_i

  def __process_store(self, store_i):
    # Extracting destination of LLIL_STORE
    if store_i.dest.operation.name == 'LLIL_REG':
      dst = store_i.dest.src
      shift = 0
    else: # assuming LLIL_ADD for now
      dst = store_i.dest.left.src
      shift = store_i.dest.right.value

    if dst == 'esp':
      # Place it on the stack
      self.stack[shift] = store_i

  def __iter__(self):
    yield self.registers['rdi']
    yield self.registers['rsi']
    yield self.registers['rdx']
    yield self.registers['rcx']
    yield self.registers['r8']
    yield self.registers['r9']

    for index in sorted(self.stack):
      yield self.stack[index]
