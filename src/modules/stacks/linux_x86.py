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

WORD_SIZE = 4

class Stack:
  def __init__(self):
    self.stack = {}
    self.stack_changing_llil = ['LLIL_STORE', 'LLIL_PUSH', 'LLIL_POP']
    self.functions_path = 'all_functions.json'

  def get_function_path(self):
    return self.functions_path

  def get_relevant_llil(self):
    return self.stack_changing_llil

  def clear(self):
    self.stack = {}

  def update(self, instr):
    if instr.operation.name == 'LLIL_PUSH':
      self.__process_push(instr)

    if instr.operation.name == 'LLIL_STORE':
      self.__process_store(instr)

    if instr.operation.name == 'LLIL_POP':
      self.__process_pop()

  def __shift_stack_right(self):
    for index in sorted(self.stack, reverse=True):
      self.stack[index+WORD_SIZE] = self.stack[index]

  def __shift_stack_left(self):
    for index in sorted(self.stack)[1:]:
      self.stack[index-WORD_SIZE] = self.stack[index]

  def __process_push(self, push_i):
    self.__shift_stack_right()
    self.stack[0] = push_i

  def __process_pop(self):
    self.__shift_stack_left()

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
    for index in sorted(self.stack):
      yield self.stack[index]
