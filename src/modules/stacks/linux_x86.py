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

ELEMENT_WIDTH = 4

class Stack:
  def __init__(self):
    self.stack = {}

  def clear(self):
    self.stack = {}

  def update(self, instr):
    if instr.operation.name == 'LLIL_PUSH':
      self.__process_push(instr)

    if instr.operation.name == 'LLIL_STORE':
      self.__process_store(instr)

  def __shift_stack(self):
    for index in sorted(self.stack, reverse=True):
      self.stack[index+ELEMENT_WIDTH] = self.stack[index]

  def __process_push(self, push_i):
    self.__shift_stack()
    self.stack[0] = push_i

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
