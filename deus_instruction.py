from struct import unpack

from binaryninja import InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType


class DeusInstruction:
    opcode: int = None
    mnemonic: str = ""
    justify: int = 6

    @classmethod
    def decode(cls, data, addr):
        length = cls.get_instruction_length(None, data)

        if chr(data[length - 1]) not in cls.opcodes:
            return None
        return cls(data, addr)

    def get_reg_width(self, reg):
        if reg[0] == "r":
            return 2
        if reg[0] == "v":
            return 8
        if reg[0] == "z":
            return 16

    def get_mem_width_ident(self, width):
        if width == 1:
            return "byte"
        if width == 2:
            return "word"
        if width == 8:
            return "qword abs"
        if width == 16:
            return "gmp"

    def get_instruction_length(self, data):
        if data[0] < 0x30 or data[0] > 0x39:
            return 1
        else:
            count = 1
            while True:
                if data[count] < 0x30 or data[count] > 0x39:
                    break
                count += 1
            return count + 1
    
    def __init__(self, data, addr):
        pass

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.length = self.length
        return info

    def get_instruction_text(self, data, addr):
        return ['', self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        return self.length


class FixedInstruction(DeusInstruction):
    length = 1 
    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        return [tokens, self.length]

class VariableInstruction(DeusInstruction):

    def get_immediate(self, data):
        if len(data) == 1:
            return 1
        try:
            return int(data[:self.length - 1], 10)
        except Exception as e:
            print(data)
            print(self.length)
            print(e)
    

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        address = InstructionTextTokenType.PossibleAddressToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(address, self.args[0], value=self.get_immediate(data)))
        return [tokens, self.length]

