from binaryninja import InstructionInfo, InstructionTextToken
from binaryninja.enums import InstructionTextTokenType

from .deus_instruction import VariableInstruction, FixedInstruction


class ADD(VariableInstruction):
    opcodes = ["e", "q", "r", "w"]
    mnemonic = "add"

    regs = {
        0x71: "rA",
        0x77: "rB",
        0x65: "vA",
        0x72: "vB"
    }

    def __init__(self, data, addr):
        self.length = self.get_instruction_length(data)
        if self.length > 1:
            arg = self.get_immediate(data)
        else:
            arg = 1
        reg = self.regs[data[self.length - 1]]
        self.args = [reg, arg]

    def get_instruction_text(self, data, addr):
        tokens = []
        text = InstructionTextTokenType.TextToken
        integer = InstructionTextTokenType.IntegerToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        register = InstructionTextTokenType.RegisterToken

        imm = self.args[1]
        reg = self.args[0]
        justify = ' '  * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(text, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, reg))
        tokens.append(InstructionTextToken(sep, ", "))
        tokens.append(InstructionTextToken(integer, hex(imm), value=imm))

        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        reg = self.args[0]
        imm = self.args[1]
        width = self.get_reg_width(reg)
        add = il.add(width, il.reg(width, reg), il.const(width, imm))
        op = il.set_reg(width, reg, add)
        il.append(op)
        return self.length

class POWM(FixedInstruction):
    opcodes = ["x"]
    mnemonic = "powm"

    def __init__(self, data, addr):
        self.args = ["zB", "zC", "zA"]

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.InstructionToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, self.args[0]))
        tokens.append(InstructionTextToken(sep, ", "))
        tokens.append(InstructionTextToken(register, self.args[1]))
        tokens.append(InstructionTextToken(sep, ", "))
        tokens.append(InstructionTextToken(register, self.args[2]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.unimplemented())
        return self.length

class ZER(FixedInstruction):
    opcodes = ["a", "p", "[", "\\"]
    mnemonic = "zer"

    regs = {
        0x61: "vB",
        0x70: "rA",
        0x5b: "rB",
        0x5c: "vA"
    }

    def __init__(self, data, addr):
        self.length = self.get_instruction_length(data)
        reg = self.regs[data[0]]
        self.args = [reg]

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.InstructionToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken

        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, self.args[0]))
        return [tokens, self.length]
    
    def get_instruction_low_level_il(self, data, addr, il):
        reg = self.args[0]
        width = self.get_reg_width(reg)
        op = il.set_reg(width, reg, il.const(width, 0))
        il.append(op)
        return self.length
