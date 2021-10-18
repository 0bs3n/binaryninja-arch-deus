from binaryninja import InstructionTextToken
from binaryninja.enums import InstructionTextTokenType

from .deus_instruction import FixedInstruction

class MRR(FixedInstruction):
    mnemonic = "mov"
    opcodes = ["b", "c", "o", "v"]
    regs = {
        0x62: ["zA", "rA"],
        0x63: ["zB", "rA"],
        0x6f: ["rB", "rA"],
        0x76: ["zC", "rA"]
    }

    def __init__(self, data, addr):
        dest = self.regs[data[0]][0]
        src = self.regs[data[0]][1]
        self.args = [dest, src]

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        
        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, self.args[0]))
        tokens.append(InstructionTextToken(sep, ", "))
        tokens.append(InstructionTextToken(register, self.args[1]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        dst_width = self.get_reg_width(self.args[0])
        src_width = self.get_reg_width(self.args[1])
        src = il.reg(src_width, self.args[1])
        op = il.set_reg(dst_width, self.args[0], src)
        il.append(op)
        return self.length

class MRM(MRR):
    opcodes = ["i", "f", "t", "g", "h", "k"]
    regs = {
        0x69: ["rA", "rB", 1],
        0x66: ["rA", "rB", 2],
        0x74: ["vB", "vA", 8],
        0x67: ["zB", "rA", 16],
        0x68: ["zC", "rA", 16],
        0x6b: ["zA", "rA", 16]
    }

    def __init__(self, data, addr):
        dest = self.regs[data[0]][0]
        src = self.regs[data[0]][1]
        mem_width = self.regs[data[0]][2]
        self.args = [dest, src, mem_width]

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        membeg = InstructionTextTokenType.BeginMemoryOperandToken
        memend = InstructionTextTokenType.EndMemoryOperandToken
        
        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, self.args[0]))
        tokens.append(InstructionTextToken(sep, ", "))
        tokens.append(InstructionTextToken(membeg, f"{self.get_mem_width_ident(self.args[2])} ["))
        tokens.append(InstructionTextToken(register, self.args[1]))
        tokens.append(InstructionTextToken(memend, "]"))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        dst_width = self.get_reg_width(self.args[0])
        src_width = self.get_reg_width(self.args[1])
        mem_width = self.args[2]
        dst_reg = self.args[0]
        src_reg = self.args[1]

        load = il.load(mem_width, il.reg(src_width, src_reg))
        op = il.set_reg(dst_width, dst_reg, load)

        il.append(op)
        return self.length

class MMR(MRR):
    opcodes = [ "d", "y" ] 
    regs = {
        0x64: ["rA", "rB", 2],
        0x79: ["vA", "vB", 8]
    }

    def __init__(self, data, addr):
        dest = self.regs[data[0]][0]
        src = self.regs[data[0]][1]
        mem_width = self.regs[data[0]][2]
        self.args = [dest, src, mem_width]

    def get_instruction_text(self, data, addr):
        tokens = []
        opcode = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        membeg = InstructionTextTokenType.BeginMemoryOperandToken
        memend = InstructionTextTokenType.EndMemoryOperandToken
        
        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(opcode, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(membeg, f"{self.get_mem_width_ident(self.args[2])} ["))
        tokens.append(InstructionTextToken(register, self.args[0]))
        tokens.append(InstructionTextToken(memend, "]"))
        tokens.append(InstructionTextToken(sep, ", "))
        tokens.append(InstructionTextToken(register, self.args[1]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        dst_width = self.get_reg_width(self.args[0])
        src_width = self.get_reg_width(self.args[1])
        mem_width = self.args[2]
        dst_reg = il.reg(dst_width, self.args[0])
        src_reg = il.reg(src_width, self.args[1])
        op = il.store(mem_width, dst_reg, src_reg)
        il.append(op)
        return self.length
