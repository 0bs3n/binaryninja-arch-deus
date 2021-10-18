from binaryninja import Architecture, InstructionInfo, InstructionTextToken, RegisterInfo, LowLevelILLabel
from binaryninja.enums import BranchType, InstructionTextTokenType, LowLevelILFlagCondition

from .deus_instruction import FixedInstruction


class JMP(FixedInstruction):
    opcodes = ["z"]
    mnemonic = "jmp"
    regs = {
        0x7a: "rA",
        0x6a: "rA"
    }

    def cond_branch(self, il, cond, dest, false_addr):
        t = None
        if il[dest].operation == LowLevelILOperation.LLIL_CONST:
            t = il.get_label_for_address(self, il[dest].constant)
        if t is None:
            t = LowLevelILLabel()
            indirect = True
        else:
            indirect = False
        f = il.get_label_for_address(self, false_addr)
        found = f is not None
        if not found:
            f = LowLevelILLabel()
        il.append(il.if_expr(cond, t, f))
        if indirect:
            il.mark_label(t)
            il.append(il.jump(dest))
        if not found:
            il.mark_label(f)

    def __init__(self, data, addr):
        reg = self.regs[data[0]]
        self.args = [reg]

    def get_instruction_text(self, data, addr):
        tokens = []
        text = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        filler = InstructionTextTokenType.TextToken
        
        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(text, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, self.args[0]))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.IndirectBranch)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        width = self.get_reg_width(self.args[0])
        reg = il.reg(width, self.args[0])
        t = LowLevelILLabel()
        expr = il.append(il.goto(t))
        il.mark_label(t) 
        expr = il.jump(il.add(width, reg, il.const(2, addr + 1)))
        il.append(expr)
        return self.length


class JEQ(JMP):
    opcodes = ["j"]
    mnemonic = "jeq"

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.IndirectBranch)
        info.add_branch(BranchType.FalseBranch, addr + self.length)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        reg = self.args[0]
        width = self.get_reg_width(reg)

        false_label = il.get_label_for_address(Architecture["deus"], addr + self.length)

        if false_label is None:
            il.add_label_for_address(Architecture["deus"], addr + self.length)
            false_label = il.get_label_for_address(Architecture["deus"], addr + self.length)

        true_label = LowLevelILLabel()

        il.append(il.if_expr(il.flag_condition(LowLevelILFlagCondition.LLFC_E), true_label, false_label))
        il.mark_label(true_label)
        il.append(il.jump(il.add(width, il.reg(width, reg), il.const(2, addr + 1))))
        return self.length


class NOP(FixedInstruction):
    opcodes = [" "]
    mnemonic = "nop"

    def get_instruction_text(self, data, addr):
        tokens = []
        text = InstructionTextTokenType.TextToken
        
        tokens.append(InstructionTextToken(text, self.mnemonic))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.nop())
        return self.length

class RET(FixedInstruction):
    opcodes = ["N"]
    mnemonic = "ret"

    def get_instruction_text(self, data, addr):
        tokens = []
        text = InstructionTextTokenType.TextToken
        
        tokens.append(InstructionTextToken(text, self.mnemonic))
        return [tokens, self.length]

    def get_instruction_info(self, data, addr):
        info = InstructionInfo()
        info.add_branch(BranchType.FunctionReturn)
        info.length = self.length
        return info

    def get_instruction_low_level_il(self, data, addr, il):
        il.append(il.ret(il.const(4, 0xdeadbeef)))
        return self.length

class CMP(FixedInstruction):
    opcodes = ["s", "u"]
    mnemonic = "cmp"

    regs = {
        0x73: ["vA", "vB"],
        0x75: ["rA", "rB"]
    }

    def __init__(self, data, addr):
        dst_reg = self.regs[data[0]][0]
        src_reg = self.regs[data[0]][1]
        self.args = [dst_reg, src_reg]

    def get_instruction_text(self, data, addr):
        tokens = []
        text = InstructionTextTokenType.TextToken
        filler = InstructionTextTokenType.TextToken
        register = InstructionTextTokenType.RegisterToken
        sep = InstructionTextTokenType.OperandSeparatorToken
        
        justify = ' ' * (self.justify - len(self.mnemonic))
        tokens.append(InstructionTextToken(text, self.mnemonic))
        tokens.append(InstructionTextToken(filler, justify))
        tokens.append(InstructionTextToken(register, self.args[0]))
        tokens.append(InstructionTextToken(sep, ", "))
        tokens.append(InstructionTextToken(register, self.args[1]))
        return [tokens, self.length]

    def get_instruction_low_level_il(self, data, addr, il):
        dst_width = self.get_reg_width(self.args[0])
        src_width = self.get_reg_width(self.args[1])
        dst_reg = il.reg(dst_width, self.args[0])
        src_reg = il.reg(src_width, self.args[1])
        il.append(il.sub(dst_width, dst_reg, src_reg, flags="z"))
        return self.length
