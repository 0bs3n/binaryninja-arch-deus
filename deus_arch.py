from typing import List
from binaryninja import log_error
from binaryninja.enums import LowLevelILFlagCondition, FlagRole

from .arithmetic_instructions import *
from .control_instructions import *
from .data_movement_instructions import *

from .deus_register import get_regs
from .deus_instruction import DeusInstruction


class DeusArchitecture(Architecture):
    instructions: List[DeusInstruction] = [JMP, JEQ, MRR, MRM, MMR, ADD, ZER, NOP, CMP, RET, POWM]
    name = 'deus'
    instr_alignment = 1
    stack_pointer = "sp"
    regs = get_regs()

    flags = ["z", "s"]
    flag_write_types = ["*", "zs", "z", "s"]
    flag_roles = {
        "z": FlagRole.ZeroFlagRole,
        "s": FlagRole.NegativeSignFlagRole
    }
    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_E: ["z"],
        LowLevelILFlagCondition.LLFC_NE: ["z"],
        LowLevelILFlagCondition.LLFC_NEG: ["s"],
        LowLevelILFlagCondition.LLFC_POS: ["s"]
    }

    flags_written_by_flag_write_type = {
        "*": ["z", "s"],
        "zs": ["z", "s"],
        "z": ["z"],
        "s": ["s"]
    }

    def decode_instruction(self, data: bytes, addr: int):
        decode_results = []
        for a in self.instructions:
            decode_result = a.decode(data, addr)
            if decode_result is None:
                continue
            decode_results.append(decode_result)
        if len(decode_results) > 1:
            log_error(f"Ambiguous decoding: {decode_result} @ {addr:08x}")
            return None
        elif len(decode_results) == 0:
            log_error(f"No omplementation found for instruction at {hex(addr)}")
            return None
        return decode_results[0]
    
    def get_instruction_text(self, data, addr):
        decode_result = self.decode_instruction(data, addr)
        if decode_result is None:
            return [[], 1]
        return decode_result.get_instruction_text(data, addr)

    def get_instruction_info(self, data, addr):
        decode_result = self.decode_instruction(data, addr)
        if decode_result is None:
            i = InstructionInfo()
            i.length = 1
            return i
        return decode_result.get_instruction_info(data, addr)

    def get_instruction_low_level_il(self, data, addr, il):
        decode_result = self.decode_instruction(data, addr)
        if decode_result is None:
            return 1
        else:
            return decode_result.get_instruction_low_level_il(data, addr, il)
