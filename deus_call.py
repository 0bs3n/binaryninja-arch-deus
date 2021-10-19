from binaryninja import CallingConvention

class DeusCallingConvention(CallingConvention):
    name = 'deus-abi'
    caller_saved_regs = []
    int_arg_regs = []
    int_return_reg = "rA"
