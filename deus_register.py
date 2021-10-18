from binaryninja import RegisterInfo

def get_regs():
    regs = dict()
    regs['rA'] = RegisterInfo('rA', 2)
    regs['rB'] = RegisterInfo('rB', 2)
    regs['vA'] = RegisterInfo('vA', 8)
    regs['vB'] = RegisterInfo('vB', 8)
    # the z registers are actually gmp MP numbers, can be up to 2**32 bits.
    # This might need to be implemented as areas of memory reserved for z regs,
    # UINT_MAX bytes each.
    regs['zA'] = RegisterInfo('zA', 16)
    regs['zB'] = RegisterInfo('zB', 16)
    regs['zC'] = RegisterInfo('zC', 16)
    regs['estate'] = RegisterInfo('estate', 1)
    regs['sp'] = RegisterInfo('sp', 8)
    return regs
