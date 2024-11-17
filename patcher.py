from qiling import *
from qiling.const import QL_VERBOSE
from qiling.const import QL_OS, QL_ARCH
from capstone import Cs
from binaryninja import Architecture
from keystone import *
from capstone.x86 import * 
from typing import Mapping
def __map_regs() -> Mapping[int, int]:
    """Map Capstone x86 regs definitions to Unicorn's.
    """

    from capstone import x86_const as cs_x86_const
    from unicorn import x86_const as uc_x86_const

    def __canonicalized_mapping(module, prefix: str) -> Mapping[str, int]:
        return dict((k[len(prefix):], getattr(module, k)) for k in dir(module) if k.startswith(prefix))

    cs_x86_regs = __canonicalized_mapping(cs_x86_const, 'X86_REG')
    uc_x86_regs = __canonicalized_mapping(uc_x86_const, 'UC_X86_REG')

    return dict((cs_x86_regs[k], uc_x86_regs[k]) for k in cs_x86_regs if k in uc_x86_regs)

# capstone to unicorn regs mapping
CS_UC_REGS = __map_regs()
# Dictionary mapping register variations to their base register
def normalize_register(reg_num):
    # General purpose registers
    #modification: replaced 64 bit with 32 cause this is a 32 bit program, this causes the register read function to error.

    if reg_num in [2, 1, 3, 19, 35]:  # AL, AH, AX, EAX, RAX
        return 19  # EAX
    elif reg_num in [5, 4, 8, 21, 37]:  # BL, BH, BX, EBX, RBX
        return 21  # RBX
    elif reg_num in [10, 9, 12, 22, 38]:  # CL, CH, CX, ECX, RCX
        return 22  # RCX
    elif reg_num in [16, 13, 18, 24, 40]:  # DL, DH, DX, EDX, RDX
        return 24  # RDX
    elif reg_num in [7, 6, 20, 36]:  # BPL, BP, EBP, RBP
        return 20  # RBP
    elif reg_num in [15, 14, 23, 39]:  # DIL, DI, EDI, RDI
        return 23  # RDI
    elif reg_num in [46, 45, 29, 43]:  # SIL, SI, ESI, RSI
        return 29  # RSI
    elif reg_num in [48, 47, 30, 44]:  # SPL, SP, ESP, RSP
        return 30  # RSP
    # R8-R15 variants
    elif reg_num in [218, 234, 226, 106]:  # R8B, R8W, R8D, R8
        return 106  # R8
    elif reg_num in [219, 235, 227, 107]:  # R9B, R9W, R9D, R9
        return 107  # R9
    elif reg_num in [220, 236, 228, 108]:  # R10B, R10W, R10D, R10
        return 108  # R10
    elif reg_num in [221, 237, 229, 109]:  # R11B, R11W, R11D, R11
        return 109  # R11
    elif reg_num in [222, 238, 230, 110]:  # R12B, R12W, R12D, R12
        return 110  # R12
    elif reg_num in [223, 239, 231, 111]:  # R13B, R13W, R13D, R13
        return 111  # R13
    elif reg_num in [224, 240, 232, 112]:  # R14B, R14W, R14D, R14
        return 112  # R14
    elif reg_num in [225, 241, 233, 113]:  # R15B, R15W, R15D, R15
        return 113  # R15
    return reg_num  # Return original if no normalization needed

def patch(patches, source_file, dest_file):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    arch = Architecture['x86']
    base_addr = 0x00400000 + 0xc00 #base + section jump
    with open(source_file, 'rb') as f:
        source = f.read()
    mod = bytearray(source)
    for patch in patches:

        if patch['conditional'] == False:

            #patch nonconds first
            asm = ks.asm('JMP 0x%x;nop;nop;nop;nop;nop;nop;' %patch['dest'], as_bytes=True)[0] #the result is 6 bytes, while the original would be 2 bytes 
            #before it xor 6 byte, add 2 byte, inc 1 byte, jmp 2 byte
            for i in range (0,9):
                mod[(patch['address']-base_addr-9)+i] = asm[i]
        
        else:
            asm = ks.asm('J%s 0x%x; NOP;NOP;NOP;NOP;NOP;NOP;NOP;'%(patch['cond'], patch['dest']), as_bytes=True)[0]

            for i in range (0,9):

                mod[(patch['set_addr']-base_addr)+i] = asm[i] #3 byte instruction replaced, + start of 7 byte instruction. Need to nop 4 bytes 


    with open(dest_file, 'wb') as f:
        f.write(mod
        )


def trace(ql: Qiling, address: int, size: int, user_data ):
      # Map set conditions to jump conditions
    condition_map = {
        'setb': 'b',    # below
        'seta': 'a',    # above
        'setbe': 'be',  # below or equal
        'setae': 'ae',  # above or equal
        'sete': 'e',    # equal
        'setne': 'ne',  # not equal
        'setl': 'l',    # less
        'setg': 'g',    # greater
        'setle': 'le',  # less or equal
        'setge': 'ge',  # greater or equal
        'sets': 's',    # sign
        'setns': 'ns',  # not sign
        'seto': 'o',    # overflow
        'setno': 'no',  # not overflow
        'setp': 'p',    # parity
        'setnp': 'np',  # not parity
    }
            
    md = user_data[0]
    prev = user_data[1]
    typ = user_data[2] #this is whether this is a conditional or not. 
    patches = user_data[3]
    """Emit tracing info for each and every instruction that is about to be executed.

    Args:
        ql: the qiling instance
        address: the address of the instruction that is about to be executed
        size: size of the instruction (in bytes)
        md: initialized disassembler object
        originally from https://github.com/qilingframework/qiling/blob/master/examples/hello_x8664_linux_disasm.py
    """

    # read current instruction bytes and disassemble it
    buf = ql.mem.read(address, size)
    insn = next(md.disasm(buf, address))

    nibbles = ql.arch.bits // 4
    color_faded = '\033[2m'
    color_reset = '\033[0m'

    # get values of the registers referenced by this instruction.
    #
    # note: since this method is called before the instruction has been emulated, the 'rip'
    # register still points to the current instruction, while the instruction considers it
    # as if it was pointing to the next one. that will cause 'rip' to show an incorrect value
    reads = (f'{md.reg_name(reg)} = {ql.arch.regs.read(CS_UC_REGS[reg]):#x}' for reg in insn.regs_access()[0])

    # construct a human-readable trace line
    trace_line = f'{insn.address:0{nibbles}x} | {insn.bytes.hex():24s} {insn.mnemonic:12} {insn.op_str:35s} | {", ".join(reads)}'
    prev.append(insn)
    if str(insn.mnemonic) == 'jmp':
        typ = 0 #non cond

        if(insn.operands[0].type == X86_OP_REG):
            ourreg = normalize_register(insn.operands[0].value.reg)
            insns = []
            previous = prev[-15:]
            for idx in range(0,len(previous)):
                i = previous[idx]
                accessed = i.regs_access()

  
                regs = accessed[1]
                if len(accessed[1]) == 0:
                    regs = []
                if len(accessed[0]) > 0:
                    regs += accessed[0]
                regs = [normalize_register(i) for i in regs]

                if ourreg in regs:
                    if 'set' in i.mnemonic:
                        cond = condition_map[i.mnemonic]
                        typ = 1
                        set_addr = i.address
                        cmp_addr = previous[idx-1].address
                        insns.append(previous[idx-1]) #so we also log the cmp instruction
                    insns.append(i)
                back2 = previous[idx-2].address
            for insn in insns:
                #reads = (f'{md.reg_name(reg)} = {ql.arch.regs.read(CS_UC_REGS[reg]):#x}' for reg in insn.regs_access()[0])
                #trace_line = f'{insn.address:0{nibbles}x} | {insn.bytes.hex():24s} {insn.mnemonic:12} {insn.op_str:35s} | {", ".join(reads)}'
                jmpfu = insn #final is the jump
                
                #with open('deobfuscator.txt','a') as f:
                #    f.write(trace_line +'\n') if you want the trace lines to debug
            if typ == 0:
                patc = {
                    'dest':  ql.arch.regs.read(CS_UC_REGS[ourreg]),
                    'conditional': False,
                    'cond': None,
                    'address': int(back2),
                    'set_addr': None,
                    'cmp_addr': None,
                }
                patches.append(patc)
    
            elif typ == 1:
                #conditional 
                patc = {
                    'dest':  ql.arch.regs.read(CS_UC_REGS[ourreg]), #TODO: Add other possibility
                    'conditional': True,
                    'cond' : cond, 
                    'address': int(jmpfu.address),
                    'set_addr': set_addr,
                    'cmp_addr': cmp_addr,

                }
                patches.append(patc)



    

    #with open('deobfuscator', 'a') as f:
    #    f.write(trace_line + '\n')

    # emit the trace line in a faded color, so it would be easier to tell trace info from other log entries
    #ql.log.info(f'{color_faded}{trace_line}{color_reset}')


def emulate():
    # Initialize Qiling instance
    try:
        ql = Qiling(
            argv=['[qillinghome]/rootfs/x86_windows/unpacked_lumma.exe'], 
            rootfs='[qillinghome]/qilling/rootfs/x86_windows',
            ostype=QL_OS.WINDOWS,
            
            verbose=QL_VERBOSE.DEBUG
        )
        md = ql.arch.disassembler
        md.detail = True
        prev = []
        typ = 0
        patches = []
        ql.hook_code(trace, user_data=[md,prev, typ, patches])

    
        
        # Run the emulation
        ql.run()
    except:
        pass
    patch(patches,  'unpacked_lumma.exe', 'deobfuscated_lumma.exe')

emulate()
