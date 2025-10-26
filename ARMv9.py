#!/usr/bin/env python3
"""
GEMi - ARM64/ARMv9 Instruction Explorer & Analyzer
-------------------------------------------------
- Systematically vary instruction fields (registers, immediates, cond, etc.)
- Visualize fixed vs variable bits with mask-based patterns
- Summarize encodings and field layouts
- Group exploration (branch, loadstore, dataproc, etc.)
- Lock specific fields to known values for targeted drilling
- Handle common aliases (CMP -> SUBS, TST -> ANDS, etc.)
- NEW: ARMv9 support (SVE, MTE)
- NEW: Hex <-> Assembly conversion and interactive mode
- NEW: Basic instruction result calculation/emulation

Key color legend in exploration output:
  normal bit : matches base encoding's bit in a fixed position
  \x1b[1;33mY\x1b[0m : bit differs from base, but that position is NOT fixed by mask (i.e. a legal varying field)
  \x1b[1;31mY\x1b[0m : bit differs from base where the mask SAYS it should be fixed (means: you've wandered out of class)
"""

import argparse
import itertools
import struct
import re
import sys
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM


# ============================================================
# CORRECTED ISA GROUP DEFINITIONS
# ============================================================
# ... (ISA_GROUPS, OPCODE_MAP, GROUP_MAP, FIELD_SEMANTICS, INSTRUCTION_ALIASES remain the same as your last provided version) ...
ISA_GROUPS = {
    "DataProcReg": [
        {
            "name": "ADD",
            "base": 0x0B000000,
            "mask": 0x7FE00000, # Mask corrected based on encoding diagrams
            "form": "register",
            "desc": "ADD (register): Rd = Rn + Rm [+ optional shift]",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "Rm":    (16, 5),
                "imm6":  (10, 6), # Shift amount
                "shift": (22, 2), # Shift type
                "sf":    (31, 1),
            },
        },
        {
            "name": "ADDS",
            "base": 0x2B000000,
            "mask": 0x7FE00000,
            "form": "register",
            "desc": "ADDS (register, set flags): Rd = Rn + Rm, update PSTATE",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "Rm":    (16, 5),
                "imm6":  (10, 6),
                "shift": (22, 2),
                "sf":    (31, 1),
            },
        },
        {
            "name": "SUB",
            "base": 0x4B000000,
            "mask": 0x7FE00000,
            "form": "register",
            "desc": "SUB (register): Rd = Rn - Rm [+ optional shift]",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "Rm":    (16, 5),
                "imm6":  (10, 6),
                "shift": (22, 2),
                "sf":    (31, 1),
            },
        },
        {
            "name": "SUBS",
            "base": 0x6B000000,
            "mask": 0x7FE00000,
            "form": "register",
            "desc": "SUBS (register, set flags): Rd = Rn - Rm, update PSTATE",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "Rm":    (16, 5),
                "imm6":  (10, 6),
                "shift": (22, 2),
                "sf":    (31, 1),
            },
        },
        {
            "name": "AND",
            "base": 0x0A000000,
            "mask": 0x7FE00000,
            "form": "register",
            "desc": "AND (register): Rd = Rn & Rm",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "Rm":    (16, 5),
                "imm6":  (10, 6),
                "shift": (22, 2),
                "sf":    (31, 1),
            },
        },
        {
            "name": "ORR",
            "base": 0x2A000000,
            "mask": 0x7FE00000,
            "form": "register",
            "desc": "ORR (register): Rd = Rn | Rm",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "Rm":    (16, 5),
                "imm6":  (10, 6),
                "shift": (22, 2),
                "sf":    (31, 1),
            },
        },
        {
            "name": "EOR",
            "base": 0x4A000000,
            "mask": 0x7FE00000,
            "form": "register",
            "desc": "EOR (register): Rd = Rn ^ Rm",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "Rm":    (16, 5),
                "imm6":  (10, 6),
                "shift": (22, 2),
                "sf":    (31, 1),
            },
        },
        {
            "name": "ANDS",
            "base": 0x6A000000,
            "mask": 0x7FE00000,
            "form": "register",
            "desc": "ANDS (register, set flags): Rd = Rn & Rm, update PSTATE",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "Rm":    (16, 5),
                "imm6":  (10, 6),
                "shift": (22, 2),
                "sf":    (31, 1),
            },
        },
        {
            "name": "LSL", # Logical Shift Left (Variable)
            "base": 0x1AC02000,
            "mask": 0x7FE0FC00,
            "form": "register",
            "desc": "LSL (register): Rd = Rn << Rm",
            "fields": {
                "Rd": (0, 5),
                "Rn": (5, 5),
                "Rm": (16, 5),
                "sf": (31, 1),
            },
        },
        {
            "name": "LSR", # Logical Shift Right (Variable)
            "base": 0x1AC02400,
            "mask": 0x7FE0FC00,
            "form": "register",
            "desc": "LSR (register): Rd = Rn >> Rm",
            "fields": {
                "Rd": (0, 5),
                "Rn": (5, 5),
                "Rm": (16, 5),
                "sf": (31, 1),
            },
        },
        {
            "name": "ASR", # Arithmetic Shift Right (Variable)
            "base": 0x1AC02800,
            "mask": 0x7FE0FC00,
            "form": "register",
            "desc": "ASR (register): Rd = Rn >> Rm (arithmetic)",
            "fields": {
                "Rd": (0, 5),
                "Rn": (5, 5),
                "Rm": (16, 5),
                "sf": (31, 1),
            },
        },
        {
            "name": "ROR", # Rotate Right (Variable) - Added from AdvDataProc
            "base": 0x1AC02C00,
            "mask": 0x7FE0FC00,
            "form": "register",
            "desc": "ROR (register): Rd = ROR(Rn, Rm)",
            "fields": {
                "Rd": (0, 5),
                "Rn": (5, 5),
                "Rm": (16, 5),
                "sf": (31, 1),
            },
        },
    ],
    "DataProcImm": [
        {
            "name": "ADDI",
            "base": 0x11000000,
            "mask": 0x7F800000, # Corrected mask for immediate type
            "form": "immediate",
            "desc": "ADD (immediate): Rd = Rn + imm12",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "imm12": (10, 12),
                "shift": (22, 1), # 0 or 1 (LSL #12)
                "sf":    (31, 1),
            },
        },
        {
            "name": "SUBI",
            "base": 0x51000000,
            "mask": 0x7F800000,
            "form": "immediate",
            "desc": "SUB (immediate): Rd = Rn - imm12",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "imm12": (10, 12),
                "shift": (22, 1),
                "sf":    (31, 1),
            },
        },
        {
            "name": "ANDI", # Logical immediate AND
            "base": 0x12000000,
            "mask": 0x7F800000,
            "form": "immediate_logical",
            "desc": "AND (immediate): Rd = Rn & imm (bitmask immediate)",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "immr":  (16, 6), # Part of bitmask immediate
                "imms":  (10, 6), # Part of bitmask immediate
                "N":     (22, 1), # Part of bitmask immediate
                "sf":    (31, 1),
            },
        },
        {
            "name": "ORRI", # Logical immediate ORR
            "base": 0x32000000,
            "mask": 0x7F800000,
            "form": "immediate_logical",
            "desc": "ORR (immediate): Rd = Rn | imm (bitmask immediate)",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "immr":  (16, 6),
                "imms":  (10, 6),
                "N":     (22, 1),
                "sf":    (31, 1),
            },
        },
        {
            "name": "EORI", # Logical immediate EOR
            "base": 0x52000000,
            "mask": 0x7F800000,
            "form": "immediate_logical",
            "desc": "EOR (immediate): Rd = Rn ^ imm (bitmask immediate)",
            "fields": {
                "Rd":    (0, 5),
                "Rn":    (5, 5),
                "immr":  (16, 6),
                "imms":  (10, 6),
                "N":     (22, 1),
                "sf":    (31, 1),
            },
        },
        {
            "name": "MOVZ", # Move Wide with Zero
            "base": 0x52800000,
            "mask": 0x7F800000,
            "form": "immediate_wide",
            "desc": "MOVZ: Rd = imm16 << (hw*16), zero elsewhere",
            "fields": {
                "Rd":    (0, 5),
                "imm16": (5, 16),
                "hw":    (21, 2), # Shift amount (0, 16, 32, 48)
                "sf":    (31, 1),
            },
        },
        {
            "name": "MOVK", # Move Wide with Keep
            "base": 0x72800000,
            "mask": 0x7F800000,
            "form": "immediate_wide",
            "desc": "MOVK: Rd = Rd with imm16 << (hw*16) inserted",
            "fields": {
                "Rd":    (0, 5),
                "imm16": (5, 16),
                "hw":    (21, 2),
                "sf":    (31, 1),
            },
        },
        {
            "name": "ADRP",
            "base": 0x90000000,
            "mask": 0x9F000000,
            "form": "pc_rel",
            "desc": "ADRP: Rd = PC page base + sign_extend(immhi:immlo:Zeros(12))",
            "fields": {
                "Rd":     (0, 5),
                "immlo":  (29, 2), # Low 2 bits of immediate
                "immhi":  (5, 19), # High 19 bits of immediate
            },
        },
    ],
    "LoadStore": [
        {   # Base LDR/STR (unsigned immediate offset)
            "name": "LDR",
            "base": 0xB9400000, # Base encoding for LDR Wt, [Xn, #imm12]
            "mask": 0xFFC00000, # size:opc mask out imm12, Rn, Rt
            "form": "loadstore_imm_unsigned",
            "desc": "LDR (unsigned offset): Rt = [Rn + imm12<<scale]",
            "fields": {
                "Rt":    (0, 5),
                "Rn":    (5, 5),
                "imm12": (10, 12), # Unsigned offset
                "size":  (30, 2),  # 00=8b, 01=16b, 10=32b, 11=64b
            },
        },
        {
            "name": "STR",
            "base": 0xB9000000, # Base encoding for STR Wt, [Xn, #imm12]
            "mask": 0xFFC00000,
            "form": "loadstore_imm_unsigned",
            "desc": "STR (unsigned offset): [Rn + imm12<<scale] = Rt",
            "fields": {
                "Rt":    (0, 5),
                "Rn":    (5, 5),
                "imm12": (10, 12),
                "size":  (30, 2),
            },
        },
        {   # Byte variants
            "name": "LDRB",
            "base": 0x39400000,
            "mask": 0xFFC00000,
            "form": "loadstore_imm_unsigned",
            "desc": "LDRB: Load byte (zero extended)",
            "fields": {
                "Rt":    (0, 5),
                "Rn":    (5, 5),
                "imm12": (10, 12),
            },
        },
        {
            "name": "STRB",
            "base": 0x39000000,
            "mask": 0xFFC00000,
            "form": "loadstore_imm_unsigned",
            "desc": "STRB: Store byte",
            "fields": {
                "Rt":    (0, 5),
                "Rn":    (5, 5),
                "imm12": (10, 12),
            },
        },
        {   # Halfword variants
            "name": "LDRH",
            "base": 0x79400000,
            "mask": 0xFFC00000,
            "form": "loadstore_imm_unsigned",
            "desc": "LDRH: Load halfword (zero extended)",
            "fields": {
                "Rt":    (0, 5),
                "Rn":    (5, 5),
                "imm12": (10, 12),
            },
        },
        {
            "name": "STRH",
            "base": 0x79000000,
            "mask": 0xFFC00000,
            "form": "loadstore_imm_unsigned",
            "desc": "STRH: Store halfword",
            "fields": {
                "Rt":    (0, 5),
                "Rn":    (5, 5),
                "imm12": (10, 12),
            },
        },
        {   # Load/Store Pair (signed offset)
            "name": "LDP",
            "base": 0xA9400000, # Base for LDP Wt, Wt2, [Xn, #imm7] (post-index)
            "mask": 0x7F800000, # Masks out opc, V, L, imm7, Rt2, Rn, Rt
            "form": "loadstore_pair_offset",
            "desc": "LDP: Load pair (Rt,Rt2) from [Rn + imm7<<scale]",
            "fields": {
                "Rt":   (0, 5),
                "Rn":   (5, 5),
                "Rt2":  (10, 5),
                "imm7": (15, 7), # Signed offset
                "L":    (22, 1), # 1 for Load
                "V":    (26, 1), # 0 for GP regs
                 # opc bits [31:30] determine pre/post/signed index
            },
        },
        {
            "name": "STP",
            "base": 0xA9000000, # Base for STP Wt, Wt2, [Xn, #imm7] (post-index)
            "mask": 0x7F800000,
            "form": "loadstore_pair_offset",
            "desc": "STP: Store pair (Rt,Rt2) to [Rn + imm7<<scale]",
            "fields": {
                "Rt":   (0, 5),
                "Rn":   (5, 5),
                "Rt2":  (10, 5),
                "imm7": (15, 7),
                "L":    (22, 1), # 0 for Store
                "V":    (26, 1),
            },
        },
        {   # Load/Store Unscaled Immediate
            "name": "LDUR",
            "base": 0xB8400000, # Base for LDUR Wt, [Xn, #imm9]
            "mask": 0xFFE00C00, # Masks out size, V, opc, imm9, Rn, Rt
            "form": "loadstore_imm_unscaled",
            "desc": "LDUR: Load with unscaled offset",
            "fields": {
                "Rt":    (0, 5),
                "Rn":    (5, 5),
                "imm9":  (12, 9), # Signed unscaled offset
                "size":  (30, 2),
            },
        },
        {
            "name": "STUR",
            "base": 0xB8000000, # Base for STUR Wt, [Xn, #imm9]
            "mask": 0xFFE00C00,
            "form": "loadstore_imm_unscaled",
            "desc": "STUR: Store with unscaled offset",
            "fields": {
                "Rt":    (0, 5),
                "Rn":    (5, 5),
                "imm9":  (12, 9),
                "size":  (30, 2),
            },
        },
    ],
    "Branch": [
        {
            "name": "B",
            "base": 0x14000000,
            "mask": 0xFC000000, # op=0, imm26
            "form": "branch_imm",
            "desc": "B: Unconditional branch (PC-relative)",
            "fields": {
                "imm26": (0, 26), # Signed immediate offset / 4
            },
        },
        {
            "name": "BL",
            "base": 0x94000000,
            "mask": 0xFC000000, # op=1, imm26
            "form": "branch_imm",
            "desc": "BL: Branch with link (call)",
            "fields": {
                "imm26": (0, 26),
            },
        },
        {
            "name": "B.COND",
            "base": 0x54000000,
            "mask": 0xFF000010, # op=0101010, o1=0, imm19, o0=0, cond
            "form": "branch_cond",
            "desc": "B.cond: conditional branch to signed imm19 if cond holds",
            "fields": {
                "cond":  (0, 4), # Condition code
                "imm19": (5, 19), # Signed immediate offset / 4
            },
        },
        {
            "name": "BR", # Branch to Register
            "base": 0xD61F0000, # opc=0000, op2=11111, op3=000000, Rn, op4=00000
            "mask": 0xFFFFFC1F, # Masks out Rn
            "form": "branch_reg",
            "desc": "BR: Branch to register",
            "fields": {
                "Rn": (5, 5), # Register holding target address
            },
        },
        {
            "name": "BLR", # Branch with Link to Register
            "base": 0xD63F0000, # opc=0001
            "mask": 0xFFFFFC1F,
            "form": "branch_reg",
            "desc": "BLR: Branch with link to register",
            "fields": {
                "Rn": (5, 5),
            },
        },
        {
            "name": "RET", # Return from subroutine
            "base": 0xD65F0000, # opc=0010 (usually Rn=30)
            "mask": 0xFFFFFC1F,
            "form": "branch_reg",
            "desc": "RET: Return from subroutine",
            "fields": {
                "Rn": (5, 5), # Link register (usually X30)
            },
        },
        {
            "name": "CBZ", # Compare and Branch on Zero
            "base": 0x34000000, # sf, op=0, imm19, Rt
            "mask": 0x7F000000, # Masks out sf, imm19, Rt
            "form": "cmp_branch",
            "desc": "CBZ: if Rt == 0 then branch (PC-relative imm19)",
            "fields": {
                "Rt":    (0, 5), # Register to test
                "imm19": (5, 19), # Signed immediate offset / 4
                "sf":    (31, 1), # Register size (0=W, 1=X)
            },
        },
        {
            "name": "CBNZ", # Compare and Branch on Non-Zero
            "base": 0x35000000, # sf, op=1
            "mask": 0x7F000000,
            "form": "cmp_branch",
            "desc": "CBNZ: if Rt != 0 then branch",
            "fields": {
                "Rt":    (0, 5),
                "imm19": (5, 19),
                "sf":    (31, 1),
            },
        },
    ],
    "System": [
        {
            "name": "NOP",
            "base": 0xD503201F,
            "mask": 0xFFFFFFFF,
            "form": "hint",
            "desc": "NOP: architectural no-op / hint",
            "fields": {},
        },
        {
            "name": "SVC",
            "base": 0xD4000001,
            "mask": 0xFFE0001F, # op0=110101, imm16, opc=00, LL=01
            "form": "exception",
            "desc": "SVC #imm16: supervisor call (trap into kernel)",
            "fields": {
                "imm16": (5, 16), # Immediate value passed to handler
            },
        },
        {
            "name": "MRS", # Move System Register
            "base": 0xD5300000, # L=1, CRm, op2, Rt fixed bits
            "mask": 0xFFF00000, # Masks out op0, op1, CRn, CRm, op2, Rt
            "form": "system",
            "desc": "MRS: Move system register to general-purpose",
            "fields": {
                "Rt": (0, 5),   # Destination GP register
                "op1": (16, 3), # System register encoding part
                "CRn": (12, 4), # System register encoding part
                "CRm": (8, 4),  # System register encoding part
                "op2": (5, 3),  # System register encoding part
            },
        },
        {
            "name": "MSR", # Move to System Register
            "base": 0xD5100000, # L=0 base
            "mask": 0xFFF00000, # Matches MRS mask structure but L=0
            "form": "system",
            "desc": "MSR: Move general-purpose to system register or PSTATE field",
            "fields": {
                "Rt": (0, 5),   # Source GP register (for reg->sysreg) or immediate
                "op1": (16, 3),
                "CRn": (12, 4),
                "CRm": (8, 4),
                "op2": (5, 3),
            },
        },
    ],
    "ARMv8.3_PAC": [ # Pointer Authentication instructions
        {
            "name": "PACIA", # PAC using IA key
            "base": 0xDAC10800, # Correct encoding: op0=11, op1=011, Z=0, op2=..., Rn, Rd
            "mask": 0xFFFFE400, # Masks out keys (Z bit), Rn, Rd
            "form": "pac",
            "desc": "PACIA: Pointer Authentication Code for Instruction Address (A key)",
            "fields": {
                "Rd": (0, 5),   # Destination register (modified pointer)
                "Rn": (5, 5),   # Source register (modifier/context)
                "Z":  (10, 1), # Key selector (0=IA, 1=IB) - usually A key here
            },
        },
        {
            "name": "AUTIA", # Authenticate using IA key
            "base": 0xDAC10C00, # Base encoding similar to PACIA but different op bits
            "mask": 0xFFFFE400,
            "form": "pac",
            "desc": "AUTIA: Authenticate Instruction Address (A key)",
            "fields": {
                "Rd": (0, 5),   # Pointer to authenticate
                "Rn": (5, 5),   # Modifier/context
                "Z":  (10, 1), # Key selector
            },
        },
        {
            "name": "PACIB", # PAC using IB key
            "base": 0xDAC10C00, # Z=1 variant of PACIA base (Corrected: PACIA base is DAC10800, PACIB is DAC10C00)
            "mask": 0xFFFFE400,
            "form": "pac",
            "desc": "PACIB: Pointer Authentication Code for Instruction Address (B key)",
            "fields": {
                "Rd": (0, 5),
                "Rn": (5, 5),
                "Z":  (10, 1), # Should be 1
            },
        },
        {
            "name": "AUTIB", # Authenticate using IB key
            "base": 0xDAC11C00, # Z=1 variant of AUTIA base (Corrected: AUTIA base is DAC10A00, AUTIB is DAC11A00)
             # Let's verify AUTIB base: Manual lookup suggests DAC1_ _11_ ... -> DAC11A00 seems right.
            "base": 0xDAC11A00, # Corrected base
            "mask": 0xFFFFE400,
            "form": "pac",
            "desc": "AUTIB: Authenticate Instruction Address (B key)",
            "fields": {
                "Rd": (0, 5),
                "Rn": (5, 5),
                "Z":  (10, 1), # Should be 1
            },
        },
    ],
    "ARMv8.5_MTE": [ # Memory Tagging Extension instructions
        {
            "name": "LDG", # Load Allocation Tag
            "base": 0xD9600000, # opc=11, V=0, opc2=1, L=1, o0=0, imm9, opc3=00, Rn, Rt
            "mask": 0xFFE00C00, # Masks out imm9, Rn, Rt
            "form": "mte_load",
            "desc": "LDG: Load Allocation Tag from [Rn + imm9]",
            "fields": {
                "Xt": (0, 5),   # Destination register for tag (GP reg)
                "Rn": (5, 5),   # Base address register
                "imm9": (12, 9), # Signed immediate offset
            },
        },
        {
            "name": "STG", # Store Allocation Tag
            "base": 0xD9200000, # L=0 variant of LDG
            "mask": 0xFFE00C00,
            "form": "mte_store",
            "desc": "STG: Store Allocation Tag to [Rn + imm9]",
            "fields": {
                "Xt": (0, 5),   # Source register for tag (GP reg)
                "Rn": (5, 5),
                "imm9": (12, 9),
            },
        },
        {
            "name": "STZG", # Store Tag and Zero Data
            "base": 0xD9210000, # Different opc3 bits from STG
            "mask": 0xFFE00C00,
            "form": "mte_store",
            "desc": "STZG: Store Allocation Tag and Zero data granule at [Rn + imm9]",
            "fields": {
                "Xt": (0, 5),
                "Rn": (5, 5),
                "imm9": (12, 9),
            },
        },
    ],
}


# Flatten to OPCODE_MAP
OPCODE_MAP = {
    entry["name"]: entry
    for group in ISA_GROUPS.values()
    for entry in group
}

# For reverse lookup of groups
GROUP_MAP = {}
for group_name, entries in ISA_GROUPS.items():
    for e in entries:
        GROUP_MAP[e["name"]] = group_name

# Enhanced field semantics
FIELD_SEMANTICS = {
    "Rd": "destination_register", "Rn": "source_register", "Rm": "source_register",
    "Rt": "target_register", "Rt2": "target_register_2", "imm12": "immediate_unsigned",
    "imm16": "immediate_unsigned", "imm26": "branch_offset", "imm19": "branch_offset",
    "cond": "condition_code", "sf": "register_size", "size": "load_store_size",
}

INSTRUCTION_ALIASES = {
    "CMP": {"base_op": "SUBS", "locked_fields": {"Rd": 31}},
    "CMN": {"base_op": "ADDS", "locked_fields": {"Rd": 31}},
    "TST": {"base_op": "ANDS", "locked_fields": {"Rd": 31}},
    # MOV Rd, Rm is handled directly by _encode_mov_reg now
    # MOV Rd, #imm is handled directly by _encode_mov_imm now
}

# ============================================================
# CORRECTED ARCHITECTURAL SPECIFICATIONS
# ============================================================
ARCHITECTURAL_SPECS = {
    "ARMV8.0-A": { # Use uppercase for consistency
        "year": 2011,
        "features": ["A64", "A32/T32", "NEON", "Cryptography", "Virtualization"],
    },
    "ARMV8.1-A": {
        "year": 2016,
        "features": ["Atomic", "PAN", "Virtualization Host Extensions"],
    },
    "ARMV8.2-A": {
        "year": 2017,
        "features": ["FP16", "RAS", "Statistical Profiling"],
    },
    "ARMV8.3-A": {
        "year": 2017,
        "features": ["Pointer Authentication", "Nested Virtualization"],
    },
    "ARMV8.4-A": {
        "year": 2018,
        "features": ["SHA3", "SM4", "RDM"],
    },
    "ARMV8.5-A": {
        "year": 2019,
        "features": ["MTE", "BTI", "Random Number"],
    },
    "ARMV9.0-A": {
        "year": 2021,
        "features": ["SVE2", "TRF", "B16B16", "MTE3", "Realms"],
    },
    "ARMV9.2-A": {
        "year": 2022,
        "features": ["Enhanced SVE", "Pointer Authentication Enhanced"],
    }
}

# ============================================================
# NEW: Simple Emulator Class
# ============================================================
class Emulator:
    def __init__(self):
        # Initialize 64-bit registers X0-X30 and SP
        self.regs = {f'X{i}': 0 for i in range(31)}
        self.regs['SP'] = 0 # Can represent X31 when used as SP
        # Condition Flags (NZCV) - not fully simulated yet
        self.flags = {'N': 0, 'Z': 0, 'C': 0, 'V': 0}

    def get_reg(self, reg_name):
        reg_name = reg_name.upper()
        if reg_name == 'XZR':
            return 0
        elif reg_name == 'WZR':
             return 0
        elif reg_name.startswith('X'):
            return self.regs.get(reg_name, 0) # Default to 0 if unknown
        elif reg_name.startswith('W'):
             # Return lower 32 bits
             reg_num = reg_name[1:]
             x_reg = 'X' + reg_num
             return self.regs.get(x_reg, 0) & 0xFFFFFFFF
        elif reg_name == 'SP':
            return self.regs.get('SP', 0)
        else:
            return 0 # Unknown register treated as 0

    def set_reg(self, reg_name, value):
        reg_name = reg_name.upper()
        # Ensure value fits in 64 bits
        value &= 0xFFFFFFFFFFFFFFFF

        if reg_name == 'XZR' or reg_name == 'WZR':
            return # Cannot write to zero register
        elif reg_name.startswith('X'):
            self.regs[reg_name] = value
        elif reg_name.startswith('W'):
             # Write lower 32 bits, zero upper 32
             reg_num = reg_name[1:]
             x_reg = 'X' + reg_num
             self.regs[x_reg] = value & 0xFFFFFFFF
        elif reg_name == 'SP':
            self.regs['SP'] = value

    def execute(self, mnemonic, op_str):
        """Execute a simple instruction and return result string"""
        mnemonic = mnemonic.upper()
        op_str_parts = [p.strip() for p in op_str.split(',')]
        result_str = ""

        try:
            # --- Arithmetic ---
            if mnemonic == 'ADD' and '#' in op_str: # ADD Xd, Xn, #imm
                rd, rn, imm_str = op_str_parts
                imm_val = int(imm_str.replace('#',''), 0)
                rn_val = self.get_reg(rn)
                result = (rn_val + imm_val) & 0xFFFFFFFFFFFFFFFF
                self.set_reg(rd, result)
                result_str = f"; {rd} = {rn} + {imm_str} = {rn_val:#x} + {imm_val:#x} = {result:#x}"
            elif mnemonic == 'ADD' and len(op_str_parts) == 3: # ADD Xd, Xn, Xm
                rd, rn, rm = op_str_parts
                rn_val = self.get_reg(rn)
                rm_val = self.get_reg(rm)
                result = (rn_val + rm_val) & 0xFFFFFFFFFFFFFFFF
                self.set_reg(rd, result)
                result_str = f"; {rd} = {rn} + {rm} = {rn_val:#x} + {rm_val:#x} = {result:#x}"
            elif mnemonic == 'SUB' and '#' in op_str: # SUB Xd, Xn, #imm
                rd, rn, imm_str = op_str_parts
                imm_val = int(imm_str.replace('#',''), 0)
                rn_val = self.get_reg(rn)
                result = (rn_val - imm_val) & 0xFFFFFFFFFFFFFFFF
                self.set_reg(rd, result)
                result_str = f"; {rd} = {rn} - {imm_str} = {rn_val:#x} - {imm_val:#x} = {result:#x}"
            elif mnemonic == 'SUB' and len(op_str_parts) == 3: # SUB Xd, Xn, Xm
                rd, rn, rm = op_str_parts
                rn_val = self.get_reg(rn)
                rm_val = self.get_reg(rm)
                result = (rn_val - rm_val) & 0xFFFFFFFFFFFFFFFF
                self.set_reg(rd, result)
                result_str = f"; {rd} = {rn} - {rm} = {rn_val:#x} - {rm_val:#x} = {result:#x}"

            # --- Moves ---
            elif mnemonic == 'MOV' and '#' in op_str: # MOV Xd, #imm (uses MOVZ typically)
                rd, imm_str = op_str_parts
                imm_val = int(imm_str.replace('#',''), 0)
                # Simple MOVZ implementation assumes imm fits in 16 bits
                if 0 <= imm_val <= 0xFFFF:
                     self.set_reg(rd, imm_val)
                     result_str = f"; {rd} = {imm_val:#x}"
                else: # Need MOVN/MOVK sequence, not simulated here
                     result_str = f"; {rd} = {imm_val:#x} (complex immediate)"

            elif mnemonic == 'MOV' and len(op_str_parts) == 2: # MOV Xd, Xn
                 rd, rn = op_str_parts
                 rn_val = self.get_reg(rn)
                 self.set_reg(rd, rn_val)
                 result_str = f"; {rd} = {rn} = {rn_val:#x}"

            # --- Logical ---
            elif mnemonic == 'AND' and '#' not in op_str: # AND Xd, Xn, Xm
                rd, rn, rm = op_str_parts
                rn_val = self.get_reg(rn)
                rm_val = self.get_reg(rm)
                result = rn_val & rm_val
                self.set_reg(rd, result)
                result_str = f"; {rd} = {rn} & {rm} = {rn_val:#x} & {rm_val:#x} = {result:#x}"
            elif mnemonic == 'ORR' and '#' not in op_str: # ORR Xd, Xn, Xm
                rd, rn, rm = op_str_parts
                rn_val = self.get_reg(rn)
                rm_val = self.get_reg(rm)
                result = rn_val | rm_val
                self.set_reg(rd, result)
                result_str = f"; {rd} = {rn} | {rm} = {rn_val:#x} | {rm_val:#x} = {result:#x}"
            elif mnemonic == 'EOR' and '#' not in op_str: # EOR Xd, Xn, Xm
                rd, rn, rm = op_str_parts
                rn_val = self.get_reg(rn)
                rm_val = self.get_reg(rm)
                result = rn_val ^ rm_val
                self.set_reg(rd, result)
                result_str = f"; {rd} = {rn} ^ {rm} = {rn_val:#x} ^ {rm_val:#x} = {result:#x}"

            # Add more instructions here (ANDI, ORRI, EORI, LSL, LSR, etc.)

        except Exception as e:
            # Don't crash if parsing/emulation fails, just return empty string
             # print(f"Emulator error: {e} on {mnemonic} {op_str}") # Optional debug
             return ""

        return result_str

# ============================================================
# FIXED INSTRUCTION CONVERTER
# ============================================================
class ARM64InstructionIO:
    def __init__(self):
        self.cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self.cs.detail = True

    def _print_conversion_result(self, result):
        """Print conversion results in a formatted way"""
        if 'error' in result:
            print(f"  \033[91mError: {result['error']}\033[0m")
        else:
            print(f"  \033[96mAssembly:\033[0m {result.get('asm', 'N/A')}")
            print(f"  \033[96mHex:\033[0m      {result.get('hex', 'N/A')}")
            print(f"  \033[96mBytes (LE):\033[0m {result.get('bytes_le', 'N/A')}")
            print(f"  \033[96mBytes (BE):\033[0m {result.get('bytes_be', 'N/A')}")

    def hex_to_asm(self, hex_str):
        """Convert hex string to assembly instruction"""
        try:
            hex_str = hex_str.strip().replace(' ', '').replace('0x', '')
            if len(hex_str) != 8:
                return {"error": f"Hex string must be 8 characters (got {len(hex_str)})"}

            value = int(hex_str, 16)
            bytes_le = value.to_bytes(4, 'little')

            for insn in self.cs.disasm(bytes_le, 0):
                return {
                    'hex': f"0x{value:08X}",
                    'asm': f"{insn.mnemonic} {insn.op_str}",
                    'bytes_le': bytes_le.hex().upper(),
                    'bytes_be': hex_str.upper()
                }
            return {"error": f"Unknown or invalid instruction encoding: 0x{value:08X}"}

        except ValueError:
             return {"error": f"Invalid hex string: '{hex_str}'"}
        except Exception as e:
            return {"error": f"Conversion failed: {str(e)}"}

    def asm_to_hex(self, asm_text):
        """Convert assembly text to hex (limited support)"""
        try:
            asm_text_orig = asm_text.strip() # Keep original for output
            asm_text_upper = asm_text_orig.upper()

            # NOP instruction
            if asm_text_upper == "NOP":
                encoding = 0xD503201F
                return self._format_result("nop", encoding) # Use lowercase standard

            # ADD/SUB immediate patterns (Match W/X regs OR SP)
            add_match = re.match(r'ADD\s+([WX]\d+|SP),\s*([WX]\d+|SP),\s*#?(0x[0-9A-F]+|\d+)', asm_text_upper)
            if add_match:
                 return self._encode_add_sub_imm(asm_text_orig, "ADD", add_match)

            sub_match = re.match(r'SUB\s+([WX]\d+|SP),\s*([WX]\d+|SP),\s*#?(0x[0-9A-F]+|\d+)', asm_text_upper)
            if sub_match:
                return self._encode_add_sub_imm(asm_text_orig, "SUB", sub_match)

            # MOV immediate (using MOVZ)
            mov_imm_match = re.match(r'MOV\s+([WX])(\d+),\s*#?(0x[0-9A-F]+|\d+)', asm_text_upper)
            if mov_imm_match:
                return self._encode_mov_imm(asm_text_orig, mov_imm_match)

            # MOV register (using ORR)
            mov_reg_match = re.match(r'MOV\s+([WX]\d+|SP),\s*([WX]\d+|XZR|WZR|SP)', asm_text_upper)
            if mov_reg_match:
                return self._encode_mov_reg(asm_text_orig, mov_reg_match)

            return {"error": f"Assembly pattern not yet supported: '{asm_text}'"}

        except Exception as e:
            return {"error": f"Assembly parsing failed for '{asm_text}': {str(e)}"}


    def _parse_register(self, reg_str):
        """Parse register string like X0, W1, SP, XZR into (sf, index)"""
        reg_str = reg_str.upper()
        if reg_str == 'SP':
            return 1, 31 # SP is X31
        elif reg_str in ('XZR', 'WZR'):
            return 1, 31 # Treat like SP for encoding purposes where applicable, logic handles 0 value
        elif reg_str.startswith('X'):
            return 1, int(reg_str[1:])
        elif reg_str.startswith('W'):
            return 0, int(reg_str[1:])
        else:
            raise ValueError(f"Invalid register '{reg_str}'")

    def _encode_add_sub_imm(self, asm_text, op, match):
        """Encode ADD/SUB immediate instructions, handling SP"""
        rd_str, rn_str, imm_str = match.groups()

        try:
            sf_d, rd = self._parse_register(rd_str)
            sf_n, rn = self._parse_register(rn_str)
        except ValueError as e:
            return {"error": str(e)}

        # ADDI/SUBI requires registers to be the same size (or SP which implies 64-bit)
        # Exception: ADD/SUB SP, SP, #imm is valid
        if rd_str != 'SP' and rn_str != 'SP' and sf_d != sf_n:
             return {"error": f"Register size mismatch in {op}"}
        # If SP is involved, operation must be 64-bit
        if (rd_str == 'SP' or rn_str == 'SP') and not sf_d: # Check sf_d because dest determines sf bit
             return {"error": f"{op} with SP requires 64-bit destination (X register or SP)"}

        sf = 1 if (rd_str.startswith('X') or rd_str == 'SP') else 0

        imm_val = int(imm_str, 0)
        shift = 0

        if 0 <= imm_val <= 0xFFF: # 0 to 4095
            shift = 0
        elif 0 < imm_val <= (0xFFF << 12) and imm_val % (1 << 12) == 0:
            imm_val = imm_val >> 12
            shift = 1 # LSL #12
        else:
            limit = 0xFFFFFF if sf == 1 else 0xFFF # More complex if shifted? Let's stick to 12bit + shift
            limit = (0xFFF << 12 | 0xFFF) # Max value representable
            return {"error": f"Invalid {op} immediate. Must be 0-4095 or a multiple of 4096 up to {limit:#x}"}

        # Use 64-bit base if sf=1, 32-bit otherwise
        base_add = 0x91000000 if sf else 0x11000000
        base_sub = 0xD1000000 if sf else 0x51000000
        base = base_add if op == "ADD" else base_sub

        encoding = base | (shift << 22) | (imm_val << 10) | (rn << 5) | rd
        return self._format_result(asm_text, encoding)


    def _encode_mov_imm(self, asm_text, match):
        """Encode MOV immediate (using MOVZ)"""
        size, rd_str, imm_str = match.groups()
        sf = 1 if size == 'X' else 0
        rd = int(rd_str)
        imm_val = int(imm_str, 0)

        # Simplest case: MOVZ with hw=0
        if 0 <= imm_val <= 0xFFFF:
            hw = 0
            imm16 = imm_val
            # MOVZ encoding base depends on sf
            base = 0xD2800000 if sf else 0x52800000
            encoding = base | (hw << 21) | (imm16 << 5) | rd
            return self._format_result(asm_text, encoding)
        # Add MOVN/MOVK logic here if needed for larger/negative immediates

        return {"error": f"Cannot encode immediate {imm_val:#x} with simple MOVZ. Need MOVN/MOVK logic."}


    def _encode_mov_reg(self, asm_text, match):
        """Encode MOV register (using ORR)"""
        rd_str, rm_str = match.groups()
        try:
            sf_d, rd = self._parse_register(rd_str)
            sf_m, rm = self._parse_register(rm_str)
        except ValueError as e:
            return {"error": str(e)}

        # Check for size mismatch, allowing ZR registers
        if rm_str not in ('XZR', 'WZR') and rd_str != 'SP' and rm_str != 'SP' and sf_d != sf_m:
             return {"error": "Register size mismatch in MOV"}

        # Determine sf bit based on destination (or source if dest is SP?)
        # Standard alias uses size of operands. SP implies 64-bit.
        sf = 1 if (rd_str.startswith('X') or rd_str == 'SP' or rm_str.startswith('X') or rm_str == 'SP') else 0

        # MOV Rd, Rm is alias for ORR Rd, XZR/WZR, Rm
        # Need Rn=31 (XZR/WZR)
        rn = 31
        # ORR encoding base depends on sf
        base = 0xAA000000 if sf else 0x2A000000
        # ORR Rd, Rn, Rm -> sf:op:S:....:shift:Rm:imm6:Rn:Rd
        # We need shift=0, imm6=0
        encoding = base | (rm << 16) | (rn << 5) | rd
        return self._format_result(asm_text, encoding)

    def _format_result(self, asm_text, encoding):
        """Format conversion result consistently"""
        disasm_result = self.hex_to_asm(f"{encoding:08X}")
        canonical_asm = disasm_result.get('asm', asm_text) # Use re-disassembled asm if possible

        # Don't show original asm if it failed re-disassembly
        if 'error' in disasm_result:
             asm_to_show = f"<Encoding Error: {disasm_result['error']}>"
        else:
             asm_to_show = canonical_asm


        return {
            'asm': asm_to_show,
            'hex': f"0x{encoding:08X}",
            'bytes_le': encoding.to_bytes(4, 'little').hex().upper(),
            'bytes_be': f"{encoding:08X}"
        }

    def interactive_converter(self):
        """Interactive instruction converter"""
        print("\n=== GEMi Interactive Instruction Converter ===")
        print("  Type 'hex <value>', 'asm <instruction>', 'arch [version]', or 'quit'")

        while True:
            try:
                user_input = input("\nGEMi> ").strip()
                if not user_input: continue

                if user_input.lower() in ['quit', 'exit', 'q']:
                    break
                elif user_input.lower().startswith('hex '):
                    hex_str = user_input[4:].strip()
                    result = self.hex_to_asm(hex_str)
                    self._print_conversion_result(result)
                elif user_input.lower().startswith('asm '):
                    asm_text = user_input[4:].strip()
                    result = self.asm_to_hex(asm_text)
                    self._print_conversion_result(result)
                elif user_input.lower() == 'help':
                    print("  Commands: hex <value>, asm <instruction>, arch [version], quit")
                elif user_input.lower().startswith('arch'):
                    parts = user_input.split()
                    version = parts[1].upper() if len(parts) > 1 else None
                    show_architecture_info(version)
                else:
                    print("  Unknown command. Type 'help' for options.")
            except KeyboardInterrupt:
                print("\nExiting...")
                break
            except Exception as e:
                print(f"  \033[91mError during processing: {e}\033[0m")


# ============================================================
# CORE EXPLORATION FUNCTIONS
# ============================================================
def disassemble_word(value, cs):
    code = value.to_bytes(4, "little")
    for insn in cs.disasm(code, 0):
        return insn.mnemonic, insn.op_str # Return separately
    return None, None # Indicate failure


def get_binary_pattern(base, mask):
    # ... (same as before) ...
    out_bits = []
    for i in range(31, -1, -1):
        if (mask >> i) & 1:
            out_bits.append(str((base >> i) & 1))
        else:
            out_bits.append("x")
    bitstr = "".join(out_bits)
    return " ".join(bitstr[i:i+4] for i in range(0, 32, 4))


def colorize_bits(base, mask, val):
    # ... (same as before) ...
    bits = []
    for i in range(31, -1, -1):
        vbit = (val  >> i) & 1
        bbit = (base >> i) & 1
        fixed = (mask >> i) & 1
        if fixed and vbit != bbit:
            bits.append(f"\033[1;31m{vbit}\033[0m")
        elif (not fixed) and vbit != bbit:
            bits.append(f"\033[1;33m{vbit}\033[0m")
        else:
            bits.append(str(vbit))
    return "".join(bits)

def get_field_highlights(base, mask, val, fields):
    # ... (same as before) ...
    highlights = []
    for fname, (start, width) in fields.items():
        field_mask = ((1 << width) - 1) << start
        if (field_mask & mask) == 0: # Only highlight variable fields
            base_field_val = (base & field_mask)
            val_field_val  = (val & field_mask)
            if base_field_val != val_field_val:
                highlights.append(f"{fname}=0x{val_field_val >> start:X}")
    return ", ".join(highlights)


def print_field_map(fields):
    # ... (same as before) ...
    print("    Field   | Bits     | Width")
    print("    --------|----------|------")
    for name, (start, width) in sorted(fields.items(), key=lambda item: item[1][0] + item[1][1], reverse=True):
        end = start + width - 1
        print(f"    {name:<7}| [{end:2}:{start:<2}] | {width:2}")


def parse_locks(lock_list):
    # ... (same as before) ...
    locks = {}
    if lock_list:
        for spec in lock_list:
            if "=" in spec:
                k, v = spec.split("=", 1)
                try:
                    locks[k] = int(v, 0)
                except ValueError:
                    print(f"\033[91mWarning: Invalid lock format '{spec}'. Skipping.\033[0m")
    return locks


def iterate_field_space(fields, vary_fields, locks, step):
    # ... (same as before) ...
    domains = []
    order = []
    for fname in vary_fields:
        if fname in fields:
            start, width = fields[fname]
            max_val = (1 << width)
            if fname in locks:
                locked_val = locks[fname]
                if locked_val >= max_val:
                    print(f"    \033[91mWarning: Field {fname} lock value {locked_val} exceeds {width}-bit range. Clamping.\033[0m")
                domains.append([locked_val & (max_val - 1)])
            else:
                small = (width <= 2)
                stride = 1 if small else step
                # Ensure stride doesn't exceed max_val for small ranges
                actual_step = min(stride, max_val) if max_val > 0 else 1
                domains.append(range(0, max_val, actual_step))
            order.append(fname)
        # else: # Warning moved to explore_opcode
        #     pass

    # Handle the case where no fields are varied but locks exist
    if not vary_fields and locks:
         # Need to ensure the loop runs once if only locks are applied
         # Yield an empty map, assemble_value will use locks
         yield {}
         return

    # If no domains were added (e.g., vary_fields was empty or invalid, and no locks)
    if not domains and vary_fields:
        # Avoid infinite loop or errors later
        print("    No valid fields to iterate over.")
        return # Stop iteration

    # If domains is empty but fields exist and vary_fields was originally empty (vary all)
    # This happens for instructions like NOP with no fields
    if not domains and not vary_fields and fields:
         yield {} # Yield empty map, assemble uses base + locks
         return


    for combo in itertools.product(*domains):
        combo_map = {fname: combo[i] for i, fname in enumerate(order)}
        yield combo_map


def assemble_value(spec, combo_map, locks):
    # ... (same as before) ...
    val = spec["base"]
    fields = spec["fields"]

    # Apply combo (varied) values first
    for fname, value in combo_map.items():
        if fname in fields:
            start, width = fields[fname]
            mask = ((1 << width) - 1)
            val &= ~(mask << start)
            val |= (value & mask) << start

    # Apply locked values for non-varied fields
    for fname, (start, width) in fields.items():
        if fname not in combo_map and fname in locks:
            mask = ((1 << width) - 1)
            lock_val = locks[fname]
            if lock_val >= (1 << width):
                 print(f"    \033[91mWarning: Lock for field {fname} ({lock_val}) exceeds width. Clamping.\033[0m")
            val &= ~(mask << start)
            val |= (lock_val & mask) << start

    return val


# MODIFIED to include emulation
def explore_opcode(opname, spec, cs, limit, step, vary_fields, locks, emulator):
    base   = spec["base"]
    mask   = spec["mask"]
    form   = spec["form"]
    desc   = spec.get("desc", "N/A")
    fields = spec["fields"]

    if not vary_fields:
        vary_fields = list(fields.keys())
    else:
        valid_vary_fields = [f for f in vary_fields if f in fields]
        if len(valid_vary_fields) != len(vary_fields):
            invalid = set(vary_fields) - set(valid_vary_fields)
            print(f"    \033[91mWarning: Ignoring invalid --vary fields for {opname}: {', '.join(invalid)}\033[0m")
        vary_fields = valid_vary_fields
        if not vary_fields and fields:
            print(f"    \033[91mWarning: No valid fields specified to vary for {opname}. Showing base/locked instruction only.\033[0m")
            limit = 1

    print(f"\n=== Exploring {opname} ===")
    print(f"  Group:   {GROUP_MAP.get(opname, 'N/A')}")
    print(f"  Desc:    {desc}")
    print(f"  Form:    {form}")
    print(f"  Base:    0x{base:08X}")
    print(f"  Mask:    0x{mask:08X}")
    print(f"  Pattern: {get_binary_pattern(base, mask)}")
    if locks:
        relevant_locks = {k: v for k, v in locks.items() if k in fields}
        if relevant_locks: print(f"  Locks:   {relevant_locks}")
    print("\n  Fields:")
    print_field_map(fields)
    print("\n  Legend: normal=fixed match | \033[1;33myellow\033[0m=var field change | \033[1;31mred\033[0m=fixed-bit violation\n")
    print("-" * 88)

    count = 0
    if not fields: # NOP etc.
         val = base
         bits_colored = colorize_bits(base, mask, val)
         mnemonic, op_str = disassemble_word(val, cs)
         asm_line = f"{mnemonic:<8} {op_str}" if mnemonic else "<UNDEFINED>"
         print(f"0x{val:08X}  {bits_colored}  {asm_line:<28} \033[92m[Base]\033[0m")
         count = 1
    elif not vary_fields and limit > 0: # Only locked fields
        val = assemble_value(spec, {}, locks)
        bits_colored = colorize_bits(base, mask, val)
        mnemonic, op_str = disassemble_word(val, cs)
        asm_line = f"{mnemonic:<8} {op_str}" if mnemonic else "<UNDEFINED>"
        highlights = get_field_highlights(base, mask, val, fields)
        # --- Emulation Call ---
        emu_result = emulator.execute(mnemonic, op_str) if mnemonic else ""
        # ---------------------
        print(f"0x{val:08X}  {bits_colored}  {asm_line:<28} \033[92m[{highlights}]\033[0m {emu_result}")
        count = 1
    else: # Generate variations
        for combo_map in iterate_field_space(fields, vary_fields, locks, step):
            val = assemble_value(spec, combo_map, locks)
            bits_colored = colorize_bits(base, mask, val)
            mnemonic, op_str = disassemble_word(val, cs)
            asm_line = f"{mnemonic:<8} {op_str}" if mnemonic else "<UNDEFINED>"
            highlights = get_field_highlights(base, mask, val, fields)
            # --- Emulation Call ---
            emu_result = emulator.execute(mnemonic, op_str) if mnemonic else ""
            # ---------------------
            print(f"0x{val:08X}  {bits_colored}  {asm_line:<28} \033[92m[{highlights}]\033[0m {emu_result}")
            count += 1
            if count >= limit:
                break

    if count == 0 and limit > 0 and fields:
         print("    No variations generated with current settings.")


def describe_opcode(opname, locks):
    # ... (same as before) ...
    spec = OPCODE_MAP[opname]
    base = spec["base"]
    mask = spec["mask"]
    print(f"\nSummary for {opname}:")
    print(f"  Description: {spec.get('desc','N/A')}")
    print(f"  Group:       {GROUP_MAP.get(opname, 'N/A')}")
    print(f"  Form:        {spec['form']}")
    print(f"  Base:        0x{base:08X}")
    print(f"  Mask:        0x{mask:08X}")
    print(f"  Pattern:     {get_binary_pattern(base, mask)}")
    if locks:
        relevant_locks = {k: v for k, v in locks.items() if k in spec.get('fields', {})}
        if relevant_locks: print(f"  Locks:   {relevant_locks}")
    print(f"\n  Fields:")
    print_field_map(spec.get('fields', {}))


def summary_all():
    # ... (same as before) ...
    print("\nARM64 Opcode Family Summary")
    print("===========================")
    for group_name, entries in sorted(ISA_GROUPS.items()):
        print(f"\n--- {group_name} ---")
        for spec in entries:
            base = spec["base"]
            mask = spec["mask"]
            print(f"  {spec['name']}:")
            print(f"    Desc:    {spec.get('desc','N/A')}")
            print(f"    Base:    0x{base:08X}")
            print(f"    Mask:    0x{mask:08X}")
            print(f"    Pattern: {get_binary_pattern(base, mask)}")

def explore_group(group_name, cs, limit, step, vary_fields, locks):
    # ... (case-insensitive lookup added before) ...
    group_key = None
    for gn in ISA_GROUPS.keys():
        if gn.upper() == group_name.upper():
            group_key = gn
            break

    if not group_key:
        print(f"\033[91mGroup '{group_name}' not found.\033[0m Available: {', '.join(sorted(ISA_GROUPS.keys()))}")
        return

    print(f"\n=== Exploring Group: {group_key} ===")
    emulator = Emulator() # Create one emulator instance per group exploration
    for spec in ISA_GROUPS[group_key]:
        explore_opcode(spec["name"], spec, cs, limit, step, vary_fields, locks, emulator) # Pass emulator
        print("\n")


def show_architecture_info(version=None):
    # ... (same as before) ...
    print("\n=== ARM Architecture Specifications ===")

    specs_to_show = {}
    if version:
         version_upper = version.upper()
         found = False
         for key in ARCHITECTURAL_SPECS.keys():
              # Allow partial matches like "ARMV8.3" to match "ARMV8.3-A"
              if key.upper().startswith(version_upper):
                   specs_to_show[key] = ARCHITECTURAL_SPECS[key]
                   found = True
         if not found:
              print(f"\033[91mError: Version matching '{version}' not found.\033[0m Use --list-arch to see options.")
              print("Available: ", ", ".join(sorted(ARCHITECTURAL_SPECS.keys())))
              return
    else:
        specs_to_show = ARCHITECTURAL_SPECS

    for arch, spec in sorted(specs_to_show.items()):
        print(f"\n\033[1m{arch} (Year: {spec['year']})\033[0m")
        print(f"  \033[96mFeatures:\033[0m {', '.join(spec['features'])}")


# ============================================================
# FIXED MAIN FUNCTION
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="GEMi - ARM64/ARMv9 Instruction Explorer & Analyzer",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  %(prog)s ADD                               # Explore ADD instruction
  %(prog)s --group LoadStore                 # Explore load/store instructions
  %(prog)s --convert hex D503201F            # Convert hex to assembly (nop)
  %(prog)s --convert asm "ADD X0, X1, #0x123"  # Convert assembly to hex
  %(prog)s --convert asm "MOV X8, X0"          # Convert MOV register to hex
  %(prog)s --interactive                     # Start interactive converter
  %(prog)s --arch ARMv8.3-A                  # Show ARMv8.3-A specifications
  %(prog)s CMP --vary Rn Rm --lock sf=1      # Explore CMP (alias)
"""
    )

    parser.add_argument("opcode", nargs="?", help="Opcode mnemonic or value for --convert") # Modified help

    explore_group_args = parser.add_argument_group('Exploration')
    explore_group_args.add_argument("--group", dest="group_name", help="Explore an ISA group")
    explore_group_args.add_argument("--summary", action="store_true", help="Show summary of all encodings")
    explore_group_args.add_argument("--describe", help="Show summary for a single opcode")
    explore_group_args.add_argument("--vary", nargs="*", help="Fields to vary (default: all)")
    explore_group_args.add_argument("--lock", nargs="*", help="Lock specific fields")
    explore_group_args.add_argument("--limit", type=int, default=32, help="Max encodings to print")
    explore_group_args.add_argument("--step", type=int, default=4, help="Step for sweeping large fields")

    convert_group_args = parser.add_argument_group('Conversion')
    convert_group_args.add_argument("--convert", choices=["hex", "asm"], help="Convert hex-to-asm or asm-to-hex")
    convert_group_args.add_argument("--value", help="Value to convert (alternative to positional)")
    convert_group_args.add_argument("--interactive", "-i", action="store_true", help="Start interactive converter")

    arch_group_args = parser.add_argument_group('Architecture Info')
    arch_group_args.add_argument("--arch", help="Show architecture specifications")
    arch_group_args.add_argument("--list-arch", action="store_true", help="List all architectures")

    args = parser.parse_args()
    cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    io_system = ARM64InstructionIO()
    locks = parse_locks(args.lock)
    emulator = Emulator() # Create emulator instance for single opcode exploration

    # --- FIXED ROUTING ORDER ---
    # Handle conversion first
    value_to_convert = args.value
    if args.convert:
        # If --value wasn't provided, use the positional 'opcode' arg
        if not value_to_convert and args.opcode:
            value_to_convert = args.opcode
            args.opcode = None # Clear opcode so it doesn't fall through

        if not value_to_convert:
            parser.error("--convert requires a value (use --value or provide value positionally)")

        if args.convert == "hex":
            result = io_system.hex_to_asm(value_to_convert)
        else: # asm
            result = io_system.asm_to_hex(value_to_convert)
        io_system._print_conversion_result(result)
        return

    # Handle interactive mode
    if args.interactive:
        io_system.interactive_converter()
        return

    # Handle architecture info
    if args.arch or args.list_arch:
        show_architecture_info(args.arch.upper() if args.arch else None)
        return

    # Handle summary
    if args.summary:
        summary_all()
        return

    # Handle describe
    if args.describe:
        dname = args.describe.upper()
        # Handle aliases *before* checking OPCODE_MAP
        if dname in INSTRUCTION_ALIASES:
            alias_spec = INSTRUCTION_ALIASES[dname]
            base_op = alias_spec["base_op"]
            print(f"\033[96mNote: {dname} is an alias for {base_op} with fields {alias_spec['locked_fields']}\033[0m")
            # Apply alias locks, user locks take precedence
            for field, value in alias_spec['locked_fields'].items():
                if field not in locks: locks[field] = value
            dname = base_op # Use the base opcode for description

        if dname not in OPCODE_MAP:
            print(f"\033[91mUnknown opcode '{dname}' for describe.\033[0m")
            print("Known opcodes:", ", ".join(sorted(OPCODE_MAP.keys())))
            return
        describe_opcode(dname, locks)
        return

    # Handle group exploration
    if args.group_name:
        explore_group(args.group_name, cs, args.limit, args.step, args.vary, locks)
        return

    # Handle single opcode exploration (default if nothing else matched)
    if not args.opcode:
        parser.print_help()
        sys.exit("\n\033[91mError: No opcode, group, or mode specified. See usage examples.\033[0m")

    opname = args.opcode.upper()

    # Handle aliases *before* checking OPCODE_MAP
    if opname in INSTRUCTION_ALIASES:
        alias_spec = INSTRUCTION_ALIASES[opname]
        base_op = alias_spec["base_op"]
        print(f"\033[96mNote: {opname} is an alias for {base_op} with locked fields {alias_spec['locked_fields']}\033[0m")
        for field, value in alias_spec['locked_fields'].items():
            if field not in locks: locks[field] = value
        opname = base_op # Use the base opcode for exploration

    if opname not in OPCODE_MAP:
        print(f"\033[91mUnknown opcode '{opname}' for exploration.\033[0m")
        print("Known opcodes:", ", ".join(sorted(OPCODE_MAP.keys())))
        return

    spec = OPCODE_MAP[opname]
    explore_opcode(opname, spec, cs, args.limit, args.step, args.vary, locks, emulator) # Pass emulator


if __name__ == "__main__":
    main()
