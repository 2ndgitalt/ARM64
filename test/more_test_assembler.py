import pytest
import sys
import os

# Add the parent directory to the path so we can import ARMv9
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ARMv9 import ARM64InstructionIO, Emulator


def test_add_immediate_with_sp():
    io = ARM64InstructionIO()
    result = io.asm_to_hex("ADD SP, SP, #0x40")
    assert 'error' not in result
    # SP is register 31, so this should encode correctly
    assert result['hex'] == '0x910003FF'  # ADD SP, SP, #0x40


def test_mov_register_encoding():
    io = ARM64InstructionIO()
    result = io.asm_to_hex("MOV X0, X1")
    assert 'error' not in result
    # MOV X0, X1 is alias for ORR X0, XZR, X1
    assert result['hex'] == '0xAA0103E0'


def test_hex_to_asm_roundtrip():
    io = ARM64InstructionIO()
    hex_val = "0x91048C20"
    asm_result = io.hex_to_asm(hex_val)
    hex_result = io.asm_to_hex(asm_result['asm'])
    assert hex_result['hex'] == hex_val


def test_emulator_overflow_handling():
    emu = Emulator()
    emu.set_reg('X0', 0xFFFFFFFFFFFFFFFF)
    message = emu.execute('ADD', 'X0, X0, #1')
    # Should handle 64-bit overflow correctly
    assert emu.get_reg('X0') == 0x0
    assert 'overflow' in message.lower() or '0x0' in message