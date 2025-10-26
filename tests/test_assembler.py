import pytest

from ARMv9 import ARM64InstructionIO, Emulator


def test_add_immediate_encoding_basic():
    io = ARM64InstructionIO()
    result = io.asm_to_hex("ADD X0, X1, #0x123")
    assert 'error' not in result
    assert result['hex'] == '0x91048C20'
    assert result['bytes_le'] == '208C0491'
    assert result['bytes_be'] == '91048C20'


@pytest.mark.parametrize(
    "asm_variant",
    [
        "ADD X0, X1, # 0x123",
        "ADD X0, X1, 0x123",
        "ADD X0, X1, #291",
        "ADD X0, X1, 291",
    ],
)
def test_add_immediate_regex_variants(asm_variant):
    io = ARM64InstructionIO()
    result = io.asm_to_hex(asm_variant)
    assert 'error' not in result
    assert result['hex'] == '0x91048C20'


def test_add_immediate_encoding_shifted():
    io = ARM64InstructionIO()
    result = io.asm_to_hex("ADD X0, X1, #0x3000")
    assert 'error' not in result
    assert result['hex'] == '0x91400C20'


def test_add_immediate_invalid_range():
    io = ARM64InstructionIO()
    result = io.asm_to_hex("ADD X0, X1, #0x12345")
    assert 'error' in result
    assert "Invalid ADD immediate" in result['error']


def test_parse_register_sp_and_zero():
    io = ARM64InstructionIO()
    assert io._parse_register('SP') == (1, 31)
    assert io._parse_register('x0') == (1, 0)
    assert io._parse_register('w1') == (0, 1)
    assert io._parse_register('XZR') == (1, 31)
    assert io._parse_register('wzr') == (1, 31)


def test_emulator_add_immediate_execution():
    emu = Emulator()
    emu.set_reg('X1', 5)
    message = emu.execute('ADD', 'X0, X1, #0x3')
    assert emu.get_reg('X0') == 8
    assert '; X0 = X1 + #0x3' in message


def test_emulator_add_register_execution():
    emu = Emulator()
    emu.set_reg('X1', 5)
    emu.set_reg('X2', 6)
    message = emu.execute('ADD', 'X0, X1, X2')
    assert emu.get_reg('X0') == 11
    assert '; X0 = X1 + X2' in message


def test_emulator_mov_and_sub():
    emu = Emulator()
    emu.execute('MOV', 'X0, #0x10')
    assert emu.get_reg('X0') == 0x10
    emu.set_reg('X1', 4)
    msg = emu.execute('SUB', 'X0, X0, X1')
    assert emu.get_reg('X0') == 0xC
    assert '; X0 = X0 - X1' in msg
